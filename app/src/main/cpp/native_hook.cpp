#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include "dobby.h"

#define TAG "NativeCryptoHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

typedef void (*CreateFunc)(JNIEnv*, jobject, jbyteArray, jbyteArray);
static CreateFunc original_create = nullptr;

// ============================================================
//  دالة ذكية للحصول على Base Address لأي مكتبة محمّلة
//  تعمل حتى مع المكتبات المضغوطة (stripped) بدون رموز مصدّرة
// ============================================================
struct FindModuleCtx {
    const char* name;
    uintptr_t   base;
};

static int find_module_cb(struct dl_phdr_info* info, size_t size, void* data) {
    FindModuleCtx* ctx = (FindModuleCtx*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, ctx->name)) {
        ctx->base = info->dlpi_addr;
        LOGI("Found %s at base: %p (path: %s)",
             ctx->name, (void*)ctx->base, info->dlpi_name);
        return 1; // توقف عن البحث
    }
    return 0;
}

uintptr_t get_module_base(const char* module_name) {
    FindModuleCtx ctx = { module_name, 0 };
    dl_iterate_phdr(find_module_cb, &ctx);
    return ctx.base;
}

// ============================================================
//  الدالة البديلة (Hook)
// ============================================================
void hooked_create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv) {
    LOGI("[!!!] CriAesDecryptor.Create CALLED!");

    if (key != nullptr) {
        jsize len = env->GetArrayLength(key);
        jbyte* data = env->GetByteArrayElements(key, nullptr);
        if (data) {
            char hex[256] = {0};
            int max = (len < 64) ? len : 64;
            for (int i = 0; i < max; i++)
                sprintf(hex + (i * 2), "%02x", (unsigned char)data[i]);
            LOGI("KEY (%d bytes): %s", len, hex);
            env->ReleaseByteArrayElements(key, data, JNI_ABORT);
        }
    }

    if (iv != nullptr) {
        jsize len = env->GetArrayLength(iv);
        jbyte* data = env->GetByteArrayElements(iv, nullptr);
        if (data) {
            char hex[256] = {0};
            int max = (len < 64) ? len : 64;
            for (int i = 0; i < max; i++)
                sprintf(hex + (i * 2), "%02x", (unsigned char)data[i]);
            LOGI("IV (%d bytes): %s", len, hex);
            env->ReleaseByteArrayElements(iv, data, JNI_ABORT);
        }
    }

    if (original_create) {
        original_create(env, thiz, key, iv);
    }
}

// ============================================================
//  نقطة الدخول التي يستدعيها Vector بعد حقن المكتبة
//  يتم استدعاؤها بعد أن تكون libUE4.so محمّلة في العملية
// ============================================================
extern "C" [[gnu::visibility("default")]] void native_init() {
    LOGI("native_init called. Starting hook installation...");

    // 1. التحقق من تحميل libUE4.so (بدون إعادة تحميل)
    void* handle = dlopen("libUE4.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!handle) {
        LOGI("libUE4.so not loaded yet, trying full dlopen...");
        handle = dlopen("libUE4.so", RTLD_LAZY);
    }
    if (!handle) {
        LOGE("Failed to dlopen libUE4.so: %s", dlerror());
        return;
    }
    LOGI("libUE4.so handle: %p", handle);

    // 2. الحصول على Base Address
    uintptr_t base = get_module_base("libUE4.so");
    if (base == 0) {
        LOGE("Failed to get libUE4.so base address!");
        return;
    }
    LOGI("libUE4.so base address: %p", (void*)base);

    // 3. حساب عنوان الدالة المستهدفة
    uintptr_t offset = 0x8bef44c;  // ⚠️ تحقق من صحة الإزاحة
    void* target_addr = (void*)(base + offset);
    LOGI("Target CriAesDecryptor.Create address: %p", target_addr);

    // 4. تثبيت الـ Hook
    int result = DobbyHook(target_addr, (void*)hooked_create, (void**)&original_create);
    if (result == 0) {
        LOGI("Hook installed SUCCESSFULLY on CriAesDecryptor.Create");
        LOGI("original_create = %p", (void*)original_create);
    } else {
        LOGE("DobbyHook FAILED with code: %d", result);
    }
}

// ============================================================
//  JNI_OnLoad - نحتفظ به فقط للسجل، ولا نثبّت Hook هنا
//  لأن توقيته غير مضمون (قد يكون libUE4.so غير محمّل بعد)
// ============================================================
extern "C" [[gnu::visibility("default")]] JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called (library loaded into target process)");
    return JNI_VERSION_1_6;
}
