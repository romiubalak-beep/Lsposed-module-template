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
static uintptr_t g_ue4_base = 0;

// البحث عن base address لـ libUE4.so
static int find_ue4_cb(struct dl_phdr_info* info, size_t size, void* data) {
    if (info->dlpi_name && strstr(info->dlpi_name, "libUE4.so")) {
        g_ue4_base = info->dlpi_addr;
        LOGI("Found libUE4.so at base: %p", (void*)g_ue4_base);
        return 1;
    }
    return 0;
}

void hooked_create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv) {
    LOGI("[!!!] CriAesDecryptor.Create CALLED!");
    if (key != nullptr) {
        jsize len = env->GetArrayLength(key);
        jbyte* data = env->GetByteArrayElements(key, nullptr);
        if (data) {
            char hex[256] = {0};
            for (int i = 0; i < len && i < 64; i++)
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
            for (int i = 0; i < len && i < 64; i++)
                sprintf(hex + (i * 2), "%02x", (unsigned char)data[i]);
            LOGI("IV (%d bytes): %s", len, hex);
            env->ReleaseByteArrayElements(iv, data, JNI_ABORT);
        }
    }
    if (original_create) original_create(env, thiz, key, iv);
}

// ⚠️ هذا يتم استدعاؤه من قبل Vector بعد تحميل المكتبة في العملية المستهدفة
extern "C" [[gnu::visibility("default")]] void native_init() {
    LOGI("native_init called. Installing hook...");

    // dlopen مع RTLD_NOLOAD للتحقق من تحميل libUE4.so مسبقًا
    void* handle = dlopen("libUE4.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!handle) {
        LOGI("libUE4.so not loaded yet, retrying with full dlopen");
        handle = dlopen("libUE4.so", RTLD_LAZY);
    }
    if (!handle) {
        LOGE("Failed to dlopen libUE4.so: %s", dlerror());
        return;
    }

    // الحصول على base address
    dl_iterate_phdr(find_ue4_cb, nullptr);
    if (!g_ue4_base) {
        LOGE("Failed to locate libUE4.so base address");
        return;
    }

    uintptr_t offset = 0x8bef44c; // ⚠️ تحقق من صحة هذه الإزاحة
    void* target_addr = (void*)(g_ue4_base + offset);
    LOGI("Target address: %p", target_addr);

    int result = DobbyHook(target_addr, (void*)hooked_create, (void**)&original_create);
    if (result == 0) {
        LOGI("Hook installed successfully");
    } else {
        LOGE("DobbyHook failed: %d", result);
    }
}
