#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include "dobby.h"

#define TAG "NativeCryptoHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// --- تعريف نوع الدالة الأصلية ---
// Create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv)
typedef void (*CreateFunc)(JNIEnv*, jobject, jbyteArray, jbyteArray);
static CreateFunc original_create = nullptr;

// --- الدالة البديلة ---
void hooked_create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv) {
    LOGI("[!!!] CriAesDecryptor.Create CALLED!");
    
    if (key != nullptr) {
        jsize len = env->GetArrayLength(key);
        jbyte* data = env->GetByteArrayElements(key, nullptr);
        if (data) {
            LOGI("KEY LENGTH: %d", len);
            char hex[128] = {0};
            for (int i = 0; i < len && i < 32; i++) {
                sprintf(hex + (i * 2), "%02x", (unsigned char)data[i]);
            }
            LOGI("KEY HEX: %s", hex);
            env->ReleaseByteArrayElements(key, data, JNI_ABORT);
        }
    }
    
    if (iv != nullptr) {
        jsize len = env->GetArrayLength(iv);
        jbyte* data = env->GetByteArrayElements(iv, nullptr);
        if (data) {
            char hex[128] = {0};
            for (int i = 0; i < len && i < 32; i++) {
                sprintf(hex + (i * 2), "%02x", (unsigned char)data[i]);
            }
            LOGI("IV HEX: %s", hex);
            env->ReleaseByteArrayElements(iv, data, JNI_ABORT);
        }
    }
    
    if (original_create) {
        original_create(env, thiz, key, iv);
    }
}

// --- دالة التهيئة (JNI_OnLoad) ---
// يتم استدعاؤها تلقائياً عند System.loadLibrary("native_hook")
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called. Hooking libUE4.so...");

    // 1. الحصول على handle لمكتبة اللعبة
    void* handle = dlopen("libUE4.so", RTLD_LAZY);
    if (!handle) {
        LOGE("Failed to dlopen libUE4.so: %s", dlerror());
        return JNI_VERSION_1_6;
    }
    LOGI("libUE4.so loaded at handle: %p", handle);

    // 2. حساب العنوان الفعلي للدالة
    // الإزاحة التي حسبناها سابقاً في ملف ELF
    uintptr_t offset = 0x8bef44c; 
    
    // للحصول على العنوان الأساسي للمكتبة، نستخدم dlinfo
    // لكن هناك طريقة أسهل في أندرويد: قراءة /proc/self/maps
    // كحل سريع، سنستخدم dlsym لأي رمز معروف (إذا وجد) للحصول على base
    // لكن بما أننا نعرف الإزاحة، يمكننا استخدام dladdr على أي عنوان داخل المكتبة للحصول على base
    // سأستخدم طريقة DobbySymbolResolver للبحث عن دالة معروفة داخل libUE4.so (مثل JNI_OnLoad الخاصة باللعبة)
    void* known_symbol = DobbySymbolResolver("libUE4.so", "JNI_OnLoad");
    if (!known_symbol) {
        // إذا فشل، نجرب البحث عن أي دالة معروفة أخرى مثل Java_com_epicgames_ue4_GameActivity_nativeInitHMDs
        known_symbol = DobbySymbolResolver("libUE4.so", "Java_com_epicgames_ue4_GameActivity_nativeInitHMDs");
    }
    
    if (!known_symbol) {
        LOGE("Failed to resolve any known symbol in libUE4.so to calculate base address.");
        return JNI_VERSION_1_6;
    }

    // حساب base address (بما أننا نعرف الإزاحة في الملف، يمكننا حساب base = known_symbol - offset_of_known_symbol)
    // لكن هذا معقد. الأسهل هو استخدام dladdr للحصول على dli_fbase
    Dl_info info;
    if (dladdr(known_symbol, &info) != 0) {
        void* base_addr = info.dli_fbase;
        LOGI("Calculated libUE4.so base address: %p", base_addr);
        
        void* target_addr = (void*)((uintptr_t)base_addr + offset);
        LOGI("Target Create function address: %p", target_addr);
        
        // 3. استخدام Dobby للاعتراض
        int result = DobbyHook(target_addr, (void*)hooked_create, (void**)&original_create);
        if (result == RS_SUCCESS) {
            LOGI("Hook installed successfully on CriAesDecryptor.Create");
        } else {
            LOGE("DobbyHook failed with error code: %d", result);
        }
    } else {
        LOGE("dladdr failed to get base address.");
    }

    return JNI_VERSION_1_6;
}
