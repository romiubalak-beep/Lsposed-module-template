#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <cstring>
#include "include/dobby.h"

#define TAG "NativeCryptoHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

// تعريف نوع الدالة الأصلية (نحتاج لمعرفة توقيعها الدقيق)
// بناءً على تحليلنا: Create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv)
typedef void (*CreateFunc)(JNIEnv*, jobject, jbyteArray, jbyteArray);
static CreateFunc original_create = nullptr;

// الدالة البديلة التي ستنفذ مكان الدالة الأصلية
void hooked_create(JNIEnv* env, jobject thiz, jbyteArray key, jbyteArray iv) {
    LOGI("[!!!] CriAesDecryptor.Create CALLED!");
    
    if (key != nullptr) {
        jsize len = env->GetArrayLength(key);
        jbyte* data = env->GetByteArrayElements(key, nullptr);
        if (data) {
            LOGI("KEY LENGTH: %d", len);
            // طباعة المفتاح بصيغة Hex
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
    
    // استدعاء الدالة الأصلية لإكمال العمل
    if (original_create) {
        original_create(env, thiz, key, iv);
    }
}

// دالة التهيئة التي سيستدعيها LSPosed عند تحميل المكتبة
extern "C" [[gnu::visibility("default")]] [[gnu::used]]
void* native_init(void* entries) {
    LOGI("Native Hook Initialized");
    
    // العنوان الذي حسبناه سابقاً (في ملف ELF)
    // ملاحظة: هذا العنوان قد يحتاج لتعديل حسب إصدار اللعبة
    uintptr_t offset = 0x8bef44c; 
    
    // الحصول على عنوان تحميل المكتبة في الذاكرة
    void* handle = dlopen("libUE4.so", RTLD_LAZY);
    if (!handle) {
        LOGI("[-] Failed to dlopen libUE4.so");
        return nullptr;
    }
    
    // حساب العنوان الفعلي في الذاكرة
    void* base_addr = nullptr;
    // طريقة بديلة للحصول على base address: نستخدم dlsym لأي رمز معروف أو نمرر عنواناً من LSPosed
    // لكن كحل سريع، سنفترض أن LSPosed قد وفر آلية للوصول للعناوين.
    // في الواقع، الأفضل استخدام DobbySymbolResolver أو تمرير handle من callback.
    
    // للتبسيط، سنستخدم DobbySymbolResolver للبحث عن الدالة إذا كانت ظاهرة (وهي ليست كذلك)
    // لذلك سنعتمد على أن المستخدم سيقوم بحقن العنوان الصحيح.
    
    // *** ملاحظة هامة: هذا الجزء يحتاج إلى ضبط دقيق بناءً على كيفية عمل LSPosed ***
    // للحصول على base address الحقيقي، يجب استخدام callback من LSPosed.
    // لكن كخطوة أولى، سنستخدم DobbyHook على العنوان الذي حسبناه.
    
    // --- محاكاة الحصول على العنوان ---
    // (هذا الجزء سيفشل إذا لم نجد طريقة للحصول على base الحقيقي)
    // في المشاريع الحقيقية، يتم تمرير handle من LSPosed في دالة native_init.
    
    // بما أننا لا نستطيع الحصول على base بسهولة هنا، سنترك هذا الجزء كقالب.
    // في المرة القادمة، سنقوم بتعديل Java لتمرير handle أو استخدام native_init بشكل صحيح.
    
    LOGI("[*] Native Init Complete (Placeholder)");
    return nullptr;
}
