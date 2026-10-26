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

// ============================================================
//  البحث عن Base Address لأي مكتبة محمّلة
// ============================================================
struct FindModuleCtx { const char* name; uintptr_t base; };

static int find_module_cb(struct dl_phdr_info* info, size_t size, void* data) {
    FindModuleCtx* ctx = (FindModuleCtx*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, ctx->name)) {
        ctx->base = info->dlpi_addr;
        LOGI("Found %s at base: %p", ctx->name, (void*)ctx->base);
        return 1;
    }
    return 0;
}

uintptr_t get_module_base(const char* name) {
    FindModuleCtx ctx = { name, 0 };
    dl_iterate_phdr(find_module_cb, &ctx);
    return ctx.base;
}

// ============================================================
//  دوال Hook (نستخدم uintptr_t للمعاملات لأننا لا نعرف التوقيع)
// ============================================================
typedef void* (*CreateFunc)(const void*, size_t, const void*, size_t);
static CreateFunc original_create = nullptr;

// مساعد: طباعة بايتات كـ hex إذا كان المؤشر يشير إلى بيانات قابلة للقراءة
static void try_dump_hex(const char* label, const void* ptr, size_t max_len) {
    if (!ptr) {
        LOGI("%s: (null)", label);
        return;
    }
    // محاولة قراءة أول max_len بايت (خطر: قد يسبب segfault إذا كان المؤشر غير صالح)
    // نستخدم فقط لطباعة أول 32 بايت كحد أقصى
    char hex[128] = {0};
    size_t n = (max_len < 32) ? max_len : 32;
    const uint8_t* p = (const uint8_t*)ptr;
    for (size_t i = 0; i < n; i++) {
        sprintf(hex + (i * 2), "%02x", p[i]);
    }
    LOGI("%s (%zu bytes): %s", label, n, hex);
}

void* hooked_create(const void* key, size_t key_len,
                    const void* iv, size_t iv_len) {
    LOGI("[!!!] criAesDecryptor_Create CALLED!");
    LOGI("  key ptr=%p, key_len=%zu", key, key_len);
    LOGI("  iv  ptr=%p, iv_len=%zu",  iv,  iv_len);

    if (key && key_len > 0 && key_len <= 64) {
        try_dump_hex("KEY", key, key_len);
    }
    if (iv && iv_len > 0 && iv_len <= 64) {
        try_dump_hex("IV", iv, iv_len);
    }

    if (original_create) {
        return original_create(key, key_len, iv, iv_len);
    }
    return nullptr;
}

// ============================================================
//  نقطة الدخول
// ============================================================
extern "C" [[gnu::visibility("default")]] void native_init() {
    LOGI("native_init called. Starting hook installation...");

    void* handle = dlopen("libUE4.so", RTLD_NOLOAD | RTLD_LAZY);
    if (!handle) {
        handle = dlopen("libUE4.so", RTLD_LAZY);
    }
    if (!handle) {
        LOGE("Failed to dlopen libUE4.so: %s", dlerror());
        return;
    }
    LOGI("libUE4.so handle: %p", handle);

    uintptr_t base = get_module_base("libUE4.so");
    if (base == 0) {
        LOGE("Failed to get libUE4.so base");
        return;
    }

    // ✅ الإزاحة الصحيحة: criAesDecryptor_Create @ 0x8c06138
    uintptr_t offset = 0x8c06138;
    void* target = (void*)(base + offset);
    LOGI("Target criAesDecryptor_Create @ %p", target);

    int result = DobbyHook(target, (void*)hooked_create, (void**)&original_create);
    if (result == 0) {
        LOGI("Hook installed SUCCESSFULLY on criAesDecryptor_Create");
        LOGI("original_create = %p", (void*)original_create);
    } else {
        LOGE("DobbyHook FAILED: %d", result);
    }

    // اختياري: اعتراض criAesDecryptor_Initialize أيضاً (قد يكون أنظف)
    // الإزاحة: 0x8c06128
    // typedef void (*InitFunc)(void*);
    // ...
}

extern "C" [[gnu::visibility("default")]] JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called");
    return JNI_VERSION_1_6;
}
