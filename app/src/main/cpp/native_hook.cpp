#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include "dobby.h"

#define TAG "NativeCryptoHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ============================================================
//  البحث عن Base Address لأي مكتبة
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
//  دوال مساعدة
// ============================================================
static void dump_hex(const char* label, const void* ptr, size_t len, size_t max_len = 64) {
    if (!ptr) {
        LOGI("%s: (null)", label);
        return;
    }
    size_t n = (len < max_len) ? len : max_len;
    char hex[256] = {0};
    const uint8_t* p = (const uint8_t*)ptr;
    for (size_t i = 0; i < n; i++) {
        sprintf(hex + (i * 2), "%02x", p[i]);
    }
    LOGI("%s [%zu bytes] (%zu shown): %s", label, len, n, hex);
}

// ============================================================
//  اعتراض criAesDecryptor_Create
//  التوقيع المفترض: void* Create(const void* key, size_t key_len, const void* iv, size_t iv_len)
//  الإزاحة: 0x8c06138
// ============================================================
typedef void* (*CreateFunc)(const void*, size_t, const void*, size_t);
static CreateFunc original_create = nullptr;

void* hooked_create(const void* key, size_t key_len, const void* iv, size_t iv_len) {
    LOGI("==================================================");
    LOGI("[!!!] criAesDecryptor_Create CALLED!");
    LOGI("  key ptr=%p, key_len=%zu", key, key_len);
    LOGI("  iv  ptr=%p, iv_len=%zu",  iv,  iv_len);

    // اطبع المفتاح إذا كان الطول معقولاً
    if (key && key_len > 0 && key_len <= 64) {
        dump_hex("KEY", key, key_len, 32);
    }
    if (iv && iv_len > 0 && iv_len <= 64) {
        dump_hex("IV", iv, iv_len, 16);
    }

    void* result = nullptr;
    if (original_create) {
        result = original_create(key, key_len, iv, iv_len);
        LOGI("  -> created instance at %p", result);
    }
    LOGI("==================================================");
    return result;
}

// ============================================================
//  اعتراض criAesDecryptor_Decrypt
//  التوقيع المفترض: size_t Decrypt(void* this_ptr, const void* in, size_t in_len, void* out, size_t out_len)
//  الإزاحة: 0x8c06a5c
// ============================================================
typedef size_t (*DecryptFunc)(void*, const void*, size_t, void*, size_t);
static DecryptFunc original_decrypt = nullptr;
static int decrypt_call_count = 0;

size_t hooked_decrypt(void* this_ptr, const void* in, size_t in_len, void* out, size_t out_len) {
    decrypt_call_count++;

    // اطبع أول 5 استدعاءات فقط لتجنب إغراق السجل
    if (decrypt_call_count <= 5) {
        LOGI("--------------------------------------------------");
        LOGI("[%d] criAesDecryptor_Decrypt CALLED", decrypt_call_count);
        LOGI("  this=%p, in=%p (len=%zu), out=%p (len=%zu)",
             this_ptr, in, in_len, out, out_len);

        if (in && in_len > 0 && in_len <= 4096) {
            dump_hex("  ENCRYPTED (in)", in, in_len, 64);
        }
    }

    size_t result = 0;
    if (original_decrypt) {
        result = original_decrypt(this_ptr, in, in_len, out, out_len);
    }

    if (decrypt_call_count <= 5) {
        LOGI("  -> returned %zu", result);
        if (out && result > 0 && result <= 4096) {
            dump_hex("  DECRYPTED (out)", out, result, 64);
        }
        LOGI("--------------------------------------------------");
    }

    return result;
}

// ============================================================
//  نقطة الدخول
// ============================================================
extern "C" [[gnu::visibility("default")]] void native_init() {
    LOGI("##################################################");
    LOGI("native_init called. Installing crypto hooks...");
    LOGI("##################################################");

    // التأكد من تحميل libUE4.so
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

    uintptr_t base = get_module_base("libUE4.so");
    if (base == 0) {
        LOGE("Failed to get libUE4.so base");
        return;
    }
    LOGI("libUE4.so base: %p", (void*)base);

    // اعتراض criAesDecryptor_Create @ 0x8c06138
    void* create_addr = (void*)(base + 0x8c06138);
    LOGI("Hooking criAesDecryptor_Create @ %p", create_addr);
    int r1 = DobbyHook(create_addr, (void*)hooked_create, (void**)&original_create);
    if (r1 == 0) {
        LOGI("✅ Hook Create SUCCESS. original=%p", (void*)original_create);
    } else {
        LOGE("❌ Hook Create FAILED: %d", r1);
    }

    // اعتراض criAesDecryptor_Decrypt @ 0x8c06a5c
    void* decrypt_addr = (void*)(base + 0x8c06a5c);
    LOGI("Hooking criAesDecryptor_Decrypt @ %p", decrypt_addr);
    int r2 = DobbyHook(decrypt_addr, (void*)hooked_decrypt, (void**)&original_decrypt);
    if (r2 == 0) {
        LOGI("✅ Hook Decrypt SUCCESS. original=%p", (void*)original_decrypt);
    } else {
        LOGE("❌ Hook Decrypt FAILED: %d", r2);
    }

    LOGI("##################################################");
    LOGI("All hooks installed. Waiting for calls...");
    LOGI("##################################################");
}

extern "C" [[gnu::visibility("default")]] JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called");
    return JNI_VERSION_1_6;
}
