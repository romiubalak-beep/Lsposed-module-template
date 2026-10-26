#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <pthread.h>
#include "shadowhook.h"

#define TAG "NativeCryptoHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// ============================================================
//  البحث عن Base Address
// ============================================================
struct FindModuleCtx { const char* name; uintptr_t base; };

static int find_module_cb(struct dl_phdr_info* info, size_t size, void* data) {
    FindModuleCtx* ctx = (FindModuleCtx*)data;
    if (info->dlpi_name && strstr(info->dlpi_name, ctx->name)) {
        ctx->base = info->dlpi_addr;
        return 1;
    }
    return 0;
}

static uintptr_t get_module_base(const char* name) {
    FindModuleCtx ctx = { name, 0 };
    dl_iterate_phdr(find_module_cb, &ctx);
    return ctx.base;
}

static void dump_hex(const char* label, const void* ptr, size_t len, size_t max_len) {
    if (!ptr || len == 0) { LOGI("%s: null", label); return; }
    size_t n = (len < max_len) ? len : max_len;
    char hex[512] = {0};
    const uint8_t* p = (const uint8_t*)ptr;
    for (size_t i = 0; i < n; i++) sprintf(hex + (i * 2), "%02x", p[i]);
    LOGI("%s [%zu bytes]: %s", label, len, hex);
}

// ============================================================
//  Create Hook
// ============================================================
typedef void* (*CreateFunc)(const void*, size_t, const void*, size_t);
static CreateFunc original_create = nullptr;

static void* hooked_create(const void* key, size_t key_len, const void* iv, size_t iv_len) {
    LOGI("==================================================");
    LOGI("[!!!] criAesDecryptor_Create CALLED!");
    LOGI("  key=%p (len=%zu), iv=%p (len=%zu)", key, key_len, iv, iv_len);
    if (key && key_len > 0 && key_len <= 64) dump_hex("KEY", key, key_len, 32);
    if (iv && iv_len > 0 && iv_len <= 64) dump_hex("IV", iv, iv_len, 16);
    void* result = original_create ? original_create(key, key_len, iv, iv_len) : nullptr;
    LOGI("  -> instance=%p", result);
    LOGI("==================================================");
    return result;
}

// ============================================================
//  Decrypt Hook
// ============================================================
typedef size_t (*DecryptFunc)(void*, const void*, size_t, void*, size_t);
static DecryptFunc original_decrypt = nullptr;
static int decrypt_count = 0;

static size_t hooked_decrypt(void* this_ptr, const void* in, size_t in_len, void* out, size_t out_len) {
    decrypt_count++;
    if (decrypt_count <= 10) {
        LOGI("--------------------------------------------------");
        LOGI("[%d] criAesDecryptor_Decrypt", decrypt_count);
        LOGI("  this=%p, in=%p (len=%zu), out=%p (len=%zu)", this_ptr, in, in_len, out, out_len);
        if (in && in_len > 0 && in_len <= 8192) dump_hex("  ENCRYPTED", in, in_len, 64);
    }
    size_t result = original_decrypt ? original_decrypt(this_ptr, in, in_len, out, out_len) : 0;
    if (decrypt_count <= 10) {
        LOGI("  -> returned %zu", result);
        if (out && result > 0 && result <= 8192) dump_hex("  DECRYPTED", out, result, 64);
        LOGI("--------------------------------------------------");
    }
    return result;
}

// ============================================================
//  Thread
// ============================================================
static void* install_hooks_thread(void* arg) {
    LOGI("Waiting for libUE4.so...");

    uintptr_t base = 0;
    for (int i = 0; i < 900; i++) {
        base = get_module_base("libUE4.so");
        if (base != 0) {
            LOGI("libUE4.so detected after %d00ms at %p", i, (void*)base);
            break;
        }
        usleep(100 * 1000);
    }

    if (base == 0) {
        LOGE("Timeout waiting for libUE4.so");
        return nullptr;
    }

    usleep(500 * 1000);
    base = get_module_base("libUE4.so");
    if (base == 0 || base < 0x1000) {
        LOGE("Invalid base: %p", (void*)base);
        return nullptr;
    }

    // تهيئة ShadowHook (وضع UNIQUE)
    int init_r = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    LOGI("shadowhook_init returned %d", init_r);

    // Hook Create @ 0x8c06138
    void* create_addr = (void*)(base + 0x8c06138);
    LOGI("Hooking Create @ %p", create_addr);
    void* orig1 = shadowhook_hook_func_addr(create_addr, (void*)hooked_create, (void**)&original_create);
    LOGI("shadowhook_hook(Create) returned %p, original=%p", orig1, (void*)original_create);

    // Hook Decrypt @ 0x8c06a5c
    void* decrypt_addr = (void*)(base + 0x8c06a5c);
    LOGI("Hooking Decrypt @ %p", decrypt_addr);
    void* orig2 = shadowhook_hook_func_addr(decrypt_addr, (void*)hooked_decrypt, (void**)&original_decrypt);
    LOGI("shadowhook_hook(Decrypt) returned %p, original=%p", orig2, (void*)original_decrypt);

    LOGI("All hooks installed via ShadowHook.");
    return nullptr;
}

// ============================================================
//  JNI_OnLoad
// ============================================================
extern "C" __attribute__((visibility("default")))
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGI("JNI_OnLoad called");
    pthread_t tid;
    if (pthread_create(&tid, nullptr, install_hooks_thread, nullptr) == 0) {
        pthread_detach(tid);
        LOGI("Background hook installer thread started");
    } else {
        LOGE("pthread_create failed");
    }
    return JNI_VERSION_1_6;
}
