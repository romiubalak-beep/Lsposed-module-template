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
    char hex[1024] = {0};
    const uint8_t* p = (const uint8_t*)ptr;
    for (size_t i = 0; i < n; i++) sprintf(hex + (i * 2), "%02x", p[i]);
    LOGI("%s [%zu bytes]: %s", label, len, hex);
}

// ============================================================
//  AES Create Hook (اختبار فقط)
// ============================================================
typedef void* (*CreateFunc)(const void*, size_t, const void*, size_t);
static CreateFunc original_create = nullptr;

static void* hooked_create(const void* key, size_t key_len, const void* iv, size_t iv_len) {
    LOGI("==================================================");
    LOGI("[AES] criAesDecryptor_Create CALLED!");
    LOGI("  key=%p (len=%zu), iv=%p (len=%zu)", key, key_len, iv, iv_len);
    if (key && key_len > 0 && key_len <= 64) dump_hex("KEY", key, key_len, 32);
    if (iv && iv_len > 0 && iv_len <= 64) dump_hex("IV", iv, iv_len, 16);
    void* result = original_create ? original_create(key, key_len, iv, iv_len) : nullptr;
    LOGI("  -> instance=%p", result);
    LOGI("==================================================");
    return result;
}

// ============================================================
//  Thread: تثبيت Hooks (اختبار: AES Create فقط)
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

    int init_r = shadowhook_init(SHADOWHOOK_MODE_UNIQUE, false);
    LOGI("shadowhook_init returned %d", init_r);

    // ====== AES Create Hook فقط ======
    void* create_addr = (void*)(base + 0x8c06138);
    LOGI("Hooking criAesDecryptor_Create @ %p", create_addr);
    shadowhook_hook_func_addr(create_addr, (void*)hooked_create, (void**)&original_create);
    LOGI("  -> original_create=%p", (void*)original_create);

    // ❌ لا تثبت hooks أخرى في هذه المرحلة

    LOGI("##################################################");
    LOGI("TEST MODE: Only criAesDecryptor_Create hooked.");
    LOGI("If game runs, add criAesDecryptor_Decrypt next.");
    LOGI("##################################################");
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
