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
//  AES Decryptor Hooks (من CRI AES)
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

typedef size_t (*DecryptFunc)(void*, const void*, size_t, void*, size_t);
static DecryptFunc original_decrypt = nullptr;
static int decrypt_count = 0;

static size_t hooked_decrypt(void* this_ptr, const void* in, size_t in_len, void* out, size_t out_len) {
    decrypt_count++;
    if (decrypt_count <= 20) {
        LOGI("--------------------------------------------------");
        LOGI("[AES] [%d] criAesDecryptor_Decrypt", decrypt_count);
        LOGI("  this=%p, in=%p (len=%zu), out=%p (len=%zu)", this_ptr, in, in_len, out, out_len);
        if (in && in_len > 0 && in_len <= 8192) dump_hex("  ENCRYPTED", in, in_len, 64);
    }
    size_t result = original_decrypt ? original_decrypt(this_ptr, in, in_len, out, out_len) : 0;
    if (decrypt_count <= 20) {
        LOGI("  -> returned %zu", result);
        if (out && result > 0 && result <= 8192) dump_hex("  DECRYPTED", out, result, 64);
        LOGI("--------------------------------------------------");
    }
    return result;
}

// ============================================================
//  criNetStm Hooks (شبكة CRIWARE)
// ============================================================

// criNetStmCustom_ThreadFuncHttp @ 0x8bf4434
typedef void* (*NetStmThreadFunc)(void*);
static NetStmThreadFunc original_netstm_thread = nullptr;

static void* hooked_netstm_thread(void* arg) {
    LOGI("==================================================");
    LOGI("[NET] criNetStmCustom_ThreadFuncHttp CALLED, arg=%p", arg);
    void* result = original_netstm_thread ? original_netstm_thread(arg) : nullptr;
    LOGI("[NET] ThreadFuncHttp RETURNED %p", result);
    LOGI("==================================================");
    return result;
}

// criNetStmCommon_UnlockBuffer @ 0x8bf3620
typedef void* (*UnlockBufferFunc)(void*);
static UnlockBufferFunc original_unlock_buffer = nullptr;

static void* hooked_unlock_buffer(void* arg) {
    LOGI("--------------------------------------------------");
    LOGI("[NET] criNetStmCommon_UnlockBuffer CALLED, arg=%p", arg);
    LOGI("--------------------------------------------------");
    return original_unlock_buffer ? original_unlock_buffer(arg) : nullptr;
}

// criNetStm_SetRequestHeader @ 0x8bf35a0
typedef void (*SetRequestHeaderFunc)(void*, const char*, const char*);
static SetRequestHeaderFunc original_set_request_header = nullptr;

static void hooked_set_request_header(void* handle, const char* name, const char* value) {
    LOGI("--------------------------------------------------");
    LOGI("[NET] criNetStm_SetRequestHeader");
    LOGI("  name=%s", name ? name : "(null)");
    LOGI("  value=%s", value ? value : "(null)");
    LOGI("--------------------------------------------------");
    if (original_set_request_header) original_set_request_header(handle, name, value);
}

// criNetStm_SetConcatMode @ 0x8bf3d6c
typedef void (*SetConcatModeFunc)(void*, int);
static SetConcatModeFunc original_set_concat_mode = nullptr;

static void hooked_set_concat_mode(void* handle, int mode) {
    LOGI("[NET] criNetStm_SetConcatMode mode=%d", mode);
    if (original_set_concat_mode) original_set_concat_mode(handle, mode);
}

// criNetStm_SetMaxTransferRate @ 0x8bf3d9c
typedef void (*SetMaxRateFunc)(void*, int);
static SetMaxRateFunc original_set_max_rate = nullptr;

static void hooked_set_max_rate(void* handle, int rate) {
    LOGI("[NET] criNetStm_SetMaxTransferRate rate=%d", rate);
    if (original_set_max_rate) original_set_max_rate(handle, rate);
}

// criNetStm_SetTimeoutMsec @ 0x8bf3d88
typedef void (*SetTimeoutFunc)(void*, int);
static SetTimeoutFunc original_set_timeout = nullptr;

static void hooked_set_timeout(void* handle, int timeout) {
    LOGI("[NET] criNetStm_SetTimeoutMsec timeout=%d", timeout);
    if (original_set_timeout) original_set_timeout(handle, timeout);
}

// ============================================================
//  Thread: انتظار libUE4.so ثم تثبيت Hooks
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

    // ====== AES Hooks ======
    void* create_addr = (void*)(base + 0x8c06138);
    LOGI("Hooking criAesDecryptor_Create @ %p", create_addr);
    shadowhook_hook_func_addr(create_addr, (void*)hooked_create, (void**)&original_create);
    LOGI("  -> original_create=%p", (void*)original_create);

    void* decrypt_addr = (void*)(base + 0x8c06a5c);
    LOGI("Hooking criAesDecryptor_Decrypt @ %p", decrypt_addr);
    shadowhook_hook_func_addr(decrypt_addr, (void*)hooked_decrypt, (void**)&original_decrypt);
    LOGI("  -> original_decrypt=%p", (void*)original_decrypt);

    // ====== NetStm Hooks ======
    void* thread_func_addr = (void*)(base + 0x8bf4434);
    LOGI("Hooking criNetStmCustom_ThreadFuncHttp @ %p", thread_func_addr);
    shadowhook_hook_func_addr(thread_func_addr, (void*)hooked_netstm_thread, (void**)&original_netstm_thread);

    void* unlock_buf_addr = (void*)(base + 0x8bf3620);
    LOGI("Hooking criNetStmCommon_UnlockBuffer @ %p", unlock_buf_addr);
    shadowhook_hook_func_addr(unlock_buf_addr, (void*)hooked_unlock_buffer, (void**)&original_unlock_buffer);

    void* set_hdr_addr = (void*)(base + 0x8bf35a0);
    LOGI("Hooking criNetStm_SetRequestHeader @ %p", set_hdr_addr);
    shadowhook_hook_func_addr(set_hdr_addr, (void*)hooked_set_request_header, (void**)&original_set_request_header);

    void* set_concat_addr = (void*)(base + 0x8bf3d6c);
    LOGI("Hooking criNetStm_SetConcatMode @ %p", set_concat_addr);
    shadowhook_hook_func_addr(set_concat_addr, (void*)hooked_set_concat_mode, (void**)&original_set_concat_mode);

    void* set_rate_addr = (void*)(base + 0x8bf3d9c);
    LOGI("Hooking criNetStm_SetMaxTransferRate @ %p", set_rate_addr);
    shadowhook_hook_func_addr(set_rate_addr, (void*)hooked_set_max_rate, (void**)&original_set_max_rate);

    void* set_timeout_addr = (void*)(base + 0x8bf3d88);
    LOGI("Hooking criNetStm_SetTimeoutMsec @ %p", set_timeout_addr);
    shadowhook_hook_func_addr(set_timeout_addr, (void*)hooked_set_timeout, (void**)&original_set_timeout);

    LOGI("##################################################");
    LOGI("All hooks installed. Waiting for calls...");
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
