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

// ============================================================
//  Thread: تثبيت Hooks (اختبار: بدون أي hooks أصلية)
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

    // ❌ لا تثبت أي hooks أصلية في هذه المرحلة

    LOGI("##################################################");
    LOGI("TEST MODE: No native hooks installed.");
    LOGI("If game runs, problem is in hooks. If crashes, problem is shadowhook_init.");
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
