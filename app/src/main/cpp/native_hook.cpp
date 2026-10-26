#include <jni.h>
#include <android/log.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdint>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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
//  AES Decryptor Hooks
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
//  Socket Hooks (send/recv/connect)
// ============================================================
typedef ssize_t (*SendFunc)(int, const void*, size_t, int);
typedef ssize_t (*RecvFunc)(int, void*, size_t, int);
typedef ssize_t (*SendtoFunc)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*RecvfromFunc)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef int (*ConnectFunc)(int, const struct sockaddr*, socklen_t);

static SendFunc original_send = nullptr;
static RecvFunc original_recv = nullptr;
static SendtoFunc original_sendto = nullptr;
static RecvfromFunc original_recvfrom = nullptr;
static ConnectFunc original_connect = nullptr;

static int send_count = 0;
static int recv_count = 0;

static ssize_t hooked_send(int sockfd, const void* buf, size_t len, int flags) {
    send_count++;
    // اطبع فقط البيانات الكبيرة (>= 64 بايت) وأول 30 استدعاء
    if (send_count <= 30 && buf && len >= 64 && len <= 65536) {
        LOGI("==================================================");
        LOGI("[SEND] fd=%d, len=%zu, flags=%d", sockfd, len, flags);
        dump_hex("  DATA", buf, len, 256);
        LOGI("==================================================");
    }
    return original_send ? original_send(sockfd, buf, len, flags) : -1;
}

static ssize_t hooked_recv(int sockfd, void* buf, size_t len, int flags) {
    ssize_t result = original_recv ? original_recv(sockfd, buf, len, flags) : -1;
    recv_count++;
    if (recv_count <= 30 && result >= 64 && result <= 65536) {
        LOGI("==================================================");
        LOGI("[RECV] fd=%d, len=%zd, flags=%d", sockfd, result, flags);
        dump_hex("  DATA", buf, result, 256);
        LOGI("==================================================");
    }
    return result;
}

static ssize_t hooked_sendto(int sockfd, const void* buf, size_t len, int flags,
                              const struct sockaddr* dest_addr, socklen_t addrlen) {
    send_count++;
    if (send_count <= 30 && buf && len >= 64 && len <= 65536) {
        LOGI("==================================================");
        LOGI("[SENDTO] fd=%d, len=%zu, flags=%d", sockfd, len, flags);
        dump_hex("  DATA", buf, len, 256);
        LOGI("==================================================");
    }
    return original_sendto ? original_sendto(sockfd, buf, len, flags, dest_addr, addrlen) : -1;
}

static ssize_t hooked_recvfrom(int sockfd, void* buf, size_t len, int flags,
                                struct sockaddr* src_addr, socklen_t* addrlen) {
    ssize_t result = original_recvfrom ? original_recvfrom(sockfd, buf, len, flags, src_addr, addrlen) : -1;
    recv_count++;
    if (recv_count <= 30 && result >= 64 && result <= 65536) {
        LOGI("==================================================");
        LOGI("[RECVFROM] fd=%d, len=%zd, flags=%d", sockfd, result, flags);
        dump_hex("  DATA", buf, result, 256);
        LOGI("==================================================");
    }
    return result;
}

static int hooked_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    LOGI("[CONNECT] fd=%d, addrlen=%u", sockfd, addrlen);
    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
        LOGI("  -> IPv4: %s:%d", ip, ntohs(sin->sin_port));
    } else if (addr && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
        char ip[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
        LOGI("  -> IPv6: [%s]:%d", ip, ntohs(sin6->sin6_port));
    }
    return original_connect ? original_connect(sockfd, addr, addrlen) : -1;
}

// ============================================================
//  Thread: تثبيت Hooks
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

    void* decrypt_addr = (void*)(base + 0x8c06a5c);
    LOGI("Hooking criAesDecryptor_Decrypt @ %p", decrypt_addr);
    shadowhook_hook_func_addr(decrypt_addr, (void*)hooked_decrypt, (void**)&original_decrypt);

    // ====== Socket Hooks (من libc) ======
    void* send_addr = (void*)dlsym(RTLD_DEFAULT, "send");
    if (send_addr) {
        LOGI("Hooking send @ %p", send_addr);
        shadowhook_hook_func_addr(send_addr, (void*)hooked_send, (void**)&original_send);
    } else {
        LOGE("send not found");
    }

    void* recv_addr = (void*)dlsym(RTLD_DEFAULT, "recv");
    if (recv_addr) {
        LOGI("Hooking recv @ %p", recv_addr);
        shadowhook_hook_func_addr(recv_addr, (void*)hooked_recv, (void**)&original_recv);
    } else {
        LOGE("recv not found");
    }

    void* sendto_addr = (void*)dlsym(RTLD_DEFAULT, "sendto");
    if (sendto_addr) {
        LOGI("Hooking sendto @ %p", sendto_addr);
        shadowhook_hook_func_addr(sendto_addr, (void*)hooked_sendto, (void**)&original_sendto);
    } else {
        LOGE("sendto not found");
    }

    void* recvfrom_addr = (void*)dlsym(RTLD_DEFAULT, "recvfrom");
    if (recvfrom_addr) {
        LOGI("Hooking recvfrom @ %p", recvfrom_addr);
        shadowhook_hook_func_addr(recvfrom_addr, (void*)hooked_recvfrom, (void**)&original_recvfrom);
    } else {
        LOGE("recvfrom not found");
    }

    void* connect_addr = (void*)dlsym(RTLD_DEFAULT, "connect");
    if (connect_addr) {
        LOGI("Hooking connect @ %p", connect_addr);
        shadowhook_hook_func_addr(connect_addr, (void*)hooked_connect, (void**)&original_connect);
    } else {
        LOGE("connect not found");
    }

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
