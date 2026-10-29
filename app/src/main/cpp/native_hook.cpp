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
#include <sys/stat.h>
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
    char hex[1024] = {0};
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
//  SSL_get_verify_result Hook
//  العنوان: 0x05708d14 (vaddr)
//  الإزاحة من base: 0x2FA2814
// ============================================================
typedef int (*SSL_get_verify_result_func)(void* ssl);
static SSL_get_verify_result_func original_verify_result = nullptr;
static int verify_result_call_count = 0;

static int hooked_verify_result(void* ssl) {
    verify_result_call_count++;
    int result = 0;
    if (original_verify_result) {
        result = original_verify_result(ssl);
    }
    LOGI("==================================================");
    LOGI("[!!!] SSL_get_verify_result CALLED #%d", verify_result_call_count);
    LOGI("  ssl=%p, original result=%d", ssl, result);
    LOGI("  → returning 0 (SUCCESS, bypass verification)");
    LOGI("==================================================");
    return 0; // دائماً نجاح
}

// ============================================================
//  Socket Hooks
// ============================================================
typedef ssize_t (*SendFunc)(int, const void*, size_t, int);
typedef ssize_t (*RecvFunc)(int, void*, size_t, int);
typedef ssize_t (*SendtoFunc)(int, const void*, size_t, int, const struct sockaddr*, socklen_t);
typedef ssize_t (*RecvfromFunc)(int, void*, size_t, int, struct sockaddr*, socklen_t*);
typedef int (*ConnectFunc)(int, const struct sockaddr*, socklen_t);
typedef ssize_t (*WriteFunc)(int, const void*, size_t);
typedef ssize_t (*ReadFunc)(int, void*, size_t);
typedef ssize_t (*SendmsgFunc)(int, const struct msghdr*, int);
typedef ssize_t (*RecvmsgFunc)(int, struct msghdr*, int);

static SendFunc original_send = nullptr;
static RecvFunc original_recv = nullptr;
static SendtoFunc original_sendto = nullptr;
static RecvfromFunc original_recvfrom = nullptr;
static ConnectFunc original_connect = nullptr;
static WriteFunc original_write = nullptr;
static ReadFunc original_read = nullptr;
static SendmsgFunc original_sendmsg = nullptr;
static RecvmsgFunc original_recvmsg = nullptr;

static int send_count = 0;
static int recv_count = 0;

static bool is_socket_fd(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return false;
    return S_ISSOCK(st.st_mode);
}

static ssize_t hooked_send(int sockfd, const void* buf, size_t len, int flags) {
    if (buf && len >= 64 && len <= 65536 && send_count < 50) {
        send_count++;
        LOGI("==================================================");
        LOGI("[SEND] fd=%d, len=%zu, flags=%d", sockfd, len, flags);
        dump_hex("  DATA", buf, len, 256);
        LOGI("==================================================");
    }
    return original_send ? original_send(sockfd, buf, len, flags) : -1;
}

static ssize_t hooked_recv(int sockfd, void* buf, size_t len, int flags) {
    ssize_t result = original_recv ? original_recv(sockfd, buf, len, flags) : -1;
    if (result >= 64 && result <= 65536 && recv_count < 50) {
        recv_count++;
        LOGI("==================================================");
        LOGI("[RECV] fd=%d, len=%zd, flags=%d", sockfd, result, flags);
        dump_hex("  DATA", buf, result, 256);
        LOGI("==================================================");
    }
    return result;
}

static ssize_t hooked_sendto(int sockfd, const void* buf, size_t len, int flags,
                              const struct sockaddr* dest_addr, socklen_t addrlen) {
    if (buf && len >= 64 && len <= 65536 && send_count < 50) {
        send_count++;
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
    if (result >= 64 && result <= 65536 && recv_count < 50) {
        recv_count++;
        LOGI("==================================================");
        LOGI("[RECVFROM] fd=%d, len=%zd, flags=%d", sockfd, result, flags);
        dump_hex("  DATA", buf, result, 256);
        LOGI("==================================================");
    }
    return result;
}

static int hooked_connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen) {
    if (addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6)) {
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in* sin = (const struct sockaddr_in*)addr;
            char ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
            LOGI("[CONNECT] fd=%d -> IPv4: %s:%d", sockfd, ip, ntohs(sin->sin_port));
        } else {
            const struct sockaddr_in6* sin6 = (const struct sockaddr_in6*)addr;
            char ip[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip));
            LOGI("[CONNECT] fd=%d -> IPv6: [%s]:%d", sockfd, ip, ntohs(sin6->sin6_port));
        }
    }
    return original_connect ? original_connect(sockfd, addr, addrlen) : -1;
}

static ssize_t hooked_write(int fd, const void* buf, size_t count) {
    if (buf && count >= 64 && count <= 65536 && send_count < 50) {
        if (is_socket_fd(fd)) {
            send_count++;
            LOGI("==================================================");
            LOGI("[WRITE] fd=%d, len=%zu", fd, count);
            dump_hex("  DATA", buf, count, 256);
            LOGI("==================================================");
        }
    }
    return original_write ? original_write(fd, buf, count) : -1;
}

static ssize_t hooked_read(int fd, void* buf, size_t count) {
    ssize_t result = original_read ? original_read(fd, buf, count) : -1;
    if (result >= 64 && result <= 65536 && recv_count < 50) {
        if (is_socket_fd(fd)) {
            recv_count++;
            LOGI("==================================================");
            LOGI("[READ] fd=%d, len=%zd", fd, result);
            dump_hex("  DATA", buf, result, 256);
            LOGI("==================================================");
        }
    }
    return result;
}

static ssize_t hooked_sendmsg(int sockfd, const struct msghdr* msg, int flags) {
    if (msg && msg->msg_iov && msg->msg_iovlen > 0 && send_count < 50) {
        send_count++;
        LOGI("==================================================");
        LOGI("[SENDMSG] fd=%d, iovlen=%zu, flags=%d", sockfd, (size_t)msg->msg_iovlen, flags);
        for (size_t i = 0; i < msg->msg_iovlen && i < 4; i++) {
            if (msg->msg_iov[i].iov_base && msg->msg_iov[i].iov_len >= 64 && msg->msg_iov[i].iov_len <= 65536) {
                dump_hex("  DATA", msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, 256);
            }
        }
        LOGI("==================================================");
    }
    return original_sendmsg ? original_sendmsg(sockfd, msg, flags) : -1;
}

static ssize_t hooked_recvmsg(int sockfd, struct msghdr* msg, int flags) {
    ssize_t result = original_recvmsg ? original_recvmsg(sockfd, msg, flags) : -1;
    if (result >= 64 && msg && msg->msg_iov && msg->msg_iovlen > 0 && recv_count < 50) {
        recv_count++;
        LOGI("==================================================");
        LOGI("[RECVMSG] fd=%d, ret=%zd, iovlen=%zu, flags=%d", sockfd, result, (size_t)msg->msg_iovlen, flags);
        for (size_t i = 0; i < msg->msg_iovlen && i < 4; i++) {
            if (msg->msg_iov[i].iov_base && msg->msg_iov[i].iov_len > 0) {
                dump_hex("  DATA", msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len, 256);
            }
        }
        LOGI("==================================================");
    }
    return result;
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

    // ====== SSL_get_verify_result Hook ======
    // 0x05708d14 - 0x2866500 = 0x2FA2814
    void* verify_addr = (void*)(base + 0x2FA2814);
    LOGI("Hooking SSL_get_verify_result @ %p", verify_addr);
    int r_verify = shadowhook_hook_func_addr(verify_addr, (void*)hooked_verify_result, (void**)&original_verify_result);
    LOGI("  → result: %d, original=%p", r_verify, (void*)original_verify_result);

    // ====== Socket Hooks ======
    void* addr;

    addr = (void*)dlsym(RTLD_DEFAULT, "send");
    if (addr) { LOGI("Hooking send @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_send, (void**)&original_send); }

    addr = (void*)dlsym(RTLD_DEFAULT, "recv");
    if (addr) { LOGI("Hooking recv @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_recv, (void**)&original_recv); }

    addr = (void*)dlsym(RTLD_DEFAULT, "sendto");
    if (addr) { LOGI("Hooking sendto @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_sendto, (void**)&original_sendto); }

    addr = (void*)dlsym(RTLD_DEFAULT, "recvfrom");
    if (addr) { LOGI("Hooking recvfrom @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_recvfrom, (void**)&original_recvfrom); }

    addr = (void*)dlsym(RTLD_DEFAULT, "connect");
    if (addr) { LOGI("Hooking connect @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_connect, (void**)&original_connect); }

    addr = (void*)dlsym(RTLD_DEFAULT, "write");
    if (addr) { LOGI("Hooking write @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_write, (void**)&original_write); }

    addr = (void*)dlsym(RTLD_DEFAULT, "read");
    if (addr) { LOGI("Hooking read @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_read, (void**)&original_read); }

    addr = (void*)dlsym(RTLD_DEFAULT, "sendmsg");
    if (addr) { LOGI("Hooking sendmsg @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_sendmsg, (void**)&original_sendmsg); }

    addr = (void*)dlsym(RTLD_DEFAULT, "recvmsg");
    if (addr) { LOGI("Hooking recvmsg @ %p", addr); shadowhook_hook_func_addr(addr, (void*)hooked_recvmsg, (void**)&original_recvmsg); }

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
