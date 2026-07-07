// ============================================================================
//  core/zygisk_entry.cpp — ONE Zygisk module for the ALL-IN-ONE VrShell patch.
//
//  Delivers the SAME payload as the DT_NEEDED build but via Zygisk — the STOCK
//  VrShell.apk is never repacked/re-signed/mounted, so its platform signature +
//  horizonos perms stay intact (no launch-first, no vrshell restart, no freeze).
//
//  ⚠ vrshell TIMING (settled the hard way):
//   * com.oculus.vrshell is a normal app (child_zygote=0, uid=10064) but Zygisk on
//     this Meta build delivers preAppSpecialize and NEVER postAppSpecialize.
//   * You CANNOT spawn a thread in preAppSpecialize: the process must be single-
//     threaded through zygote specialization; a second thread (even one that only
//     sleeps) aborts the specialize -> boot crash-loop (verified: the thread never
//     even reached its first wakeup log).
//   * SOLUTION: preAppSpecialize only INLINE-HOOKS android_dlopen_ext (a pure memory
//     patch — mprotect+memcpy, NO thread, so specialize stays single-threaded). The
//     app calls android_dlopen_ext to load its native libs AFTER specialize; our hook
//     then spawns the worker boot (guarded by getuid()!=0 so it never fires while the
//     process is still mid-specialize as root). Inline (not PLT) so it catches EVERY
//     caller regardless of which lib loads libshell. The workers poll exec regions for
//     libshell's code (name-independent — libshell is mmap'd from inside VrShell.apk).
// ============================================================================
#define LOG_TAG "AIO-Zygisk"
#include "hookutil.h"          // hu::feat_report / prop_on / logging
#include "zygisk.hpp"
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <dlfcn.h>
#include <sys/mman.h>

// Diagnostic to /dev/kmsg (reliable from an app process under permissive SELinux).
static void zdbg(const char* fmt, ...) {
    char b[256];
    va_list ap; va_start(ap, fmt); vsnprintf(b, sizeof b, fmt, ap); va_end(ap);
    __android_log_print(ANDROID_LOG_ERROR, "VRSHZYG", "%s", b);
    int fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) { char l[300]; int n = snprintf(l, sizeof l, "VRSHZYG: %s\n", b); if (n > 0) write(fd, l, (size_t)n); close(fd); }
}

// Exported worker entries, one per feature TU (defined under AIO_MERGE_BUILD).
extern "C" void* aio_worker_entry(void*);      // far-clip / moonjump / teleport / crashproof / debug-UI
extern "C" void* rt_worker_entry(void*);       // on-device cull/coord DUMPER + MCP socket
extern "C" void* player_worker_entry(void*);   // walk / rotate / pos

// Bridges so the rendertrace TU can read/write the SHARED hu:: feature-status registry.
extern "C" int  aio_status_json(char* out, int cap)                        { return hu::get_status_json(out, cap); }
extern "C" void aio_feat_report(const char* name, bool ok, const char* d)  { hu::feat_report(name, ok, d ? d : ""); }

// Read /proc/self/cmdline into buf (NUL-separated argv0 is what we want).
static void read_cmdline(char* buf, size_t n) {
    buf[0] = 0;
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) { ssize_t r = read(fd, buf, n - 1); if (r > 0) buf[r] = 0; else buf[0] = 0; close(fd); }
}

// Staggered feature boot (AIO first so it grabs its signatures on clean libshell pages).
static void* run_workers(void*) {
    LOGI("vrshell-zygisk boot — ALL-IN-ONE: aio + dumper + player");

    // CRITICAL: the feature workers' aio_in_vrshell() gate reads /proc/self/cmdline, but that is set
    // by the Java ActivityThread AFTER native postAppSpecialize — at spawn time it is still "zygote64",
    // so the workers would bail. Wait until cmdline actually becomes com.oculus.vrshell (Java app init
    // has run) before dispatching, so every worker's own vrshell check passes.
    char cmd[128];
    for (int i = 0; i < 200; ++i) {          // up to ~20s
        read_cmdline(cmd, sizeof cmd);
        if (strstr(cmd, "com.oculus.vrshell")) break;
        usleep(100 * 1000);
    }

    pthread_t ta;
    bool okA = pthread_create(&ta, nullptr, aio_worker_entry, nullptr) == 0;
    if (okA) pthread_detach(ta);
    hu::feat_report("aio-worker", okA, okA ? "spawned (zygisk)" : "pthread_create failed");

    usleep(4000 * 1000);
    if (hu::prop_on("rendertrace", true)) {
        pthread_t tr;
        bool okR = pthread_create(&tr, nullptr, rt_worker_entry, nullptr) == 0;
        if (okR) pthread_detach(tr);
        hu::feat_report("dumper-worker", okR, okR ? "spawned" : "pthread_create failed");
    } else {
        hu::feat_report("dumper-worker", false, "hsr.rendertrace=0 (disabled)");
    }

    usleep(1000 * 1000);
    pthread_t tp;
    bool okP = pthread_create(&tp, nullptr, player_worker_entry, nullptr) == 0;
    if (okP) pthread_detach(tp);
    hu::feat_report("player-worker", okP, okP ? "spawned" : "pthread_create failed");
    LOGI("vrshell-zygisk boot done — all feature workers dispatched");
    return nullptr;
}

// ---- inline hook of android_dlopen_ext -------------------------------------------------------
typedef void* (*dlopen_ext_t)(const char*, int, const void*);
static dlopen_ext_t g_orig_dlopen_ext = nullptr;   // thunk: relocated prologue + jump to fn+16
static bool         g_boot_started    = false;

static void spawn_workers_once() {
    if (g_boot_started) return;
    if (getuid() == 0) return;             // still mid-specialize (root) — wait for a later call
    g_boot_started = true;
    zdbg("android_dlopen_ext post-specialize (uid=%d pid=%d) -> spawning AIO workers", getuid(), getpid());
    pthread_t t;
    if (pthread_create(&t, nullptr, run_workers, nullptr) == 0) pthread_detach(t);
    else LOGE("vrshell-zygisk: run_workers pthread_create failed");
}

static void* my_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    spawn_workers_once();
    return g_orig_dlopen_ext(filename, flags, extinfo);
}

// Steal fn[0..15] into an executable thunk (4 position-independent prologue insns + jump to fn+16),
// then overwrite fn[0..15] with an absolute jump to my_dlopen_ext. Same mechanism as the AIO's
// apply_crashproof. android_dlopen_ext's first 4 insns (stp/mov/xpaclri/mov x3,x30) are all
// position-independent (its only PC-relative insn, the `bl`, is at offset 0x10), so the copy is safe.
static bool install_dlopen_inline_hook() {
    uint8_t* fn = (uint8_t*) dlsym(RTLD_DEFAULT, "android_dlopen_ext");
    if (!fn) { zdbg("dlsym(android_dlopen_ext) failed"); return false; }
    size_t PG = (size_t) sysconf(_SC_PAGESIZE);
    void* thunk = mmap(nullptr, PG, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (thunk == MAP_FAILED) { zdbg("thunk mmap failed"); return false; }
    uint32_t t[8]; int tn = 0;
    memcpy(t, fn, 16); tn = 4;                       // 4 relocated prologue insns
    t[tn++] = 0x58000050u;                           // LDR X16,[PC,#8]
    t[tn++] = 0xD61F0200u;                           // BR  X16
    uintptr_t cont = (uintptr_t)fn + 16;
    t[tn++] = (uint32_t)(cont & 0xFFFFFFFFu);
    t[tn++] = (uint32_t)((uint64_t)cont >> 32);
    memcpy(thunk, t, (size_t)tn * 4);
    mprotect(thunk, PG, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)thunk, (char*)thunk + tn * 4);
    g_orig_dlopen_ext = (dlopen_ext_t) thunk;

    uintptr_t tw = (uintptr_t) &my_dlopen_ext;
    uint32_t jmp[4] = { 0x58000050u, 0xD61F0200u, (uint32_t)(tw & 0xFFFFFFFFu), (uint32_t)((uint64_t)tw >> 32) };
    uintptr_t a = (uintptr_t)fn & ~(uintptr_t)(PG - 1);
    uintptr_t b = ((uintptr_t)fn + 16 + PG - 1) & ~(uintptr_t)(PG - 1);
    if (mprotect((void*)a, b - a, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) { zdbg("mprotect fn failed"); return false; }
    memcpy(fn, jmp, 16);
    mprotect((void*)a, b - a, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)fn, (char*)fn + 16);
    return true;
}

using namespace zygisk;

class VrShellAIO : public ModuleBase {
public:
    void onLoad(Api* api, JNIEnv* env) override { api_ = api; env_ = env; }

    void preAppSpecialize(AppSpecializeArgs* args) override {
        target_ = false;
        bool child_zygote = false;
        const char* nice = nullptr;
        if (args && args->nice_name) {
            nice = env_->GetStringUTFChars(args->nice_name, nullptr);
            target_ = nice && strncmp(nice, "com.oculus.vrshell", 18) == 0;
        }
        if (args && args->is_child_zygote) child_zygote = *args->is_child_zygote;
        if (nice) env_->ReleaseStringUTFChars(args->nice_name, nice);

        if (!target_) { api_->setOption(DLCLOSE_MODULE_LIBRARY); return; }
        if (child_zygote) return;   // never patch a zygote; its real app fork gets its own preApp

        // POST-DELIVERY TEST (zero crash risk): do NOTHING in pre except log (via LOGCAT, since kmsg
        // is writable here as root). We rely on postAppSpecialize to spawn the workers.
        LOGI("preApp vrshell pid=%d — deferring to postAppSpecialize (LOGCAT check)", getpid());
        zdbg("preApp vrshell pid=%d — awaiting postAppSpecialize", getpid());
    }

    void postAppSpecialize(const AppSpecializeArgs*) override {
        if (!target_) return;
        // Use zdbg (ERROR level) — INFO is filtered in this context (pre's LOGI never showed but its
        // zdbg did). __android_log_print(ERROR) works from the app uid; the kmsg write just no-ops.
        zdbg("postApp vrshell DELIVERED pid=%d uid=%d — spawning AIO workers (clean path)", getpid(), (int)getuid());
        spawn_workers_once();   // getuid()!=0 here (app uid) so it spawns
    }

private:
    Api* api_ = nullptr;
    JNIEnv* env_ = nullptr;
    bool target_ = false;
};

REGISTER_ZYGISK_MODULE(VrShellAIO)
