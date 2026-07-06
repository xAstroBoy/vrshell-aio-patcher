// ============================================================================
//  QuestUngater — unlock VrShell's BUILT-IN HIDDEN MENUS.
// ----------------------------------------------------------------------------
//  The profile-picture HOVER menu (the "quick action menu") gates its dev/debug
//  entries behind entitlement byte-flags in the ShellConfig struct. IDA V205.2
//  `ShellApp__E982F8` (the shellConfig->JSON telemetry builder) reveals the exact
//  layout: config = *(g_ShellApp + 376), and each flag is one byte:
//     +1165 IsInUnlockedMode            <- the gate on the hidden dev-menu entries
//     +1234 IsSystemQuickActionEnabled  <- the profile-hover quick-action menu
//     +1028 IsOculusTrustedUser         <- internal/trusted user (unhides dev tools)
//     +1045 IsDebugViewInjectionEnabled <- debug view injection
//  We resolve g_ShellApp by the SAME signature the teleport feature uses (an
//  ADRP/LDR pair), then FORCE those bytes = 1 every tick (the entitlement layer can
//  repopulate the struct from the GK server, so a one-shot write can be undone).
//  ⛔ NOT touched: +40 IsKioskModeEnabled (would LOCK the device) and +1173
//     IsDisableShellAppMenuFeatureEnabled (would HIDE the menu — leave 0).
//
//  Standalone feature TU: own LOG_TAG, own worker; the ONE orchestrator spawns
//  unlock_worker_entry() in the merged build. Reports ARMED/FAILED via feat_report.
// ============================================================================
#define LOG_TAG "QuestUngater"
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cinttypes>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include "hookutil.h"
using namespace hu;

// Crash-SAFE memory probe/patch: pread/pwrite on /proc/self/mem fault-as-error
// (return -1) instead of SIGSEGV, so scanning candidate pointers OR writing the
// unlock bytes can never freeze vrshell even if a guess is wrong.
static int g_memfd = -1;
static bool mem_open() { if (g_memfd < 0) g_memfd = open("/proc/self/mem", O_RDWR | O_CLOEXEC); return g_memfd >= 0; }
static bool safe_read(uintptr_t addr, void* out, size_t len) {
    if (!mem_open()) return false;
    return pread(g_memfd, out, len, (off_t)addr) == (ssize_t)len;
}
static bool safe_write(uintptr_t addr, const void* in, size_t len) {
    if (!mem_open()) return false;
    return pwrite(g_memfd, in, len, (off_t)addr) == (ssize_t)len;
}

// g_ShellApp resolver: same ADRP/LDR-pair signature the AIO teleport feature uses.
//   ... ADRP X8,g_ShellApp@PAGE ; LDR X24,[X8,#g_ShellApp@PAGEOFF] ; CBZ X24,* ...
static const char* kShellAppSig    = "e8 16 40 f9 a8 83 1d f8 ?? ?? ?? 90 ?? ?? 40 f9 ?? ?? 00 b4 f6 03 00 aa";
static const int   kShellAppAdrpOff = 8;                 // ADRP is at (match + 8)
static uint8_t*    g_shellApp_ptr   = nullptr;           // &g_ShellApp (the global slot)

static const int   kOffs[]  = { 1165, 1234, 1028, 1045 };
static const char* kNames[] = { "IsInUnlockedMode", "IsSystemQuickActionEnabled",
                                "IsOculusTrustedUser", "IsDebugViewInjectionEnabled" };

static bool resolve_shellapp() {
    uint8_t* fn = find_sig(kShellAppSig);                // scans mapped libshell exec segs
    if (!fn) return false;                               // libshell not mapped / sig absent yet
    g_shellApp_ptr = resolve_adrp_global(fn + kShellAppAdrpOff);
    return g_shellApp_ptr != nullptr;
}

// A candidate config must be readable across the WHOLE flag range (>=1279 bytes) with
// boolean-ish bytes at every known flag offset — a strong fingerprint that rejects the
// message-queue false positive. All reads crash-safe via /proc/self/mem.
static bool looks_like_config(uintptr_t c) {
    if (c < 0x10000 || (c & 7)) return false;
    static const int probe[] = { 40, 43, 44, 45, 46, 64, 65, 84, 1028, 1029, 1030, 1045, 1046, 1165, 1234, 1278 };
    uint8_t b;
    for (int off : probe) { if (!safe_read(c + off, &b, 1)) return false; if (b > 1) return false; }
    return true;
}

// Find config = the ShellConfig byte-flag struct. Teleport's g_ShellApp is a heap
// object that does NOT hold config at +376 (the real ShellApp is a stack object). So
// we double-deref: app -> some member pointer -> (+376) -> config. Cached once found.
static uintptr_t g_config = 0;
static uintptr_t find_config() {
    if (g_config) return g_config;
    if (!g_shellApp_ptr) return 0;
    uintptr_t app = 0; if (!safe_read((uintptr_t)g_shellApp_ptr, &app, 8) || !app) return 0;
    uintptr_t direct = 0; safe_read(app + 376, &direct, 8);
    if (looks_like_config(direct)) { g_config = direct; LOGI("config DIRECT @app+376 = 0x%" PRIxPTR, direct); return g_config; }
    // double-deref: for each member pointer in app, check *(member+376)
    for (int off = 8; off <= 4096; off += 8) {
        uintptr_t mid = 0; if (!safe_read(app + off, &mid, 8) || mid < 0x10000 || (mid & 7)) continue;
        uintptr_t cfg = 0; if (!safe_read(mid + 376, &cfg, 8)) continue;
        if (looks_like_config(cfg)) { g_config = cfg;
            LOGI("config via app+%d -> shellApp 0x%" PRIxPTR " -> +376 = 0x%" PRIxPTR, off, mid, cfg);
            return g_config; }
    }
    return 0;
}

// Returns: -2 sig unresolved, -1 config not located yet, >=0 = bytes forced this tick.
static int poke_unlock() {
    if (!g_shellApp_ptr) return -2;
    uintptr_t cfg = find_config();
    if (!cfg) return -1;
    static bool diag = false;
    if (!diag) { diag = true;
        uint8_t u=0,q=0,t=0,d=0; safe_read(cfg+1165,&u,1); safe_read(cfg+1234,&q,1); safe_read(cfg+1028,&t,1); safe_read(cfg+1045,&d,1);
        LOGI("config 0x%" PRIxPTR " PRE: %s=%u %s=%u %s=%u %s=%u", cfg, kNames[0],u, kNames[1],q, kNames[2],t, kNames[3],d);
    }
    int flipped = 0; uint8_t one = 1, cur = 0;
    for (int off : kOffs) { if (safe_read(cfg + off, &cur, 1) && cur != 1) { if (safe_write(cfg + off, &one, 1)) flipped++; } }
    return flipped;
}

static void* worker(void*) {
    LOGI("QuestUngater worker — resolving g_ShellApp to unlock hidden menus");
    // wait for libshell to map + the g_ShellApp global to resolve (retry ~20 min max)
    for (int i = 0; i < 24000 && !g_shellApp_ptr; ++i) { if (resolve_shellapp()) break; usleep(50 * 1000); }
    if (!g_shellApp_ptr) { LOGW("g_ShellApp sig never resolved — hidden menus left gated");
                           feat_report("ungater", false, "g_ShellApp sig not found"); return nullptr; }
    LOGI("g_ShellApp slot @0x%" PRIxPTR " resolved; forcing unlock flags each tick", (uintptr_t)g_shellApp_ptr);
    bool armed = false; int li = 0;
    for (;; ++li) {
        int u = poke_unlock();
        if (u >= 0 && !armed) { armed = true;
            feat_report("ungater", true, "hidden menus unlocked (unlocked+quickaction+trusted+debugview)"); }
        else if (u < 0 && !armed && (li % 75) == 0) {   // ~5s cadence while config not yet located
            uintptr_t app = 0; safe_read((uintptr_t)g_shellApp_ptr, &app, 8);
            feat_report("ungater", false, app ? "searching ShellApp for config struct" : "ShellApp instance null");
        }
        usleep(66 * 1000);
    }
    return nullptr;
}

#ifdef AIO_MERGE_BUILD
// MERGED build: the ONE orchestrator spawns this. Self-gates to the vrshell process.
extern "C" void* unlock_worker_entry(void*) {
    char cl[256] = {0};
    if (FILE* f = fopen("/proc/self/cmdline", "re")) { size_t n = fread(cl, 1, sizeof cl - 1, f); fclose(f); (void)n; }
    if (!strstr(cl, "com.oculus.vrshell")) { LOGW("unlock_worker_entry: not vrshell — skipping"); return nullptr; }
    return worker(nullptr);
}
#else
__attribute__((constructor))
static void ungater_ctor() {
    static bool started = false; if (started) return; started = true;
    char cl[256] = {0};
    if (FILE* f = fopen("/proc/self/cmdline", "re")) { size_t n = fread(cl, 1, sizeof cl - 1, f); fclose(f); (void)n; }
    if (!strstr(cl, "com.oculus.vrshell")) return;
    pthread_t t; if (pthread_create(&t, nullptr, worker, nullptr) == 0) pthread_detach(t);
}
#endif
