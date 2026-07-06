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

// ── CONFIG-CAPTURE HOOK (the real ungater fix) ───────────────────────────────
// The config byte-flag struct is *(realShellApp + 376). The real ShellApp is a STACK
// object — constructed in fn__FC2E70 as `ShellApp s[298]` on the ShellVrThread stack
// (IDA: fn__FC2E70 -> ShellApp__ShellApp(s,...)), so it is in NO global. That is why the
// teleport-g_ShellApp + double-deref search never located it ("searching ShellApp for
// config struct"). ShellApp__E982F8 (the shellConfig->JSON telemetry builder) is called
// ONCE at construction with X0 = the real ShellApp; we hook its entry, read config =
// *(X0+376), and stash the (stable, heap-allocated) config pointer. killall-restart on
// deploy re-runs construction, so the one-shot hook always fires after we install it.
static volatile uintptr_t g_hooked_config = 0;
static bool g_cfgHooked = false;
// ShellApp__E982F8 entry — 40 bytes, all fixed opcodes (SUB SP / STP x3 / ADD X29 / MOVI /
// MRS X23,TPIDR_EL0 / MOV X19,X1 / LDR guard); a construction-prologue fingerprint unique
// enough that find_sig can't collide. First 16 bytes = the 4 insns install_hook relocates.
static const char* kCfgFnSig =
  "ff 83 02 d1 fd 7b 06 a9 f7 3b 00 f9 f6 57 08 a9 f4 4f 09 a9 fd 83 01 91 00 e4 00 6f 57 d0 3b d5 f3 03 01 aa e8 16 40 f9";
static bool install_config_hook() {
    if (g_cfgHooked) return true;
    uint8_t* fn = find_sig(kCfgFnSig);
    if (!fn) return false;                               // libshell not mapped yet
    uintptr_t cont = (uintptr_t)fn + 16;                 // resume after the 4 relocated insns
    uintptr_t slot = (uintptr_t)&g_hooked_config;
    uint32_t c[16]; int n = 0;
    int ldrSlot = n++;                                   // [0] LDR X10,[PC,#slot]
    c[n++] = 0xF940BC09u;                                // [1] LDR X9,[X0,#376]  config=*(a1+376)
    c[n++] = 0xF9000149u;                                // [2] STR X9,[X10]      *slot=config
    c[n++] = 0xD10283FFu;                                // [3] (orig) SUB SP,SP,#..
    c[n++] = 0xA9067BFDu;                                // [4] (orig) STP X29,X30,[SP,#0x60]
    c[n++] = 0xF9003BF7u;                                // [5] (orig) STR X23,[SP,#0x70]
    c[n++] = 0xA90857F6u;                                // [6] (orig) STP X22,X21,[SP,#0x80]
    int ldrCont = n++;                                   // [7] LDR X16,[PC,#cont]
    c[n++] = 0xD61F0200u;                                // [8] BR X16 -> fn+16
    int contq = n; c[n++] = (uint32_t)(cont & 0xFFFFFFFFu); c[n++] = (uint32_t)((uint64_t)cont >> 32);
    int slotq = n; c[n++] = (uint32_t)(slot & 0xFFFFFFFFu); c[n++] = (uint32_t)((uint64_t)slot >> 32);
    c[ldrSlot] = LDR_XLIT(10, slotq - ldrSlot);
    c[ldrCont] = LDR_XLIT(16, contq - ldrCont);
    if (!install_hook(fn, c, n)) return false;
    g_cfgHooked = true;
    LOGI("config-capture hook @ ShellApp__E982F8 0x%" PRIxPTR " (captures *(ShellApp+376) at construction)", (uintptr_t)fn);
    return true;
}

// ── EARLY HOOK ARMING — the fix for "hidden menus stopped unlocking" ──────────
// ShellApp__E982F8 runs EXACTLY ONCE, at ShellApp construction on the ShellVrThread.
// The merged orchestrator spawns the ungater WORKER ~5s into startup (after the
// dumper/player staggers), so a hook installed there arms AFTER ShellApp is already
// built — the one-shot never fires and the worker spins "waiting for ShellApp
// construction" forever (the exact regression once the questctl_aio Zygisk early-
// injection was disabled and the lib now loads only via libshell's DT_NEEDED).
// We ARE that DT_NEEDED, so our init_array runs at libshell load — before libshell's
// own init and long before the VR thread constructs ShellApp. The ONE orchestrator
// ctor calls this SYNCHRONOUSLY at that point, arming the capture hook in time.
// Idempotent + vrshell-gated; libshell exec segs are already mmap'd (we're its
// dependency) so find_sig resolves on the first try — the short retry only covers a
// not-yet-settled mapping. Safe from the linker thread: find_sig/install_hook are
// pure libc (maps scan + mprotect + mmap), no dlopen/pthread/static-init deps.
extern "C" void unlock_arm_config_hook(void) {
    if (g_cfgHooked) return;
    char cl[256] = {0};
    if (FILE* f = fopen("/proc/self/cmdline", "re")) { size_t n = fread(cl, 1, sizeof cl - 1, f); fclose(f); (void)n; }
    if (!strstr(cl, "com.oculus.vrshell")) return;   // inert outside the shell host process
    for (int i = 0; i < 40 && !g_cfgHooked; ++i) { if (install_config_hook()) break; usleep(2 * 1000); }
    if (g_cfgHooked) LOGI("config hook armed EARLY at lib-load (before ShellApp construction)");
    else             LOGW("early config-hook arm: libshell sig not resolved at ctor — worker loop will retry");
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
    // PRIMARY: the E982F8 construction hook captured config = *(realShellApp+376) directly.
    if (g_hooked_config && looks_like_config(g_hooked_config)) {
        g_config = g_hooked_config; LOGI("config via E982F8 hook = 0x%" PRIxPTR, g_config); return g_config; }
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
    if (!g_shellApp_ptr && !g_cfgHooked) return -2;
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
    LOGI("QuestUngater worker — hooking ShellApp config builder + resolving g_ShellApp");
    // Install the config-capture hook ASAP — it MUST be in place before the VR thread
    // constructs the ShellApp (which is when ShellApp__E982F8 runs once). The lib ctor
    // runs at libshell dlopen (all exec segs already mapped), well ahead of construction.
    for (int i = 0; i < 24000 && !g_cfgHooked; ++i) { if (install_config_hook()) break; usleep(50 * 1000); }
    // Fallback path: resolve the teleport g_ShellApp global too (used only if the hook
    // ever misses construction, e.g. a hot-swap that didn't restart vrshell).
    for (int i = 0; i < 200 && !g_shellApp_ptr; ++i) { if (resolve_shellapp()) break; usleep(50 * 1000); }
    if (!g_cfgHooked && !g_shellApp_ptr) { LOGW("neither config hook nor g_ShellApp resolved — hidden menus left gated");
                           feat_report("ungater", false, "config hook + g_ShellApp both unresolved"); return nullptr; }
    LOGI("ungater armed (cfgHook=%d shellApp=%p); forcing unlock flags each tick", g_cfgHooked, (void*)g_shellApp_ptr);
    bool armed = false; int li = 0;
    for (;; ++li) {
        int u = poke_unlock();
        if (u >= 0 && !armed) { armed = true;
            feat_report("ungater", true, "hidden menus unlocked (unlocked+quickaction+trusted+debugview)"); }
        else if (u < 0 && !armed && (li % 75) == 0) {   // ~5s cadence while config not yet located
            feat_report("ungater", false, g_cfgHooked ? "config hook armed — waiting for ShellApp construction"
                                                       : "config not located yet");
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
