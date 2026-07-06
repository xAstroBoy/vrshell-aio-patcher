// ============================================================================
//  core/orchestrator.cpp — the ONE constructor for the ALL-IN-ONE .so.
//
//  WHY THIS EXISTS: each feature TU (aio / rendertrace / player) used to carry
//  its OWN __attribute__((constructor)). When all three were linked into ONE
//  libquestctl_aio.so the linker's init_array ordering + section GC dropped one
//  of them — the merged build armed the dumper (rendertrace) but NOT moonjump
//  (aio), and player-ctl (which had no companion ctor at all) never armed. That
//  is the "far-clip works but jump doesn't" bug.
//
//  THE FIX: compile the per-feature ctors out (-DAIO_MERGE_BUILD) and drive every
//  feature from THIS single constructor. Because this TU *references* all three
//  worker entry symbols, none can be GC'd, and there is exactly ONE ctor so there
//  is no ordering ambiguity. The workers are spawned in a short staggered order
//  (AIO first, so it grabs its far-clip / locomotion signatures on clean libshell
//  pages before the dumper starts trampolining the same code) — one process, one
//  boot sequence, ALL hooks. Each feature still logs under its own LOG_TAG and
//  reports ARMED/FAILED through hu::feat_report so we see exactly what needs
//  intervention.  << ALL - IN - ONE >>
// ============================================================================
#define LOG_TAG "AIO-Core"
#include "hookutil.h"          // hu::feat_report / prop_on / logging
#include <pthread.h>

// Exported worker entries, one per feature TU (defined under AIO_MERGE_BUILD).
extern "C" void* aio_worker_entry(void*);      // far-clip / moonjump / teleport / crashproof / debug-UI
extern "C" void* rt_worker_entry(void*);       // on-device cull/coord DUMPER + MCP socket
extern "C" void* player_worker_entry(void*);   // walk / rotate / pos
extern "C" void* unlock_worker_entry(void*);   // QuestUngater: unlock built-in hidden menus

// Bridges so the rendertrace TU (which does NOT include hookutil.h) can read/write the SHARED
// hu:: feature-status registry — powers the `stat` bridge command (one view of every hook: armed/failed).
extern "C" int  aio_status_json(char* out, int cap)                        { return hu::get_status_json(out, cap); }
extern "C" void aio_feat_report(const char* name, bool ok, const char* d)  { hu::feat_report(name, ok, d ? d : ""); }

static bool orch_in_vrshell() {
    char buf[256] = {0};
    FILE* f = fopen("/proc/self/cmdline", "re");
    if (!f) return false;
    size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f); (void)n;
    return strstr(buf, "com.oculus.vrshell") != nullptr;
}

// Boot thread: keep the constructor itself instant (init_array runs on the linker
// thread). Spawns each feature worker in a staggered sequence and registers its
// launch in the status registry so `questctl status` / the MCP can read it back.
static void* orch_boot(void*) {
    LOGI("orchestrator boot — ALL-IN-ONE: aio + dumper + player, one worker sequence");

    // 1) AIO first (far-clip / moonjump / teleport / crashproof / debug-UI). It hooks
    //    the asset-init dispatch synchronously inside its entry, then loops installing
    //    the render/locomotion sites as the env comes up.
    pthread_t ta;
    bool okA = pthread_create(&ta, nullptr, aio_worker_entry, nullptr) == 0;
    if (okA) pthread_detach(ta);
    hu::feat_report("aio-worker", okA, okA ? "spawned" : "pthread_create failed");

    // 2) Dumper — stagger ~4s so AIO matches its signatures on un-trampolined libshell
    //    pages first (the dumper overwrites cull-job bytes; racing it perturbed the
    //    AIO locomotion-sig scan in the old two-ctor build).
    usleep(4000 * 1000);
    if (hu::prop_on("rendertrace", true)) {
        pthread_t tr;
        bool okR = pthread_create(&tr, nullptr, rt_worker_entry, nullptr) == 0;
        if (okR) pthread_detach(tr);
        hu::feat_report("dumper-worker", okR, okR ? "spawned" : "pthread_create failed");
    } else {
        hu::feat_report("dumper-worker", false, "hsr.rendertrace=0 (disabled)");
    }

    // 3) Player-ctl (walk/rotate/pos) — small extra stagger, independent hook sites.
    usleep(1000 * 1000);
    pthread_t tp;
    bool okP = pthread_create(&tp, nullptr, player_worker_entry, nullptr) == 0;
    if (okP) pthread_detach(tp);
    hu::feat_report("player-worker", okP, okP ? "spawned" : "pthread_create failed");

    // 4) QuestUngater — unlock built-in hidden menus (resolves g_ShellApp, forces flags).
    pthread_t tu;
    bool okU = pthread_create(&tu, nullptr, unlock_worker_entry, nullptr) == 0;
    if (okU) pthread_detach(tu);
    hu::feat_report("ungater-worker", okU, okU ? "spawned" : "pthread_create failed");

    LOGI("orchestrator boot done — all feature workers dispatched");
    return nullptr;
}

__attribute__((constructor))
static void orchestrator_ctor() {
    static bool started = false;
    if (started) return;
    started = true;
    if (!orch_in_vrshell()) return;   // inert outside the vrshell host process
    LOGI("ALL-IN-ONE ctor — libshell pulled us in; launching orchestrator boot");
    pthread_t t;
    if (pthread_create(&t, nullptr, orch_boot, nullptr) == 0) pthread_detach(t);
    else LOGE("orchestrator: boot pthread_create failed — NO features will arm");
}
