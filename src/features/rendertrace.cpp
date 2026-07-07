// ============================================================================
//  HSR Render-Trace — Zygisk module (ROOTED, in-memory, libshell on disk untouched)
// ----------------------------------------------------------------------------
//  Goal: understand the V205 render/cull/skeleton pipeline ON DEVICE (the desktop
//  preview is NOT faithful), and pin down WHY ported skinned meshes disappear or
//  land in the wrong place. Two complementary mechanisms, both gated by props:
//
//   (1) UNLOCK META'S OWN LOGS (hsr.rt_verbose, default ON when module active):
//       libshell ships a huge body of Log_write_formatted() messages — cull,
//       skeleton, skinned-mesh validation, occlusion — all gated by Log_levelEnabled
//       (0x9F31A4), which reads two adjacent globals:
//          n3            @ libshell+0x29EB9EC  = global DEFAULT log level (byte)
//          dword_29EB9ED @ libshell+0x29EB9ED  = "use per-channel config" flag (byte)
//       Log_levelEnabled: if flag==1 -> per-channel level; else -> n3 >= requested.
//       So we force n3=0xFF (max) and flag=0 (ignore channel config) => EVERYTHING
//       passes. This surfaces e.g. "Inconsistent data: {} vertices are skinned but
//       mesh has {} vertices" / "Mesh is not skinned to any joint" (gltf_mesh_io,
//       0x1D0E58C) — a LOAD-time rejection that silently drops our cooked skinned
//       mesh — plus "Culling Pipeline {}", "setModelVisible", skeleton-corruption
//       checks, etc.
//
//   (2) NUMERIC CULL TRACE (hsr.rt_cull, default ON): the values Meta does NOT
//       print. RenderableCullJob__9BA420 (libshell+0x9BA420) is the per-FRAME
//       frustum-cull pass; it walks the renderable list internally and culls when
//       the closest-point-on-AABB distance² exceeds the cull threshold a2[33]. We
//       install an ENTRY trampoline that calls a C thunk; the thunk RE-WALKS the
//       same list READ-ONLY and logs, per renderable: center (proxy+80),
//       half-extents (proxy+96), computed dist², the threshold, and CULLED/keep.
//       This is THE diagnostic for "skinned disappearing/misplaced": it shows
//       exactly which meshes get culled and where their bounding volume sits (the
//       double-transform 2E bug puts the box at twice the entity position).
//       Throttled to ~2 Hz with a per-call cap so it never hot-paths the headset.
//
//   (3) SKELETON TRACE (hsr.rt_skel, default ON): SkeletonSystem_vf7__1480F70
//       (libshell+0x1480F70) is the per-frame skeleton update that builds skinned
//       cull bounds — per-joint, SKIPPING JOINT 0 (the loop runs n-1 times). We log
//       skeleton self + joint count once per frame (throttled).
//
//  All hooks are runtime byte-trampolines installed after a /proc/self/maps signature
//  scan of the embedded libshell; disk is never touched; Magisk re-applies each boot;
//  signature-missing => no-op. Mirrors the proven _zygisk_farclip install pattern.
// ============================================================================
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cinttypes>
#include <string>                    // std::string for app->wall pin (ABI-matches libshell's libc++)
#include <unistd.h>
#include <pthread.h>
#include <dlfcn.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/system_properties.h>
#include <android/log.h>

#include "zygisk.hpp"

#define LOG_TAG "HSR-RT"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// Bridges into the SHARED hu:: feature-status registry (defined in orchestrator.cpp, which includes
// hookutil.h). Lets the `stat` command show EVERY feature/hook (aio + dumper) armed-or-failed in one shot.
extern "C" int  aio_status_json(char* out, int cap);
extern "C" void aio_feat_report(const char* name, bool ok, const char* detail);

// ── libshell V205 offsets (IDA-confirmed, port 13338 DB) ────────────────────
//  We anchor on fn__EFA9D0 by signature (identical bytes to V79's far-clip fn,
//  re-confirmed on the V205 DB), then everything else is base-relative.
static const uint8_t kPrologue[16] = { 0xff,0x83,0x01,0xd1, 0xfd,0x7b,0x04,0xa9, 0xf4,0x4f,0x05,0xa9, 0xfd,0x03,0x01,0x91 };
static const uint8_t kSig[16]      = { 0x08,0xcc,0x40,0xb9, 0x09,0x5c,0x40,0xf9, 0x08,0x79,0x1f,0x12, 0x08,0xcc,0x00,0xb9 };
static const int     kSigOff       = 0x1C;
static const uintptr_t OFF_EFA9D0          = 0xEFA9D0;   // anchor (far-clip fn)
static const uintptr_t OFF_LOGLEVEL_N3     = 0x29EB9EC;  // global default log level (byte)
static const uintptr_t OFF_LOGLEVEL_FLAG   = 0x29EB9ED;  // "use per-channel config" flag (byte)
static const uintptr_t OFF_CULLJOB         = 0x9BA39C;   // RenderableCullJob (per-frame frustum cull) — re-anchored for the current stock libshell build (was 0x9BA420)
static const uintptr_t OFF_SKEL_VF7        = 0x1480F4C;  // SkeletonSystem_vf7 (per-frame skeleton/skinned-bounds) — re-anchored (was 0x1480F70)
static const uintptr_t OFF_SLIDELOCO       = 0x18CCE7C;  // SlideLocomotionController_update (player pos/rot/move) — re-anchored (was 0x18CCEA0)
static const int       LOCO_POS_OFF        = 144;        // a3+144 = live player position (IDA/player-ctl note)
// ⛔ 1625F74/AC0958 are the MHE HzAnimSystem (shell panels/hands) — NOT the path our HSR-RenderGraph env
//    uses (both came back calls=0 / all-rejected). The env's skinned meshes bind sbSkinningMatrices via the
//    HSR renderer's RenderableProxy__ABC928. The live per-frame joint matrices are in the render system's
//    per-instance array: v7 = *(x3) + 248*x1; idx = *(int*)(v7+236); v68 = x0 + 1232*idx;
//    jointStart=*(v68+336), jointEnd=*(v68+344), count=(end-start)/64, matrix 64B ea (translation @+48).
// RELIABLE skeleton anchor: AnimationPlayback__210FA48(x0=skeleton, x1=jointName, x2=out) — decompiled,
// it reads the POSED joint matrix from skeleton+72 (resultModelMatrices_ start)/+80 (end), 64B ea,
// translation @+48. Hooking it captures the skeleton ptr -> read ALL posed joints = the env's live pose.
static const uintptr_t OFF_HZANIM_210FA48  = 0x210FA24;   // AnimationPlayback pose — re-anchored for the current stock libshell (was 0x210FA48)
// Game teleport message (player.cpp / nativeTeleportToCoordinates @0xFBDB54): resolve g_ShellApp, operator-new
// a 128B msg {x@0,y@4,z@8,yaw@12,type=35@120}, post to *(g_ShellApp+16) via TypedMessageQueue kind=98. This is
// the game's OWN teleport (respects collision, sets FACING yaw) — the proven way to ROTATE the player on device.
static const uintptr_t OFF_G_SHELLAPP      = 0x2981030;  // g_ShellApp global
static const uintptr_t OFF_OP_NEW          = 0x27D5120;  // operator new wrapper (__wrap__Znwm)
static const uintptr_t OFF_TMQ_POST        = 0xEA9DCC;   // TypedMessageQueue post

static uint8_t* g_base = nullptr;

// AIO TU accessors (same .so): the moonjump owns the loco hook, so ITS cmd block holds the live player pos +
// the no-gravity flag. We drive/read them from the ctl server so `nogravity`/`playerpos` reflect real state.
extern "C" void aio_set_nogravity(int on);
extern "C" int  aio_get_nogravity();
extern "C" int  aio_get_curpos(float out[3]);

// ── runtime world snapshot (stashed by the hooks so the MCP control server can
//    inspect/dump the live cull world on demand, between frames) ──────────────
static volatile uint64_t g_cullctx = 0;   // last RenderableCullJob a2 (cull context: camera, frusta, thresholds)
static volatile uint64_t g_listmgr = 0;   // last RenderableCullJob a4 (&listMgr -> renderable list head)
static volatile uint64_t g_skelres = 0;   // last SkeletonSystem_vf7 result (skeleton system)
static volatile uint64_t g_loco_this = 0; // last SlideLocomotionController `this` (a1)
static volatile uint64_t g_loco_a3 = 0;   // last SlideLocomotionController update a3 (a3+144 = player pos)
static volatile int      g_logmask = 0;   // bit0=cull logging, bit1=skel logging (MCP can flip without reinstall)
static volatile int      g_forcevis = 0;  // 1 => cull trampoline flips every renderable to NOCULL (ext.x<0) to TEST/defeat culling
static volatile int      g_forcevis_n = 0;// count flipped last frame (confirms the override is live)

// ── SKINNING SNAPSHOT — the DEVICE's runtime-computed joint matrices, captured in the HzAnim
//    trampoline (HzAnimSystem__EF4138). Keyed by mesh AssetRef id so `envdump`/`hzanim` can
//    correlate each animated mesh's TRUE device transform with the cooker's asset ids. This is
//    the ONLY place the animated (skinned) world position exists — the render proxy's model
//    matrix stays identity for world-baked skinned meshes, and the cull bound is 1e5-overridden. ─
static const int CURVE_N = 48;   // ring length: ~6 s of motion at the 8 Hz curve sample rate
struct HzRec {
    uint64_t obj;          // the HzAnim renderable object (x2)
    uint64_t assetId[2];   // mesh MurmurHash128 (lo,hi)
    int      nj;           // joint count
    float    m0[16];       // joint[0] full 4x4 (the STATIC root for our 2-joint rigid cook)
    float    mN[16];       // joint[last] full 4x4 (the MOVING joint that carries the path)
    uint64_t stamp;        // last-seen ms
    float    curve[CURVE_N][3];  // ANIMATION STEPS/CURVE: ring of the mover-joint translation over time
    int      cw;           // ring write index
    int      cn;           // samples written (<=CURVE_N)
    uint64_t cms;          // last curve-sample ms (8 Hz throttle)
};
static const int HZ_MAX = 128;
static HzRec           g_hz[HZ_MAX];
static volatile int    g_hz_n = 0;
static volatile uint64_t g_hz_calls = 0;   // times the skinning fn fired (0 => meshes NOT skinned = FROZEN)
static volatile uint64_t g_hz_rej   = 0;   // times a call was rejected by the guards (bad ptr / nj)

// proxy pointers captured during the cull walk (list only valid mid-cull) so `envdump` can
// re-read each proxy's stable transform/resource between frames.
static uint64_t        g_proxies[512];
static volatile int    g_nproxies = 0;

// ── safe self-memory access: process_vm_readv/writev on our own pid returns EFAULT
//    on a bad address instead of SIGSEGV-ing vrshell (so MCP read/write can't crash it) ──
static long safe_read(uint64_t addr, void* out, size_t len) {
    struct iovec lo{ out, len }, ro{ (void*)addr, len };
    return process_vm_readv(getpid(), &lo, 1, &ro, 1, 0);
}
static long safe_write(uint64_t addr, const void* in, size_t len) {
    // page must be writable; flip it RW first (libshell .data/.bss usually already is)
    size_t PG=(size_t)sysconf(_SC_PAGESIZE); uintptr_t pg=addr & ~(uintptr_t)(PG-1);
    mprotect((void*)pg, PG + ((addr+len > pg+PG) ? PG : 0), PROT_READ|PROT_WRITE);
    struct iovec lo{ (void*)in, len }, ro{ (void*)addr, len };
    return process_vm_writev(getpid(), &lo, 1, &ro, 1, 0);
}

// ── /proc/self/maps signature scan for the embedded libshell anchor ─────────
static uint8_t* find_anchor() {
    FILE* f = fopen("/proc/self/maps", "re");
    if (!f) return nullptr;
    char line[1024]; uint8_t* hit = nullptr;
    while (fgets(line, sizeof line, f) && !hit) {
        if (!strstr(line, "VrShell.apk") && !strstr(line, "libshell")) continue;
        uintptr_t lo = 0, hi = 0; char perms[8] = {0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &lo, &hi, perms) != 3 || hi <= lo || perms[2] != 'x') continue;
        mprotect((void*)lo, (size_t)(hi - lo), PROT_READ | PROT_EXEC);
        uint8_t* p = (uint8_t*)lo; uint8_t* end = (uint8_t*)hi - sizeof kSig;
        for (; p <= end; ++p) {
            if (memcmp(p, kSig, sizeof kSig) != 0) continue;
            uint8_t* fn = p - kSigOff;
            // Accept EITHER the original prologue OR the AIO far-clip jump-stub: in the merged
            // build the orchestrator installs the far-clip hook at fn__EFA9D0 FIRST, overwriting
            // its prologue with 0x58000050 (LDR X16,[PC,#8]). Without this, rendertrace loops
            // forever "scanning for anchor" and the control server / dumper never come up.
            if (fn >= (uint8_t*)lo &&
                (memcmp(fn, kPrologue, sizeof kPrologue) == 0 || *(uint32_t*)fn == 0x58000050u)) { hit = fn; break; }
        }
    }
    fclose(f);
    return hit;
}

// ── prop helpers (hsr.<name> | persist.hsr.<name>) ──────────────────────────
static bool prop_on(const char* name, bool dflt) {
    char buf[PROP_VALUE_MAX] = {0}, k[96];
    snprintf(k, sizeof k, "hsr.%s", name);
    if (__system_property_get(k, buf) <= 0) { snprintf(k, sizeof k, "persist.hsr.%s", name); __system_property_get(k, buf); }
    if (!buf[0]) return dflt;
    char c = buf[0]; return c=='1'||c=='t'||c=='T'||c=='y'||c=='Y';
}
static int prop_int(const char* name, int dflt) {
    char buf[PROP_VALUE_MAX] = {0}, k[96];
    snprintf(k, sizeof k, "hsr.%s", name);
    if (__system_property_get(k, buf) <= 0) { snprintf(k, sizeof k, "persist.hsr.%s", name); __system_property_get(k, buf); }
    if (!buf[0]) return dflt;
    return (int)strtol(buf, nullptr, 10);
}
static void wr8(uint8_t* p, uint8_t v) {
    size_t PG=(size_t)sysconf(_SC_PAGESIZE); uintptr_t pg=(uintptr_t)p & ~(uintptr_t)(PG-1);
    if (mprotect((void*)pg, PG, PROT_READ|PROT_WRITE)==0) *(volatile uint8_t*)p = v;
}

// ── monotonic ms (for log throttling) ───────────────────────────────────────
static uint64_t now_ms() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec*1000ull + ts.tv_nsec/1000000ull;
}

// ============================================================================
//  C THUNKS — called from the entry trampolines. READ-ONLY; never mutate game
//  state. All throttled so the headset never softlocks (cf. the Frida hot-path
//  softlock note). Args mirror the original function's x0..x5 at entry.
// ============================================================================

// closest-point-on-AABB distance² from camera, mirroring RenderableCullJob math.
static inline float closest_dist2(const float* cam, const float* center, const float* halfext) {
    float d2 = 0.f;
    for (int i = 0; i < 3; i++) {
        float mn = center[i] - halfext[i], mx = center[i] + halfext[i];
        float c = cam[i] < mn ? mn : (cam[i] > mx ? mx : cam[i]);
        float dd = c - cam[i]; d2 += dd*dd;
    }
    return d2;
}

// plausible arm64 userspace pointer: 8-aligned, above the null page, within the 39/48-bit VA.
static inline bool okptr(uint64_t p) { return p >= 0x1000 && p < 0x8000000000ULL && (p & 7) == 0; }
// 4-aligned float pointer (planes are float-aligned, not necessarily 8).
static inline bool okfptr(uint64_t p) { return p >= 0x1000 && p < 0x8000000000ULL && (p & 3) == 0; }

// Faithful port of loc_9BA36C (the RenderableCullJob frustum test): conservative
// positive-vertex AABB-vs-6-plane test. plane = (nx,ny,nz,d); "inside" half-space is
// n·x + d >= 0. Pick the box corner farthest along +n (max where n>=0 else min); if that
// p-vertex is behind a plane (dist < 0) the whole box is outside that plane -> not inside.
// Returns true iff the AABB is inside (or straddling) all 6 planes of this one frustum.
static bool aabb_in_frustum(const float* c, const float* e, const float* pl /*6*4 floats*/) {
    for (int p = 0; p < 6; p++) {
        const float* n = pl + p*4;
        float pvx = n[0] >= 0.f ? c[0]+e[0] : c[0]-e[0];
        float pvy = n[1] >= 0.f ? c[1]+e[1] : c[1]-e[1];
        float pvz = n[2] >= 0.f ? c[2]+e[2] : c[2]-e[2];
        if (n[0]*pvx + n[1]*pvy + n[2]*pvz + n[3] < 0.f) return false;  // box fully behind plane
    }
    return true;
}

// Classify one renderable proxy EXACTLY as RenderableCullJob__9BA420 does (center proxy+80,
// half-ext proxy+96; ext.x<0 => nocull; closest-point dist² vs a2[33]; else inside-any-frustum).
// Fills c3/e3, returns verdict string. a2 = the cull context.
static const char* classify_proxy(uint64_t a2, uint64_t proxy, float* c3, float* e3) {
    const float* center  = (const float*)(proxy + 80);
    const float* halfext = (const float*)(proxy + 96);
    c3[0]=center[0]; c3[1]=center[1]; c3[2]=center[2];
    e3[0]=halfext[0]; e3[1]=halfext[1]; e3[2]=halfext[2];
    if (halfext[0] != halfext[0] || halfext[0] > 1e8f) return "BADBOUNDS";
    if (halfext[0] < 0.f) return "NOCULL";                 // ext.x<0 => always visible
    const float* a2f=(const float*)a2; const float* cam=a2f+40; float thr=a2f[132];
    if (closest_dist2(cam, center, halfext) > thr) return "DIST-CULL";
    int64_t cw=*(const int64_t*)(a2+320); uint64_t nfr=(uint64_t)cw & 0x3FFFFFFFFFFFFFFFULL;
    const float* frusta=(cw>=0)?(const float*)(a2+336):(const float*)(*(const uint64_t*)(a2+336));
    if (okfptr((uint64_t)frusta) && nfr>0 && nfr<64) {
        for (uint64_t f=0; f<nfr; f++) if (aabb_in_frustum(center,halfext,frusta+f*24)) return "VISIBLE";
        return "FRUSTUM-CULL";                             // <-- disappear-on-rotate cause
    }
    return "VISIBLE";                                      // no frusta info -> can't frustum-cull
}

// Walk the last-seen renderable list (stashed g_cullctx/g_listmgr), writing one line per
// renderable: "idx cx cy cz ex ey ez VERDICT". Shared by the logcat trace AND the MCP socket.
static int render_world_dump(char* out, int cap) {
    uint64_t a2=g_cullctx, a4=g_listmgr;
    if (!okptr(a2) || !okptr(a4)) return snprintf(out,cap,"ERR no cull context yet (need rt_cull armed + 1 frame)\n");
    const float* a2f=(const float*)a2; const float* cam=a2f+40; float thr=a2f[132];
    int64_t cw=*(const int64_t*)(a2+320); uint64_t nfr=(uint64_t)cw & 0x3FFFFFFFFFFFFFFFULL;
    int len = snprintf(out,cap,"cam=%.3f,%.3f,%.3f thr_m=%.1f frusta=%llu\n",
                       cam[0],cam[1],cam[2], thr>0?__builtin_sqrtf(thr):-1.f, (unsigned long long)nfr);
    uint64_t v8=*(uint64_t*)a4; if(!okptr(v8)) return len;
    uint64_t node=*(uint64_t*)(v8+96);
    int n=0,scanned=0;
    for (; okptr(node) && n<512 && scanned<8192 && len<cap-160; node=*(uint64_t*)node, scanned++) {
        uint64_t proxy=*(uint64_t*)(node+16); if(!okptr(proxy)) continue;
        if (n < 512) g_proxies[n] = proxy;                 // stash for `envdump` (proxy objects are stable between frames)
        float c[3],e[3]; const char* v=classify_proxy(a2,proxy,c,e);
        len += snprintf(out+len, cap-len, "%d %.3f %.3f %.3f %.3f %.3f %.3f %s proxy=0x%llx\n",
                        n, c[0],c[1],c[2], e[0],e[1],e[2], v, (unsigned long long)proxy);
        n++;
    }
    g_nproxies = n;
    len += snprintf(out+len, cap-len, "# total=%d scanned=%d\n", n, scanned);
    return len;
}

// Live world snapshot, captured INSIDE the cull trampoline (where the list pointers are valid)
// and served verbatim to the MCP server — the renderable list is only populated/valid during
// the cull pass, so re-walking it later (between frames) finds nothing.
static char            g_world_buf[24576];
static volatile int    g_world_len = 0;
static volatile uint64_t g_world_ms = 0;

// RenderableCullJob__9BA420(a1, a2=cullCtx, a3=layerMask, a4=&listMgr, a5=&view, a6).
// Each pass (throttled ~5 Hz) snapshots the per-renderable cull verdicts into g_world_buf for
// the MCP `renderables` command, and — if cull logging is on — also emits them to logcat.
// FORCE-NOCULL: walk the live cull list and flip each real renderable's half-ext.x negative — the
// device's RenderableCullJob marks ext.x<0 as NOCULL (always visible). Runs EVERY cull frame, BEFORE
// the original cull reads the bound, so it persistently defeats frustum/dist culling even though the
// SkeletonSystem rewrites a positive bound earlier each frame. Reversible: clearing g_forcevis stops
// the writes and each system's normal bound takes over next frame. THIS is the lever the cook can't
// reach (the device recomputes skinned bounds and ignores all cooked bound data).
static void force_nocull_walk(uint64_t a4) {
    if (!okptr(a4)) return;
    uint64_t a2 = g_cullctx;
    const float* cam = okptr(a2) ? ((const float*)a2 + 40) : nullptr;   // cull-context camera pos (a2f+40)
    uint64_t v8=*(uint64_t*)a4; if(!okptr(v8)) return;
    uint64_t node=*(uint64_t*)(v8+96);
    int scanned=0, flipped=0;
    for (; okptr(node) && scanned<8192; node=*(uint64_t*)node, scanned++) {
        uint64_t proxy=*(uint64_t*)(node+16); if(!okptr(proxy)) continue;
        float* he=(float*)(proxy+96);
        float* c=(float*)(proxy+80);
        float x=he[0];
        // ONLY distant real-mesh bounds. Skip: the near-camera compositor/fade/panels (a full-screen
        // black fade forced-visible = the dark screen), the 1e5 scene-spanning statics (already fine),
        // and tiny far probes. The skinned omnidroid is a medium bound (~3..20) several metres out.
        if (!(x==x) || x <= 0.6f || x >= 5000.f) continue;                // not tiny, not the 1e5 override
        if (cam) { float dx=c[0]-cam[0], dy=c[1]-cam[1], dz=c[2]-cam[2];
                   if (dx*dx+dy*dy+dz*dz < 100.f) continue; }             // within 10 m of the eye -> compositor/hands, leave alone
        // Give it the SAME scene-spanning POSITIVE bound the static meshes use (center 0, ext 1e5):
        // passes the frustum test (never culled) AND renders normally. NOT ext.x<0 — that's NOCULL but a
        // degenerate extent that ALSO kills the draw (the mesh vanished completely). The skinned geometry
        // still draws at its skeleton-posed position; this only replaces the cull bound the device recomputes.
        c[0]=0.f; c[1]=0.f; c[2]=0.f;
        he[0]=100000.f; he[1]=100000.f; he[2]=100000.f; flipped++;
    }
    g_forcevis_n = flipped;
}

static void pin_tick();                                  // fwd (defined below, after the pin globals)
extern "C" __attribute__((used))
void hsr_rt_cull(uint64_t /*a1*/, uint64_t a2, uint64_t /*a3*/, uint64_t a4, uint64_t /*a5*/, uint64_t /*a6*/) {
    pin_tick();                                           // execute a staged app->wall pin (per-frame, shell thread)
    g_cullctx = a2; g_listmgr = a4;                        // stash ctx (cam/frusta still valid later)
    if (g_forcevis) force_nocull_walk(a4);                 // TEST/FIX: turn culling OFF (every frame, before the original cull)
    uint64_t t = now_ms(); if (t - g_world_ms < 200) return;   // ~5 Hz snapshot
    g_world_ms = t;
    int len = render_world_dump(g_world_buf, sizeof g_world_buf);   // walk LIVE (pointers valid now)
    g_world_len = len;
    if (g_logmask & 1) {                                   // also mirror to logcat
        char* p=g_world_buf; char* end=g_world_buf+len;
        while (p < end) { char* nl=(char*)memchr(p,'\n',end-p); if(!nl)nl=end; LOGI("CULL %.*s",(int)(nl-p),p); p=nl+1; }
    }
}

// SkeletonSystem_vf7__1480F70(result): walks skeletons at result+96..result+104;
//   per skeleton v4=*v1: joint array bytes = *(v4+592)-*(v4+584), jointCount = bytes>>6,
//   and the per-joint cull-bounds loop runs jointCount-1 times (SKIPS JOINT 0).
extern "C" __attribute__((used))
void hsr_rt_skel(uint64_t result) {
    // Stash ONLY a NON-EMPTY skeleton array. SkeletonSystem_vf7 is called for multiple systems (env
    // meshes AND the hand system, which is empty when no hands are tracked). Stashing every call let the
    // empty hand call overwrite the env one -> `skeletons` read empty. Keep the last non-empty result.
    if (okptr(result)) {
        uint64_t b=0,e=0;
        if (safe_read(result+96,&b,8)>=0 && safe_read(result+104,&e,8)>=0 && okptr(b) && okptr(e) && e>b && (e-b)<(1u<<20))
            g_skelres = result;
    }
    if (okptr(result)) ;                                    // (legacy always-stash removed)
    if (!(g_logmask & 2)) return;                          // logging off -> just stash
    static uint64_t last = 0;
    uint64_t t = now_ms(); if (t - last < 1000) return;    // ~1 Hz
    last = t;
    if (!okptr(result)) return;
    uint64_t b = *(uint64_t*)(result + 96);
    uint64_t e = *(uint64_t*)(result + 104);
    if (!okptr(b) || !okptr(e) || e < b || (e - b) > (1u<<20)) return;
    int nskel = (int)((e - b) / 8);
    LOGI("SKEL update: %d skeleton(s)", nskel);
    int shown = 0;
    for (uint64_t p = b; p < e && shown < 8; p += 8, shown++) {
        uint64_t v4 = *(uint64_t*)p; if (!okptr(v4)) continue;
        uint64_t jb = *(uint64_t*)(v4 + 584), je = *(uint64_t*)(v4 + 592);
        int jc = (je >= jb) ? (int)((je - jb) >> 6) : -1;
        uint8_t built = *(uint8_t*)(v4 + 56);              // ==1 => bounds rebuilt this frame
        LOGI("  skel[%d] self=%p joints=%d boundsRebuilt=%d (cull loop runs %d, SKIPS joint0)",
             shown, (void*)v4, jc, built, jc>0?jc-1:0);
    }
}

// HzAnimSystem__1625F74(x0=entity a1, x1=ctx, x2=flag). The DEVICE's per-frame batch skinning
// update. a1+240/+248 = std::vector<mat4>{start,end} of the ANIMATED joint transforms (what
// actually poses the skinned verts); matrices 64B each; joint translation = m[12..14]. Mesh
// AssetRef id via the first render part: part=*(*(a1+152)+8); id=*(*(part+456)+8). Keyed by a1.
// RenderableProxy__ABC928(x0=renderSystem float*, x1=renderableIndex, x2, x3=&renderList). The HSR skinning
// bind: per-instance joint matrices live in the render system. Reads them + records the 8 Hz mover-joint
// curve, keyed by the render instance index. This is the DEVICE's real runtime skinning pose for our env.
static volatile uint64_t g_hz_x1ok = 0;   // # calls that resolved a valid posed-joint array (skeleton)
static volatile uint64_t g_hzlast = 0;     // rate-cap: process the capture at most ~250 Hz (never hot-path)
extern "C" __attribute__((used))
void hsr_rt_hzanim(uint64_t x0, uint64_t /*jointName*/, uint64_t /*out*/, uint64_t /*x3*/, uint64_t /*x4*/) {
    g_hz_calls++;
    uint64_t t = now_ms(); if (t - g_hzlast < 4) return;   // 250 Hz cap (getJointByName can be per-joint hot)
    g_hzlast = t;
    uint64_t sk = x0; if (!okptr(sk)) { g_hz_rej++; return; }
    uint64_t jb = 0, je = 0;
    if (safe_read(sk+72,&jb,8) < 0 || safe_read(sk+80,&je,8) < 0 || !okptr(jb) || je <= jb) { g_hz_rej++; return; }  // resultModelMatrices_
    int nj = (int)((je - jb) >> 6); if (nj < 1 || nj > 256) { g_hz_rej++; return; }
    g_hz_x1ok++;
    uint64_t key = sk;
    int slot = -1;
    for (int i = 0; i < g_hz_n; i++) if (g_hz[i].obj == key) { slot = i; break; }
    if (slot < 0) { if (g_hz_n >= HZ_MAX) return; slot = g_hz_n++; }
    HzRec& r = g_hz[slot];
    if (r.obj != key) { r.cw = 0; r.cn = 0; r.cms = 0; }
    r.obj = key; r.assetId[0] = jb; r.assetId[1] = sk; r.nj = nj; r.stamp = t;
    safe_read(jb, r.m0, 64);
    safe_read(jb + (uint64_t)(nj-1)*64, r.mN, 64);
    if (t - r.cms >= 125) {
        r.cms = t;
        r.curve[r.cw][0]=r.mN[12]; r.curve[r.cw][1]=r.mN[13]; r.curve[r.cw][2]=r.mN[14];
        r.cw = (r.cw+1) % CURVE_N; if (r.cn < CURVE_N) r.cn++;
    }
}

// ── APP → WALL PLACEMENT pinning ─────────────────────────────────────────────────
// VrShell's own AllocentricLaunchController::HandlePinAppAtWall(this, std::string* component,
// int rank) @ base+0x117A268 pins the named app to the wall locator whose rank matches (that
// rank is the wall placement's propRank). It does NOT re-check allocentric capability — so it
// pins ARBITRARY apps, which is exactly the "stick any app to a wall" ask (the drag UI only
// offers whitelisted apps; the function underneath doesn't care). We (1) capture the controller
// `this` from PrePinDefaultApps (fires at env load), (2) let the `pinwall` command stage the
// app component + rank, and (3) EXECUTE the pin from the per-frame loco hook = the shell's OWN
// thread. HandlePinAppAtWall mutates the controller's pinned-app map + calls the app-launch
// path (flecs/shell state) — calling it from the socket thread would race and crash.
static volatile uint64_t g_alc_ctrl   = 0;      // AllocentricLaunchController `this`
static char              g_pin_app[256] = {0};  // staged app component name (socket thread writes)
static volatile int      g_pin_rank    = 0;
static volatile int      g_pin_pending = 0;
typedef long (*PinAppFn)(void* self, void* compStr, int rank);
// diagnostics captured on the shell thread when a pin fires (the shell's own logs are filtered from logcat):
static volatile int      g_pin_done    = 0;      // a pin executed since last stage
static volatile long     g_pin_ret     = 0;      // HandlePinAppAtWall return
static volatile int      g_pin_nlocs   = -1;     // wall-locator vector count (ctrl+240..248, 60B stride); -1=not read
static volatile int      g_pin_ranks[16] = {0};  // the ranks present in the wall-locator vector
static volatile int      g_pin_nranks  = 0;
static const uintptr_t   OFF_PREPIN    = 0x11776F4;  // AllocentricLaunchController::PrePinDefaultApps — re-anchored for the current stock libshell (was 0x11776F8)
static const uintptr_t   OFF_PINATWALL = 0x117A264;  // AllocentricLaunchController::HandlePinAppAtWall (vf6) — re-anchored (was 0x117A268)

// PrePinDefaultApps(a1=controller): capture the controller. Runs at env load on the shell thread.
extern "C" __attribute__((used))
void hsr_rt_prepin(uint64_t a1, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) {
    if (okptr(a1)) g_alc_ctrl = a1;
}

// SlideLocomotionController_update(a1=this, a2, a3, a4, a5). Stashes the controller `this`
// and a3 (a3+144 = live player position per the player-ctl reversing) so the MCP server can
// read/write player pos/rot and movement on demand. ALSO the safe execution point for a staged
// app->wall pin (this runs each frame on the shell's own thread).
extern "C" __attribute__((used))
void hsr_rt_loco(uint64_t a1, uint64_t /*a2*/, uint64_t a3, uint64_t /*a4*/, uint64_t /*a5*/) {
    if (okptr(a1)) g_loco_this = a1;
    if (okptr(a3)) g_loco_a3 = a3;
}

// Execute a staged app->wall pin on the shell thread. Called from the per-frame cull hook (the loco hook is
// owned by aio.cpp's moonjump, so it never installs here). HandlePinAppAtWall touches the controller's pinned-app
// map + the app-launch path, so it MUST run on the shell's own thread — a per-frame render/sim hook, not the socket.
static void pin_tick() {
    if (!(g_pin_pending && g_alc_ctrl && g_base)) return;
    // DIAGNOSE the wall-locator vector (ctrl+240=begin, +248=end, 60B stride, rank at +4): if there's no locator
    // for this rank HandlePinAppAtWall silently no-ops, which is exactly the "I don't see it pinned" symptom.
    uint64_t vb = *(volatile uint64_t*)(g_alc_ctrl + 240), ve = *(volatile uint64_t*)(g_alc_ctrl + 248);
    int nl = (okptr(vb) && ve > vb && (ve - vb) % 60 == 0) ? (int)((ve - vb) / 60) : 0;
    g_pin_nlocs = nl; g_pin_nranks = 0;
    for (int i = 0; i < nl && i < 16; ++i) g_pin_ranks[g_pin_nranks++] = *(volatile int*)(vb + (uint64_t)i*60 + 4);
    std::string comp(g_pin_app);
    g_pin_ret = ((PinAppFn)(g_base + OFF_PINATWALL))((void*)g_alc_ctrl, &comp, g_pin_rank);
    g_pin_pending = 0; g_pin_done = 1;
}

// ── GLOBAL ANIMATION TIMELINE control (freeze/slow/scrub) ────────────────────────
// IDA: HzAnimPlayback::update(this, float dt) [__C888A8] advances every layer by
//   v10 = *(float*)(this+20) * dt   -> *(this+20) is the per-playback SPEED multiplier.
// Overriding it globally = a device-wide animation time control: 0=FREEZE, 0.05=slow-mo,
// 1.0=normal. This is the on-device equivalent of the desktop renderer's `at=` scrub, so we
// can stop the world where a mesh (the comet) is at its visible phase and inspect it.
// Store the float BITS via an INTEGER write so the thunk emits NO FP ops -> the float dt in
// s0 is untouched before the real function runs (the entry-hook saves x0..x17, NOT s0..s7).
static volatile uint32_t g_anim_speed_bits = 0x3F800000u;   // 1.0f
static volatile int      g_anim_enable     = 0;             // 0 = leave authored speeds alone
static volatile uint32_t g_world_phase_bits = 0;           // exact-timeline: float bits of the 0..1 phase to pin
static volatile int      g_world_setphase   = 0;            // 1 = pin every layer to that phase (desktop slider sync)
extern "C" void hsr_rt_anim(uint64_t a1, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t) {
    if (!(a1 > 0x1000000000ULL && a1 < 0x800000000000ULL)) return;
    if (g_anim_enable) *(volatile uint32_t*)(a1 + 20) = g_anim_speed_bits;   // world speed/freeze (integer store: no s0 clobber)
    if (g_world_setphase) {   // EXACT desktop-timeline sync: pin every layer's state-0 phase to the desktop slider position
        uint64_t lb = *(volatile uint64_t*)(a1 + 384), le = *(volatile uint64_t*)(a1 + 392);   // HzAnimPlayback layers vec (320B ea)
        if (lb > 0x1000000000ULL && lb < 0x800000000000ULL && le > lb && (le - lb) <= 320*48) {
            for (uint64_t L = lb; L + 152 <= le && L < lb + 320*48; L += 320) {
                uint32_t cur = *(volatile uint32_t*)(L + 148);            // HzAnimLayer state-0 normalized phase
                if (cur <= 0x3F800000u) *(volatile uint32_t*)(L + 148) = g_world_phase_bits;   // overwrite ONLY plausible 0..1 floats (bit compare = no FP)
            }
        }
    }
}

// ── getTime() SHADER CLOCK (2nd world clock): globalUniforms.time @ UBO byte +596. Drives EVERY cook getTime()
//    shader — flipbooks, train, UV-scroll, scale/rotate/pulse, VAT, motes. HzAnim (+20) does NOT touch these.
//    Hook = GlobalDescriptorManager::bind(this, a2, float* k=x2, ...); k = the per-frame uniform block, k+596 = elapsed s.
static volatile uint64_t g_guni_this = 0;     // GlobalDescriptorManager* (this=x0) — walk it to find the mapped UBO
static volatile uint64_t g_guni_a2   = 0;     // x1
static volatile uint64_t g_guni_k    = 0;     // x2 (float*)
static volatile uint64_t g_gtime_addr = 0;    // RESOLVED mapped-UBO time address (set via `gtime find`)
static volatile float    g_gtime_val = 0.f;   // seconds to write (hold-captured, or explicit set)
static volatile int      g_gtime_mode = 0;    // 0=off (DEFAULT, no write), 1=freeze/hold, 2=set-absolute
static volatile int      g_gtime_cap  = 0;    // hold: captured the current clock yet?
extern "C" void hsr_rt_guni(uint64_t a1, uint64_t a2, uint64_t k, uint64_t, uint64_t, uint64_t) {
    if (a1 > 0x1000000000ULL && a1 < 0x800000000000ULL) g_guni_this = a1;
    if (a2 > 0x1000000000ULL && a2 < 0x800000000000ULL) g_guni_a2 = a2;
    if (k  > 0x1000000000ULL && k  < 0x800000000000ULL) g_guni_k  = k;
    if (!g_gtime_mode || !g_gtime_addr) return;
    uint64_t A = g_gtime_addr;
    if (!(A > 0x1000000000ULL && A < 0x800000000000ULL)) return;
    float cur = *(volatile float*)A;
    if (!(cur >= 0.f && cur < 1.0e7f)) return;        // sanity: must look like an elapsed-seconds clock
    if (g_gtime_mode == 1) { if (!g_gtime_cap) { g_gtime_val = cur; g_gtime_cap = 1; } }
    *(volatile float*)A = g_gtime_val;                 // freeze (held) or set (explicit) -> flipbooks/train stop/scrub
}

// ── getTime CLOCK, REAL control (store-site override). IDA (V205.2, GlobalDescriptorManager.cpp):
//    the device writes globalUniforms.time EVERY frame inside bind:
//        0xDE97F4  LDR X21,[X8,#0x20]     ; X21 = the 784-byte mapped globalUniforms UBO (holder+0x20)
//        0xDE9804  BLR X8                 ; S0 = getElapsedSeconds()   (virtual clock)
//        0xDE9808  STR S0,[X21,#0x250]    ; globalUniforms.time = elapsed  <-- byte +592 (0x250), NOT +596!
//    The bind-ENTRY GTIME hook (hsr_rt_guni) can't win: the store runs AFTER entry and re-writes the
//    real value. So we hook the STORE SITE 0xDE9804 with a POST-order trampoline (runs the 4 original
//    PC-independent insns first, so the real time lands at buf+592, THEN calls this thunk with X21) and
//    OVERRIDE buf+592 here. This is the ONLY clock the cook getTime() shaders read (flipbooks, train,
//    uv-scroll, scale/rotate/pulse, VAT, motes). See [[project_hsr_device_gtime_clock]].
static volatile uint64_t g_gu_buf = 0;    // captured 784B globalUniforms mapped buffer
// EMPIRICALLY VERIFIED on device: globalUniforms.time = buf+596 (0x254) — ticks ~1.0/sec (elapsed seconds).
// The de9808 `STR S0,[X21,#0x250]` writes buf+592 = a CONSTANT 1.0 (NOT the clock — a decoy). The real
// elapsed clock at +596 is written separately, but the SAME X21 buffer, and our bind hook runs at bind
// (draw) time so overriding +596 here wins for that frame's draw.
static const uint32_t GU_TIME_OFF = 596;
extern "C" void hsr_gtime_store2(uint64_t buf) {
    if (!(buf > 0x1000000000ULL && buf < 0x800000000000ULL)) return;
    g_gu_buf = buf;
    if (!g_gtime_mode) return;                        // 0 = passthrough (authored elapsed time)
    float cur = *(volatile float*)(buf + GU_TIME_OFF);// the real elapsed-seconds clock (+596)
    if (!(cur >= 0.f && cur < 1.0e7f)) return;         // sanity: must look like an elapsed clock
    if (g_gtime_mode == 1 && !g_gtime_cap) { g_gtime_val = cur; g_gtime_cap = 1; }   // freeze -> hold current
    *(volatile float*)(buf + GU_TIME_OFF) = g_gtime_val;   // freeze/set -> flipbooks/train/uvscroll stop or scrub
}

// ── ARM64 trampoline: save volatiles, call thunk(funcId-shifted args), restore,
//    run relocated original prologue (16B), branch to fn+16. Thunk receives the
//    function's original x0..x5 (so the C thunk can re-walk lists etc.). ──────
static bool install_entry_hook(uint8_t* fn, void* thunk) {
    size_t PG = (size_t)sysconf(_SC_PAGESIZE);
    void* tramp = mmap(nullptr, PG, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;
    uintptr_t cont = (uintptr_t)fn + 16;
    uintptr_t th   = (uintptr_t)thunk;

    uint32_t code[40]; int k = 0;
    // prologue: save x0..x17, x29, x30 in a 0xA0 (160B, 16-aligned) frame. x18 is the
    // platform reg (we don't touch it); x19..x28 are callee-saved by the AAPCS thunk.
    code[k++] = 0xA9B67BFD;          // STP X29,X30,[SP,#-0xA0]!   (alloc 0xA0; x29/x30 at +0x00)
    code[k++] = 0x910003FD;          // MOV X29, SP
    code[k++] = 0xA90107E0;          // STP X0,X1,[SP,#0x10]
    code[k++] = 0xA9020FE2;          // STP X2,X3,[SP,#0x20]
    code[k++] = 0xA90317E4;          // STP X4,X5,[SP,#0x30]
    code[k++] = 0xA9041FE6;          // STP X6,X7,[SP,#0x40]
    code[k++] = 0xA90527E8;          // STP X8,X9,[SP,#0x50]
    code[k++] = 0xA9062FEA;          // STP X10,X11,[SP,#0x60]
    code[k++] = 0xA90737EC;          // STP X12,X13,[SP,#0x70]
    code[k++] = 0xA9083FEE;          // STP X14,X15,[SP,#0x80]
    code[k++] = 0xA90947F0;          // STP X16,X17,[SP,#0x90]
    // set up thunk args: x0..x5 = original x0..x5 (reload from saved slots)
    code[k++] = 0xA94107E0;          // LDP X0,X1,[SP,#0x10]
    code[k++] = 0xA9420FE2;          // LDP X2,X3,[SP,#0x20]
    code[k++] = 0xA94317E4;          // LDP X4,X5,[SP,#0x30]
    // call thunk: LDR X16,[PC,#.thunk]; BLR X16   (literal offset patched below)
    int ldrThunkAt = k;
    code[k++] = 0x58000010u;         // LDR X16,[PC,#imm]  (Rt=16; imm patched)
    code[k++] = 0xD63F0200;          // BLR X16
    // restore x0..x17, x29, x30
    code[k++] = 0xA94107E0;          // LDP X0,X1,[SP,#0x10]
    code[k++] = 0xA9420FE2;          // LDP X2,X3,[SP,#0x20]
    code[k++] = 0xA94317E4;          // LDP X4,X5,[SP,#0x30]
    code[k++] = 0xA9441FE6;          // LDP X6,X7,[SP,#0x40]
    code[k++] = 0xA94527E8;          // LDP X8,X9,[SP,#0x50]
    code[k++] = 0xA9462FEA;          // LDP X10,X11,[SP,#0x60]
    code[k++] = 0xA94737EC;          // LDP X12,X13,[SP,#0x70]
    code[k++] = 0xA9483FEE;          // LDP X14,X15,[SP,#0x80]
    code[k++] = 0xA94947F0;          // LDP X16,X17,[SP,#0x90]
    code[k++] = 0xA8CA7BFD;          // LDP X29,X30,[SP],#0xA0  (dealloc)
    // relocated original prologue (16 bytes = 4 insns). All target prologues here are
    // SP-relative or pre-indexed (PC-independent), safe to copy verbatim.
    memcpy(&code[k], fn, 16); k += 4;
    // continue at fn+16
    code[k++] = 0x58000049;          // LDR X9,[PC,#8]
    code[k++] = 0xD61F0120;          // BR  X9
    code[k++] = (uint32_t)(cont & 0xFFFFFFFFu);
    code[k++] = (uint32_t)(cont >> 32);
    // thunk literal (64-bit), 8-aligned
    if (k & 1) code[k++] = 0xD503201F; // NOP pad
    int thunkLitIdx = k;
    code[k++] = (uint32_t)(th & 0xFFFFFFFFu);
    code[k++] = (uint32_t)(th >> 32);
    // patch the LDR X16 literal word-offset (literal index minus LDR index)
    code[ldrThunkAt] = 0x58000010u | ((uint32_t)((thunkLitIdx - ldrThunkAt) & 0x7FFFF) << 5);

    memcpy(tramp, code, (size_t)k*4);
    mprotect(tramp, PG, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)tramp, (char*)tramp + (size_t)k*4);

    // overwrite fn[0..15] with an absolute jump to the trampoline
    uintptr_t tr = (uintptr_t)tramp;
    uint32_t jmp[4] = { 0x58000050u, 0xD61F0200u, (uint32_t)(tr & 0xFFFFFFFFu), (uint32_t)(tr >> 32) };
    uintptr_t a = (uintptr_t)fn & ~(uintptr_t)(PG - 1);
    uintptr_t b = ((uintptr_t)fn + 16 + PG - 1) & ~(uintptr_t)(PG - 1);
    if (mprotect((void*)a, b - a, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) return false;
    memcpy(fn, jmp, 16);
    mprotect((void*)a, b - a, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)fn, (char*)fn + 16);
    return true;
}

// ── getTime STORE-SITE inline hook (POST-order), hardcoded for the +596 time write inside
//    GlobalDescriptorManager::bind at 0xDE986C  `STR S0,[X21,#0x254]` (X21 = the 784B globalUniforms UBO,
//    globalUniforms.time = +596). This is the SOLE per-frame writer of +596 (verified: only store at that
//    offset in bind). We run the store first (real elapsed lands at +596), THEN call thunk(X0=X21) which
//    overrides +596 -> so freeze/scrub STICKS (no later write clobbers it). We overwrite 16 bytes
//    (de986c STR; de9870 LDR X0,[X22]; de9874 CBZ X0,DEA404 <PC-relative>; de9878 LDR X8,[X0]) and
//    faithfully re-emit them, fixing the CBZ to two absolute far-branches. Continue = fn+16 (0xDE987C).
static bool install_gtime_store_hook(uint8_t* fn, void* thunk) {
    size_t PG = (size_t)sysconf(_SC_PAGESIZE);
    void* tramp = mmap(nullptr, PG, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tramp == MAP_FAILED) return false;
    uintptr_t cont1 = (uintptr_t)fn + 16;          // 0xDE987C (fall-through, X0!=0)
    uintptr_t cont2 = (uintptr_t)fn + 0xB98;        // 0xDEA404 (CBZ taken, X0==0)  (0xDEA404-0xDE986C)
    uintptr_t th    = (uintptr_t)thunk;
    uint32_t code[64]; int k = 0;
    // (A) relocated de986c: STR S0,[X21,#0x254]  -> real elapsed written to globalUniforms.time (+596)
    code[k++] = 0xBD0256A0;
    // (B) save volatiles x0..x17,x29,x30
    code[k++] = 0xA9B67BFD; code[k++] = 0x910003FD;
    code[k++] = 0xA90107E0; code[k++] = 0xA9020FE2; code[k++] = 0xA90317E4;
    code[k++] = 0xA9041FE6; code[k++] = 0xA90527E8; code[k++] = 0xA9062FEA;
    code[k++] = 0xA90737EC; code[k++] = 0xA9083FEE; code[k++] = 0xA90947F0;
    // (C) arg0 = X21 (the UBO), call thunk (overrides +596 AFTER the real store)
    code[k++] = 0xAA1503E0;   // MOV X0,X21
    int ldrThunkAt = k;
    code[k++] = 0x58000010u;  // LDR X16,[PC,#imm]  (patched)
    code[k++] = 0xD63F0200;   // BLR X16
    // (D) restore
    code[k++] = 0xA94107E0; code[k++] = 0xA9420FE2; code[k++] = 0xA94317E4;
    code[k++] = 0xA9441FE6; code[k++] = 0xA94527E8; code[k++] = 0xA9462FEA;
    code[k++] = 0xA94737EC; code[k++] = 0xA9483FEE; code[k++] = 0xA94947F0;
    code[k++] = 0xA8CA7BFD;
    // (E) relocated de9870 + CBZ(fixed) + de9878 + far continues
    code[k++] = 0xF94002C0;   // LDR X0,[X22]         (de9870)
    code[k++] = 0xB40000C0;   // CBZ X0, #24 -> L_zero (X0==0 path)
    code[k++] = 0xF9400008;   // LDR X8,[X0]          (de9878)
    code[k++] = 0x58000049;   // LDR X9,[PC,#8]  -> cont1
    code[k++] = 0xD61F0120;   // BR X9
    code[k++] = (uint32_t)(cont1 & 0xFFFFFFFFu);
    code[k++] = (uint32_t)(cont1 >> 32);
    // L_zero:
    code[k++] = 0x58000049;   // LDR X9,[PC,#8]  -> cont2
    code[k++] = 0xD61F0120;   // BR X9
    code[k++] = (uint32_t)(cont2 & 0xFFFFFFFFu);
    code[k++] = (uint32_t)(cont2 >> 32);
    if (k & 1) code[k++] = 0xD503201F;   // NOP pad -> 8-align thunk literal
    int thunkLitIdx = k;
    code[k++] = (uint32_t)(th & 0xFFFFFFFFu);
    code[k++] = (uint32_t)(th >> 32);
    code[ldrThunkAt] = 0x58000010u | ((uint32_t)((thunkLitIdx - ldrThunkAt) & 0x7FFFF) << 5);

    memcpy(tramp, code, (size_t)k*4);
    mprotect(tramp, PG, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)tramp, (char*)tramp + (size_t)k*4);

    uintptr_t tr = (uintptr_t)tramp;
    uint32_t jmp[4] = { 0x58000050u, 0xD61F0200u, (uint32_t)(tr & 0xFFFFFFFFu), (uint32_t)(tr >> 32) };  // LDR X16,[PC,#8]; BR X16
    uintptr_t a = (uintptr_t)fn & ~(uintptr_t)(PG - 1);
    uintptr_t b = ((uintptr_t)fn + 16 + PG - 1) & ~(uintptr_t)(PG - 1);
    if (mprotect((void*)a, b - a, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) return false;
    memcpy(fn, jmp, 16);
    mprotect((void*)a, b - a, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)fn, (char*)fn + 16);
    return true;
}

// ── MCP CONTROL SERVER ──────────────────────────────────────────────────────
//  A tiny localhost TCP line-protocol server so an MCP server (over `adb forward
//  tcp:PORT`) can inspect/control the live render world. Commands (newline-delim):
//    ping                         -> "pong base=0x..."
//    base                         -> libshell base hex
//    renderables                  -> per-renderable center/ext/verdict (the cull world)
//    skeletons                    -> per-skeleton joint counts/bounds-rebuilt
//    read  <ADDR> <LEN>           -> hex dump (ADDR = 0xABS or +OFFSET from base)
//    write <ADDR> <HEXBYTES>      -> poke raw bytes
//    rf32  <ADDR>                 -> read float        | wf32 <ADDR> <FLOAT>
//    r32   <ADDR>                 -> read u32          | w32  <ADDR> <U32>
//    log   <cull|skel> <0|1>      -> toggle logcat trace live (no reinstall)
//    loglevel <N>                 -> poke libshell n3 (SUSPECT — anti-tamper, see above)
//  ADDR forms: "+1480F70" = g_base+0x1480F70 (preferred), or "0x..." absolute.
static uint64_t parse_addr(const char* s) {
    while (*s==' ') s++;
    if (*s=='+') return (uint64_t)g_base + strtoull(s+1, nullptr, 16);
    return strtoull(s, nullptr, 16);
}
// Head/eye FORWARD heading (yaw degrees) from the live cull frustum planes (a2+336, 6 inward-normal planes ×4
// floats per eye): summing the plane normals cancels the lateral parts of the side planes + the near/far pair,
// leaving ~the view forward. yaw = atan2(fx, -fz) — the SAME convention the desktop cam uses (fwd = sin,·,-cos),
// so the editor can draw + align to it directly. This is what the player is actually LOOKING at.
static bool cull_forward_yaw(float* yawDeg, float* fxOut, float* fzOut) {
    uint64_t a2=g_cullctx; if(!okptr(a2)) return false;
    int64_t cw=*(const int64_t*)(a2+320); uint64_t nfr=(uint64_t)cw & 0x3FFFFFFFFFFFFFFFULL;
    const float* fr=(cw>=0)?(const float*)(a2+336):(const float*)(*(const uint64_t*)(a2+336));
    if(!okfptr((uint64_t)fr) || nfr==0 || nfr>=64) return false;
    float fx=0,fz=0;
    const float* p=fr;                                   // FIRST frustum (one eye) = 6 planes × 4 floats
    for(int k=0;k<6;k++){ fx+=p[k*4+0]; fz+=p[k*4+2]; }
    float l=__builtin_sqrtf(fx*fx+fz*fz); if(l<1e-4f) return false; fx/=l; fz/=l;
    if(fxOut)*fxOut=fx; if(fzOut)*fzOut=fz;
    *yawDeg = __builtin_atan2f(fx, -fz)*57.29578f;
    return true;
}
// TP-HOLD: park the player at a fixed WORLD pos, re-writing it every ~8ms so physics/gravity can't pull it away.
// Lets us fly the headset UP to a distant mesh (the comet at ~192,114,-264) to inspect whether it renders on device.
// Needs the loco context (g_loco_a3, captured after you MOVE once on the headset). `tp x y z` / `tp off`.
static volatile float g_tp_x=0.f, g_tp_y=0.f, g_tp_z=0.f; static volatile int g_tp_hold=0;
static void* tp_hold_thread(void*) {
    for(;;){ if (g_tp_hold && okptr(g_loco_a3)) { float p[3]={g_tp_x,g_tp_y,g_tp_z}; safe_write(g_loco_a3+LOCO_POS_OFF, p, 12); }
             usleep(8000); }
    return nullptr;
}
// GAME teleport (no fall in-bounds; sets facing YAW) — the proven ROTATE path. Replicated from
// nativeTeleportToCoordinates: resolve g_ShellApp, alloc a 128B msg, post to its TypedMessageQueue kind=98.
static bool post_teleport(uint8_t* base, float x, float y, float z, float yaw) {
    if (!base) return false;
    uintptr_t app = *(volatile uintptr_t*)(base + OFF_G_SHELLAPP);
    if (!okptr(app)) return false;
    void* queue = *(void**)(app + 16);
    if (!okptr((uint64_t)queue)) return false;
    void* (*op_new)(size_t)        = (void*(*)(size_t))(base + OFF_OP_NEW);
    void  (*tmq)(void*,int*,void*) = (void(*)(void*,int*,void*))(base + OFF_TMQ_POST);
    uint8_t* msg = (uint8_t*)op_new(128);
    if (!msg) return false;
    memset(msg, 0, 128);
    *(float*)(msg+0)=x; *(float*)(msg+4)=y; *(float*)(msg+8)=z; *(float*)(msg+12)=yaw;
    *(int*)(msg+120)=35;
    int kind=98; tmq(queue, &kind, msg);
    return true;
}
// Read a libshell std::string (SSO) at address s into buf. Long form: bit0 of s[0] set -> {cap,len@+8,ptr@+16}.
static int rt_read_sso(uint64_t s, char* buf, int n) {
    buf[0]=0; if(!okptr(s)) return 0;
    uint8_t b0=0; if(safe_read(s,&b0,1)<0) return 0;
    if(b0&1){ uint64_t len=0,ptr=0; safe_read(s+8,&len,8); safe_read(s+16,&ptr,8);
        if(!okptr(ptr))return 0; if(len>(uint64_t)(n-1))len=n-1; safe_read(ptr,buf,(long)len); buf[len]=0; return (int)len; }
    int len=b0>>1; if(len>n-1)len=n-1; safe_read(s+1,buf,len); buf[len]=0; return len;
}
// The device DOES keep a readable ASSET NAME for every resource: proxy+464=resource -> res+32=AssetRef,
// which holds an INLINE null-terminated cook path string (e.g. "meta/home_c25@cometdbg/m006.material:material")
// near AssetRef+96. Names are cook-renamed (m001/m002/...) — the original (comet_alpha) is stripped at cook,
// but this maps the opaque 128-bit hash id to a real name. Scan the AssetRef block for the printable path.
static int rt_asset_name(uint64_t proxy, char* buf, int n) {
    buf[0]=0;
    uint64_t res=0; if(safe_read(proxy+464,&res,8)<0||!okptr(res)) return 0;
    uint64_t ar=0;  if(safe_read(res+32,&ar,8)<0||!okptr(ar))    return 0;
    // The name path lives behind AssetRef -> entry(*ar) -> char* at entry+64 (null-terminated), e.g.
    // "meta/home_c25@cometdbg/m005_comet_alpha_mat_asset.rendmesh:mesh". Try that chain first.
    uint64_t entry=0;
    if(safe_read(ar,&entry,8)>=0 && okptr(entry)){
        uint64_t cp=0;
        if(safe_read(entry+64,&cp,8)>=0 && okptr(cp)){
            char tmp[160]; long g=safe_read(cp,tmp,sizeof tmp-1);
            if(g>0){ int L=0; while(L<(int)g && tmp[L]>=0x20 && tmp[L]<=0x7e) L++; tmp[L]=0;
                if(L>=6 && strchr(tmp,'/')){ if(L>n-1)L=n-1; memcpy(buf,tmp,L); buf[L]=0; return L; } }
        }
    }
    // Fallback (old cook / other layouts): inline printable path in the AssetRef block.
    unsigned char blk[320]; if(safe_read(ar,blk,sizeof blk)<0) return 0;
    int best=-1,bestlen=0;
    for(int i=0;i<(int)sizeof blk;){
        if(blk[i]<0x20||blk[i]>0x7e){ i++; continue; }
        int j=i; while(j<(int)sizeof blk && blk[j]>=0x20 && blk[j]<=0x7e) j++;
        int len=j-i; bool slash=false; for(int k=i;k<j;k++) if(blk[k]=='/') slash=true;
        if(len>=6 && slash && len>bestlen){ best=i; bestlen=len; }
        i=j;
    }
    if(best<0) return 0;
    if(bestlen>n-1) bestlen=n-1;
    memcpy(buf,blk+best,bestlen); buf[bestlen]=0; return bestlen;
}
// Match a search substr against the readable TAIL of an asset name (after the last '/'), so "comet" hits
// "m005_comet_alpha…" but NOT the "…/cometdbg/" package prefix. Empty query = match all.
static bool rt_name_match(uint64_t proxy, const char* q, char* nameOut, int n) {
    if(rt_asset_name(proxy,nameOut,n)<=0) return (!*q);   // no name: only the empty query matches
    const char* tail = strrchr(nameOut,'/'); tail = tail?tail+1:nameOut;
    return (!*q) || strstr(tail,q)!=nullptr;
}
// Material NAME of a renderable's part P: proxy+464=resource -> res+144 parts(64B) -> part+48=material
// -> mat+336=sharedShader -> +80=nameList -> [0] -> +48 = std::string. (Same walk as `meshmat`.)
static int rt_part_matname(uint64_t proxy, int p, char* buf, int n) {
    buf[0]=0;
    uint64_t res=0; if(safe_read(proxy+464,&res,8)<0||!okptr(res)) return 0;
    uint64_t pb=0,pe=0; safe_read(res+144,&pb,8); safe_read(res+152,&pe,8);
    if(!okptr(pb)||pe<=pb||(pe-pb)>0x40000) return -1;   // -1 => no parts (caller can still print asset id)
    int nparts=(int)((pe-pb)/64); if(p>=nparts) return -1;
    uint64_t mat=0; if(safe_read(pb+(uint64_t)p*64+48,&mat,8)<0||!okptr(mat)) return 0;
    uint64_t sh=0; safe_read(mat+336,&sh,8); if(!okptr(sh)) return 0;
    uint64_t lst=0; safe_read(sh+80,&lst,8); if(!okptr(lst)) return 0;
    uint64_t e0=0; safe_read(lst,&e0,8); if(!okptr(e0)) return 0;
    return rt_read_sso(e0+48, buf, n);
}
static int rt_nparts(uint64_t proxy){ uint64_t res=0; if(safe_read(proxy+464,&res,8)<0||!okptr(res))return 0;
    uint64_t pb=0,pe=0; safe_read(res+144,&pb,8); safe_read(res+152,&pe,8);
    if(!okptr(pb)||pe<=pb||(pe-pb)>0x40000)return 0; return (int)((pe-pb)/64); }
// FULL device dump of ONE renderable: POS/model/asset/parts + per-part material NAME/shader/flags/constant-buffers.
// Shared by `meshmat 0xPROXY` and `findmesh <name>`. Returns bytes written.
static int rt_dump_mesh(uint64_t proxy, int idx, char* out, int cap) {
    int o=0;
    float bx[3]={0},by[3]={0},bz[3]={0},tp[3]={0},ctr[3]={0},ext[3]={0};
    safe_read(proxy+256,bx,12);safe_read(proxy+272,by,12);safe_read(proxy+288,bz,12);safe_read(proxy+304,tp,12);
    safe_read(proxy+80,ctr,12); safe_read(proxy+96,ext,12);
    o+=snprintf(out+o,cap-o,"=== [%d] proxy=0x%llx ===\n[POS] world=%.3f,%.3f,%.3f cullCen=%.1f,%.1f,%.1f ext=%.1f,%.1f,%.1f\n",
        idx,(unsigned long long)proxy, tp[0],tp[1],tp[2], ctr[0],ctr[1],ctr[2], ext[0],ext[1],ext[2]);
    o+=snprintf(out+o,cap-o,"[MODEL] X=%.3f,%.3f,%.3f Y=%.3f,%.3f,%.3f Z=%.3f,%.3f,%.3f\n",bx[0],bx[1],bx[2],by[0],by[1],by[2],bz[0],bz[1],bz[2]);
    uint64_t res=0; safe_read(proxy+464,&res,8);
    if(!okptr(res)) return o+snprintf(out+o,cap-o,"[ERR] no resource\n");
    uint64_t mid[2]={0,0},ar=0; if(safe_read(res+32,&ar,8)>=0&&okptr(ar)) safe_read(ar+8,mid,16);
    char anm[96]="?"; rt_asset_name(proxy,anm,sizeof anm);
    o+=snprintf(out+o,cap-o,"[NAME] %s\n[ASSET] hash=%016llx%016llx\n",anm,(unsigned long long)mid[1],(unsigned long long)mid[0]);
    uint64_t pb=0,pe=0; safe_read(res+144,&pb,8); safe_read(res+152,&pe,8);
    if(!okptr(pb)||pe<=pb) return o+snprintf(out+o,cap-o,"[ERR] no parts (pb=0x%llx pe=0x%llx)\n",(unsigned long long)pb,(unsigned long long)pe);
    int nparts=(int)((pe-pb)/64);
    o+=snprintf(out+o,cap-o,"[PARTS] %d\n",nparts);
    for(int p=0;p<nparts&&p<8&&o<cap-420;p++){
        uint64_t part=pb+(uint64_t)p*64, mat=0; safe_read(part+48,&mat,8);
        o+=snprintf(out+o,cap-o,"[PART %d] material=0x%llx\n",p,(unsigned long long)mat);
        if(!okptr(mat)) continue;
        uint64_t sh=0; safe_read(mat+336,&sh,8);
        char nm[80]="?"; if(okptr(sh)){ uint64_t lst=0; safe_read(sh+80,&lst,8);
            if(okptr(lst)){ uint64_t e0=0; safe_read(lst,&e0,8); if(okptr(e0)) rt_read_sso(e0+48,nm,sizeof nm); } }
        uint8_t flag=0; uint64_t bmask=0; safe_read(mat+24,&flag,1); safe_read(mat+32,&bmask,8);
        o+=snprintf(out+o,cap-o,"  name=\"%s\" shared=0x%llx flag=%d mask=0x%llx\n",nm,(unsigned long long)sh,flag,(unsigned long long)bmask);
        uint64_t cb=0; safe_read(mat+48,&cb,8);
        if(okptr(cb)) for(int s=0;s<12&&o<cap-140;s++){ uint64_t e=cb+(uint64_t)s*104,ds=0,de=0;
            if(safe_read(e+8,&ds,8)<0||safe_read(e+16,&de,8)<0) break;
            if(!okptr(ds)||de<=ds||(de-ds)>4096) continue; int nb=(int)(de-ds); if(nb>48)nb=48; int nf=nb/4;
            float f[12]={0}; safe_read(ds,f,nf*4);
            o+=snprintf(out+o,cap-o,"  cb[%d] %dB:",s,(int)(de-ds));
            for(int k=0;k<nf&&k<10;k++) o+=snprintf(out+o,cap-o," %.3f",f[k]); o+=snprintf(out+o,cap-o,"\n"); }
    }
    return o;
}
static int mcp_dispatch(char* cmd, char* out, int cap) {
    while (*cmd==' ') cmd++;
    if (!strncmp(cmd,"ping",4))        return snprintf(out,cap,"pong base=%p\n",(void*)g_base);
    if (!strncmp(cmd,"base",4))        return snprintf(out,cap,"%p\n",(void*)g_base);
    if (!strncmp(cmd,"renderables",11)) {   // serve the live snapshot captured in the cull trampoline
        if (g_world_len <= 0) return snprintf(out,cap,"ERR no snapshot yet (need MCP armed + 1 cull frame)\n");
        int n = g_world_len < cap-1 ? g_world_len : cap-1; memcpy(out,g_world_buf,n); out[n]=0; return n;
    }
    if (!strncmp(cmd,"skeletons",9)) {
        // The RENDER skeletons (SkeletonSystem_vf7) — each has its POSED joint matrices at *(v4+584)
        // (64B ea, translation @+48). THIS is the env's live HzAnim runtime pose. Dumps per skeleton:
        // joint count + the first few joints' world translations + the last joint's — poll over time to
        // see the animation curve; compare to the desktop/cook to find any mismatch.
        uint64_t r=g_skelres; if(!okptr(r)) return snprintf(out,cap,"ERR no skeleton ctx (need rt_skel armed + a skinned env)\n");
        uint64_t b=0,e=0; safe_read(r+96,&b,8); safe_read(r+104,&e,8);
        if(!okptr(b)||!okptr(e)||e<b||(e-b)>(1u<<20)) return snprintf(out,cap,"ERR skel range (b=0x%llx e=0x%llx)\n",(unsigned long long)b,(unsigned long long)e);
        int len=snprintf(out,cap,"skeletons=%d (posed joint world translations — poll for the curve)\n",(int)((e-b)/8)); int i=0;
        for(uint64_t p=b;p<e&&len<cap-256;p+=8,i++){ uint64_t v4=0; if(safe_read(p,&v4,8)<0||!okptr(v4))continue;
            uint64_t jb=0,je=0; safe_read(v4+584,&jb,8); safe_read(v4+592,&je,8);
            int jc=(okptr(jb)&&je>=jb)?(int)((je-jb)>>6):-1; uint8_t rb=0; safe_read(v4+56,&rb,1);
            len+=snprintf(out+len,cap-len,"[%d] self=0x%llx joints=%d rebuilt=%d\n",i,(unsigned long long)v4,jc,rb);
            if(okptr(jb)&&jc>0) for(int j=0;j<jc&&j<6&&len<cap-64;j++){ float t[3]={0,0,0}; safe_read(jb+(uint64_t)j*64+48,t,12);
                len+=snprintf(out+len,cap-len,"    j%d: %.3f, %.3f, %.3f\n", j, t[0],t[1],t[2]); }
        }
        return len;
    }
    if (!strncmp(cmd,"read ",5)) {
        char* a=cmd+5; char* sp=strchr(a,' '); if(!sp) return snprintf(out,cap,"ERR usage: read ADDR LEN\n");
        uint64_t addr=parse_addr(a); int len=(int)strtol(sp+1,nullptr,0); if(len<1)len=1; if(len>4096)len=4096;
        static uint8_t tmp[4096]; long r=safe_read(addr,tmp,len);
        if(r<0) return snprintf(out,cap,"ERR EFAULT 0x%llx\n",(unsigned long long)addr);
        int o=snprintf(out,cap,"0x%llx: ",(unsigned long long)addr);
        for(int i=0;i<r&&o<cap-3;i++) o+=snprintf(out+o,cap-o,"%02x",tmp[i]);
        o+=snprintf(out+o,cap-o,"\n"); return o;
    }
    if (!strncmp(cmd,"write ",6)) {
        char* a=cmd+6; char* sp=strchr(a,' '); if(!sp) return snprintf(out,cap,"ERR usage: write ADDR HEX\n");
        uint64_t addr=parse_addr(a); char* hex=sp+1; static uint8_t tmp[4096]; int n=0;
        for(; hex[0]&&hex[1]&&n<4096; hex+=2){ char b[3]={hex[0],hex[1],0}; tmp[n++]=(uint8_t)strtol(b,nullptr,16); }
        long w=safe_write(addr,tmp,n);
        if (w<0) return snprintf(out,cap,"ERR EFAULT 0x%llx\n",(unsigned long long)addr);
        return snprintf(out,cap,"OK wrote %d @0x%llx\n", n, (unsigned long long)addr);
    }
    if (!strncmp(cmd,"rf32 ",5)) { uint64_t a=parse_addr(cmd+5); float v; if(safe_read(a,&v,4)<0)return snprintf(out,cap,"ERR EFAULT\n"); return snprintf(out,cap,"%.6f\n",v); }
    if (!strncmp(cmd,"r32 ",4))  { uint64_t a=parse_addr(cmd+4); uint32_t v; if(safe_read(a,&v,4)<0)return snprintf(out,cap,"ERR EFAULT\n"); return snprintf(out,cap,"%u (0x%x)\n",v,v); }
    if (!strncmp(cmd,"wf32 ",5)) { char* sp=strchr(cmd+5,' '); if(!sp)return snprintf(out,cap,"ERR usage: wf32 ADDR FLOAT\n"); uint64_t a=parse_addr(cmd+5); float v=strtof(sp+1,nullptr); return snprintf(out,cap, safe_write(a,&v,4)<0?"ERR\n":"OK %.6f@0x%llx\n", (double)v,(unsigned long long)a); }
    if (!strncmp(cmd,"w32 ",4))  { char* sp=strchr(cmd+4,' '); if(!sp)return snprintf(out,cap,"ERR usage: w32 ADDR U32\n"); uint64_t a=parse_addr(cmd+4); uint32_t v=(uint32_t)strtoul(sp+1,nullptr,0); return snprintf(out,cap, safe_write(a,&v,4)<0?"ERR\n":"OK 0x%x@0x%llx\n", v,(unsigned long long)a); }
    if (!strncmp(cmd,"meshprobe ",10)) {
        // STRUCTURED per-mesh probe of renderable #N: float-grid the proxy (to spot the 4x4 model
        // matrix — a row whose translation ≈ the AABB center at proxy+80), and qword-walk the
        // render-data sub-object *(proxy+16), flagging any pointer that leads to ASCII (the mesh
        // NAME). All reads crash-safe via /proc/self/mem. This is the discovery step for the real
        // processed transform + name on device (the cull AABB alone misses skinned/nocull meshes).
        // Arg is a PROXY ADDRESS (0x… from the `renderables` dump) — the live list is only valid
        // during the cull pass, so we probe the proxy directly rather than re-walk between frames.
        uint64_t proxy = parse_addr(cmd+10);
        if(!okptr(proxy)) return snprintf(out,cap,"ERR usage: meshprobe 0xPROXYADDR (get addrs from `renderables`)\n");
        uint64_t vt=0,rd=0; safe_read(proxy,&vt,8); safe_read(proxy+16,&rd,8);
        float ctr[3]={0,0,0}, ext[3]={0,0,0}; safe_read(proxy+80,ctr,12); safe_read(proxy+96,ext,12);
        int o=snprintf(out,cap,"proxy=0x%llx vtable=0x%llx renderData(+16)=0x%llx\n  cullAABB center=%.3f,%.3f,%.3f ext=%.3f,%.3f,%.3f\n",
                       (unsigned long long)proxy,(unsigned long long)vt,(unsigned long long)rd, ctr[0],ctr[1],ctr[2], ext[0],ext[1],ext[2]);
        // DECODED MODEL MATRIX — the real PROCESSED world transform. 3x3 rotation/scale basis at
        // proxy+256 (cols X/Y/Z), translation at proxy+304. This is the true per-mesh runtime
        // position+orientation even for skinned/nocull meshes whose cull-AABB reads (0,0,0).
        float bx[3]={0,0,0},by[3]={0,0,0},bz[3]={0,0,0},tp[3]={0,0,0};
        safe_read(proxy+256,bx,12); safe_read(proxy+272,by,12); safe_read(proxy+288,bz,12); safe_read(proxy+304,tp,12);
        float sx=__builtin_sqrtf(bx[0]*bx[0]+bx[1]*bx[1]+bx[2]*bx[2]);
        float sy=__builtin_sqrtf(by[0]*by[0]+by[1]*by[1]+by[2]*by[2]);
        float sz=__builtin_sqrtf(bz[0]*bz[0]+bz[1]*bz[1]+bz[2]*bz[2]);
        o+=snprintf(out+o,cap-o,"[MODEL] worldPos=%.4f,%.4f,%.4f  scale~=%.3f,%.3f,%.3f\n",tp[0],tp[1],tp[2],sx,sy,sz);
        o+=snprintf(out+o,cap-o,"  rotBasis X=%.4f,%.4f,%.4f Y=%.4f,%.4f,%.4f Z=%.4f,%.4f,%.4f\n",
                    bx[0],bx[1],bx[2], by[0],by[1],by[2], bz[0],bz[1],bz[2]);
        o+=snprintf(out+o,cap-o,"-- raw proxy floats (matrix @+256, translation @+304) --\n");
        for(int off=240; off<=320 && o<cap-96; off+=16){ float f[4]={0,0,0,0}; safe_read(proxy+off,f,16);
            o+=snprintf(out+o,cap-o,"  p+%3d: %11.4f %11.4f %11.4f %11.4f\n",off,f[0],f[1],f[2],f[3]); }
        // MeshRenderable RESOURCE @ *(proxy+464) (IDA: MeshRenderable_vf6 reads *(this+464)) — holds
        // the mesh/material/shader/texture pointers + tint floats. Dump its qwords, resolving each
        // pointer that leads to ASCII (mesh/material/shader NAMES) so device meshes map to cooker meshes.
        uint64_t res=0; safe_read(proxy+464,&res,8);
        uint64_t rvt=0; if(okptr(res)) safe_read(res,&rvt,8);
        o+=snprintf(out+o,cap-o,"[RESOURCE] *(proxy+464)=0x%llx vtable=0x%llx (map via read 0x%llx 96)\n",
                    (unsigned long long)res,(unsigned long long)rvt,(unsigned long long)rvt);
        auto scan=[&](uint64_t obj,const char* tag,int n){ if(!okptr(obj))return;
            for(int off=0; off<=n && o<cap-80; off+=8){ uint64_t q=0; if(safe_read(obj+off,&q,8)<0)continue;
                char note[40]=""; if(okptr(q)){ char s[28]={0}; if(safe_read(q,s,24)>=0){ int ok=(s[0]>=32&&s[0]<=126);
                    for(int k=0;k<12&&ok&&s[k];k++) if((unsigned char)s[k]<32||(unsigned char)s[k]>126) ok=0;
                    if(ok&&s[0]) snprintf(note,sizeof note," ->\"%.22s\"",s); } }
                float* fv=(float*)&q; char fn[40]=""; if(!note[0]&&(fv[0]>1e-6f&&fv[0]<1e6f||fv[1]>1e-6f&&fv[1]<1e6f)) snprintf(fn,sizeof fn," (f %.3f,%.3f)",fv[0],fv[1]);
                o+=snprintf(out+o,cap-o,"  %s+%3d: 0x%llx%s%s\n",tag,off,(unsigned long long)q,note,fn); } };
        // AssetRefs at res+32 & res+40 (IDA: Mesh dtor calls AssetRef_release on *(res+32),*(res+40);
        // AssetRef_release reads the 16-byte asset id at AssetRef+8). This id = the MurmurHash128
        // asset identity of the mesh/material/shader -> CORRELATE with the cooker's asset ids.
        for(int arOff=32; arOff<=40 && o<cap-80; arOff+=8){ uint64_t ar=0; safe_read(res+arOff,&ar,8);
            if(okptr(ar)){ uint64_t id[2]={0,0}; if(safe_read(ar+8,id,16)>=0)
                o+=snprintf(out+o,cap-o,"  [ASSET] res+%d -> AssetRef 0x%llx assetId=%016llx%016llx\n",
                            arOff,(unsigned long long)ar,(unsigned long long)id[1],(unsigned long long)id[0]); } }
        // Resource std::vector triples (begin/end/cap) at res+64/+120/+144 = submesh/material/texture
        // lists (IDA: Mesh dtor destroys vectors at +64/+96/+120). Each element (8-byte ptr) -> an
        // object; its +8 is often an AssetRef asset-id (per-texture/material MurmurHash128).
        static const int vecOffs[]={64,120,144};
        for(int vi=0; vi<3 && o<cap-96; vi++){ uint64_t b=0,e=0; safe_read(res+vecOffs[vi],&b,8); safe_read(res+vecOffs[vi]+8,&e,8);
            if(!okptr(b)||e<=b||(e-b)>4096) continue; int ne=(int)((e-b)/8);
            o+=snprintf(out+o,cap-o,"  [VEC res+%d] %d elems:\n",vecOffs[vi],ne);
            for(int k=0;k<ne&&k<8&&o<cap-96;k++){ uint64_t el=0; safe_read(b+k*8,&el,8);
                uint64_t id[2]={0,0}; char note[48]="";
                if(okptr(el)){ safe_read(el+8,id,16); if(id[0]||id[1]) snprintf(note,sizeof note," id=%016llx%016llx",(unsigned long long)id[1],(unsigned long long)id[0]); }
                o+=snprintf(out+o,cap-o,"    [%d] 0x%llx%s\n",k,(unsigned long long)el,note); } }
        scan(res,"res",192);
        // renderData fallback (some renderables carry the name inline here)
        if(okptr(rd)){ uint8_t buf[256]={0}; long got=safe_read(rd,buf,256);
            for(int i=0;i<got-4 && o<cap-64;i++){ int run=0; while(i+run<got && buf[i+run]>=32 && buf[i+run]<=126 && run<40) run++;
                if(run>=5){ char s[41]={0}; memcpy(s,buf+i,run); s[run]=0; o+=snprintf(out+o,cap-o,"  rd+%3d inline: \"%s\"\n",i,s); i+=run; } } }
        // [ANIM] the HSR skinning capture (ABC928) is keyed by render-instance index, not mesh asset id, so
        // per-proxy correlation isn't 1:1 here — use the `hzanim` command for the full skinned-instance table
        // (device runtime joint matrices + 8 Hz curve). Note whether ANY skinning is being captured.
        o+=snprintf(out+o,cap-o,"[ANIM] %d skinned instance(s) captured this session — see `hzanim` for joint matrices + curve\n", g_hz_n);
        return o;
    }
    if (!strncmp(cmd,"meshmat",7)) {
        // FULL per-mesh device dump: POSITION/coords + MATERIAL (name + constant buffers = tint/uvScaleOffset/etc)
        // + SHADER/program name. Walks proxy->resource(+464)->parts(res+144, 64B)->material(part+48).
        // Material struct (IDA renderer/Material.cpp __9FC4C0): material NAME = *(*(mat+336)+80)[0]+48 (std::string SSO);
        // constant buffers @ mat+48 (104B entries: +8 dataStart, +16 dataEnd) = the live matParams float block.
        uint64_t proxy = parse_addr(cmd+8);
        if(!okptr(proxy)) return snprintf(out,cap,"ERR usage: meshmat 0xPROXY (get from envdump/findmat/findmesh proxy= field)\n");
        return rt_dump_mesh(proxy, -1, out, cap);
    }
    if (!strncmp(cmd,"findmesh",8)) {
        // FIND + FULL DUMP: walk every renderable, match its material/shader NAME by <substr>, and dump the
        // COMPLETE per-mesh info (pos/model/asset/parts/material/shader/constant-buffers) for each match (cap 5).
        const char* qs=cmd+8; while(*qs==' ')++qs;
        int np=g_nproxies; if(np<=0) return snprintf(out,cap,"ERR no proxies (need rt_mcp armed + 1 cull frame)\n");
        int o=snprintf(out,cap,"findmesh \"%s\":\n",qs); int hits=0;
        for(int i=0;i<np && o<cap-700 && hits<5;i++){
            uint64_t proxy=g_proxies[i]; if(!okptr(proxy)) continue;
            int nparts=rt_nparts(proxy); if(nparts<1||nparts>512) continue;
            bool match=false;
            char anm[160]="?"; if(rt_name_match(proxy,qs,anm,sizeof anm)) match=true;   // by ASSET NAME tail (m005_comet_alpha)
            for(int p=0;p<nparts&&p<16&&!match;p++){ char nm[80]="?"; if(rt_part_matname(proxy,p,nm,sizeof nm)>0 && nm[0] && *qs && strstr(nm,qs)) match=true; }   // or SHADER name
            if(!match) continue;
            o+=rt_dump_mesh(proxy,i,out+o,cap-o); hits++;
        }
        o+=snprintf(out+o,cap-o,"# %d matches dumped (cap 5)\n",hits);
        return o;
    }
    if (!strncmp(cmd,"findmat",7)) {
        // NAME LOOKUP (reliable, no Y-guessing): walk EVERY captured renderable + all its parts, read the
        // material NAME, print idx/proxy/part/worldPos for every part whose name contains <substr>. Empty
        // substr = list all named parts. e.g. `findmat comet` -> all comet_alpha meshes + their proxies.
        const char* qs=cmd+7; while(*qs==' ')++qs;
        int np=g_nproxies; if(np<=0) return snprintf(out,cap,"ERR no proxies (need rt_mcp armed + 1 cull frame)\n");
        int o=snprintf(out,cap,"findmat \"%s\":  idx proxy  worldPos  ASSETNAME  (shader)\n",qs);
        int hits=0;
        for(int i=0;i<np && o<cap-300;i++){
            uint64_t proxy=g_proxies[i]; if(!okptr(proxy)) continue;
            int nparts=rt_nparts(proxy); if(nparts<1||nparts>512) continue;
            float tp[3]={0,0,0}; safe_read(proxy+304,tp,12);
            char anm[160]="?"; bool nameHit=rt_name_match(proxy,qs,anm,sizeof anm);   // match TAIL (m005_comet_alpha), not cometdbg
            char snm[80]="?"; rt_part_matname(proxy,0,snm,sizeof snm);   // shader name
            char* as=anm; if(strstr(as,"/")) as=strrchr(as,'/')+1;       // display: strip package prefix
            char* ss=snm; if(strstr(ss,"/shaders/")) ss=strstr(ss,"/shaders/")+9;
            if(nameHit || (*qs && strstr(snm,qs))){
                o+=snprintf(out+o,cap-o,"[%d] 0x%llx (%.0f,%.0f,%.0f) %s (%s)\n",
                            i,(unsigned long long)proxy,tp[0],tp[1],tp[2],as,ss);
                hits++;
            }
        }
        o+=snprintf(out+o,cap-o,"# %d hits across %d proxies\n",hits,np);
        return o;
    }
    if (!strncmp(cmd,"skinread",8)) {
        // DEVICE-TRUTH skinning read: walk each rendered mesh proxy -> resource(+464) -> parts(res+144, 64B ea)
        // -> material(part+48) -> constant-buffer array(material+48, entries 104B: +8 dataStart, +16 dataEnd).
        // The JointMatrices UBO = a constant whose data is N*64 bytes (N mat4 skinning matrices). Dump each such
        // buffer's joint[0] and joint[last] WORLD translations (m[12..14]) + the mesh asset id. THIS is the exact
        // per-joint skinning the device's MeshShellEnv vertex shader uses — poll over time for the animation curve;
        // compare to the desktop to pin the on-device discrepancy. (Structure verified live on 2026-07-01.)
        int np = g_nproxies; if (np <= 0) return snprintf(out,cap,"ERR no proxies (need rt_mcp armed + 1 cull frame)\n");
        int o = snprintf(out,cap,"skinread: device JointMatrices per skinned mesh (idx assetId part slot nj  j0(x,y,z)  jLast(x,y,z))\n");
        int found = 0;
        for (int i=0;i<np && o<cap-220;i++){
            uint64_t proxy=g_proxies[i]; if(!okptr(proxy)) continue;
            uint64_t res=0; if(safe_read(proxy+464,&res,8)<0||!okptr(res)) continue;
            uint64_t pb=0,pe=0; safe_read(res+144,&pb,8); safe_read(res+152,&pe,8);
            if(!okptr(pb)||pe<=pb||(pe-pb)>0x40000) continue;
            int nparts=(int)((pe-pb)/64); if(nparts<1||nparts>512) continue;
            uint64_t mid[2]={0,0}, ar=0; if(safe_read(res+32,&ar,8)>=0&&okptr(ar)) safe_read(ar+8,mid,16);
            for(int p=0;p<nparts && o<cap-220;p++){
                uint64_t part=pb+(uint64_t)p*64, mat=0; if(safe_read(part+48,&mat,8)<0||!okptr(mat)) continue;
                uint64_t cb=0; if(safe_read(mat+48,&cb,8)<0||!okptr(cb)) continue;
                for(int s=0;s<64 && o<cap-220;s++){ uint64_t e=cb+(uint64_t)s*104, ds=0,de=0;
                    if(safe_read(e+8,&ds,8)<0||safe_read(e+16,&de,8)<0) break;
                    if(!okptr(ds)||de<=ds) continue; uint64_t sz=de-ds;
                    if((sz&63)==0 && sz>=128 && sz<=(uint64_t)256*64){ int nj=(int)(sz/64);
                        float t0[3]={0,0,0}, tn[3]={0,0,0}; safe_read(ds+48,t0,12); safe_read(ds+(sz-64)+48,tn,12);
                        o+=snprintf(out+o,cap-o,"[%d] %016llx%016llx p%d s%d nj=%d  j0=%.1f,%.1f,%.1f  jL=%.1f,%.1f,%.1f\n",
                            i,(unsigned long long)mid[1],(unsigned long long)mid[0],p,s,nj,
                            t0[0],t0[1],t0[2], tn[0],tn[1],tn[2]);
                        found++;
                    }
                }
            }
        }
        o+=snprintf(out+o,cap-o,"# %d skinning buffers found across %d proxies\n", found, np);
        return o;
    }
    if (!strncmp(cmd,"hzanim",6)) {
        // The DEVICE's runtime skinning matrices captured in the HzAnim trampoline — one row per
        // animated (skinned) mesh: mesh asset id, joint count, joint[0] (root) + joint[last] (mover)
        // translations, and the full mover 4x4. THIS is the comet's/creatures' true device pose.
        if (g_hz_n <= 0) return snprintf(out,cap,
            "no skeletons captured. 210FA48 calls=%llu  resolvedPose=%llu  rejected=%llu\n"
            "  (calls>0 & resolved=0 => 210FA48 runs but skeleton+72 resultModelMatrices_ didn't resolve — wrong offset.\n"
            "   calls=0 => getJointByName not called for env meshes — they don't do joint queries.)\n",
            (unsigned long long)g_hz_calls,(unsigned long long)g_hz_x1ok,(unsigned long long)g_hz_rej);
        int o = snprintf(out,cap,"hzanim skeletons=%d (210FA48 calls=%llu resolved=%llu)  [skeleton nj  j0..jN posed world translations + curve]\n",
                         g_hz_n,(unsigned long long)g_hz_calls,(unsigned long long)g_hz_x1ok);
        for (int i=0;i<g_hz_n && o<cap-256;i++){ HzRec& r=g_hz[i];
            o+=snprintf(out+o,cap-o,"[%d] skel=0x%llx jointBuf=0x%llx nj=%d\n", i,
                        (unsigned long long)r.assetId[1],(unsigned long long)r.assetId[0], r.nj);
            o+=snprintf(out+o,cap-o,"    root  t=%.3f,%.3f,%.3f\n", r.m0[12],r.m0[13],r.m0[14]);
            o+=snprintf(out+o,cap-o,"    mover t=%.3f,%.3f,%.3f  basisX=%.3f,%.3f,%.3f Y=%.3f,%.3f,%.3f Z=%.3f,%.3f,%.3f\n",
                        r.mN[12],r.mN[13],r.mN[14], r.mN[0],r.mN[1],r.mN[2], r.mN[4],r.mN[5],r.mN[6], r.mN[8],r.mN[9],r.mN[10]);
            o+=snprintf(out+o,cap-o,"    curve(%d @8Hz, oldest->newest):\n", r.cn);
            for(int s=0;s<r.cn && o<cap-64;s++){ int idx=(r.cw - r.cn + s + 2*CURVE_N)%CURVE_N;
                o+=snprintf(out+o,cap-o,"      %2d: %.2f, %.2f, %.2f\n", s, r.curve[idx][0],r.curve[idx][1],r.curve[idx][2]); }
        }
        return o;
    }
    if (!strncmp(cmd,"envdump",7)) {
        // WHOLE-ENV runtime dump: one compact line per renderable — mesh asset id (correlate with the
        // cooker), the PROCESSED world transform (proxy+304 pos + proxy+256 scale), cull center/ext, and
        // for skinned meshes the live mover-joint translation (matched from the HzAnim table by asset id).
        // Reads stable proxy objects captured during the last cull walk, so it works between frames.
        int np = g_nproxies; if (np<=0) return snprintf(out,cap,"ERR no proxies (need rt_mcp armed + 1 cull frame)\n");
        int o = snprintf(out,cap,"envdump renderables=%d skinned=%d\n idx  meshAssetId                         worldPos(x,y,z)          scale     cullExt   [skin nj mover]\n", np, g_hz_n);
        for (int i=0;i<np && o<cap-220;i++){
            uint64_t proxy=g_proxies[i]; if(!okptr(proxy)) continue;
            uint64_t res=0; safe_read(proxy+464,&res,8);
            uint64_t mid[2]={0,0}; if(okptr(res)){ uint64_t ar=0; if(safe_read(res+32,&ar,8)>=0 && okptr(ar)) safe_read(ar+8,mid,16); }
            float tp[3]={0,0,0}, bx[3]={0,0,0}, ctr[3]={0,0,0}, ext[3]={0,0,0};
            safe_read(proxy+304,tp,12); safe_read(proxy+256,bx,12); safe_read(proxy+80,ctr,12); safe_read(proxy+96,ext,12);
            float sx=__builtin_sqrtf(bx[0]*bx[0]+bx[1]*bx[1]+bx[2]*bx[2]);
            // cull-AABB CENTER (proxy+80) + EXT (proxy+96): for a skinned mesh the bound spans rest→posed,
            // so the animated far tip ≈ center+ext and the near/rest ≈ center-ext. This is the live device
            // animation coordinate, keyed by mesh asset id (correlate with the cook's [COOK-ID]).
            char anm[80]="?"; rt_asset_name(proxy,anm,sizeof anm);    // real cook asset NAME (m006.material) — no hash
            char* as=anm; if(strstr(as,"/")) as=strrchr(as,'/')+1;
            o+=snprintf(out+o,cap-o," %3d  wp=%.1f,%.1f,%.1f sc=%.2f ext=%.0f proxy=0x%llx  %s\n",
                        i, tp[0],tp[1],tp[2], sx, ext[0], (unsigned long long)proxy, as);
        }
        o+=snprintf(out+o,cap-o,"# %d renderables\n", np);
        return o;
    }
    if (!strncmp(cmd,"loco",4)) {   // dump the stashed locomotion controller pointers (for offset-finding)
        return snprintf(out,cap,"loco_this=0x%llx a3=0x%llx pos_off=%d\n",
                        (unsigned long long)g_loco_this,(unsigned long long)g_loco_a3,LOCO_POS_OFF);
    }
    if (!strncmp(cmd,"playerpos",9)) {   // player feet + head/eye + FACING yaw + no-gravity state — parseable line
        char head[80]={0};
        if (okptr(g_cullctx)) { const float* cam=(const float*)g_cullctx+40;
            snprintf(head,sizeof head,"head=%.3f,%.3f,%.3f ",cam[0],cam[1],cam[2]); }
        char face[40]={0}; float yd;
        if (cull_forward_yaw(&yd,nullptr,nullptr)) snprintf(face,sizeof face,"face=%.1f ", yd);   // head-forward heading (deg)
        int ng = aio_get_nogravity();
        uint64_t a3=g_loco_a3;
        if (okptr(a3)) { float p[8]; if(safe_read(a3+LOCO_POS_OFF,p,sizeof p)>=0)
            return snprintf(out,cap,"%s%sfeet=%.3f,%.3f,%.3f nograv=%d +12..=%.3f,%.3f,%.3f,%.3f,%.3f\n",
                            head, face, p[0],p[1],p[2], ng, p[3],p[4],p[5],p[6],p[7]); }
        float c3[3]={0,0,0}; int tick=aio_get_curpos(c3);
        if (tick>0) return snprintf(out,cap,"%s%sfeet=%.3f,%.3f,%.3f nograv=%d (aio)\n", head, face, c3[0],c3[1],c3[2], ng);
        return snprintf(out,cap,"%s%sfeet=? nograv=%d ERR no loco ctx (MOVE once on the headset)\n", head, face, ng);
    }
    if (!strncmp(cmd,"tp",2) && (cmd[2]==' '||cmd[2]==0)) {   // TP-HOLD: park player at x,y,z (gravity-defying) to inspect distant meshes
        const char* a=cmd+2; while(*a==' ')++a;
        if(!strncmp(a,"off",3)){ g_tp_hold=0; return snprintf(out,cap,"OK tp-hold OFF (gravity resumes)\n"); }
        float x=0,y=0,z=0; if(sscanf(a,"%f %f %f",&x,&y,&z)==3){ g_tp_x=x; g_tp_y=y; g_tp_z=z; g_tp_hold=1;
            return snprintf(out,cap, okptr(g_loco_a3)?"OK tp-hold -> %.1f,%.1f,%.1f (held every 8ms; `tp off` to release)\n"
                                                     :"tp set %.1f,%.1f,%.1f but NO loco ctx — MOVE once on the headset, then re-send tp\n", (double)x,(double)y,(double)z); }
        return snprintf(out,cap,"usage: tp <x> <y> <z> | tp off\n");
    }
    // NO-GRAVITY toggle (editor "Player" gizmo / MCP): the AIO moonjump owns the loco hook, so the real
    // anti-gravity lives at its post-gravity ccmove site (zeroes the vertical velocity every frame → the
    // player never falls after a teleport). Drive that flag. `nogravity` / `nogravity 1` = on, `nogravity 0`.
    if (!strncmp(cmd,"nogravity",9)) {
        const char* a=cmd+9; while(*a==' ')++a;
        bool on = (*a==0) || *a=='1' || *a=='t' || *a=='y' || !strncmp(a,"on",2);
        if (*a=='0' || *a=='f' || *a=='n' || !strncmp(a,"off",3)) on=false;
        aio_set_nogravity(on?1:0);
        int st = aio_get_nogravity();
        if (st < 0) return snprintf(out,cap,"nogravity=%d requested but AIO loco not armed yet (env up? moonjump on?)\n", on);
        return snprintf(out,cap,"OK nogravity %s (player holds height after teleport; `warp x y z` to place)\n", st?"ON":"OFF");
    }
    // ROTATE the player to face YAW (radians) via the game's own teleport message (proven; sets facing). Posts
    // at the HELD target when no-gravity is on (so it doesn't yank the player down), else the current feet pos.
    if (!strncmp(cmd,"rot",3) && (cmd[3]==' '||cmd[3]==0)) {
        const char* a=cmd+3; while(*a==' ')++a; float yaw=strtof(a,nullptr);
        // teleport to the CURRENT feet (+ yaw). AIO owns the loco hook, so its curpos is the live pos; fall
        // back to rendertrace's own a3 if that ever captures. No-gravity keeps the height after the msg.
        float x,y,z;
        float c3[3]; int tick=aio_get_curpos(c3);
        if (tick>0) { x=c3[0]; y=c3[1]; z=c3[2]; }
        else { uint64_t a3=g_loco_a3; if(!okptr(a3)) return snprintf(out,cap,"ERR no player pos yet (MOVE once on the headset)\n");
               float p[3]; if(safe_read(a3+LOCO_POS_OFF,p,12)<0) return snprintf(out,cap,"ERR EFAULT\n"); x=p[0];y=p[1];z=p[2]; }
        if (!post_teleport(g_base, x,y,z, yaw)) return snprintf(out,cap,"ERR no ShellApp (env not up)\n");
        return snprintf(out,cap,"OK rot -> yaw %.3f at %.2f,%.2f,%.2f\n",(double)yaw,(double)x,(double)y,(double)z);
    }
    // GAME teleport (no fall IN-BOUNDS, optional facing yaw) — distinct from tp-hold: posts the ShellApp msg so
    // the game applies it with collision. `warp x y z [yaw]`. Out-of-bounds falls -> use nogravity+tp for that.
    if (!strncmp(cmd,"warp",4) && (cmd[4]==' '||cmd[4]==0)) {
        float x=0,y=0,z=0,yaw=0; int got=sscanf(cmd+4,"%f %f %f %f",&x,&y,&z,&yaw);
        if (got<3) return snprintf(out,cap,"usage: warp <x> <y> <z> [yaw]\n");
        if (!post_teleport(g_base, x,y,z, yaw)) return snprintf(out,cap,"ERR no ShellApp (env not up)\n");
        return snprintf(out,cap,"OK warp -> %.2f,%.2f,%.2f yaw %.3f\n",(double)x,(double)y,(double)z,(double)yaw);
    }
    if (!strncmp(cmd,"pinwall",7)) {   // stick ANY app to a wall placement: pinwall <app.component> <rank>
        char app[256]={0}; int rank=0;
        if (sscanf(cmd+7," %255s %d", app, &rank)!=2) return snprintf(out,cap,"usage: pinwall <app.component> <rank>  (rank = the wall placement's propRank)\n");
        if (!g_alc_ctrl) return snprintf(out,cap,"ERR controller not captured yet (load a home env first)\n");
        strncpy(g_pin_app, app, sizeof g_pin_app - 1); g_pin_app[sizeof g_pin_app - 1]=0;
        g_pin_rank = rank; g_pin_pending = 1; g_pin_done = 0;   // executed on the shell thread by the loco hook next frame
        return snprintf(out,cap,"OK staged pin '%s' at wall rank %d (then run `pinstat`)\n", app, rank);
    }
    if (!strncmp(cmd,"pinstat",7)) {   // report what the last staged pin actually saw on the shell thread
        int n = snprintf(out,cap,"ctrl=0x%llx done=%d ret=%ld wallLocators=%d ranks=[",
                         (unsigned long long)g_alc_ctrl, g_pin_done, g_pin_ret, g_pin_nlocs);
        for (int i=0;i<g_pin_nranks && n<cap-8;++i) n += snprintf(out+n,cap-n,"%s%d",i?",":"",g_pin_ranks[i]);
        n += snprintf(out+n,cap-n,"] pending=%d\n", g_pin_pending);
        return n;
    }
    if (!strncmp(cmd,"setpos ",7)) {   // write player position (a3+144). NOTE: physics may overwrite next frame.
        float v[3]={0,0,0}; sscanf(cmd+7,"%f %f %f",&v[0],&v[1],&v[2]);
        uint64_t a3=g_loco_a3; if(!okptr(a3)) return snprintf(out,cap,"ERR no loco ctx\n");
        long w=safe_write(a3+LOCO_POS_OFF,v,12);
        return snprintf(out,cap, w<0?"ERR EFAULT\n":"OK setpos %.2f,%.2f,%.2f (may be re-asserted by physics)\n",(double)v[0],(double)v[1],(double)v[2]);
    }
    if (!strncmp(cmd,"move ",5)) {     // add delta to player position (a3+144)
        float d[3]={0,0,0}; sscanf(cmd+5,"%f %f %f",&d[0],&d[1],&d[2]);
        uint64_t a3=g_loco_a3; if(!okptr(a3)) return snprintf(out,cap,"ERR no loco ctx\n");
        float p[3]; if(safe_read(a3+LOCO_POS_OFF,p,12)<0) return snprintf(out,cap,"ERR EFAULT\n");
        p[0]+=d[0]; p[1]+=d[1]; p[2]+=d[2];
        safe_write(a3+LOCO_POS_OFF,p,12);
        return snprintf(out,cap,"OK move -> %.2f,%.2f,%.2f\n",(double)p[0],(double)p[1],(double)p[2]);
    }
    if (!strncmp(cmd,"log ",4)) {
        int on = strstr(cmd,"1")!=nullptr;
        if(strstr(cmd,"cull")) g_logmask = on ? (g_logmask|1) : (g_logmask&~1);
        if(strstr(cmd,"skel")) g_logmask = on ? (g_logmask|2) : (g_logmask&~2);
        return snprintf(out,cap,"OK logmask=%d\n",g_logmask);
    }
    if (!strncmp(cmd,"forcevis ",9)) {   // turn culling OFF (flip every renderable to NOCULL each frame) — TEST the cull is the cause
        g_forcevis = strstr(cmd,"1")!=nullptr;
        return snprintf(out,cap,"OK forcevis=%d flipped=%d (culling %s)\n", g_forcevis, g_forcevis_n, g_forcevis?"DISABLED/all-visible":"normal");
    }
    if (!strncmp(cmd,"loglevel ",9)) { int n=(int)strtol(cmd+9,nullptr,0); if(n<0)n=0; if(n>9)n=9;
        wr8(g_base+OFF_LOGLEVEL_N3,(uint8_t)n); wr8(g_base+OFF_LOGLEVEL_FLAG,0); return snprintf(out,cap,"OK n3=%d (SUSPECT)\n",n); }
    if (!strncmp(cmd,"stat",4)) {   // one view of EVERY feature/hook armed-or-failed (aio moonjump/far-clip + dumper hooks)
        return aio_status_json(out, cap);
    }
    if (!strncmp(cmd,"gtime",5)) {   // FIND/verify the getTime shader clock (globalUniforms.time @ buf+592)
        const char* a=cmd+5; while(*a==' ')++a;
        if (!strncmp(a,"addr",4)) { g_gtime_addr=parse_addr(a+4); return snprintf(out,cap,"OK gtime clock addr=0x%llx (world settime / world 0 now drive it)\n",(unsigned long long)g_gtime_addr); }
        // GTIMESTORE hook captures the live UBO in g_gu_buf; time = *(float*)(g_gu_buf+592). THIS is the clock.
        float tnow=-1.f; if (okptr(g_gu_buf)) safe_read(g_gu_buf+596,&tnow,4);
        int o=snprintf(out,cap,"gtime: UBO=0x%llx  time(buf+596)=%.4f  mode=%d val=%.4f  [bind this=0x%llx a2=0x%llx k=0x%llx addr=0x%llx]\n",
            (unsigned long long)g_gu_buf,tnow,g_gtime_mode,g_gtime_val,
            (unsigned long long)g_guni_this,(unsigned long long)g_guni_a2,(unsigned long long)g_guni_k,(unsigned long long)g_gtime_addr);
        // walk `this` qwords -> each is a candidate object; probe +0..+768 of each (and this itself) for a float clock
        auto probe=[&](uint64_t base,const char* tag){ if(!okptr(base)||o>=cap-90) return;
            for(int off=0; off<=736 && o<cap-40; off+=4){ float f=0; if(safe_read(base+off,&f,4)<0) break;
                if(f>0.05f && f<1.0e7f && f==f){ o+=snprintf(out+o,cap-o,"  %s+%d=%.3f@0x%llx\n",tag,off,f,(unsigned long long)(base+off)); } } };
        probe(g_guni_this,"this"); probe(g_guni_k,"k"); probe(g_guni_a2,"a2");
        if (okptr(g_guni_this)) for(int off=0; off<=280 && o<cap-64; off+=8){ uint64_t q=0; if(safe_read(g_guni_this+off,&q,8)<0)break;
            if(okptr(q)){ char t2[16]; snprintf(t2,sizeof t2,"*[%d]",off); probe(q,t2); } }
        return o;
    }
    // GLOBAL WORLD-TIME control — affects the ENTIRE world: BOTH clocks. HzAnim (comet/birds) via HzAnimPlayback speed,
    // AND the getTime() shader clock (flipbooks/train/UV-scroll/scale/rotate/pulse/VAT) via globalUniforms.time (+596).
    // `world 0`=FREEZE everything | 0.05=slow(HzAnim) | 2=2x(HzAnim) | 1=normal | off=release | setphase <0..1>(HzAnim) | settime <sec>(getTime).
    if (!strncmp(cmd,"world",5) || !strncmp(cmd,"animspeed",9)) {
        const char* a = cmd + (cmd[0]=='w'?5:9); while(*a==' ')++a;
        if (*a==0) return snprintf(out,cap,"world: hzSpeed=%.3f hzPin=%d  gtimeMode=%d gtime=%.3f  (world 0=freeze|0.05=slow|2=2x|1=normal|off|setphase <0..1>|settime <sec>)\n",
                                   *(float*)&g_anim_speed_bits, g_world_setphase, g_gtime_mode, g_gtime_val);
        if (!strncmp(a,"setphase",8)) {   // HzAnim EXACT pin to normalized phase p (desktop slider sync)
            const char* p=a+8; while(*p==' ')++p; float ph=strtof(p,nullptr); if(ph<0.f)ph=0.f; if(ph>1.f)ph=1.f;
            union { float f; uint32_t u; } cv; cv.f=ph; g_world_phase_bits=cv.u; g_world_setphase=1; g_anim_speed_bits=0; g_anim_enable=1;
            return snprintf(out,cap,"OK HzAnim pinned to phase %.4f\n", ph);
        }
        if (!strncmp(a,"settime",7)) {   // getTime shader clock EXACT set to <sec> (desktop slider sync: flipbooks/train)
            const char* p=a+7; while(*p==' ')++p; float t=strtof(p,nullptr); if(t<0.f)t=0.f;
            g_gtime_val=t; g_gtime_mode=2;
            return snprintf(out,cap,"OK getTime clock set to %.4fs (flipbooks/train/uvscroll pinned)\n", t);
        }
        if (!strncmp(a,"off",3)) { g_anim_enable=0; g_world_setphase=0; g_gtime_mode=0; return snprintf(out,cap,"OK world override OFF (both clocks resume)\n"); }
        float v=strtof(a,nullptr);
        if (v<0.f) { g_anim_enable=0; g_world_setphase=0; g_gtime_mode=0; return snprintf(out,cap,"OK world override OFF (both clocks resume)\n"); }
        union { float f; uint32_t u; } cv; cv.f=v; g_anim_speed_bits=cv.u; g_anim_enable=1; g_world_setphase=0;
        if (v==0.f) { g_gtime_mode=1; g_gtime_cap=0; }   // FREEZE -> also hold the getTime clock (flipbooks/train stop)
        else        { g_gtime_mode=0; }                  // speed/normal -> getTime runs (only 0 freezes it)
        return snprintf(out,cap,"OK WORLD %s (HzAnim speed=%.3f, getTime %s)\n", v==0.f?"FROZEN":"running", v, v==0.f?"held":"free");
    }
    return snprintf(out,cap,"ERR unknown cmd (ping|base|stat|gtime|renderables|envdump|findmat|findmesh|meshmat|meshprobe|hzanim|skeletons|read|write|r32|w32|rf32|wf32|log|loglevel|world|forcevis|loco|playerpos|tp|nogravity|rot|warp|pinwall|setpos|move)\n");
}
// One CONNECTION = one detached thread. PERSISTENT: loop reading '\n'-terminated commands, dispatch + reply to
// EACH, until the client closes (recv<=0). A ONE-SHOT client (send one line + close) still works. A LIVE client
// (the editor's player gizmo) keeps ONE socket open and streams warp/rot at drag rate = NO per-command connect
// round-trip = smooth. ⛔ The server used to be SINGLE-CLIENT (one accept() then a blocking recv loop), so the
// editor's persistent Track-Player socket STARVED every other client (an MCP tool, a second editor, a diagnostic
// warp) — they'd connect into the backlog and never get accept()ed until the editor closed = "teleport doesn't
// work while tracking". Now each connection gets its own thread + its own response buffer, so clients coexist.
// (mcp_dispatch's warp/pos/nogravity are last-writer-wins on device memory — concurrent callers are benign.)
static void* mcp_client_thread(void* arg) {
    int c = (int)(intptr_t)arg;
    char* resp = (char*)malloc(65536);                       // per-connection (was a shared static -> not reentrant)
    if (!resp) { close(c); return nullptr; }
    char line[1024]; int li=0; char ch;
    for (;;) {
        int n = recv(c,&ch,1,0);
        if (n<=0) break;                                     // client closed / error -> done with this connection
        if (ch=='\r') continue;
        if (ch=='\n') { line[li]=0; if (li){ int rl=mcp_dispatch(line,resp,65536); if (send(c,resp,rl,0)<=0) break; } li=0; continue; }
        if (li < (int)sizeof line-1) line[li++]=ch;
    }
    free(resp); close(c); return nullptr;
}
static void* control_server(void*) {
    int port = prop_int("rt_port", 27042);
    int s = socket(AF_INET, SOCK_STREAM, 0); if (s < 0) { LOGW("mcp: socket failed"); return nullptr; }
    int one=1; setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    sockaddr_in addr{}; addr.sin_family=AF_INET; addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK); addr.sin_port=htons(port);
    if (bind(s,(sockaddr*)&addr,sizeof addr)<0) { LOGW("mcp: bind 127.0.0.1:%d failed (in use?)",port); close(s); return nullptr; }
    listen(s, 8);
    LOGI("MCP control server LIVE on 127.0.0.1:%d  (adb forward tcp:%d tcp:%d) [multi-client]", port, port, port);
    for (;;) {
        int c = accept(s, nullptr, nullptr); if (c < 0) continue;
        pthread_t t;
        if (pthread_create(&t, nullptr, mcp_client_thread, (void*)(intptr_t)c) == 0) pthread_detach(t);
        else close(c);                                       // thread spawn failed -> drop this client, keep serving
    }
}

static void apply_patch() {
    LOGI("worker: started (scanning for libshell anchor)");
    uint8_t* fn = nullptr;
    for (int i = 0; i < 24000 && !fn; ++i) {
        fn = find_anchor();
        if (fn) break;
        usleep(50 * 1000);
        if (i == 400) LOGI("waiting for VrShell render code (env not rendering yet)…");
    }
    if (!fn) { LOGW("anchor not found in 20min — leaving stock"); return; }
    g_base = fn - OFF_EFA9D0;
    LOGI("libshell base @ %p (anchor fn__EFA9D0 @ %p)", (void*)g_base, (void*)fn);

    // (1) Optionally raise libshell's global log level. DEFAULT OFF (level 0 = don't poke).
    //     ⚠ The n3 byte-poke is SUSPECT: setting it correlated with libshell tearing down its
    //     systems ("shutting down SkinnedMeshSystem/SkeletonSystem/OcclusionSystem"). That is
    //     NOT a kernel watchdog — libshell ships memory-integrity guards (it logs "Skeleton
    //     member corrupted 'memoryCheckBase_'" etc.), so our write (or wr8 leaving the page RW)
    //     likely trips an anti-tamper check -> graceful self-shutdown. Treat this path as
    //     unproven/buggy; prefer the cull/skel trampolines (device-stable) for the real
    //     diagnostic. Kept opt-in for experiments only.
    int lvl = prop_int("rt_loglevel", 0);
    if (lvl > 0) {
        if (lvl > 9) lvl = 9;                       // never 0xFF (floods hot paths -> watchdog)
        wr8(g_base + OFF_LOGLEVEL_N3,   (uint8_t)lvl);
        wr8(g_base + OFF_LOGLEVEL_FLAG, 0x00);       // use the global default level for all channels
        LOGI("LOGLEVEL: n3=%d flag=0 (opt-in; >9 capped). Watch tags Shell/ShellHsr for "
             "SkinnedMeshSystem/SkeletonSystem/OcclusionSystem + 'Inconsistent data'/'not skinned'.", lvl);
    }

    // (2) MCP control server (default ON): localhost socket for runtime inspect/control.
    bool wantMcp  = prop_on("rt_mcp", true);
    bool wantCull = prop_on("rt_cull", false);
    bool wantSkel = prop_on("rt_skel", false);

    // ⚠ BUILD-SAFETY: these are FIXED offsets from the V205.2 IDB. If the device libshell
    // differs, base+offset lands on the WRONG function and the trampoline CORRUPTS unrelated
    // code (e.g. the shell's profile-hover menu vanished). So before hooking we verify the
    // target's first 8 bytes EXACTLY match the IDB prologue; on mismatch we SKIP + log (never
    // corrupt), which also tells us the offset is stale for this build.
    static const uint8_t PRO_CULLJOB[8]   = {0xff,0x43,0x03,0xd1,0xfd,0x7b,0x07,0xa9};
    static const uint8_t PRO_SKEL[8]      = {0xef,0x3b,0xb6,0x6d,0xed,0x33,0x01,0x6d};
    static const uint8_t PRO_SLIDELOCO[8] = {0xff,0x83,0x05,0xd1,0xea,0x73,0x00,0xfd};
    static const uint8_t PRO_HZANIM[8]    = {0xff,0xc3,0x01,0xd1,0xfd,0x7b,0x04,0xa9};  // AnimationPlayback__210FA48 (SUB SP; STP)
    static const uint8_t PRO_PREPIN[8]    = {0xfd,0x7b,0xba,0xa9,0xfb,0x0b,0x00,0xf9};  // PrePinDefaultApps (STP X29,X30,[SP,#-0x60]!; STR X27)
    auto verify_pro = [](uint8_t* fn, const uint8_t* exp, const char* nm) -> bool {
        uint8_t got[8]; if (safe_read((uint64_t)fn, got, 8) < 0) { LOGW("%s @ %p: unreadable — SKIP", nm, fn); return false; }
        if (memcmp(got, exp, 8) != 0) { LOGW("%s @ %p: prologue MISMATCH (build != IDB) exp %02x%02x%02x%02x got %02x%02x%02x%02x — SKIP (offset stale, would corrupt)",
                nm, fn, exp[0],exp[1],exp[2],exp[3], got[0],got[1],got[2],got[3]); return false; }
        LOGI("%s @ %p: prologue OK (build matches IDB)", nm, fn); return true; };

    // The cull hook STASHES the live world for the MCP server, so arm it if EITHER cull
    // logging OR the MCP is wanted. Likewise the skel hook for `skeletons`.
    bool okc=false, oks=false, okl=false, okh=false, oka=false;
    if (wantCull || wantMcp) {
        okc = verify_pro(g_base+OFF_CULLJOB, PRO_CULLJOB, "CULL") && install_entry_hook(g_base + OFF_CULLJOB, (void*)hsr_rt_cull);
        if (okc) LOGI("CULL hook @ %p armed", (void*)(g_base+OFF_CULLJOB)); else LOGW("cull hook: not armed");
        aio_feat_report("rt-cull", okc, okc ? "cull walk + world stash" : "prologue mismatch / install failed");
    }
    if (wantSkel || wantMcp) {
        oks = verify_pro(g_base+OFF_SKEL_VF7, PRO_SKEL, "SKEL") && install_entry_hook(g_base + OFF_SKEL_VF7, (void*)hsr_rt_skel);
        if (oks) LOGI("SKEL hook @ %p armed", (void*)(g_base+OFF_SKEL_VF7)); else LOGW("skel hook: not armed");
        aio_feat_report("rt-skel", oks, oks ? "skeleton/skinned-bounds" : "prologue mismatch / install failed");
    }
    if (wantMcp) {   // locomotion hook: stash the player controller for pos/rot/move commands
        uint8_t* lf = g_base + OFF_SLIDELOCO;
        if (*(volatile uint32_t*)lf == 0x58000050u) {
            // The AIO moonjump worker (runs first) already hooked SlideLocomotionController_update's
            // entry — the SAME function. It owns the loco path and exposes player pos via its cmd
            // block, so this is expected + fine, not a failure.
            aio_feat_report("rt-loco", true, "loco owned by moonjump (player pos via moonjump)");
        } else {
            okl = verify_pro(lf, PRO_SLIDELOCO, "LOCO") && install_entry_hook(lf, (void*)hsr_rt_loco);
            if (okl) LOGI("LOCO hook @ %p armed", (void*)lf); else LOGW("loco hook: not armed");
            aio_feat_report("rt-loco", okl, okl ? "player pos/rot/move" : "prologue mismatch / install failed");
        }
    }
    if (wantMcp) {   // APP->WALL pin: capture the AllocentricLaunchController `this` from PrePinDefaultApps (env load)
        bool okp = verify_pro(g_base+OFF_PREPIN, PRO_PREPIN, "PREPIN") && install_entry_hook(g_base + OFF_PREPIN, (void*)hsr_rt_prepin);
        if (okp) LOGI("PREPIN hook @ %p armed (app->wall via `pinwall`)", (void*)(g_base+OFF_PREPIN)); else LOGW("prepin hook: not armed");
        aio_feat_report("pin-wall", okp, okp ? "app->wall pin armed (pinwall <app> <rank>)" : "PrePinDefaultApps prologue mismatch");
    }
    if (wantMcp) {   // HSR skinning hook (RenderableProxy__ABC928): capture the DEVICE's runtime joint matrices + curve
        okh = verify_pro(g_base+OFF_HZANIM_210FA48, PRO_HZANIM, "HZANIM") && install_entry_hook(g_base + OFF_HZANIM_210FA48, (void*)hsr_rt_hzanim);
        if (okh) LOGI("HZANIM hook @ %p armed", (void*)(g_base+OFF_HZANIM_210FA48)); else LOGW("hzanim hook: not armed");
        aio_feat_report("rt-hzanim", okh, okh ? "AnimationPlayback pose (hzanim)" : "prologue mismatch / install failed");
    }
    if (wantMcp) {   // GLOBAL WORLD-TIME hook: HzAnimPlayback::update — override *(this+20) speed = freeze/slow/scrub
        static const uintptr_t OFF_HZPLAYBACK_VF2 = 0xC8883C;   // HzAnimPlayback::update — re-anchored for the current stock libshell (was 0xC888A8)
        static const uint8_t PRO_HZPLAYBACK[8] = {0xeb,0x2b,0xb8,0x6d,0xe9,0x23,0x01,0x6d};   // STP q11,q10,[sp,#-256]!; STP q9,q8,[sp,#16]
        oka = verify_pro(g_base+OFF_HZPLAYBACK_VF2, PRO_HZPLAYBACK, "WORLDTIME") && install_entry_hook(g_base + OFF_HZPLAYBACK_VF2, (void*)hsr_rt_anim);
        if (oka) LOGI("WORLDTIME hook @ %p armed (global freeze/speed via `world`)", (void*)(g_base+OFF_HZPLAYBACK_VF2)); else LOGW("worldtime hook: not armed");
        aio_feat_report("world-time", oka, oka ? "global freeze/speed (world cmd)" : "prologue mismatch / install failed");
    }
    if (wantMcp) {   // getTime() SHADER CLOCK: GlobalDescriptorManager::bind — override globalUniforms.time (+596)
        static const uintptr_t OFF_GUNI = 0xDE9034;
        static const uint8_t PRO_GUNI[8] = {0xef,0x3b,0xb6,0x6d,0xed,0x33,0x01,0x6d};   // STP q15,q14,[sp,#-160]!; STP q13,q12,[sp,#16]
        bool okg = verify_pro(g_base+OFF_GUNI, PRO_GUNI, "GTIME") && install_entry_hook(g_base + OFF_GUNI, (void*)hsr_rt_guni);
        if (okg) LOGI("GTIME hook @ %p armed (bind entry; diag capture of this/a2/k)", (void*)(g_base+OFF_GUNI)); else LOGW("gtime hook: not armed");
        aio_feat_report("gtime", okg, okg ? "bind-entry diag (this/a2/k)" : "prologue mismatch / install failed");
    }
    if (wantMcp) {   // getTime STORE-SITE hook = the REAL clock override. globalUniforms.time (+596) is written
                     // every frame at bind+0xDE986C `STR S0,[X21,#0x254]` (the SOLE +596 writer). We hook it
                     // post-store so `world 0`/`world settime`/`world <0>` freeze/scrub flipbooks/train/uvscroll/VAT.
        static const uintptr_t OFF_GTIME_STORE = 0xDE986C;
        static const uint8_t PRO_GTIME_STORE[8] = {0xa0,0x56,0x02,0xbd,0xc0,0x02,0x40,0xf9};   // STR S0,[X21,#0x254]; LDR X0,[X22]
        bool okgs = verify_pro(g_base+OFF_GTIME_STORE, PRO_GTIME_STORE, "GTIMESTORE") && install_gtime_store_hook(g_base + OFF_GTIME_STORE, (void*)hsr_gtime_store2);
        if (okgs) LOGI("GTIMESTORE hook @ %p armed (globalUniforms.time +596 OVERRIDE = flipbook/train/uvscroll freeze/scrub)", (void*)(g_base+OFF_GTIME_STORE));
        else LOGW("gtime-store hook: not armed");
        aio_feat_report("gtime-store", okgs, okgs ? "getTime clock OVERRIDE (buf+596)" : "prologue mismatch / install failed");
    }
    g_logmask = (wantCull ? 1 : 0) | (wantSkel ? 2 : 0);   // MCP can flip these live via "log" cmd

    if (wantMcp) { pthread_t mt; pthread_create(&mt, nullptr, control_server, nullptr); pthread_detach(mt);
                   pthread_t tt; pthread_create(&tt, nullptr, tp_hold_thread, nullptr); pthread_detach(tt); }

    LOGI("render-trace armed (mcp=%d cull=%d skel=%d). logcat -s HSR-RT.", wantMcp, wantCull, wantSkel);
}

static void* worker(void*) { apply_patch(); return nullptr; }

// Companion-path worker: librendertrace.so is pulled in as a DT_NEEDED of libshell
// VERY early (via libnativeloader, before the process is renamed from "zygote64" to
// "com.oculus.vrshell"), so a cmdline check at ctor time is unreliable. Defer it: let
// the process settle, then confirm we're in vrshell before patching. In any non-vrshell
// process that somehow loads us, libshell's signature simply never appears and we exit.
static bool in_vrshell();
static void* companion_worker(void*) {
    for (int i = 0; i < 50 && !in_vrshell(); i++) usleep(100 * 1000);  // up to ~5s for rename
    if (!in_vrshell()) { LOGW("companion: not vrshell after settle — exiting"); return nullptr; }
    apply_patch();
    return nullptr;
}

// ── DELIVERY MODE B: smali-injected companion lib ───────────────────────────
//  Instead of relying on Zygisk catching the vrshell fork, we patch VrShell.apk's
//  smali to call System.loadLibrary("rendertrace") *before* it loads libshell, and
//  overlayfs the patched APK in via a Magisk module. When loaded that way, this
//  constructor fires at dlopen time INSIDE vrshell and spawns the same worker
//  (which polls /proc/self/maps for libshell, then installs the hooks). Guarded so
//  it's inert if the .so is ever dlopened somewhere that ISN'T vrshell (e.g. the
//  zygote dlopen of the Zygisk-module build — there the Zygisk path handles it).
static bool in_vrshell() {
    char buf[256] = {0};
    FILE* f = fopen("/proc/self/cmdline", "re");
    if (!f) return false;
    size_t n = fread(buf, 1, sizeof buf - 1, f); fclose(f);
    (void)n;
    return strstr(buf, "com.oculus.vrshell") != nullptr;
}
#ifndef AIO_MERGE_BUILD
// STANDALONE build owns its ctor. In the ALL-IN-ONE merged build the single
// core/orchestrator.cpp ctor calls rt_worker_entry (below) instead, so both this
// dumper AND the AIO (moonjump) arm from ONE worker sequence — never again two
// competing ctors where one gets dropped.
__attribute__((constructor))
static void rendertrace_ctor() {
    static bool started = false;
    if (started) return;
    started = true;
    // Always spawn; the companion worker self-gates (confirms vrshell after the process
    // settles). librendertrace is delivered ONLY as libshell's DT_NEEDED, so in practice
    // this only ever runs inside the vrshell process that hosts libshell.
    LOGI("companion ctor: librendertrace loaded — spawning settle+patch worker");
    pthread_t t; pthread_create(&t, nullptr, companion_worker, nullptr); pthread_detach(t);
}
#else
// MERGED build: exported entry the orchestrator spawns (self-gates to vrshell).
extern "C" void* rt_worker_entry(void*) {
    LOGI("rendertrace worker entry (merged) — settle + install cull/coord dumper");
    return companion_worker(nullptr);
}
#endif

class RenderTraceModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override { api_ = api; env_ = env; }
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const char* nice = env_->GetStringUTFChars(args->nice_name, nullptr);
        target_ = nice && strcmp(nice, "com.oculus.vrshell") == 0;
        if (nice) env_->ReleaseStringUTFChars(args->nice_name, nice);
        if (!target_) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!target_) return;
        if (!prop_on("rendertrace", true)) { LOGI("hsr.rendertrace=0 -> disabled"); return; }
        pthread_t t; pthread_create(&t, nullptr, worker, nullptr); pthread_detach(t);
    }
private:
    zygisk::Api* api_ = nullptr; JNIEnv* env_ = nullptr; bool target_ = false;
};

REGISTER_ZYGISK_MODULE(RenderTraceModule)
