// ============================================================================
//  Quest Player-Ctl — NeoZygisk module: drive the VR-shell player from the MCP.
// ----------------------------------------------------------------------------
//  Hooks SlideLocomotionController_update (libshell 0x18CCEA0). IDA-confirmed:
//      v127 = move velocity;  *(a3+144) = v127 + *(a2+32)  -> a2+32 = PLAYER POS (xyz floats)
//      thumbstick = *(a2+216)=X, *(a2+220)=Y
//  PRE-hook (inline trampoline, runs before the original each frame; only scratch
//  X9/X10/X11 — same pattern as the far-clip module):
//    * TELEPORT (no fall): cmd.tp_pending -> overwrite a2+32=(x,y,z), clear flag.
//    * WALK: cmd.walk_on -> overwrite the thumbstick a2+216/220=(fwd,strafe).
//
//  ⚠ CRITICAL NeoZygisk lesson (learned the hard way — a baked &module_global
//  CRASHED vrshell): NeoZygisk relocates/hides the module .so AFTER specialize,
//  so any module .data address baked into the trampoline goes STALE (the worker
//  still resolves it live via the GOT, but the in-shell trampoline holds the dead
//  pointer -> SIGSEGV). FIX: the command block lives in an independent mmap'd page
//  (NOT module memory — never relocated), its 64-bit address baked as an LDR-literal
//  .quad (the far-clip's proven value-only pattern). The worker keeps the mmap
//  pointer on its own stack (no module global).
//
//  SAFE BY DEFAULT: does NOTHING until `setprop hsr.playerctl 1`. If a hook ever
//  misbehaves, `setprop hsr.playerctl 0` + reload vrshell recovers with NO reboot
//  (the next fork's worker just waits). Disk untouched. Resolve libshell base via
//  the far-clip fn__EFA9D0 signature; loco = base+0x18CCEA0.
//  ⚠ also disable the far-clip locomotion (hsr.unlimjump 0; hsr.fly 0) — it hooks
//  the same fn; the guard below aborts if it got there first.
// ============================================================================
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <cinttypes>
#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include "zygisk.hpp"

#define LOG_TAG "QuestPlayerCtl"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Command block — lives in an mmap'd page (NOT module .data). Layout is baked into
// the trampoline's byte offsets, so do not reorder.
struct CmdBlock {
    volatile uint32_t tp_pending;   // +0  : 1 = apply teleport this frame, auto-clears
    volatile float    tp[3];        // +4  : target x,y,z  -> a2+32
    volatile uint32_t walk_on;      // +16 : 1 = force the thumbstick
    volatile float    walk[2];      // +20 : fwd, strafe   -> a2+216/220
    volatile uint32_t tick;         // +28 : trampoline increments each loco-update call (is it running?)
    volatile float    curpos[3];    // +32 : trampoline copies a3+144 here each frame (the live player pos)
};

// fn__EFA9D0: UNIQUE inner sig at +0x1C disambiguated by the prologue at +0 (kSig alone
// false-positives). The far-clip module overwrites fn__EFA9D0's prologue with its jump-stub,
// so accept EITHER the original prologue OR that stub (0x58000050 = LDR X16,[PC,#8]).
static const uint8_t kPrologue[16] = { 0xff,0x83,0x01,0xd1, 0xfd,0x7b,0x04,0xa9, 0xf4,0x4f,0x05,0xa9, 0xfd,0x03,0x01,0x91 };
static const uint8_t kSig[16]      = { 0x08,0xcc,0x40,0xb9, 0x09,0x5c,0x40,0xf9, 0x08,0x79,0x1f,0x12, 0x08,0xcc,0x00,0xb9 };
static const int       kSigOff = 0x1C;
static const uintptr_t kEfaOff  = 0xE408C8;   // far-clip fn file offset — v206 2.6 (was v205 0xEFA9D0)
static const uintptr_t kLocoOff = 0xED7A78;   // SlideLocomotionController::update vf2 — v206 (was v205 0x18CCEA0)
static const uint32_t  kLocoPrologue = 0xD103C3FFu;  // SUB SP,SP,#0xF0 (v206 @0xED7A78; was 0xD10583FF / #0x160)

static uint8_t* find_efa() {
    FILE* f = fopen("/proc/self/maps", "re"); if (!f) return nullptr;
    char line[1024]; uint8_t* hit = nullptr;
    while (fgets(line, sizeof line, f) && !hit) {
        if (!strstr(line, "VrShell.apk") && !strstr(line, "libshell")) continue;
        uintptr_t lo=0, hi=0; char perms[8]={0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &lo, &hi, perms) != 3 || hi<=lo || perms[2]!='x') continue;
        mprotect((void*)lo, (size_t)(hi-lo), PROT_READ|PROT_EXEC);
        uint8_t* end = (uint8_t*)hi - sizeof kSig;
        for (uint8_t* p=(uint8_t*)lo; p<=end; ++p) {
            if (memcmp(p, kSig, sizeof kSig)) continue;
            uint8_t* fn = p - kSigOff;                 // kSig sits at fn+0x1C
            if (fn>=(uint8_t*)lo && (memcmp(fn, kPrologue, sizeof kPrologue)==0 || *(uint32_t*)fn==0x58000050u)) { hit=fn; break; }
        }
    }
    fclose(f); return hit;
}

static bool prop_on(const char* name, bool dflt) {
    char buf[PROP_VALUE_MAX]={0}, k[96];
    snprintf(k,sizeof k,"hsr.%s",name);
    if (__system_property_get(k,buf)<=0){ snprintf(k,sizeof k,"persist.hsr.%s",name); __system_property_get(k,buf); }
    if (!buf[0]) return dflt;
    char c=buf[0]; return c=='1'||c=='t'||c=='T'||c=='y'||c=='Y';
}

static bool install(uint8_t* fn, const uint32_t* code, int words) {
    size_t PG=(size_t)sysconf(_SC_PAGESIZE);
    void* tr = mmap(nullptr, PG, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (tr==MAP_FAILED) return false;
    memcpy(tr, code, (size_t)words*4);
    mprotect(tr, PG, PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)tr, (char*)tr+(size_t)words*4);
    uintptr_t t=(uintptr_t)tr;
    uint32_t jmp[4]={0x58000050u,0xD61F0200u,(uint32_t)(t&0xFFFFFFFFu),(uint32_t)(t>>32)};
    uintptr_t a=(uintptr_t)fn & ~(uintptr_t)(PG-1);
    uintptr_t b=((uintptr_t)fn+16+PG-1)&~(uintptr_t)(PG-1);
    if (mprotect((void*)a,b-a,PROT_READ|PROT_WRITE|PROT_EXEC)!=0) return false;
    memcpy(fn,jmp,16);
    mprotect((void*)a,b-a,PROT_READ|PROT_EXEC);
    __builtin___clear_cache((char*)fn,(char*)fn+16);
    return true;
}

// arm64 encodings — X1=a2 (controller state); X10=&cmd (from an LDR-literal); W9/W11 scratch.
static inline uint32_t LDR_W (int rt,int rn,int off){ return 0xB9400000u | ((uint32_t)(off>>2)<<10) | ((uint32_t)rn<<5) | (uint32_t)rt; }
static inline uint32_t STR_W (int rt,int rn,int off){ return 0xB9000000u | ((uint32_t)(off>>2)<<10) | ((uint32_t)rn<<5) | (uint32_t)rt; }
static inline uint32_t CBZ_W (int rt,int n_ins){     return 0x34000000u | (((uint32_t)n_ins & 0x7FFFF)<<5) | (uint32_t)rt; }
static inline uint32_t LDR_XLIT(int rt,int n_words){ return 0x58000000u | (((uint32_t)n_words & 0x7FFFF)<<5) | (uint32_t)rt; }

// POST-hook detour: run the ORIGINAL update first, THEN overwrite its OUTPUT a3+144 (the new player
// position the caller applies to the playspace). a2+32 is only the per-frame INPUT base (recomputed each
// tick) — writing it pre-update did nothing; a3+144 is what actually moves the player. Forcing the raw
// stick crashes libshell, so we don't touch it. a3 = X2 (3rd arg) = the locomotion-output struct.
static bool install_loco(uint8_t* lf, CmdBlock* cmd) {
    uintptr_t cont = (uintptr_t)lf + 16;
    uint32_t c[64]; int n=0;
    c[n++]=0xD10043FFu;                  // SUB SP,SP,#16
    c[n++]=0xF90007FEu;                  // STR X30,[SP,#8]    save real LR
    c[n++]=0xF90003F3u;                  // STR X19,[SP,#0]    save X19
    c[n++]=0xAA0203F3u;                  // MOV X19,X2         X19 = a3 (callee-saved, survives the call)
    int bl=n++;                          // BL origcall (patched) — run the original update body
    // ---- post: original returned; X19 = a3 (output). Overwrite a3+144 on a pending teleport. ----
    int ldr10=n++;                       // LDR X10,[PC,#cmdq] (patched)  X10 = &cmd
    c[n++]=LDR_W(9,10,28); c[n++]=0x11000529u; c[n++]=STR_W(9,10,28); // cmd.tick++ (proves the update ran)
    c[n++]=LDR_W(11,19,144); c[n++]=STR_W(11,10,32);   // cmd.curpos[0] = a3+144 (live player world x)
    c[n++]=LDR_W(11,19,148); c[n++]=STR_W(11,10,36);   // cmd.curpos[1] = y
    c[n++]=LDR_W(11,19,152); c[n++]=STR_W(11,10,40);   // cmd.curpos[2] = z
    c[n++]=LDR_W(9,10,0);                // W9 = tp_pending
    int cbz=n++;                         // CBZ W9, skip (patched)
    // teleport = ONE-FRAME move delta a3+176 = cmd.tp - a3+144(current) -> caller integrates -> instant jump (no fall)
    c[n++]=0xBD40054Cu; c[n++]=0xBD40926Bu; c[n++]=0x1E2B398Bu; c[n++]=0xBD00B26Bu; // x: S12=tp.x; S11=cur.x; FSUB S11,S12,S11; STR S11,[X19,#176]
    c[n++]=0xBD40094Cu; c[n++]=0xBD40966Bu; c[n++]=0x1E2B398Bu; c[n++]=0xBD00B66Bu; // y: -> a3+180
    c[n++]=0xBD400D4Cu; c[n++]=0xBD409A6Bu; c[n++]=0x1E2B398Bu; c[n++]=0xBD00BA6Bu; // z: -> a3+184
    c[n++]=STR_W(31,10,0);               // cmd.tp_pending = 0  (one-shot)
    int skip=n; c[cbz]=CBZ_W(9, skip-cbz);
    // ---- walk: overwrite the OUTPUT per-frame move delta a3+176 (=v127) the caller integrates into the playspace ----
    c[n++]=LDR_W(9,10,16);               // W9 = walk_on
    int cbzw=n++;                        // CBZ W9, skip_walk
    c[n++]=LDR_W(11,10,20); c[n++]=STR_W(11,19,176);   // a3+176 delta.x = walk[0]
    c[n++]=STR_W(31,19,180);                           // a3+180 delta.y = 0
    c[n++]=LDR_W(11,10,24); c[n++]=STR_W(11,19,184);   // a3+184 delta.z = walk[1]
    int skipw=n; c[cbzw]=CBZ_W(9, skipw-cbzw);
    c[n++]=0xF94007FEu;                  // LDR X30,[SP,#8]    restore real LR
    c[n++]=0xF94003F3u;                  // LDR X19,[SP,#0]
    c[n++]=0x910043FFu;                  // ADD SP,SP,#16
    c[n++]=0xD65F03C0u;                  // RET  -> the real caller
    int orig=n; c[bl]=0x94000000u | ((uint32_t)(orig-bl) & 0x3FFFFFFu);   // BL origcall
    memcpy(&c[n], lf, 16); n+=4;         // relocated prologue (4 SP-rel insns — IDA-verified)
    c[n++]=0x58000049u;                  // LDR X9,[PC,#8]
    c[n++]=0xD61F0120u;                  // BR  X9   -> fn+16 (rest of the original; its RET returns to 'post')
    c[n++]=(uint32_t)(cont&0xFFFFFFFFu); c[n++]=(uint32_t)(cont>>32);     // .quad fn+16
    int cmdq=n;
    c[n++]=(uint32_t)((uintptr_t)cmd&0xFFFFFFFFu); c[n++]=(uint32_t)((uintptr_t)cmd>>32); // .quad cmd
    c[ldr10]=LDR_XLIT(10, cmdq-ldr10);
    return install(lf, c, n);
}

// The GAME's own teleport (no fall): nativeTeleportToCoordinates @libshell 0xFBDB54 reads g_ShellApp
// (0x2981030), allocates a 128-byte message {x@0,y@4,z@8, type=35@120}, and posts it to the ShellApp's
// TypedMessageQueue (*(g_ShellApp+16)) with kind=98. Replicated here in pure C from the worker thread.
static void post_teleport(uint8_t* base, float x, float y, float z, float yaw) {
    uintptr_t app = *(volatile uintptr_t*)(base + 0x2A2A030);   // g_ShellApp — v206 (was v205 0x2981030)
    if (!app) return;
    void* queue = *(void**)(app + 16);
    if (!queue) return;
    void* (*op_new)(size_t)            = (void*(*)(size_t))(base + 0x286F4B0);   // operator new — v206 (was v205 0x27D5120)
    void  (*tmq)(void*,int*,void*)     = (void(*)(void*,int*,void*))(base + 0xCC9944); // TypedMessageQueue post — v206 (was 0xEA9DCC)
    uint8_t* msg = (uint8_t*)op_new(128);
    if (!msg) return;
    memset(msg, 0, 128);
    *(float*)(msg+0)=x; *(float*)(msg+4)=y; *(float*)(msg+8)=z; *(float*)(msg+12)=yaw; // x,y,z + facing yaw (4th float)
    *(int*)(msg+120)=35;                                         // message type
    int kind=98;
    tmq(queue, &kind, msg);                                      // ShellApp consumes + frees msg
}

static void* worker(void*) {
    // SAFE DEFAULT: idle until explicitly enabled. Can never boot-loop.
    while (!prop_on("playerctl", false)) usleep(500*1000);
    LOGI("playerctl enabled — locating libshell render code…");
    uint8_t* fn=nullptr;
    for (int i=0;i<3600 && !fn;++i){ fn=find_efa(); if(fn)break; usleep(50*1000); }
    if(!fn){ LOGW("libshell sig not found — abort"); return nullptr; }
    uint8_t* lf = fn - kEfaOff + kLocoOff;
    uint8_t* base = fn - kEfaOff;        // libshell load base (for g_ShellApp + the teleport msg post)
    uint32_t p0 = *(volatile uint32_t*)lf;
    if (p0 == 0x58000050u){
        LOGW("loco @0x%" PRIxPTR " already hooked (far-clip locomotion on?) — abort; set hsr.unlimjump 0 + hsr.fly 0 and reload", (uintptr_t)lf);
        return nullptr;
    }
    if (p0 != kLocoPrologue){   // sanity: confirms the libshell base is right + loco is unhooked
        LOGW("loco prologue mismatch @0x%" PRIxPTR " (got 0x%08x, want 0x%08x) — base wrong, abort", (uintptr_t)lf, p0, kLocoPrologue);
        return nullptr;
    }
    LOGI("fn__EFA9D0@0x%" PRIxPTR " base@0x%" PRIxPTR " loco@0x%" PRIxPTR " prologue=0x%08x OK", (uintptr_t)fn, (uintptr_t)(fn-kEfaOff), (uintptr_t)lf, p0);
    size_t PG=(size_t)sysconf(_SC_PAGESIZE);
    CmdBlock* cmd=(CmdBlock*)mmap(nullptr,PG,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    if (cmd==MAP_FAILED){ LOGW("cmd mmap failed"); return nullptr; }
    memset((void*)cmd,0,sizeof*cmd);
    if (!install_loco(lf,cmd)){ LOGW("install failed"); return nullptr; }
    LOGI("PLAYER-CTL armed: loco@0x%" PRIxPTR " cmd@%p (mmap)", (uintptr_t)lf, (void*)cmd);

    char buf[PROP_VALUE_MAX]; int li=0; float wtgt[3]={0,0,0}; bool wact=false;
    for (;;) {                                          // poll command props ~15 Hz; cmd is a local (no module .data)
        if (++li % 15 == 0) LOGI("tick=%u  player pos=%.2f %.2f %.2f", cmd->tick, cmd->curpos[0], cmd->curpos[1], cmd->curpos[2]);
        buf[0]=0; if (__system_property_get("hsr.tp", buf)>0 && buf[0]) {
            float x,y,z,yaw=0.f; int got=sscanf(buf,"%f %f %f %f",&x,&y,&z,&yaw);
            if (got>=3){
                post_teleport(base, x, y, z, yaw);             // game's own teleport message (no fall); optional 4th = yaw
                __system_property_set("hsr.tp","");
                LOGI("teleport -> %.2f %.2f %.2f yaw %.2f (ShellApp msg)", x,y,z,yaw);
            }
        }
        buf[0]=0; if (__system_property_get("hsr.rot", buf)>0 && buf[0]) {   // rotate in place = teleport to curpos + yaw
            float yaw;
            if (cmd->tick==0) { LOGW("rotate ignored — env not rendering (curpos stale)"); }   // guard: don't tp to a stale pos
            else if (sscanf(buf,"%f",&yaw)==1){
                post_teleport(base, cmd->curpos[0], cmd->curpos[1], cmd->curpos[2], yaw);
                __system_property_set("hsr.rot","");
                LOGI("rotate -> yaw %.2f at %.2f %.2f %.2f", yaw, cmd->curpos[0],cmd->curpos[1],cmd->curpos[2]);
            }
        }
        buf[0]=0; if (__system_property_get("hsr.walk", buf)>0) {
            if (!buf[0]) cmd->walk_on=0;
            else { float a,b; if (sscanf(buf,"%f %f",&a,&b)==2){ cmd->walk[0]=a; cmd->walk[1]=b; cmd->walk_on=(a||b)?1:0; } }
        }
        // walk = accumulate a virtual target from the START pos + delta (NOT the live curpos, which jitters
        // with physical movement/falls) and teleport to it ~2.5Hz (throttled; 15Hz floods the queue -> crash).
        if (cmd->walk_on && cmd->tick>0) {   // tick>0 = env rendering = curpos valid (don't seed/step from a stale pos)
            if (!wact){ wtgt[0]=cmd->curpos[0]; wtgt[1]=cmd->curpos[1]; wtgt[2]=cmd->curpos[2]; wact=true; }
            if ((li % 6)==0){ wtgt[0]+=cmd->walk[0]; wtgt[2]+=cmd->walk[1]; post_teleport(base, wtgt[0], wtgt[1], wtgt[2], 0.f); }
        } else wact=false;
        usleep(66*1000);
    }
    return nullptr;
}

class PlayerCtlModule : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api* api, JNIEnv* env) override { api_=api; env_=env; }
    void preAppSpecialize(zygisk::AppSpecializeArgs* args) override {
        const char* nice = env_->GetStringUTFChars(args->nice_name, nullptr);
        target_ = nice && !strcmp(nice, "com.oculus.vrshell");
        if (nice) env_->ReleaseStringUTFChars(args->nice_name, nice);
        if (!target_) api_->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }
    void postAppSpecialize(const zygisk::AppSpecializeArgs*) override {
        if (!target_) return;
        pthread_t t; pthread_create(&t, nullptr, worker, nullptr); pthread_detach(t);
    }
private:
    zygisk::Api* api_=nullptr; JNIEnv* env_=nullptr; bool target_=false;
};
REGISTER_ZYGISK_MODULE(PlayerCtlModule)

#ifdef AIO_MERGE_BUILD
// MERGED build: player-ctl had NO companion ctor (zygisk-only), so as a DT_NEEDED
// it never armed. The orchestrator now calls this so walk/rotate/pos come along in
// the ALL-IN-ONE .so. Gated to the vrshell host process.
extern "C" void* player_worker_entry(void*) {
    char cl[256] = {0};
    if (FILE* f = fopen("/proc/self/cmdline", "re")) { size_t n = fread(cl, 1, sizeof cl - 1, f); fclose(f); (void)n; }
    if (!strstr(cl, "com.oculus.vrshell")) { LOGW("player_worker_entry: not vrshell — skipping"); return nullptr; }
    LOGI("player-ctl worker entry (merged) — installing walk/rotate/pos");
    return worker(nullptr);
}
#endif
