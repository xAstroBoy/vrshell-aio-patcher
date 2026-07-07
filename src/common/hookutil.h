// ============================================================================
//  hookutil.h — SHARED helper API for every vrshell_patches feature.
//  ONE copy of the pattern-scan / ADRP-resolve / trampoline-install / prop /
//  status-report machinery (was copy-pasted across aio/rendertrace/player).
//  Every feature #includes this, declares its OWN LOG_TAG, and reports OK/FAIL
//  through feat_report() so the orchestrator prints exactly what failed and
//  the MCP/dumper can serve the live status ("where do we need to intervene").
// ============================================================================
#pragma once
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <sys/system_properties.h>
#include <android/log.h>

// ── per-feature logging: each .cpp does `#define LOG_TAG "AIO-FarClip"` before
//    including this, so every feature's lines are grep-able by their own tag. ──
#ifndef LOG_TAG
#define LOG_TAG "AIO"
#endif
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

namespace hu {

// ── FEATURE STATUS REGISTRY — the "report when something failed" spine ────────
// Every feature install returns bool and calls feat_report(name, ok, detail).
// The orchestrator logs one line per feature; get_status_json() feeds the MCP so
// Claude can read, at runtime, WHICH hook armed and which needs intervention.
struct FeatStatus { const char* name; bool armed; char detail[96]; };
inline FeatStatus g_feat[32]; inline int g_nfeat = 0;
inline int get_status_json(char* out, int cap);   // fwd
// Flood-proof status: mirror the WHOLE registry to /data/local/tmp/aio_status.json on
// every update. `debug.logLevel Verbose` floods logcat and rolls our one-shot lines off,
// so this file is the reliable "where do we need to intervene" source (adb pull / cat it,
// or the MCP reads it). Rewritten atomically-ish each report.
inline void feat_dump_file() {
    char js[4096]; int n = get_status_json(js, sizeof js);
    if (n < 0) n = 0; if (n > (int)sizeof js) n = (int)sizeof js;
    FILE* f = fopen("/data/local/tmp/aio_status.json", "we");
    if (f) { fwrite(js, 1, (size_t)n, f); fclose(f); }
}
inline bool feat_report(const char* name, bool ok, const char* detail = "") {
    for (int i = 0; i < g_nfeat; i++) if (!strcmp(g_feat[i].name, name)) { g_feat[i].armed = ok; snprintf(g_feat[i].detail, sizeof g_feat[i].detail, "%s", detail); goto log; }
    if (g_nfeat < 32) { g_feat[g_nfeat].name = name; g_feat[g_nfeat].armed = ok; snprintf(g_feat[g_nfeat].detail, sizeof g_feat[g_nfeat].detail, "%s", detail); g_nfeat++; }
log:
    __android_log_print(ok ? ANDROID_LOG_INFO : ANDROID_LOG_ERROR, "AIO-Status",
                        "%-14s %s %s", name, ok ? "ARMED  ✓" : "FAILED ✗", detail);
    feat_dump_file();
    return ok;
}
inline int get_status_json(char* out, int cap) {   // for the MCP `status` command
    // CRASH-SAFE: snprintf() returns the WOULD-BE length, so `n` can run past `cap` when the
    // buffer fills. Passing the resulting negative (cap - n) to the next snprintf underflows to
    // a huge size_t and trips bionic's FORTIFY vsnprintf guard -> SIGABRT (this is exactly what
    // crash-looped vrshell). Clamp `n` into [0, cap-1] after every write so the remaining size
    // handed to snprintf is always >= 1. Never underflows regardless of feature count/detail len.
    if (!out || cap <= 0) return 0;
    int n = snprintf(out, (size_t)cap, "{\"features\":[");
    if (n < 0) { out[0] = 0; return 0; }
    if (n >= cap) n = cap - 1;
    for (int i = 0; i < g_nfeat && n < cap - 1; i++) {
        int w = snprintf(out + n, (size_t)(cap - n),
                         "%s{\"name\":\"%s\",\"armed\":%s,\"detail\":\"%s\"}",
                         i ? "," : "", g_feat[i].name, g_feat[i].armed ? "true" : "false", g_feat[i].detail);
        if (w < 0) break;
        n += w; if (n >= cap) { n = cap - 1; break; }
    }
    if (n < cap - 1) {
        int w = snprintf(out + n, (size_t)(cap - n), "]}\n");
        if (w > 0) { n += w; if (n >= cap) n = cap - 1; }
    }
    return n;
}

// ── props: hsr.<name> / persist.hsr.<name> ───────────────────────────────────
inline bool prop_on(const char* name, bool dflt) {
    char b[PROP_VALUE_MAX] = {0}, k[96]; snprintf(k, sizeof k, "hsr.%s", name);
    if (__system_property_get(k, b) <= 0) { snprintf(k, sizeof k, "persist.hsr.%s", name); __system_property_get(k, b); }
    if (!b[0]) return dflt; char c = b[0]; return c=='1'||c=='t'||c=='T'||c=='y'||c=='Y';
}
inline float prop_f(const char* name, float dflt, float lo, float hi) {
    char b[PROP_VALUE_MAX] = {0}, k[96]; snprintf(k, sizeof k, "hsr.%s", name);
    if (__system_property_get(k, b) <= 0) { snprintf(k, sizeof k, "persist.hsr.%s", name); __system_property_get(k, b); }
    if (!b[0]) return dflt; float v = strtof(b, nullptr); return (v > lo && v < hi) ? v : dflt;
}

// ── raw patch writes (page-unprotect + write) ────────────────────────────────
inline void wr32(uint8_t* p, uint32_t v) { size_t PG=(size_t)sysconf(_SC_PAGESIZE); uintptr_t pg=(uintptr_t)p & ~(uintptr_t)(PG-1); if (mprotect((void*)pg,PG,PROT_READ|PROT_WRITE)==0) *(volatile uint32_t*)p=v; }
inline void wr8 (uint8_t* p, uint8_t  v) { size_t PG=(size_t)sysconf(_SC_PAGESIZE); uintptr_t pg=(uintptr_t)p & ~(uintptr_t)(PG-1); if (mprotect((void*)pg,PG,PROT_READ|PROT_WRITE)==0) *(volatile uint8_t*)p=v; }

// ── ARM64 decode: resolve a PC-relative global from ADRP(+ADD/LDR) ───────────
inline uint64_t adrp_page(uint8_t* pc){ uint32_t w=*(uint32_t*)pc; int64_t immlo=(w>>29)&3, immhi=(w>>5)&0x7FFFF, imm=(immhi<<2)|immlo; if(imm&(1LL<<20)) imm-=(1LL<<21); return ((uint64_t)pc & ~0xFFFULL)+((uint64_t)imm<<12); }
inline uint8_t* resolve_adrp_global(uint8_t* pc){ uint64_t page=adrp_page(pc); uint32_t nx=*(uint32_t*)(pc+4), off; if((nx&0x7F800000u)==0x11000000u||(nx&0x7F800000u)==0x91000000u) off=(nx>>10)&0xFFF; else { uint32_t im=(nx>>10)&0xFFF, sz=(nx>>30)&3; off=im<<sz; } return (uint8_t*)(page+off); }

// ── pattern scan over libshell exec segments ─────────────────────────────────
typedef uint8_t* (*scan_cb)(uint8_t* lo, uint8_t* hi);
inline uint8_t* for_each_exec_seg(scan_cb cb){ FILE* f=fopen("/proc/self/maps","re"); if(!f) return nullptr; char ln[1024]; uint8_t* hit=nullptr;
    while(fgets(ln,sizeof ln,f)&&!hit){ if(!strstr(ln,"VrShell.apk")&&!strstr(ln,"libshell")) continue; uintptr_t lo=0,hi=0; char pm[8]={0};
        if(sscanf(ln,"%" SCNxPTR "-%" SCNxPTR " %7s",&lo,&hi,pm)!=3||hi<=lo||pm[2]!='x') continue; mprotect((void*)lo,(size_t)(hi-lo),PROT_READ|PROT_EXEC); hit=cb((uint8_t*)lo,(uint8_t*)hi);} fclose(f); return hit; }
inline uintptr_t g_libLo=0, g_libHi=0;
inline void capture_lib_range(){ FILE* f=fopen("/proc/self/maps","re"); if(!f) return; char ln[1024]; uintptr_t lo=(uintptr_t)-1,hi=0;
    while(fgets(ln,sizeof ln,f)){ if(!strstr(ln,"VrShell.apk")&&!strstr(ln,"libshell")) continue; uintptr_t a=0,b=0; if(sscanf(ln,"%" SCNxPTR "-%" SCNxPTR,&a,&b)!=2||b<=a) continue; if(a<lo)lo=a; if(b>hi)hi=b; } fclose(f); if(hi>lo){g_libLo=lo;g_libHi=hi;} }
inline int parse_sig(const char* s,uint8_t* by,uint8_t* mk,int cap){ int n=0; auto hex=[](char c)->int{return (c>='0'&&c<='9')?c-'0':((c|0x20)>='a'&&(c|0x20)<='f')?(c|0x20)-'a'+10:-1;};
    for(const char* p=s;*p&&n<cap;){ while(*p==' ')++p; if(!*p)break; if(p[0]=='?'){by[n]=0;mk[n]=0;++n;p+=(p[1]=='?')?2:1;} else{int h=hex(p[0]),l=hex(p[1]); if(h<0||l<0)break; by[n]=(uint8_t)((h<<4)|l);mk[n]=0xFF;++n;p+=2;} } return n; }
inline uint8_t* scan_seg(uint8_t* lo,uint8_t* hi,const uint8_t* b,const uint8_t* m,int n){ if(n<=0)return nullptr; uint8_t* end=hi-n; for(uint8_t* p=lo;p<=end;++p){int i=0;for(;i<n;++i)if(m[i]&&p[i]!=b[i])break; if(i==n)return p;} return nullptr; }
inline const uint8_t* g_b; inline const uint8_t* g_m; inline int g_n;
inline uint8_t* cb_generic(uint8_t* lo,uint8_t* hi){ return scan_seg(lo,hi,g_b,g_m,g_n); }
inline uint8_t* find_sig(const char* sig){ static uint8_t b[128],m[128]; int n=parse_sig(sig,b,m,sizeof b); g_b=b;g_m=m;g_n=n; return for_each_exec_seg(cb_generic); }

// ── trampoline install (overwrite fn[0..15] with abs jump to mmap'd code) ─────
inline bool install_hook(uint8_t* fn,const uint32_t* code,int words){ size_t PG=(size_t)sysconf(_SC_PAGESIZE); void* tr=mmap(nullptr,PG,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0); if(tr==MAP_FAILED)return false;
    memcpy(tr,code,(size_t)words*4); mprotect(tr,PG,PROT_READ|PROT_EXEC); __builtin___clear_cache((char*)tr,(char*)tr+(size_t)words*4); uintptr_t t=(uintptr_t)tr;
    uint32_t jmp[4]={0x58000050u,0xD61F0200u,(uint32_t)(t&0xFFFFFFFFu),(uint32_t)((uint64_t)t>>32)}; uintptr_t a=(uintptr_t)fn & ~(uintptr_t)(PG-1), b=((uintptr_t)fn+16+PG-1)&~(uintptr_t)(PG-1);
    if(mprotect((void*)a,b-a,PROT_READ|PROT_WRITE|PROT_EXEC)!=0)return false; memcpy(fn,jmp,16); mprotect((void*)a,b-a,PROT_READ|PROT_EXEC); __builtin___clear_cache((char*)fn,(char*)fn+16); return true; }

// arm64 encoders for detours
inline uint32_t LDR_W (int rt,int rn,int off){ return 0xB9400000u|((uint32_t)(off>>2)<<10)|((uint32_t)rn<<5)|(uint32_t)rt; }
inline uint32_t STR_W (int rt,int rn,int off){ return 0xB9000000u|((uint32_t)(off>>2)<<10)|((uint32_t)rn<<5)|(uint32_t)rt; }
inline uint32_t CBZ_W (int rt,int n){         return 0x34000000u|(((uint32_t)n&0x7FFFF)<<5)|(uint32_t)rt; }
inline uint32_t LDR_XLIT(int rt,int n){       return 0x58000000u|(((uint32_t)n&0x7FFFF)<<5)|(uint32_t)rt; }

} // namespace hu
