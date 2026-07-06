#!/system/bin/sh
# vrshell_patches ALL-IN-ONE — boot service: kill the menu-pop annoyance + arm every feature.
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
sleep 5
# MENU/IDLE FIX: prox off => headset ALWAYS "worn" => universal menu/dock stops auto-popping over the env
# (and no idle-sleep). Toggle live: `questctl awake|sleep`.
setprop persist.device_config.mros_vendor.hmd_disable_prox_sensor true
am broadcast -a com.oculus.vrpowermanager.prox_close >/dev/null 2>&1
# ── OS-level DEBUG UNLOCK — ALWAYS ON, no gate. libshell reads these Android debug
#    system-props at startup and unhides its verbose/debug paths (asset/shader/scene
#    detail). This is the OS layer of the "hidden gated debug features".
setprop debug.oculus.shell.logLevel Verbose
setprop debug.logLevel Verbose
setprop debug.oculus.shell.enableDebugMenu 1
# ── in-.so features (the ONE libquestctl_aio.so orchestrator reads these). Debug
#    features are UNGATED in code (always installed); these props only tune values.
setprop hsr.rendertrace 1     # on-device dumper (HSR-RT logcat: per-renderable center/ext/verdict)
setprop hsr.rt_cull 1
setprop persist.hsr.farclip_on 1; setprop persist.hsr.farclip 1000000   # far-clip
setprop hsr.crashproof 1       # bad-mesh throw wrapper
setprop hsr.moonjump 1         # hold-JUMP = fly
# debug-UI + verbose are FORCED ON in code (no prop gate). jumpprobe stays off (log flood).
log -t vrshell_patches "boot: prox off (no menu-pop) + OS debug verbose + all features armed"
