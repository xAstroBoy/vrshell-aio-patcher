#!/system/bin/sh
# LAUNCH-FIRST swap (the working way): do NOT mount the patched apk at boot.
# 1. Let STOCK VrShell boot -> PMS scans the platform-signed stock apk, records the PLATFORM
#    signature and GRANTS horizonos.permission.READ_SETTINGS/WRITE_SETTINGS (signature|knownSigner).
# 2. AFTER boot, bind the patched apk over the system path and restart VrShell. A runtime bind +
#    process restart does NOT trigger a PMS re-scan, so PMS keeps the platform sig + granted perms.
#    The relaunched process loads the patched bytes (libquestctl_aio DT_NEEDED = moonjump/far-clip)
#    and runs WITH those perms -> NO SecurityException crash.
#    (Mounting the patched apk AT boot made PMS scan the debug-signed apk -> perm denied -> crash.)
STABLE=/data/adb/vrshell_patched.apk
TGT=/system_ext/priv-app/VrShell/VrShell.apk
SZ=$(stat -c%s "$STABLE" 2>/dev/null || echo 0)
[ "$SZ" -gt 1000000 ] || exit 0
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
# let PMS finish + stock VrShell come up fully (platform sig recorded, perms granted)
sleep 25
chcon u:object_r:system_file:s0 "$STABLE" 2>/dev/null; chmod 644 "$STABLE"
nsenter --mount=/proc/1/ns/mnt -- umount "$TGT" 2>/dev/null
nsenter --mount=/proc/1/ns/mnt -- mount -o bind "$STABLE" "$TGT" \
  && log -t vrshell_hotswap "launch-first: patched apk bound over stock ($SZ) — restarting VrShell (PMS keeps platform sig)"
# restart so the live shell loads the patched bytes; PMS perms already granted from the stock scan
am force-stop com.oculus.vrshell 2>/dev/null
# confirm patch armed; if the shell re-forked before Zygisk-independent DT_NEEDED load, one more kick
( sleep 20
  if ! logcat -d -s QuestCtlAIO AIO-Core 2>/dev/null | grep -q "FAR-CLIP killed\|LOCOMOTION\|ALL-IN-ONE ctor"; then
    log -t vrshell_hotswap "launch-first: patch not seen yet, one more restart"
    am force-stop com.oculus.vrshell 2>/dev/null
  fi ) &
