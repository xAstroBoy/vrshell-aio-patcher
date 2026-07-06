#!/system/bin/sh
# LAUNCH-FIRST swap: let STOCK VrShell boot (PMS records the platform sig + grants perms), THEN bind
# the patched apk over the system path and restart VrShell. A runtime bind + restart does NOT trigger
# a PMS re-scan, so PMS keeps the platform sig -> the patched bytes (libquestctl_aio DT_NEEDED = moonjump/
# far-clip/ungater) run WITH those perms, no SecurityException.
STABLE=/data/adb/vrshell_patched.apk
TGT=/system_ext/priv-app/VrShell/VrShell.apk
STATUS=/data/local/tmp/aio_status.json
SZ=$(stat -c%s "$STABLE" 2>/dev/null || echo 0)
[ "$SZ" -gt 1000000 ] || exit 0
until [ "$(getprop sys.boot_completed)" = "1" ]; do sleep 2; done
sleep 25
chcon u:object_r:system_file:s0 "$STABLE" 2>/dev/null; chmod 644 "$STABLE"
nsenter --mount=/proc/1/ns/mnt -- umount "$TGT" 2>/dev/null
nsenter --mount=/proc/1/ns/mnt -- mount -o bind "$STABLE" "$TGT" \
  && log -t vrshell_hotswap "patched apk bound over stock ($SZ) — will restart+confirm the ungater"

# CONFIRM the ungater actually armed, and retry until it does. CRITICAL: during the early-boot window
# (~first few minutes) a VrShell restart does NOT load the DT_NEEDED libquestctl_aio (the AIO status
# file never appears); a restart AFTER the window arms first-try. So we (a) clear the STALE status file
# (it persists in /data/local/tmp across reboots), then (b) restart + poll the PERSISTENT status file
# (logcat rolls during boot and is useless here), retrying patiently until aio_status.json reports the
# ungater armed. Self-terminating once confirmed.
armed() { grep -q '"name":"ungater","armed":true' "$STATUS" 2>/dev/null; }
rm -f "$STATUS" 2>/dev/null
am force-stop com.oculus.vrshell 2>/dev/null
( n=0
  while [ $n -lt 24 ]; do
    sleep 22
    if armed; then log -t vrshell_hotswap "ungater CONFIRMED (status file) after $n retries"; exit 0; fi
    n=$((n+1))
    log -t vrshell_hotswap "ungater not armed yet (try $n/24) — restarting VrShell"
    rm -f "$STATUS" 2>/dev/null
    am force-stop com.oculus.vrshell 2>/dev/null
  done
  log -t vrshell_hotswap "ungater NOT confirmed after $n retries (shell runs patched; menus may be gated)"
) &
