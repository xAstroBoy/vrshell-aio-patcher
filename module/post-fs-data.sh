#!/system/bin/sh
# VrShell hotswap — bind the patched VrShell.apk over the system shell at boot.
# ⛔ REBOOT STALE-INODE FIX: the module dir lives on magisk overlayfs; reading VrShell.apk from there
#    at boot returns a STALE cached inode (an OLD build) -> wrong shell mounted -> "moonjump/bridge gone".
#    The deploy writes the patched apk to a PLAIN ext4 path (/data/adb/vrshell_patched.apk); we bind THAT
#    directly here (no copy from the overlay), so the freshest bytes are always mounted.
STABLE=/data/adb/vrshell_patched.apk
TGT=/system_ext/priv-app/VrShell/VrShell.apk
SZ=$(stat -c%s "$STABLE" 2>/dev/null || echo 0)
if [ -f "$STABLE" ] && [ "$SZ" -gt 1000000 ]; then
  chcon u:object_r:system_file:s0 "$STABLE" 2>/dev/null
  chmod 644 "$STABLE"
  nsenter --mount=/proc/1/ns/mnt -- umount "$TGT" 2>/dev/null
  nsenter --mount=/proc/1/ns/mnt -- mount -o bind "$STABLE" "$TGT" \
    && log -t vrshell_hotswap "mounted patched vrshell from $STABLE ($SZ bytes)"
fi
