#!/usr/bin/env bash
# ALL-IN-ONE VrShell build + deploy: bake librendertrace.so (on-device dumper) alongside libquestctl_aio.so
# (moonjump/far-clip/teleport AIO) as DT_NEEDED of libshell, then hot-swap it in via the vrshell_hotswap
# Magisk overlay (magic-mount, no reboot) and restart vrshell. Both patches live in ONE patched vrshell =
# more control than Zygisk injection (the user's requirement). See README.md.
#
#   ./build_and_deploy.sh            # pulls the CURRENT (moonjump) vrshell as the base, adds the dumper
#   BASE=/path/base.apk ./build_and_deploy.sh   # use a specific base apk
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"; cd "$HERE"
BT="${BUILD_TOOLS:-/c/Android/build-tools/34.0.0}"
KS="$HERE/inputs/debug.keystore"; KP="android"
RT_SO="$HERE/inputs/librendertrace.so"
WORK="$HERE/work"; mkdir -p "$WORK"

# 1. BASE = the moonjump vrshell currently mounted by vrshell_hotswap (has libquestctl_aio DT_NEEDED)
BASE="${BASE:-}"
if [ -z "$BASE" ]; then
  echo ">> pulling current vrshell (moonjump base) from device..."
  adb shell 'su -c "cp /data/adb/modules/vrshell_hotswap/VrShell.apk /sdcard/_aio_base.apk"'
  adb pull /sdcard/_aio_base.apk "$WORK/base.apk"   # (run from PowerShell if MSYS mangles /sdcard)
  BASE="$WORK/base.apk"
fi

# 2. BAKE: add librendertrace.so DT_NEEDED (keeps libquestctl_aio). Add more .so's as extra args here.
python build_aio.py "$BASE" "$WORK/aio_unsigned.apk" "$RT_SO"

# 3. ALIGN + SIGN
"$BT/zipalign.exe" -p -f 4 "$WORK/aio_unsigned.apk" "$WORK/aio_aligned.apk"
"$BT/apksigner.bat" sign --ks "$KS" --ks-pass "pass:$KP" --key-pass "pass:$KP" \
  --out "$HERE/VrShell_aio.apk" "$WORK/aio_aligned.apk"
echo ">> built: $HERE/VrShell_aio.apk"

# 4. DEPLOY via the hotswap overlay (magic-mount, no reboot). ⚠ run the adb push from PowerShell if
#    Git-bash MSYS mangles /sdcard (see README). Copy MUST fully complete before mount (verify size!).
adb push "$HERE/VrShell_aio.apk" /sdcard/aio.apk
SZ=$(stat -c%s "$HERE/VrShell_aio.apk")
adb shell "su -c '
  nsenter --mount=/proc/1/ns/mnt -- umount /system_ext/priv-app/VrShell/VrShell.apk 2>/dev/null
  cp -f /sdcard/aio.apk /data/adb/modules/vrshell_hotswap/VrShell.apk; sync
  [ \"\$(stat -c%s /data/adb/modules/vrshell_hotswap/VrShell.apk)\" = \"$SZ\" ] || { echo COPY-TRUNCATED; exit 1; }
  chcon u:object_r:system_file:s0 /data/adb/modules/vrshell_hotswap/VrShell.apk
  chmod 644 /data/adb/modules/vrshell_hotswap/VrShell.apk
  nsenter --mount=/proc/1/ns/mnt -- mount -o bind /data/adb/modules/vrshell_hotswap/VrShell.apk /system_ext/priv-app/VrShell/VrShell.apk
  setprop hsr.rendertrace 1; setprop hsr.rt_cull 1
  killall com.oculus.vrshell 2>/dev/null
'"
echo ">> deployed + restarted. Verify: adb logcat -s HSR-RT  (dumper) ; test moonjump hold-to-fly (aio)."
