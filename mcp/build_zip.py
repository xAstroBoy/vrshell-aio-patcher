import zipfile, os
src = r"d:\Quest Stuff\Restore Old Envs\_zygisk_rendertrace"
out = r"C:\hsr_rendertrace.zip"

update_binary = (
    "#!/sbin/sh\n"
    "umask 022\n"
    "ui_print() { echo \"$1\"; }\n"
    "require_new_magisk() { ui_print \"! Please install Magisk v20.4+\"; exit 1; }\n"
    "OUTFD=$2\n"
    "ZIPFILE=$3\n"
    "mount /data 2>/dev/null\n"
    "[ -f /data/adb/magisk/util_functions.sh ] || require_new_magisk\n"
    ". /data/adb/magisk/util_functions.sh\n"
    "[ $MAGISK_VER_CODE -lt 20400 ] && require_new_magisk\n"
    "install_module\n"
    "exit 0\n"
)

z = zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED)
z.write(os.path.join(src, "module.prop"), "module.prop")
z.write(os.path.join(src, "service.sh"), "service.sh")
z.write(os.path.join(src, "libs", "arm64-v8a",  "librendertrace.so"), "zygisk/arm64-v8a.so")
z.write(os.path.join(src, "libs", "armeabi-v7a", "librendertrace.so"), "zygisk/armeabi-v7a.so")
z.writestr("META-INF/com/google/android/update-binary", update_binary)
z.writestr("META-INF/com/google/android/updater-script", "#MAGISK\n")
z.close()

zz = zipfile.ZipFile(out)
print("ENTRIES (forward slashes required):")
for n in zz.namelist():
    print("  ", n)
print("OK ->", out)
