#!/usr/bin/env python3
# Replace ONE native lib inside an APK (STORED, no other entry touched), drop the old
# signature. Used to swap the merged libquestctl_aio.so into the moonjump VrShell.apk
# WITHOUT re-writing libshell (its DT_NEEDED already points at libquestctl_aio.so).
#   replace_lib.py <in.apk> <out.apk> <lib_arch_path> <new_so>
import sys, zipfile, shutil, os
in_apk, out_apk, arch_path, new_so = sys.argv[1:5]
with open(new_so, "rb") as f: new_bytes = f.read()
src = zipfile.ZipFile(in_apk, "r")
if os.path.exists(out_apk): os.remove(out_apk)
dst = zipfile.ZipFile(out_apk, "w")
replaced = False
for it in src.infolist():
    name = it.filename
    if name.startswith("META-INF/") and name.split("/")[-1].split(".")[-1] in ("RSA","SF","MF","EC","DSA"):
        continue  # drop old signature
    data = new_bytes if name == arch_path else src.read(name)
    if name == arch_path: replaced = True
    # keep .so STORED (uncompressed) so the linker can mmap it directly; others as-is
    zi = zipfile.ZipInfo(name, date_time=it.date_time)
    zi.external_attr = it.external_attr
    zi.compress_type = zipfile.ZIP_STORED if (name.endswith(".so") or it.compress_type == zipfile.ZIP_STORED) else zipfile.ZIP_DEFLATED
    dst.writestr(zi, data)
src.close(); dst.close()
if not replaced:
    print("ERROR: entry not found in apk:", arch_path); sys.exit(1)
print("replaced", arch_path, "->", len(new_bytes), "bytes STORED; old sig dropped")
