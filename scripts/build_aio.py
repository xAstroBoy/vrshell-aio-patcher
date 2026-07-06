#!/usr/bin/env python3
# Build an ALL-IN-ONE patched VrShell.apk: bake EXTRA native .so's as DT_NEEDED of libshell.so
# (so libshell's own linker loads them into the vrshell process = full in-process control, more than
# Zygisk injection). Keeps whatever DT_NEEDED the base already has (e.g. libquestctl_aio.so = moonjump/
# far-clip/teleport AIO) and ADDS the ones you pass (e.g. librendertrace.so = the on-device dumper).
#
#   python build_aio.py <base_vrshell.apk> <out_unsigned.apk> <extra1.so> [extra2.so ...]
#
# The extra .so's are copied into lib/arm64-v8a/ and appended to libshell's DT_NEEDED. Old META-INF
# signature is dropped (re-sign after with apksigner). Native .so entries are STORED (uncompressed) so
# zipalign -p can page-align them for mmap. Then: zipalign -p -f 4 in out ; apksigner sign ...
import lief, zipfile, sys, os

def main():
    if len(sys.argv) < 4:
        print("usage: build_aio.py <base.apk> <out.apk> <extra1.so> [extra2.so ...]"); sys.exit(2)
    base, out = sys.argv[1], sys.argv[2]
    extras = sys.argv[3:]
    z = zipfile.ZipFile(base)
    libshell = z.read('lib/arm64-v8a/libshell.so')
    b = lief.parse(list(libshell))
    have = [e.name for e in b.dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.NEEDED]
    print("base libshell DT_NEEDED (non-std):",
          [n for n in have if not n.startswith(('libc','libm','libdl','liblog','libz','libandroid','libvulkan','libGL','libEGL','libOpenSL','libnative'))])
    add = []
    for so in extras:
        name = os.path.basename(so)
        if name not in have:
            b.add_library(name); add.append(name)
    print("added DT_NEEDED:", add)
    patched_path = out + ".libshell.tmp"
    b.write(patched_path)
    patched = open(patched_path, 'rb').read(); os.remove(patched_path)

    zo = zipfile.ZipFile(out, 'w')
    for it in z.infolist():
        fn = it.filename
        if fn == 'lib/arm64-v8a/libshell.so': continue
        if fn.startswith('META-INF/') and fn.rsplit('.', 1)[-1].upper() in ('RSA','SF','MF','DSA','EC'): continue
        data = z.read(fn)
        ct = zipfile.ZIP_STORED if fn.endswith('.so') else it.compress_type
        ni = zipfile.ZipInfo(fn, date_time=it.date_time); ni.compress_type = ct; ni.external_attr = it.external_attr
        zo.writestr(ni, data)
    entries = [('lib/arm64-v8a/libshell.so', patched)]
    for so in extras:
        entries.append(('lib/arm64-v8a/' + os.path.basename(so), open(so, 'rb').read()))
    for fn, data in entries:
        ni = zipfile.ZipInfo(fn); ni.compress_type = zipfile.ZIP_STORED; zo.writestr(ni, data)
    zo.close()

    # verify
    b2 = lief.parse(list(zipfile.ZipFile(out).read('lib/arm64-v8a/libshell.so')))
    n2 = [e.name for e in b2.dynamic_entries if e.tag == lief.ELF.DynamicEntry.TAG.NEEDED]
    for so in extras:
        assert os.path.basename(so) in n2, "FAILED to add " + so
    print("OK ->", out, "| DT_NEEDED now includes:", [os.path.basename(s) for s in extras])

if __name__ == '__main__':
    main()
