"""Re-wraps the packed streams of a RAR 1.5 archive (same compression as RAR 1.3) into the old RAR 1.3/1.4
'RE~^' container, computing the 1.4 checksum from the 7-Zip-extracted originals."""
import struct, sys, os, subprocess, shutil
def ck14(b):
    c = 0
    for x in b:
        c = (c + x) & 0xFFFF; c = ((c << 1) | (c >> 15)) & 0xFFFF
    return c
src, dst = sys.argv[1], sys.argv[2]
d = open(src, 'rb').read()
assert d[:7] == b'Rar!\x1a\x07\x00'
ext = dst + '.x15'; shutil.rmtree(ext, ignore_errors=True)
subprocess.run(['/opt/tools/bin/7zz', 'x', '-y', '-o' + ext, src], stdout=subprocess.DEVNULL)
p = 7; solid = False; files = []
while p + 7 <= len(d):
    crc, typ, fl, hs = struct.unpack('<HBHH', d[p:p + 7])
    if typ == 0x73: solid = bool(fl & 0x08); p += hs; continue
    if typ == 0x74:
        pack, unp, host, fcrc, ftime, ver, meth, nsz, attr = struct.unpack('<IIBIIBBHI', d[p + 7:p + 32])
        name = d[p + 32:p + 32 + nsz].decode('latin1')
        data = d[p + hs:p + hs + pack]
        files.append((name, unp, ftime, attr, meth, data, ver)); p += hs + pack; continue
    add = struct.unpack('<I', d[p + 7:p + 11])[0] if fl & 0x8000 else 0
    p += hs + add
out = bytearray(b'RE~^' + struct.pack('<HB', 7, 0x08 if solid else 0))
for name, unp, ftime, attr, meth, data, ver in files:
    orig = open(os.path.join(ext, name.replace('\\', '/')), 'rb').read() if not attr & 0x10 else b''
    assert len(orig) == unp, (name, len(orig), unp)
    nb = name.encode('latin1')
    out += struct.pack('<IIHHIBBBBB', len(data), unp, ck14(orig), 21 + len(nb), ftime, attr & 0xFF, 0, 2, len(nb), 0 if meth == 0x30 else meth - 0x30) + nb + data
    print(name, unp, 'method', meth - 0x30, 'ver', ver, 'ck14 %04x' % ck14(orig))
open(dst, 'wb').write(out); shutil.rmtree(ext, ignore_errors=True)
print('solid' if solid else 'not solid', len(files), 'files ->', dst)
