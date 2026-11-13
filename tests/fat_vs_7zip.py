#!/usr/bin/env python3
"""Converts PCjs JSON disk images to raw IMG files and compares Symbol Hunter's FAT reader with 7-Zip's."""
import json, struct, os, sys, glob, subprocess, zlib, re

SRC = '/opt/tools/src/pcjs-disks'
OUT = '/opt/work/realdisks'
DEV = '/home/claude/symhunt/build/dev.sh'
os.makedirs(OUT, exist_ok=True)

def convert(jpath, opath):
    d = json.load(open(jpath))
    if isinstance(d, dict): d = d.get('diskData') or d.get('imageData') or d.get('data')
    if not isinstance(d, list): return False
    out = bytearray()
    for cyl in d:
        for head in cyl:
            for sec in sorted(head, key=lambda s: s.get('sector', s.get('s', 0))):
                size = sec.get('length', sec.get('l', 512))
                vals = sec.get('data', sec.get('d', []))
                b = b''.join(struct.pack('<i', v) for v in vals)
                if len(b) < size:
                    pat = b[-4:] if len(b) >= 4 else b'\0\0\0\0'
                    b += pat * ((size - len(b)) // 4 + 1)
                out += b[:size]
    open(opath, 'wb').write(out)
    return True

def sevenzip_list(img):
    r = subprocess.run(['/opt/tools/bin/7zz', 'x', '-y', '-so', img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    tmp = img + '.7z.d'
    subprocess.run(['rm', '-rf', tmp]); os.makedirs(tmp)
    subprocess.run(['/opt/tools/bin/7zz', 'x', '-y', '-o' + tmp, img], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {}
    for root, _, files in os.walk(tmp):
        for f in files:
            p = os.path.join(root, f)
            rel = os.path.relpath(p, tmp).replace(os.sep, '/')
            res[rel.upper()] = '%08x' % (zlib.crc32(open(p, 'rb').read()) & 0xffffffff)
    subprocess.run(['rm', '-rf', tmp])
    return res

def mine(img):
    lst = img + '.list'
    subprocess.run([DEV, 'List', img, lst], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    res = {}; header = ''
    for line in open(lst, encoding='utf-8', errors='replace'):
        line = line.rstrip('\n')
        if line.startswith('#') and not header: header = line
        if line.startswith(('#', '!')):
            if line.startswith('!'): header = line
            continue
        p = line.split('|')
        if len(p) >= 3 and not p[0].startswith('_'): res[p[0].upper()] = p[2]
    return res, header

ok = bad = skipped = 0
for j in sorted(glob.glob(f'{SRC}/**/*.json', recursive=True)):
    name = os.path.basename(j)[:-5]
    img = f'{OUT}/{name}.img'
    try:
        if not convert(j, img): skipped += 1; continue
    except Exception as e:
        skipped += 1; continue
    ref = sevenzip_list(img)
    got, hdr = mine(img)
    if not ref:
        print(f'SKIP  {name}: 7-Zip cannot read it ({os.path.getsize(img)} bytes); mine: {hdr}')
        skipped += 1; continue
    ref = {k: v for k, v in ref.items() if all(32 <= ord(c) < 127 for c in k) and not re.search(r'[?*<>|";]', k)}   # DOS cannot create these names; 7-Zip also lists directory slack as files
    missing = [k for k in ref if k not in got]
    diff = [k for k in ref if k in got and got[k] != ref[k]]
    if missing or diff:
        bad += 1
        print(f'FAIL  {name}: {hdr} missing={missing[:4]} diff={diff[:4]}')
    else:
        ok += 1
print(f'\n{ok} disks match 7-Zip exactly, {bad} differ, {skipped} skipped')
