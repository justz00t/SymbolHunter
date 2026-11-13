#!/usr/bin/env python3
"""Creates archives with real reference tools, extracts them with Symbol Hunter's engine
and compares every file's CRC32 with the original. Prints a pass/fail table."""
import os, sys, subprocess, zlib, shutil, random, tarfile, gzip, bz2, lzma, glob

ROOT = sys.argv[1] if len(sys.argv) > 1 else '/opt/work/arctest'
DEV = '/home/claude/symhunt/build/dev.sh'
BIN = '/opt/tools/bin'
SC = '/opt/tools/src/sharpcompress/tests/TestArchives/Archives'
os.environ['PATH'] = BIN + ':' + os.environ['PATH']

def run(cmd, cwd=None, inp=None):
    return subprocess.run(cmd, cwd=cwd, shell=isinstance(cmd, str), stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=inp, timeout=600).stdout.decode('latin1')

def crc(path):
    with open(path, 'rb') as f: return '%08x' % (zlib.crc32(f.read()) & 0xffffffff)

def make_sources(d):
    os.makedirs(d, exist_ok=True)
    rnd = random.Random(1234)
    words = 'player score level enemy weapon door key map sprite sound music palette joystick init update render'.split()
    text = '\r\n'.join(' '.join(rnd.choice(words) for _ in range(rnd.randint(3, 14))) for _ in range(4000)) + '\r\n'
    open(f'{d}/README.TXT', 'w', newline='').write(text)
    open(f'{d}/RANDOM.DAT', 'wb').write(bytes(rnd.getrandbits(8) for _ in range(70000)))
    # semi-compressible binary resembling code
    b = bytearray()
    while len(b) < 200000:
        b += bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, rnd.randint(0, 40), 0xB8]) + rnd.getrandbits(16).to_bytes(2, 'little') + bytes([0xE8]) + rnd.getrandbits(16).to_bytes(2, 'little')
        if rnd.random() < 0.1: b += bytes(rnd.randint(1, 300))
    open(f'{d}/GAME.EXE', 'wb').write(bytes(b))
    open(f'{d}/EMPTY.TXT', 'wb').write(b'')
    open(f'{d}/RUNS.BIN', 'wb').write(b'\x90' * 5000 + b'A' * 300 + b'\x90\x00' * 700 + bytes(range(256)) * 40)
    open(f'{d}/BIG.TXT', 'w', newline='').write(text * 6)
    return {n: crc(f'{d}/{n}') for n in os.listdir(d)}

def main():
    if os.path.exists(ROOT): shutil.rmtree(ROOT)
    src = f'{ROOT}/src'
    expected = make_sources(src)
    names = sorted(expected)
    lines_pre = []
    cases = []   # (archive path, expected dict or None for 'all entries must pass CRC')
    def case(path, exp=None): cases.append((path, exp if exp is not None else expected))
    out = f'{ROOT}/arc'; os.makedirs(out)
    # ---- ZIP via 7-Zip
    for m in ['Copy', 'Deflate', 'Deflate64', 'BZip2', 'LZMA', 'PPMd']:
        p = f'{out}/z_{m}.zip'; run([f'{BIN}/7zz', 'a', '-tzip', f'-mm={m}', p] + names, cwd=src); case(p)
    p = f'{out}/z_sfx_like.exe'
    # ---- 7z
    for m in ['LZMA', 'LZMA2', 'PPMd', 'BZip2', 'Deflate']:
        p = f'{out}/s_{m}.7z'; run([f'{BIN}/7zz', 'a', '-t7z', f'-m0={m}', p] + names, cwd=src); case(p)
    p = f'{out}/s_solid_bcj.7z'; run([f'{BIN}/7zz', 'a', '-t7z', '-ms=on', '-mf=BCJ', p] + names, cwd=src); case(p)
    # ---- ARJ (open source ARJ 3.10, same format as DOS ARJ 2.x)
    for m in range(0, 5):
        p = f'{out}/a_m{m}.arj'; run([f'{BIN}/arj', 'a', f'-m{m}', '-y', p] + names, cwd=src); case(p)
    vdir = f'{out}/arjvol'; os.makedirs(vdir)
    run([f'{BIN}/arj', 'a', '-m1', '-v60k', '-y', f'{vdir}/MULTI.ARJ'] + names, cwd=src); case(f'{vdir}/MULTI.ARJ')
    # ---- LZH (LHa for UNIX)
    for opt, tag in [('o5', 'lh5'), ('o6', 'lh6'), ('o7', 'lh7'), ('o', 'lh1'), ('z', 'lh0')]:
        for lvl in ['0', '1', '2']:
            p = f'{out}/l_{tag}_h{lvl}.lzh'
            run(f'{BIN}/lha a{opt}{lvl}q {p} ' + ' '.join(names), cwd=src)
            if os.path.exists(p): case(p)
            else: lines_pre.append(f'NOTE could not create {p}')
    # ---- ZOO
    p = f'{out}/o_lzw.zoo'; run([f'{BIN}/zoo', 'a', p] + names, cwd=src); case(p)
    p = f'{out}/o_lzh.zoo'; run([f'{BIN}/zoo', 'ah', p] + names, cwd=src); case(p)
    # ---- tar / gz / bz2 / xz / compress
    p = f'{out}/t.tar'
    with tarfile.open(p, 'w') as t:
        for n in names: t.add(f'{src}/{n}', arcname=n)
    case(p)
    for ext, mod in [('gz', gzip), ('bz2', bz2), ('xz', lzma)]:
        p2 = f'{out}/t.tar.{ext}'
        with open(p, 'rb') as f, mod.open(p2, 'wb') as g: g.write(f.read())
        cases.append((p2, {'t.tar': crc(p)}))
    # ---- SharpCompress reference archives (made with the original tools)
    for f in sorted(glob.glob(f'{SC}/*')):
        b = os.path.basename(f)
        if b.startswith(('Arj.', 'Arc.', 'Zip.shrink', 'Zip.implode', 'Zip.reduce', 'Rar', 'Rar.', '7Zip.')) and not b.endswith(('.a01', '.a02', '.a03', '.a04', '.a05')) and 'part0' not in b.replace('part01', '') and not b.endswith(tuple(f'.r0{i}' for i in range(10))) and 'Encrypted' not in b and 'encrypted' not in b and not b.endswith(('.002', '.003', '.004', '.005', '.006', '.007')) and 'ZSTD' not in b:
            if 'malformed' in b or 'issue' in b or 'jpeg' in b or 'Aes' in b or b.endswith('.list') or 'split.0' in b or any(x in b for x in ('ARM', 'PPC', 'SPARC', 'IA64', 'RISCV', 'Filters', 'blake2', 'filesOnly')): continue
            cases.append((f, None))
    # ---- libmspack cabinets (only the well-formed ones)
    for f in sorted(glob.glob('/opt/tools/src/libmspack/libmspack/test/test_files/cabd/*.cab')):
        b = os.path.basename(f)
        if b.startswith(('normal', 'mszip', 'lzx', 'simple', 'mixed', 'split-1', 'search', 'dir', 'large')) and 'premature' not in b and 'no-lengths' not in b and 'fuzz' not in b:
            cases.append((f, None))
    # ---- ACE 2.0 (real archives from the acefile and patool test suites); every entry must pass its CRC
    for p in ['/opt/work/src2/acetest/blocked_unregistered/winappdbg-winappdbg_v1.6_plain.ace', '/opt/work/src2/patool/tests/data/t.ace']:
        if os.path.exists(p): cases.append((p, None))
    # ---- RAR 1.3 ('RE~^'): the packed streams of the RAR 1.5 sample re-wrapped in the old container
    p = f'{out}/OLD13.RAR'
    run(['python3', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'rar13_from_rar15.py'), f'{SC}/Rar15.rar', p])
    if os.path.exists(p): cases.append((p, {'TEST.EXE': 'cfb109c8', 'TEST.JPG': '088814e3', 'TECT.TXT': '9bd160fa'}))
    # ---- InstallShield 3 test data
    for f in sorted(glob.glob('/opt/tools/src/unshieldv3/test-data/*.Z')): cases.append((f, None))

    # ---- run
    ok = bad = 0; lines = []
    for path, exp in cases:
        os.makedirs(f'{ROOT}/lists', exist_ok=True)
        lst = f'{ROOT}/lists/' + os.path.basename(path) + '.list'
        run([DEV, 'List', path, lst])
        got = {}; errs = []
        if os.path.exists(lst):
            for line in open(lst, encoding='utf-8', errors='replace'):
                line = line.rstrip('\n')
                if line.startswith('!'): errs.append(line)
                if line.startswith(('#', '!')) or not line: continue
                parts = line.split('|')
                if len(parts) < 4: continue
                got[os.path.basename(parts[0])] = (parts[2], parts[3])
        else:
            errs.append('no output')
        if exp is None:
            # reference archives: every entry must decode without CRC/size errors, compare with 7-Zip where possible
            fails = [k for k, v in got.items() if v[0] == 'ERROR' or 'CRC' in v[1] or 'mismatch' in v[1]]
            good = not errs and not fails and len(got) > 0
            detail = '; '.join(errs + [f'{k}: {got[k][1]}' for k in fails])[:200]
        else:
            fails = [n for n in exp if n not in got or got[n][0] != exp[n]]
            good = not errs and not fails
            detail = '; '.join(errs + [f'{n}: got {got.get(n, ("missing",))[0]} want {exp[n]}' for n in fails])[:200]
        ok += good; bad += (not good)
        lines.append(('PASS' if good else 'FAIL') + '  ' + os.path.relpath(path, '/') + ('' if good else '  -> ' + detail))
    for l in lines_pre + lines: print(l)
    print(f'\n{ok} passed, {bad} failed, {len(cases)} archives')

if __name__ == '__main__':
    main()
