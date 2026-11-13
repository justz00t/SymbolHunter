#!/usr/bin/env python3
"""Robustness test: damages every corpus archive/image in several ways (truncation, flipped bytes,
zeroed sectors) and scans the result. Passes when nothing hangs, nothing crashes and every
problem is classified (no raw 'error' entries)."""
import os, sys, random, shutil, json, subprocess, collections
SRC = sys.argv[1] if len(sys.argv) > 1 else '/opt/work/corpus'
OUT = sys.argv[2] if len(sys.argv) > 2 else '/opt/work/fuzz'
SEED = int(sys.argv[3]) if len(sys.argv) > 3 else 7
rnd = random.Random(SEED)
shutil.rmtree(OUT, ignore_errors=True); os.makedirs(OUT)
n = 0
for dp, dn, fn in os.walk(SRC):
    for f in fn:
        p = os.path.join(dp, f)
        if os.path.getsize(p) > 3 * 1024 * 1024 or 'garbage' in dp: continue
        d = open(p, 'rb').read()
        if len(d) < 64: continue
        rel = os.path.relpath(p, SRC).replace('/', '_')
        variants = {}
        for frac in (0.1, 0.5, 0.9): variants[f't{int(frac * 100)}'] = d[:max(16, int(len(d) * frac))]
        for k in range(2):
            b = bytearray(d)
            for _ in range(8): b[rnd.randrange(64 if len(b) > 1024 else 0, len(b))] ^= 1 << rnd.randrange(8)
            variants[f'flip{k}'] = bytes(b)
        b = bytearray(d); o = rnd.randrange(0, max(1, len(b) - 512)); b[o:o + 512] = bytes(min(512, len(b) - o)); variants['zero'] = bytes(b)
        b = bytearray(d); o = rnd.randrange(0, max(1, len(b) - 4096)); b[o:o + 4096] = bytes(rnd.getrandbits(8) for _ in range(min(4096, len(b) - o))); variants['junk'] = bytes(b)
        b = bytearray(d)
        for _ in range(max(4, len(b) // 100)): b[rnd.randrange(0, len(b))] = rnd.getrandbits(8)
        variants['heavy'] = bytes(b)
        if len(d) > 4096:
            b = bytearray(d); x = rnd.randrange(0, len(b) - 1024); y = rnd.randrange(0, len(b) - 1024)
            b[x:x + 1024], b[y:y + 1024] = d[y:y + 1024], d[x:x + 1024]; variants['swap'] = bytes(b)
        for tag, data in variants.items():
            stem, ext = os.path.splitext(rel)
            open(os.path.join(OUT, f'{stem}.{tag}{ext}'), 'wb').write(data); n += 1
print(n, 'damaged files written')
res_json = '/tmp/fuzz_result.json'
r = subprocess.run(['/home/claude/symhunt/build/dev.sh', 'ScanT', OUT, res_json, '4', '60'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=7200)
out = r.stdout.decode(errors='replace').strip()
print(out.splitlines()[-1] if out else 'no output', '| exit code', r.returncode)
items = json.load(open(res_json))['items']
kinds = collections.Counter(p['kind'] for it in items for p in it['problems'])
print('items', len(items), '| statuses', dict(collections.Counter(it['status'] for it in items)))
print('problem kinds', dict(kinds))
bad = [(it['path'], p['kind'], p['where'], p['message']) for it in items for p in it['problems'] if p['kind'] in ('error', 'timeout')]
for b in bad[:60]: print('  ', b[1], b[0], '|', b[2][-60:], '|', b[3][:160])
print('RESULT:', 'PASS' if r.returncode == 0 and not bad and len(items) == n else f'FAIL ({len(bad)} unclassified/timeouts)')
