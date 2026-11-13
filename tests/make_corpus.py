#!/usr/bin/env python3
"""Builds an end-to-end test collection that mimics a real DOS-era archive collection.
Every top-level item has an expectation in expected.json:
   {"path": ..., "must": [kinds that must be found], "max": "None|Weak|Medium" (strongest allowed when must is empty),
    "volumes": n (optional: number of extra volumes that must be joined), "partof": True (continuation volume)}"""
import os, sys, shutil, subprocess, json, zipfile, tarfile, gzip, random, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import writers as W
sys.path.insert(0, '/opt/tools/src/pycdlib')
import pycdlib

OUT = sys.argv[1] if len(sys.argv) > 1 else '/opt/work/corpus'
D = '/opt/work/dbg'
BIN = '/opt/tools/bin'
os.environ['PATH'] = BIN + ':' + os.environ['PATH']
rnd = random.Random(42)

def rd(p): return open(p, 'rb').read()

DBG = {  # file name in the collection -> (source, kind expected)
    'TC20DBG.EXE': ('tc20/tc20dbg.exe', 'BORLAND_TD'), 'TCPPDBG.EXE': ('tcpp10/tcppdbg.exe', 'BORLAND_TD'),
    'TP55DBG.EXE': ('tp55/tp55dbg.exe', 'BORLAND_TD'), 'TP70DBG.EXE': ('tp70/tp70dbg.exe', 'BORLAND_TD'),
    'TASMDBG.EXE': ('tasm/tasmdbg.exe', 'BORLAND_TD'), 'MSC5DBG.EXE': ('msc51/msc5dbg.exe', 'CODEVIEW'),
    'MASMDBG.EXE': ('masm/masmdbg.exe', 'CODEVIEW'), 'QCDBG.EXE': ('qc25/qcdbg.exe', 'CODEVIEW'),
    'QBDBG.EXE': ('qb45/qbdbg.exe', 'CODEVIEW'), 'ZTCDBG.EXE': ('ztc30/ztcdbg.exe', 'CODEVIEW'),
    'W16WAT.EXE': ('watcom/w16wat.exe', 'WATCOM'), 'W16CV.EXE': ('watcom/w16cv.exe', 'CODEVIEW'),
    'W16DW.EXE': ('watcom/w16dw.exe', 'DWARF'), 'W4GWAT.EXE': ('watcom/w4gwat.exe', 'WATCOM'),
    'W4GCV.EXE': ('watcom/w4gcv.exe', 'CODEVIEW'), 'WPLWAT.EXP': ('watcom/wplwat.exp', 'WATCOM'),
    'WWINCV.EXE': ('watcom/wwincv.exe', 'CODEVIEW'), 'DJDBG.EXE': ('djgpp/djdbg.exe', 'COFF_SYMS'),
    'TC20DBG.MAP': ('tc20/tc20dbg.map', 'MAP'), 'W16WAT.MAP': ('watcom/w16wat.map', 'MAP'), 'MSC5DBG.MAP': ('msc51/msc5dbg.map', 'MAP'),
    'GAMEU.TPU': ('tp55/gameu.tpu', 'TPU'), 'GAMEDBG.OBJ': ('tc20/gamedbg.obj', 'OMF_DEBUG'), 'W16DBG.LIB': ('watcom/w16dbg.lib', 'OMF_DEBUG'),
}
REL = {'TC20REL.EXE': 'tc20/tc20rel.exe', 'TCPPREL.EXE': 'tcpp10/tcpprel.exe', 'TP55REL.EXE': 'tp55/tp55rel.exe', 'TP70REL.EXE': 'tp70/tp70rel.exe',
       'TASMREL.EXE': 'tasm/tasmrel.exe', 'MSC5REL.EXE': 'msc51/msc5rel.exe', 'MASMREL.EXE': 'masm/masmrel.exe', 'W16REL.EXE': 'watcom/w16rel.exe',
       'W4GREL.EXE': 'watcom/w4grel.exe', 'DJREL.EXE': 'djgpp/djrel.exe'}
def dbg(n): return rd(f'{D}/{DBG[n][0]}')
def rel(n): return rd(f'{D}/{REL[n]}')
def kind(n): return DBG[n][1]

def filler(n=3):
    files = {'README.TXT': ('Welcome to the game!\r\n' * 40).encode(), 'GAME.DAT': bytes(rnd.getrandbits(8) for _ in range(20000)),
             'LEVELS.DAT': bytes(rnd.choice(b'....##@@$') for _ in range(12000)), 'PALETTE.PAL': bytes(range(256)) * 3}
    return dict(list(files.items())[:n])

expect = []
def E(path, must=None, maxs='None', **kw):
    d = {'path': path, 'must': must or [], 'max': maxs}; d.update(kw); expect.append(d)

def put(rel_path, data):
    p = os.path.join(OUT, rel_path); os.makedirs(os.path.dirname(p), exist_ok=True)
    open(p, 'wb').write(data); return p

def zipit(files, method=zipfile.ZIP_DEFLATED):
    import io
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w', method) as z:
        for n, d in files.items(): z.writestr(zipfile.ZipInfo(n, (1994, 5, 17, 13, 37, 0)), d, compress_type=method)
    return b.getvalue()

def tool_archive(tool_cmd, files, ext):
    """Run a reference archiver in a temp folder; returns archive bytes."""
    tmp = os.path.join(OUT, '_tmp'); shutil.rmtree(tmp, ignore_errors=True); os.makedirs(tmp)
    for n, d in files.items():
        p = os.path.join(tmp, n); os.makedirs(os.path.dirname(p), exist_ok=True); open(p, 'wb').write(d)
    arc = os.path.join(tmp, 'OUT' + ext)
    cmd = tool_cmd.replace('{arc}', arc).replace('{files}', ' '.join(files.keys()))
    subprocess.run(cmd, shell=True, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    data = rd(arc); shutil.rmtree(tmp); return data

def iso_image(files, joliet=True):
    import io
    iso = pycdlib.PyCdlib(); iso.new(interchange_level=1, joliet=3 if joliet else None, vol_ident='GAMECD')
    dirs = set()
    for n, d in files.items():
        parts = n.split('/')
        for k in range(1, len(parts)):
            dp = '/' + '/'.join(parts[:k])
            if dp not in dirs:
                dirs.add(dp)
                iso.add_directory(dp.upper(), joliet_path=dp if joliet else None)
        iso.add_fp(io.BytesIO(d), len(d), '/' + n.upper() + ';1', joliet_path='/' + n if joliet else None)
    b = io.BytesIO(); iso.write_fp(b); iso.close(); return b.getvalue()

def to_bin2352(iso):
    out = bytearray(); sync = b'\x00' + b'\xff' * 10 + b'\x00'
    for i in range(len(iso) // 2048):
        m, s, f = (i + 150) // 4500, ((i + 150) // 75) % 60, (i + 150) % 75
        out += sync + bytes([int(str(m), 16), int(str(s), 16), int(str(f), 16), 1]) + iso[i * 2048:(i + 1) * 2048] + bytes(288)
    return bytes(out)

def main():
    if os.path.exists(OUT): shutil.rmtree(OUT)
    os.makedirs(OUT)
    names = list(DBG.keys())

    # ---- 1. every debug format inside rotating archive types
    fmts = ['zip', 'zipstore', 'zipbz2', 'ziplzma', 'arj1', 'arj2', 'arj3', 'arj4', 'lh5', 'lh6', 'lh7', 'lh1', 'lh0', 'zoo', 'zooh', 'arc', '7z', 'tgz', 'cab', 'szdd']
    for i, n in enumerate(names):
        f = fmts[i % len(fmts)]
        files = dict(filler(2)); files[n] = dbg(n)
        base = f'single/{i:02d}_{n.split(".")[0]}_{f}'
        if f == 'zip': p = put(base + '.zip', zipit(files))
        elif f == 'zipstore': p = put(base + '.zip', zipit(files, zipfile.ZIP_STORED))
        elif f == 'zipbz2': p = put(base + '.zip', zipit(files, zipfile.ZIP_BZIP2))
        elif f == 'ziplzma': p = put(base + '.zip', zipit(files, zipfile.ZIP_LZMA))
        elif f.startswith('arj'): p = put(base + '.arj', tool_archive(f'arj a -m{f[3]} -y {{arc}} {{files}}', files, '.ARJ'))
        elif f in ('lh5', 'lh6', 'lh7'): p = put(base + '.lzh', tool_archive(f'lha ao{f[2]}q {{arc}} {{files}}', files, '.LZH'))
        elif f == 'lh1': p = put(base + '.lzh', tool_archive('lha aoq {arc} {files}', files, '.LZH'))
        elif f == 'lh0': p = put(base + '.lzh', tool_archive('lha azq {arc} {files}', files, '.LZH'))
        elif f == 'zoo': p = put(base + '.zoo', tool_archive('zoo a {arc} {files}', files, '.zoo'))
        elif f == 'zooh': p = put(base + '.zoo', tool_archive('zoo ah {arc} {files}', files, '.zoo'))
        elif f == 'arc': p = put(base + '.arc', W.arc_stored_and_packed(files))
        elif f == '7z': p = put(base + '.7z', tool_archive('7zz a -t7z -mx=9 {arc} {files}', files, '.7z'))
        elif f == 'tgz':
            import io; b = io.BytesIO()
            with tarfile.open(fileobj=b, mode='w') as t:
                for k, v in files.items():
                    ti = tarfile.TarInfo(k); ti.size = len(v); t.addfile(ti, io.BytesIO(v))
            p = put(base + '.tgz', gzip.compress(b.getvalue()))
        elif f == 'cab': p = put(base + '.cab', W.cab_mszip(files))
        elif f == 'szdd': p = put(base + '.ex_' if n.endswith('.EXE') else base + '.' + n.split('.')[1][:2] + '_', W.szdd(dbg(n), n.split('.')[1][-1].encode()))
        E(os.path.relpath(p, OUT), [kind(n)])

    # ---- 2. release builds in every archive type: must not report symbols
    for i, n in enumerate(REL):
        files = dict(filler(3)); files[n] = rel(n)
        f = ['zip', 'arj', 'lzh', 'zoo', '7z'][i % 5]
        base = f'negative/{i:02d}_{n.split(".")[0]}'
        if f == 'zip': p = put(base + '.zip', zipit(files))
        elif f == 'arj': p = put(base + '.arj', tool_archive('arj a -m1 -y {arc} {files}', files, '.ARJ'))
        elif f == 'lzh': p = put(base + '.lzh', tool_archive('lha ao5q {arc} {files}', files, '.LZH'))
        elif f == 'zoo': p = put(base + '.zoo', tool_archive('zoo ah {arc} {files}', files, '.zoo'))
        else: p = put(base + '.7z', tool_archive('7zz a -t7z {arc} {files}', files, '.7z'))
        E(os.path.relpath(p, OUT), [], 'Weak')
    p = put('negative/random.bin', bytes(rnd.getrandbits(8) for _ in range(300000))); E('negative/random.bin', [], 'None')
    p = put('negative/docs.zip', zipit(filler(4))); E('negative/docs.zip', [], 'None')

    # ---- 3. disk images of every kind
    game = {'GAME/' + 'TP70DBG.EXE': dbg('TP70DBG.EXE'), 'GAME/README.TXT': b'readme\r\n', 'AUTOEXEC.BAT': b'@echo off\r\n'}
    img144 = W.fat_image(game, 1474560)
    E(os.path.relpath(put('images/floppy144.img', img144), OUT), ['BORLAND_TD'])
    img720 = W.fat_image({'W16WAT.EXE': dbg('W16WAT.EXE')}, 737280); E(os.path.relpath(put('images/floppy720.ima', img720), OUT), ['WATCOM'])
    img360 = W.fat_image({'MSC5DBG.EXE': dbg('MSC5DBG.EXE')}, 368640); E(os.path.relpath(put('images/floppy360.dsk', img360), OUT), ['CODEVIEW'])
    img160 = W.fat_image({'QBDBG.EXE': dbg('QBDBG.EXE')}, 163840, nobpb=True); E(os.path.relpath(put('images/dos1_160k.img', img160), OUT), ['CODEVIEW'])
    img12 = W.fat_image({'TASMDBG.EXE': dbg('TASMDBG.EXE')}, 1228800); E(os.path.relpath(put('images/floppy12m.img', img12), OUT), ['BORLAND_TD'])
    hdd = W.mbr_disk(W.fat_image({'DEV/W4GWAT.EXE': dbg('W4GWAT.EXE'), 'DEV/W16WAT.MAP': dbg('W16WAT.MAP')}, 16 * 1024 * 1024, fat16=True, hidden=63))
    E(os.path.relpath(put('images/harddisk.img', hdd), OUT), ['WATCOM', 'MAP'])
    E(os.path.relpath(put('images/harddisk.vhd', W.vhd_fixed(hdd)), OUT), ['WATCOM', 'MAP'])
    E(os.path.relpath(put('images/teledisk.td0', W.td0(W.fat_image({'TC20DBG.EXE': dbg('TC20DBG.EXE')}, 368640), 9, 2)), OUT), ['BORLAND_TD'])
    E(os.path.relpath(put('images/teledisk_adv.td0', W.td0(W.fat_image({'TCPPDBG.EXE': dbg('TCPPDBG.EXE')}, 368640), 9, 2, advanced=True)), OUT), ['BORLAND_TD'])
    E(os.path.relpath(put('images/imagedisk.imd', W.imd(W.fat_image({'ZTCDBG.EXE': dbg('ZTCDBG.EXE')}, 737280), 9, 2)), OUT), ['CODEVIEW'])
    E(os.path.relpath(put('images/copyqm.cqm', W.cqm(W.fat_image({'W16CV.EXE': dbg('W16CV.EXE')}, 1474560), 18, 2)), OUT), ['CODEVIEW'])
    iso = iso_image({'SETUP/W4GCV.EXE': dbg('W4GCV.EXE'), 'README.TXT': b'cd readme\r\n', 'DATA/LEVELS.DAT': bytes(50000)})
    E(os.path.relpath(put('images/gamecd.iso', iso), OUT), ['CODEVIEW'])
    E(os.path.relpath(put('images/gamecd.bin', to_bin2352(iso)), OUT), ['CODEVIEW'])
    E(os.path.relpath(put('images/gamecd_nojoliet.iso', iso_image({'GAME/DJDBG.EXE': dbg('DJDBG.EXE')}, joliet=False)), OUT), ['COFF_SYMS'])
    dele = W.fat_image({'GAME.EXE': rel('TC20REL.EXE')}, 1474560, deleted={'GAME.MAP': dbg('TC20DBG.MAP')})
    E(os.path.relpath(put('images/deleted_map.img', dele), OUT), ['MAP'])
    E(os.path.relpath(put('images/retail_only.img', W.fat_image({'GAME.EXE': rel('W16REL.EXE'), 'GAME.DAT': bytes(30000)}, 1474560)), OUT), [], 'Weak')

    # ---- 4. nesting
    inner_arj = tool_archive('arj a -m2 -y {arc} {files}', {'TP55DBG.EXE': dbg('TP55DBG.EXE')}, '.ARJ')
    img = W.fat_image({'INSTALL/GAME.ARJ': inner_arj, 'INSTALL.BAT': b'arj x game.arj\r\n'}, 1474560)
    p = put('nested/zip_img_arj.zip', zipit({'DISK1.IMG': img})); E('nested/zip_img_arj.zip', ['BORLAND_TD'])
    lzh = tool_archive('lha ao5q {arc} {files}', {'WWINCV.EXE': dbg('WWINCV.EXE')}, '.LZH')
    zip_inner = zipit({'GAME.LZH': lzh})
    iso2 = iso_image({'INSTALL/GAME.ZIP': zip_inner})
    p = put('nested/7z_iso_zip_lzh.7z', tool_archive('7zz a -t7z {arc} {files}', {'GAMECD.ISO': iso2}, '.7z')); E('nested/7z_iso_zip_lzh.7z', ['CODEVIEW'])
    deep = dbg('MASMDBG.EXE')
    deep = zipit({'L5.EXE': deep}); deep = tool_archive('arj a -y {arc} {files}', {'L4.ZIP': deep}, '.ARJ')
    deep = tool_archive('lha ao5q {arc} {files}', {'L3.ARJ': deep}, '.LZH'); deep = W.fat_image({'L2.LZH': deep}, 1474560)
    p = put('nested/deep5.zip', zipit({'L1.IMG': deep})); E('nested/deep5.zip', ['CODEVIEW'])
    # self-extracting: EXE stub + archive
    sfx_zip = rel('TC20REL.EXE') + zipit({'GAME/MSC5DBG.EXE': dbg('MSC5DBG.EXE')})
    p = put('nested/pksfx_like.exe', sfx_zip); E('nested/pksfx_like.exe', ['CODEVIEW'], partial_ok=True)
    sfx_arj = rel('TC20REL.EXE') + tool_archive('arj a -y {arc} {files}', {'QCDBG.EXE': dbg('QCDBG.EXE')}, '.ARJ')
    p = put('nested/arjsfx_like.exe', sfx_arj); E('nested/arjsfx_like.exe', ['CODEVIEW'])
    sfx_lzh = rel('TC20REL.EXE') + tool_archive('lha ao5q {arc} {files}', {'ZTCDBG.EXE': dbg('ZTCDBG.EXE')}, '.LZH')
    p = put('nested/lhasfx_like.exe', sfx_lzh); E('nested/lhasfx_like.exe', ['CODEVIEW'])

    # ---- 5. multi-volume and split sets
    big = {'GAME/TC20DBG.EXE': dbg('TC20DBG.EXE'), 'GAME/DATA1.DAT': bytes(rnd.getrandbits(8) for _ in range(90000)), 'GAME/DATA2.DAT': bytes(rnd.getrandbits(8) for _ in range(90000))}
    tmp = os.path.join(OUT, '_tmpv'); os.makedirs(tmp)
    for n, d in big.items():
        os.makedirs(os.path.join(tmp, os.path.dirname(n)), exist_ok=True); open(os.path.join(tmp, n), 'wb').write(d)
    os.makedirs(f'{OUT}/volumes/arjset')
    subprocess.run(f'arj a -r -m1 -v70k -y {OUT}/volumes/arjset/GAME.ARJ GAME', shell=True, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    vols = sorted(os.listdir(f'{OUT}/volumes/arjset'))
    E('volumes/arjset/GAME.ARJ', ['BORLAND_TD'], volumes=len(vols) - 1)
    for v in vols:
        if v != 'GAME.ARJ': E('volumes/arjset/' + v, [], 'None', partof=True)
    # ARJ volumes spread over two disk images inside ABC1.ZIP / ABC2.ZIP
    os.makedirs(f'{OUT}/_tmpv2')
    subprocess.run(f'arj a -r -m1 -v150k -y {OUT}/_tmpv2/DATA.ARJ GAME', shell=True, cwd=tmp, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    v2 = sorted(os.listdir(f'{OUT}/_tmpv2'))
    disk1 = W.fat_image({'DATA.ARJ': rd(f'{OUT}/_tmpv2/DATA.ARJ'), 'INSTALL.BAT': b'arj x data.arj\r\n'}, 1474560)
    disk2 = W.fat_image({x: rd(f'{OUT}/_tmpv2/{x}') for x in v2 if x != 'DATA.ARJ'}, 1474560)
    put('volumes/crossdisk/ABC1.ZIP', zipit({'DISK1.IMG': disk1})); put('volumes/crossdisk/ABC2.ZIP', zipit({'DISK2.IMG': disk2}))
    E('volumes/crossdisk/ABC1.ZIP', ['BORLAND_TD']); E('volumes/crossdisk/ABC2.ZIP', [], 'Strong')
    # raw split of a ZIP into .001/.002/.003
    zbig = zipit({'GAME/W4GWAT.EXE': dbg('W4GWAT.EXE'), 'GAME/DATA.DAT': bytes(rnd.getrandbits(8) for _ in range(150000))}, zipfile.ZIP_STORED)
    k = len(zbig) // 3
    for i, part in enumerate([zbig[:k], zbig[k:2 * k], zbig[2 * k:]]): put(f'volumes/split/GAME.ZIP.{i + 1:03d}', part)
    E('volumes/split/GAME.ZIP.001', ['WATCOM'], volumes=2); E('volumes/split/GAME.ZIP.002', [], 'None', partof=True); E('volumes/split/GAME.ZIP.003', [], 'None', partof=True)
    # renamed raw split: SAVE1.ZIP SAVE2.ZIP
    zr = zipit({'W16CV.EXE': dbg('W16CV.EXE'), 'PAD.DAT': bytes(rnd.getrandbits(8) for _ in range(60000))}, zipfile.ZIP_STORED)
    put('volumes/rawnum/SAVE1.ZIP', zr[:len(zr) // 2]); put('volumes/rawnum/SAVE2.ZIP', zr[len(zr) // 2:])
    E('volumes/rawnum/SAVE1.ZIP', ['CODEVIEW'], volumes=1); E('volumes/rawnum/SAVE2.ZIP', [], 'None', partof=True)
    # PKZIP spanned set renamed as DOOM1.ZIP DOOM2.ZIP DOOM3.ZIP
    zs = zipit({'DOOM/QBDBG.EXE': dbg('QBDBG.EXE'), 'DOOM/WAD.DAT': bytes(rnd.getrandbits(8) for _ in range(80000)), 'DOOM/README.TXT': b'x' * 3000})
    for i, part in enumerate(W.spanned_zip(zs, 3)): put(f'volumes/spanned/DOOM{i + 1}.ZIP', part)
    E('volumes/spanned/DOOM1.ZIP', ['CODEVIEW'], volumes=2); E('volumes/spanned/DOOM2.ZIP', [], 'None', partof=True); E('volumes/spanned/DOOM3.ZIP', [], 'None', partof=True)
    # .Z01 split ZIP
    for i, part in enumerate(W.spanned_zip(zipit({'MASMDBG.EXE': dbg('MASMDBG.EXE'), 'BIG.DAT': bytes(rnd.getrandbits(8) for _ in range(40000))}), 2)):
        put('volumes/zsplit/DEMO.' + ('Z01' if i == 0 else 'ZIP'), part)
    E('volumes/zsplit/DEMO.ZIP', ['CODEVIEW'], volumes=1); E('volumes/zsplit/DEMO.Z01', [], 'None', partof=True)
    # independent numbered archives (each complete): both must be scanned on their own
    put('volumes/independent/PART1.ZIP', zipit({'TP55DBG.EXE': dbg('TP55DBG.EXE')})); put('volumes/independent/PART2.ZIP', zipit({'GAMEU.TPU': dbg('GAMEU.TPU')}))
    E('volumes/independent/PART1.ZIP', ['BORLAND_TD']); E('volumes/independent/PART2.ZIP', ['TPU'])
    shutil.rmtree(tmp); shutil.rmtree(f'{OUT}/_tmpv2')

    # ---- 6. loose files and sources
    put('loose/GAME.C', rd(f'{D}/tc20/GAME.C')); E('loose/GAME.C', ['SOURCE'])
    put('loose/W16DBG.LIB', dbg('W16DBG.LIB')); E('loose/W16DBG.LIB', ['OMF_DEBUG'])
    put('loose/TC20REL.EXE', rel('TC20REL.EXE')); E('loose/TC20REL.EXE', [], 'Weak')
    put('loose/W4GREL.EXE', rel('W4GREL.EXE')); E('loose/W4GREL.EXE', [], 'None')

    # ---- RAR 1.3 (1993-94 'RE~^' format), single and multi-volume (.RAR .R00 .R01)
    put('archives/rar13/OLDGAME.RAR', W.rar13({'GAME/TC20DBG.EXE': dbg('TC20DBG.EXE'), 'README.TXT': b'Old game\r\n' * 50}))
    E('archives/rar13/OLDGAME.RAR', ['BORLAND_TD'])
    vols13 = W.rar13({'README.TXT': b'Disk set\r\n' * 300, 'DEV/MSC5DBG.EXE': dbg('MSC5DBG.EXE'), 'LEVELS.DAT': bytes(rnd.getrandbits(8) for _ in range(9000))}, volume_size=16000)
    for i, v in enumerate(vols13): put('volumes/rar13vol/DEMO.' + ('RAR' if i == 0 else f'R{i - 1:02d}'), v)
    E('volumes/rar13vol/DEMO.RAR', ['CODEVIEW'], volumes=len(vols13) - 1)
    for i in range(1, len(vols13)): E(f'volumes/rar13vol/DEMO.R{i - 1:02d}', [], 'None', partof=True)

    # ---- ACE (stored entries made here; real compressed ACE archives are in the round-trip test)
    put('archives/ace/OLDGAME.ACE', W.ace({'GAME\\TC20DBG.EXE': dbg('TC20DBG.EXE'), 'README.TXT': b'ACE test\r\n' * 40}))
    E('archives/ace/OLDGAME.ACE', ['BORLAND_TD'])
    avols = W.ace({'README.TXT': b'Disk set\r\n' * 300, 'DEV\\MSC5DBG.EXE': dbg('MSC5DBG.EXE')}, volume_size=12000)
    for i, v in enumerate(avols): put('volumes/acevol/DEMO.' + ('ACE' if i == 0 else f'C{i - 1:02d}'), v)
    E('volumes/acevol/DEMO.ACE', ['CODEVIEW'], volumes=len(avols) - 1)
    for i in range(1, len(avols)): E(f'volumes/acevol/DEMO.C{i - 1:02d}', [], 'None', partof=True)

    # ---- MAME CHD hard disks and CD-ROMs (made with MAME's own chdman when it is available)
    CHDMAN = '/opt/work/chdman/chdman'
    if os.path.exists(CHDMAN):
        import subprocess as _sp, tempfile, shutil as _sh
        tmp = tempfile.mkdtemp()
        hd = open(os.path.join(OUT, 'images/harddisk.img'), 'rb').read()
        def chdman(*a):
            _sp.run([CHDMAN] + list(a) + ['-f'], stdout=_sp.DEVNULL, stderr=_sp.DEVNULL, check=True)
        open(f'{tmp}/hd.img', 'wb').write(hd)
        os.makedirs(os.path.join(OUT, 'chd/hd'), exist_ok=True)
        chdman('createhd', '-i', f'{tmp}/hd.img', '-o', os.path.join(OUT, 'chd/hd/GAMEHD.CHD'))
        E('chd/hd/GAMEHD.CHD', ['WATCOM', 'MAP'])
        # MAME romset layout: the clone's CHD stores only differences from the parent's CHD
        os.makedirs(os.path.join(OUT, 'chd/romset/parentgame'), exist_ok=True); os.makedirs(os.path.join(OUT, 'chd/romset/clonegame'), exist_ok=True)
        _sh.copy(os.path.join(OUT, 'chd/hd/GAMEHD.CHD'), os.path.join(OUT, 'chd/romset/parentgame/disk.chd'))
        hd2 = bytearray(hd); hd2[-65536:] = bytes(rnd.getrandbits(8) for _ in range(65536))
        open(f'{tmp}/hd2.img', 'wb').write(hd2)
        chdman('createhd', '-i', f'{tmp}/hd2.img', '-o', os.path.join(OUT, 'chd/romset/clonegame/disk.chd'), '-op', os.path.join(OUT, 'chd/romset/parentgame/disk.chd'))
        E('chd/romset/parentgame/disk.chd', ['WATCOM', 'MAP']); E('chd/romset/clonegame/disk.chd', ['WATCOM', 'MAP'])
        # CD-ROM: raw MODE1/2352 data track + audio track, and a plain MODE1/2048 image
        iso = open(os.path.join(OUT, 'images/gamecd_nojoliet.iso'), 'rb').read()
        def msf(l):
            l += 150; m, r = divmod(l, 4500); s2, f = divmod(r, 75); b = lambda x: ((x // 10) << 4) | (x % 10)
            return bytes([b(m), b(s2), b(f)])
        raw = b''.join(b'\x00' + b'\xff' * 10 + b'\x00' + msf(i) + b'\x01' + iso[i * 2048:(i + 1) * 2048] + bytes(288) for i in range(len(iso) // 2048))
        open(f'{tmp}/t1.bin', 'wb').write(raw); open(f'{tmp}/t2.bin', 'wb').write(bytes(rnd.getrandbits(8) for _ in range(2352 * 150)))
        open(f'{tmp}/cd.cue', 'w').write('FILE "t1.bin" BINARY\n  TRACK 01 MODE1/2352\n    INDEX 01 00:00:00\nFILE "t2.bin" BINARY\n  TRACK 02 AUDIO\n    INDEX 01 00:00:00\n')
        open(f'{tmp}/g.iso', 'wb').write(iso); open(f'{tmp}/iso.cue', 'w').write('FILE "g.iso" BINARY\n  TRACK 01 MODE1/2048\n    INDEX 01 00:00:00\n')
        os.makedirs(os.path.join(OUT, 'chd/cd'), exist_ok=True)
        chdman('createcd', '-i', f'{tmp}/cd.cue', '-o', os.path.join(OUT, 'chd/cd/GAMECD.CHD'))
        chdman('createcd', '-i', f'{tmp}/iso.cue', '-o', os.path.join(OUT, 'chd/cd/GAMECD2.CHD'), '-c', 'cdzl')
        E('chd/cd/GAMECD.CHD', ['COFF_SYMS']); E('chd/cd/GAMECD2.CHD', ['COFF_SYMS'])
        # zstd-compressed CHDs cannot be read yet: must be reported, not crash
        os.makedirs(os.path.join(OUT, 'chd/zstd'), exist_ok=True)
        chdman('createhd', '-i', f'{tmp}/hd.img', '-o', os.path.join(OUT, 'chd/zstd/ZSTDHD.CHD'), '-c', 'zstd')
        E('chd/zstd/ZSTDHD.CHD', [], 'Weak', partial_ok=True, problems=['unsupported'])
        _sh.rmtree(tmp)

    # ---- 7. damaged and unusual containers (incomplete downloads, bad sectors, embedded cabinets)
    big = bytes(rnd.getrandbits(8) for _ in range(90000))
    z = zipit({'TC20DBG.EXE': dbg('TC20DBG.EXE'), 'MUSIC.DAT': big}, zipfile.ZIP_STORED)
    put('damaged/HALFDL.ZIP', z[:int(len(z) * 0.7)]); E('damaged/HALFDL.ZIP', ['BORLAND_TD'], partial_ok=True, problems=['corrupt'])
    a = tool_archive('arj a -m1 -y {arc} {files}', {'MSC5DBG.EXE': dbg('MSC5DBG.EXE'), 'MUSIC.DAT': big}, '.ARJ')
    put('damaged/HALFDL.ARJ', a[:int(len(a) * 0.7)]); E('damaged/HALFDL.ARJ', ['CODEVIEW'], partial_ok=True, problems=['corrupt'])
    l = tool_archive('lha ao5q {arc} {files}', {'W16WAT.EXE': dbg('W16WAT.EXE'), 'ZMUSIC.DAT': big}, '.LZH')   # LHa stores in name order
    put('damaged/HALFDL.LZH', l[:int(len(l) * 0.7)]); E('damaged/HALFDL.LZH', ['WATCOM'], partial_ok=True, problems=['corrupt'])
    c = W.cab_mszip({'TP70DBG.EXE': dbg('TP70DBG.EXE'), 'MUSIC.DAT': big})
    put('damaged/HALFDL.CAB', c[:int(len(c) * 0.8)]); E('damaged/HALFDL.CAB', ['BORLAND_TD'], partial_ok=True, problems=['corrupt'])
    # one flipped byte in a stored entry far from the debug data: CRC error reported, symbols still found
    zc = bytearray(zipit({'QCDBG.EXE': dbg('QCDBG.EXE')}, zipfile.ZIP_STORED)); zc[200] ^= 0xFF
    put('damaged/BADCRC.ZIP', bytes(zc)); E('damaged/BADCRC.ZIP', ['CODEVIEW'], partial_ok=True, problems=['crc'])
    # floppy with unreadable (zeroed) sectors in the middle; the debug file before them survives
    fimg = bytearray(W.fat_image({'ZTCDBG.EXE': dbg('ZTCDBG.EXE'), 'BIGDATA.DAT': big * 4}, 1474560))
    fimg[900 * 1024:1000 * 1024] = bytes(100 * 1024)
    put('damaged/BADSECT.IMG', bytes(fimg)); E('damaged/BADSECT.IMG', ['CODEVIEW'], partial_ok=True)
    # an installer data file with a cabinet stored inside it
    put('damaged/INSTALL.DAT', b'SETUPDATA\x1a' + bytes(5000) + W.cab_mszip({'TASMDBG.EXE': dbg('TASMDBG.EXE'), 'README.TXT': b'hello' * 300}) + b'\x00' * 333)
    E('damaged/INSTALL.DAT', ['BORLAND_TD'])
    # random garbage named like archives must not crash or produce findings
    for ext in ('ZIP', 'ARJ', 'LZH', 'ARC', 'ZOO', 'CAB', 'RAR', '7Z', 'IMG', 'TD0', 'IMD'):
        g = bytes(rnd.getrandbits(8) for _ in range(30000))
        put(f'damaged/garbage/NOISE.{ext}', g); E(f'damaged/garbage/NOISE.{ext}', [], 'Weak', partial_ok=True)

    json.dump(expect, open(os.path.join(OUT, '..', 'corpus_expected.json'), 'w'), indent=1)
    print(len(expect), 'expectations written')

if __name__ == '__main__':
    main()
