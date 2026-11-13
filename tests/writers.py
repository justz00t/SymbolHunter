"""Minimal writers for test containers that have no reference tool here (validated against 7-Zip where possible)."""
import struct, zlib, io, os, datetime

def dos_datetime(dt=datetime.datetime(1994, 5, 17, 13, 37, 0)):
    d = ((dt.year - 1980) << 9) | (dt.month << 5) | dt.day
    t = (dt.hour << 11) | (dt.minute << 5) | (dt.second // 2)
    return d, t

# ------------------------------------------------------------------ FAT
GEOM = {  # size: (spc, root, spf, media, spt, heads)
    1474560: (1, 224, 9, 0xF0, 18, 2), 737280: (2, 112, 3, 0xF9, 9, 2), 368640: (2, 112, 2, 0xFD, 9, 2),
    163840: (1, 64, 1, 0xFE, 8, 1), 1228800: (1, 224, 7, 0xF9, 15, 2), 327680: (2, 112, 1, 0xFF, 8, 2)}

def short_name(n):
    n = n.upper()
    base, _, ext = n.partition('.')
    return (base[:8].ljust(8) + ext[:3].ljust(3)).encode('ascii')

def fat_image(files, size=1474560, label='GAMEDISK', nobpb=False, deleted=None, fat16=False, hidden=0):
    """files: dict 'DIR/NAME.EXT' -> bytes. deleted: dict name -> bytes (root dir, contiguous, FAT entries free)."""
    bps = 512
    if fat16:
        spc, root, media, rsv, nfats = 4, 512, 0xF8, 1, 2
        tot = size // bps
        clusters_est = tot // spc
        spf = (clusters_est * 2 + bps - 1) // bps + 1
        spt, heads = 63, 16
    else:
        spc, root, spf, media, spt, heads = GEOM[size]; rsv, nfats = 1, 2; tot = size // bps
    img = bytearray(size)
    root_secs = root * 32 // bps
    data_start = rsv + nfats * spf + root_secs
    nclusters = (tot - data_start) // spc
    fatbits = 16 if fat16 else 12
    fat = [0] * (nclusters + 2)
    fat[0] = 0xF00 | media if not fat16 else 0xFF00 | media
    fat[1] = 0xFFF if not fat16 else 0xFFFF
    eoc = 0xFFF if not fat16 else 0xFFFF
    nxt = [2]
    csize = spc * bps
    def alloc(data, mark=True):
        n = max(1, (len(data) + csize - 1) // csize)
        first = nxt[0]
        for i in range(n):
            c = first + i
            if mark: fat[c] = c + 1 if i < n - 1 else eoc
            pos = (data_start + (c - 2) * spc) * bps
            chunk = data[i * csize:(i + 1) * csize]
            img[pos:pos + len(chunk)] = chunk
        nxt[0] += n
        return first
    d, t = dos_datetime()
    def entry(name11, attr, first, sz):
        return name11 + bytes([attr]) + bytes(10) + struct.pack('<HHHI', t, d, first, sz)
    # build tree
    tree = {}
    for path, data in files.items():
        parts = path.split('/')
        node = tree
        for p in parts[:-1]: node = node.setdefault(p.upper() + '/', {})
        node[parts[-1].upper()] = data
    def write_dir(node, parent_cluster, is_root):
        ents = bytearray()
        for name, val in node.items():
            if name.endswith('/'):
                sub_first = nxt[0]; nxt[0] += 1; fat[sub_first] = eoc
                sub = entry(b'.          ', 0x10, sub_first, 0) + entry(b'..         ', 0x10, 0 if is_root else parent_cluster, 0)
                sub += write_dir(val, sub_first, False)
                if len(sub) > csize: raise ValueError('subdir too big for test writer')
                pos = (data_start + (sub_first - 2) * spc) * bps
                img[pos:pos + len(sub)] = sub
                ents += entry(short_name(name[:-1]), 0x10, sub_first, 0)
            else:
                first = alloc(val) if len(val) else 0
                ents += entry(short_name(name), 0x20, first, len(val))
        return bytes(ents)
    rootents = bytearray()
    if not nobpb: rootents += short_name(label)[:11] + bytes([0x08]) + bytes(10) + struct.pack('<HHHI', t, d, 0, 0)
    rootents += write_dir(tree, 0, True)
    if deleted:
        for name, data in deleted.items():
            first = alloc(data, mark=False)
            e = bytearray(entry(short_name(name), 0x20, first, len(data))); e[0] = 0xE5
            rootents += e
    rp = (rsv + nfats * spf) * bps
    img[rp:rp + len(rootents)] = rootents
    # FAT table
    if fatbits == 12:
        fb = bytearray(spf * bps)
        for i, v in enumerate(fat):
            off = i + i // 2
            if off + 1 >= len(fb): break
            if i & 1: fb[off] = (fb[off] & 0x0F) | ((v << 4) & 0xF0); fb[off + 1] = (v >> 4) & 0xFF
            else: fb[off] = v & 0xFF; fb[off + 1] = (fb[off + 1] & 0xF0) | ((v >> 8) & 0x0F)
    else:
        fb = bytearray(spf * bps)
        for i, v in enumerate(fat):
            if i * 2 + 1 < len(fb): struct.pack_into('<H', fb, i * 2, v)
    for k in range(nfats):
        p = (rsv + k * spf) * bps
        img[p:p + len(fb)] = fb
    if not nobpb:
        img[0:3] = b'\xEB\x3C\x90'; img[3:11] = b'MSDOS5.0'
        struct.pack_into('<HBHBHHBHHHII', img, 11, bps, spc, rsv, nfats, root, tot if tot < 65536 else 0, media, spf, spt, heads, hidden, tot if tot >= 65536 else 0)
        img[36] = 0x80 if fat16 else 0; img[38] = 0x29; struct.pack_into('<I', img, 39, 0x1234ABCD)
        img[43:54] = label.upper().ljust(11)[:11].encode(); img[54:62] = (b'FAT16   ' if fat16 else b'FAT12   ')
        img[62] = 0xFA; img[510:512] = b'\x55\xAA'
    else:
        img[0] = 0xE9; img[1] = 0x2C; img[2] = 0x00
    return bytes(img)

def mbr_disk(partition_image, lba=63, ptype=6):
    """Hard disk image: MBR + one partition."""
    total = lba * 512 + len(partition_image)
    img = bytearray(total)
    e = 446
    img[e] = 0x80; img[e + 4] = ptype
    struct.pack_into('<II', img, e + 8, lba, len(partition_image) // 512)
    img[510:512] = b'\x55\xAA'
    img[lba * 512:] = partition_image
    return bytes(img)

def vhd_fixed(raw):
    footer = bytearray(512)
    footer[0:8] = b'conectix'; struct.pack_into('>I', footer, 8, 2); struct.pack_into('>I', footer, 12, 0x00010000)
    struct.pack_into('>Q', footer, 16, 0xFFFFFFFFFFFFFFFF); footer[28:32] = b'test'
    struct.pack_into('>Q', footer, 40, len(raw)); struct.pack_into('>Q', footer, 48, len(raw))
    struct.pack_into('>I', footer, 60, 2)
    csum = (~sum(footer)) & 0xFFFFFFFF
    struct.pack_into('>I', footer, 64, csum)
    return raw + bytes(footer)

# ------------------------------------------------------------------ floppy dump formats
def sectors_of(img, spt, heads):
    """yield (cyl, head, sec(1-based), data)"""
    n = len(img) // 512
    for lba in range(n):
        c = lba // (spt * heads); h = (lba // spt) % heads; s = lba % spt + 1
        yield c, h, s, img[lba * 512:(lba + 1) * 512]

def imd(img, spt, heads):
    out = bytearray(b'IMD 1.18: 17/05/1994 13:37:00\r\ntest image\x1a')
    cyls = len(img) // (512 * spt * heads)
    for c in range(cyls):
        for h in range(heads):
            out += bytes([5, c, h, spt, 2]) + bytes(range(1, spt + 1))
            for s in range(spt):
                lba = (c * heads + h) * spt + s
                d = img[lba * 512:(lba + 1) * 512]
                if d == bytes([d[0]]) * 512: out += bytes([2, d[0]])
                else: out += b'\x01' + d
    return bytes(out)

def td0_crc(b, crc=0):
    for x in b:
        crc ^= x << 8
        for _ in range(8): crc = ((crc << 1) ^ 0xA097) if crc & 0x8000 else crc << 1
        crc &= 0xFFFF
    return crc

def td0(img, spt, heads, advanced=False):
    body = bytearray()
    cyls = len(img) // (512 * spt * heads)
    for c in range(cyls):
        for h in range(heads):
            th = bytes([spt, c, h]); body += th + bytes([td0_crc(th) & 0xFF])
            for s in range(spt):
                lba = (c * heads + h) * spt + s
                d = img[lba * 512:(lba + 1) * 512]
                sh = bytes([c, h, s + 1, 2, 0, td0_crc(d) & 0xFF]); body += sh
                if d == bytes([d[0]]) * 512:
                    payload = b'\x01' + struct.pack('<H', 256) + bytes([d[0], d[0]])
                elif s % 3 == 1:   # exercise RLE encoding (method 2): literal blocks only
                    payload = b'\x02'
                    for k in range(0, 512, 128): payload += bytes([0, 128]) + d[k:k + 128]
                else:
                    payload = b'\x00' + d
                body += struct.pack('<H', len(payload)) + payload
    body += b'\xFF\x00\x00\x00'
    hdr = bytearray(b'td' if advanced else b'TD') + bytes([0, 0, 0x15, 2, 4, 0, 1, heads, 0, 0])
    struct.pack_into('<H', hdr, 10, td0_crc(hdr[:10]))
    if advanced: body = lzhuf_encode_literals(bytes(body))
    return bytes(hdr) + bytes(body)

def lzhuf_encode_literals(data):
    """Okumura LZHUF stream that codes every byte as a literal (adaptive Huffman only)."""
    N_CHAR = 256 - 2 + 60; T = N_CHAR * 2 - 1; R = T - 1; MAX_FREQ = 0x8000
    freq = [0] * (T + 1); prnt = [0] * (T + N_CHAR); son = [0] * T
    for i in range(N_CHAR): freq[i] = 1; son[i] = i + T; prnt[i + T] = i
    i, j = 0, N_CHAR
    while j <= R: freq[j] = freq[i] + freq[i + 1]; son[j] = i; prnt[i] = prnt[i + 1] = j; i += 2; j += 1
    freq[T] = 0xFFFF; prnt[R] = 0
    def reconst():
        j = 0
        for i in range(T):
            if son[i] >= T: freq[j] = (freq[i] + 1) // 2; son[j] = son[i]; j += 1
        i = 0; j = N_CHAR
        while j < T:
            k = i + 1; f = freq[j] = freq[i] + freq[k]
            k = j - 1
            while f < freq[k]: k -= 1
            k += 1
            freq[k + 1:j + 1] = freq[k:j]; freq[k] = f
            son[k + 1:j + 1] = son[k:j]; son[k] = i
            i += 2; j += 1
        for i in range(T):
            k = son[i]
            if k >= T: prnt[k] = i
            else: prnt[k] = prnt[k + 1] = i
    def update(c):
        if freq[R] == MAX_FREQ: reconst()
        c = prnt[c + T]
        while True:
            freq[c] += 1; k = freq[c]
            l = c + 1
            if k > freq[l]:
                l += 1
                while k > freq[l]: l += 1
                l -= 1
                freq[c] = freq[l]; freq[l] = k
                i = son[c]; prnt[i] = l
                if i < T: prnt[i + 1] = l
                j = son[l]; son[l] = i
                prnt[j] = c
                if j < T: prnt[j + 1] = c
                son[c] = j
                c = l
            c = prnt[c]
            if c == 0: break
    bits = []
    for b in data:
        code = []; k = prnt[b + T]       # position of the leaf in the tree
        while True:
            code.append(k & 1)            # odd position = second child = bit 1
            k = prnt[k]
            if k == R: break
        bits.extend(reversed(code))
        update(b)
    # pad and pack MSB-first
    while len(bits) % 8: bits.append(0)
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for k in range(8): v = (v << 1) | bits[i + k]
        out.append(v)
    return bytes(out) + b'\0' * 8

def cqm(img, spt, heads):
    cyls = len(img) // (512 * spt * heads)
    h = bytearray(133)
    h[0:3] = b'CQ\x14'; struct.pack_into('<H', h, 3, 512); h[5] = 1; struct.pack_into('<H', h, 6, 1); h[8] = 2
    struct.pack_into('<H', h, 9, 224); struct.pack_into('<H', h, 0x0B, len(img) // 512); h[0x0D] = 0xF0
    struct.pack_into('<H', h, 0x0E, 9); struct.pack_into('<H', h, 0x10, spt); struct.pack_into('<H', h, 0x12, heads)
    h[0x1C:0x1C + 9] = b'test disk'; h[0x5A] = cyls; h[0x5B] = cyls; h[0x74] = 1
    body = bytearray(); i = 0
    while i < len(img):
        # run of identical bytes?
        j = i
        while j < len(img) and j - i < 30000 and img[j] == img[i]: j += 1
        if j - i >= 8:
            body += struct.pack('<h', -(j - i)) + bytes([img[i]]); i = j; continue
        k = i
        while k < len(img) and k - i < 30000:
            if k + 8 <= len(img) and img[k:k + 8] == bytes([img[k]]) * 8: break
            k += 1
        body += struct.pack('<h', k - i) + img[i:k]; i = k
    h[132] = (-sum(h[:132])) & 0xFF
    return bytes(h) + bytes(body)

# ------------------------------------------------------------------ archives without reference tools
def arc_stored_and_packed(files):
    """ARC archive: method 2 (stored) and method 3 (packed, RLE90) entries."""
    out = bytearray()
    d, t = dos_datetime()
    for i, (name, data) in enumerate(files.items()):
        crc = 0
        for b in data:
            crc ^= b
            for _ in range(8): crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
        method = 3 if i % 2 else 2
        payload = rle90(data) if method == 3 else data
        nm = name.upper().encode()[:12].ljust(13, b'\0')
        out += b'\x1a' + bytes([method]) + nm + struct.pack('<IHHHI', len(payload), d, t, crc, len(data)) + payload
    out += b'\x1a\x00'
    return bytes(out)

def rle90(data):
    out = bytearray(); i = 0
    while i < len(data):
        c = data[i]; j = i + 1
        while j < len(data) and data[j] == c and j - i < 255: j += 1
        run = j - i
        if c == 0x90:
            out += b'\x90\x00'; i += 1; continue
        if run >= 3: out += bytes([c, 0x90, run]); i = j
        else: out.append(c); i += 1
    return bytes(out)

def szdd(data, missing=b'E'):
    """MS COMPRESS SZDD with a greedy LZSS encoder."""
    out = bytearray(b'SZDD\x88\xf0\x27\x33A') + missing + struct.pack('<I', len(data))
    win = bytearray(b' ' * 4096); pos = 4096 - 16
    i = 0
    while i < len(data):
        flags = 0; chunk = bytearray()
        for bit in range(8):
            if i >= len(data): break
            best_len = 0; best_pos = 0
            if i >= 3:
                start = max(0, i - 4000)
                seg = bytes(data[start:i])
                for L in range(min(18, len(data) - i), 2, -1):
                    k = seg.rfind(data[i:i + L])
                    if k >= 0 and start + k + L <= i:
                        best_len = L; best_pos = (pos - (i - (start + k))) & 0xFFF; break
            if best_len >= 3:
                chunk += bytes([best_pos & 0xFF, ((best_pos >> 4) & 0xF0) | (best_len - 3)])
                for k in range(best_len): win[pos] = data[i]; pos = (pos + 1) & 0xFFF; i += 1
            else:
                flags |= 1 << bit; chunk.append(data[i]); win[pos] = data[i]; pos = (pos + 1) & 0xFFF; i += 1
        out.append(flags); out += chunk
    return bytes(out)

def cab_mszip(files):
    """Single-folder MSZIP cabinet."""
    blob = b''.join(files.values())
    blocks = []; prev = b''
    for i in range(0, max(1, len(blob)), 32768):
        chunk = blob[i:i + 32768]
        co = zlib.compressobj(9, zlib.DEFLATED, -15, zdict=prev) if prev else zlib.compressobj(9, zlib.DEFLATED, -15)
        comp = b'CK' + co.compress(chunk) + co.flush()
        blocks.append((comp, len(chunk)))
        prev = (prev + chunk)[-32768:]
    names = list(files.keys())
    hdr_size = 36; folder_size = 8
    files_size = sum(16 + len(n) + 1 for n in names)
    coff_files = hdr_size + folder_size
    data_start = coff_files + files_size
    total = data_start + sum(8 + len(c) for c, _ in blocks)
    out = bytearray(b'MSCF') + struct.pack('<IIIII', 0, total, 0, coff_files, 0) + bytes([3, 1]) + struct.pack('<HHHHH', 1, len(names), 0, 0x4321, 0)
    out += struct.pack('<IHH', data_start, len(blocks), 1)
    d, t = dos_datetime(); off = 0
    for n in names:
        out += struct.pack('<IIHHHH', len(files[n]), off, 0, d, t, 0x20) + n.encode() + b'\0'
        off += len(files[n])
    for comp, ulen in blocks:
        out += struct.pack('<IHH', 0, len(comp), ulen) + comp
    return bytes(out)

def spanned_zip(zbytes, parts):
    """Turns a normal ZIP into a PKZIP-style spanned set (disk-relative offsets). Returns list of part bytes."""
    eocd = zbytes.rfind(b'PK\x05\x06')
    cd_size, cd_off = struct.unpack_from('<II', zbytes, eocd + 12)
    data_end = cd_off
    cut = [0] + [data_end * k // parts for k in range(1, parts)] + [data_end]
    starts = cut[:-1]
    def disk_of(off):
        for k in range(len(starts) - 1, -1, -1):
            if off >= starts[k]: return k
        return 0
    cd = bytearray(zbytes[cd_off:cd_off + cd_size]); p = 0
    while p < len(cd):
        nl, xl, cl = struct.unpack_from('<HHH', cd, p + 28)
        lo = struct.unpack_from('<I', cd, p + 42)[0]
        k = disk_of(lo)
        struct.pack_into('<H', cd, p + 34, k); struct.pack_into('<I', cd, p + 42, lo - starts[k])
        p += 46 + nl + xl + cl
    last = len(starts) - 1
    out = [bytearray(zbytes[starts[k]:cut[k + 1]]) for k in range(len(starts))]
    last_data_len = len(out[last])
    e = bytearray(zbytes[eocd:])
    struct.pack_into('<HHHH', e, 4, last, last, sum(1 for _ in range(0)) or struct.unpack_from('<H', zbytes, eocd + 8)[0], struct.unpack_from('<H', zbytes, eocd + 10)[0])
    struct.pack_into('<I', e, 16, last_data_len)
    out[last] += cd + e
    return [bytes(o) for o in out]

def rar13_checksum(b):
    c = 0
    for x in b:
        c = (c + x) & 0xFFFF; c = ((c << 1) | (c >> 15)) & 0xFFFF
    return c

def rar13(files, volume_size=None):
    """RAR 1.3/1.4 ('RE~^') archive with stored entries; with volume_size, a list of volumes
    (.RAR, .R00, ...) where files are split across volumes with the split-before/after flags."""
    t = dos_datetime()
    ftime = struct.unpack('<I', struct.pack('<HH', t[1], t[0]))[0] if isinstance(t, tuple) else 0
    vols = [bytearray(b'RE~^' + struct.pack('<HB', 7, 1 if volume_size else 0))]
    def hdr(name, part, unp, ck, flags):
        nb = name.encode('latin1')
        return struct.pack('<IIHHIBBBBB', len(part), unp, ck, 21 + len(nb), ftime, 0x20, flags, 2, len(nb), 0) + nb
    for name, data in files.items():
        ck = rar13_checksum(data); rest = data; first = True
        while True:
            cur = vols[-1]
            room = (volume_size - len(cur) - 21 - len(name)) if volume_size else len(rest)
            if volume_size and room <= 0:
                vols.append(bytearray(b'RE~^' + struct.pack('<HB', 7, 1))); continue
            part, rest2 = rest[:room], rest[room:]
            flags = (0 if first else 0x01) | (0x02 if rest2 else 0)
            cur += hdr(name, part, len(data), ck, flags) + part
            first = False; rest = rest2
            if not rest: break
            vols.append(bytearray(b'RE~^' + struct.pack('<HB', 7, 1)))
    return [bytes(v) for v in vols] if volume_size else bytes(vols[0])

def ace_crc32(b):
    return (~zlib.crc32(b)) & 0xFFFFFFFF   # ACE: standard CRC-32 without the final inversion

def ace(files, volume_size=None):
    """ACE 2.0 archive with stored entries; with volume_size, volumes (.ACE, .C00, ...) with continued files."""
    t = dos_datetime(); dt = struct.unpack('<I', struct.pack('<HH', t[1], t[0]))[0]
    def hdr(body):
        return struct.pack('<HH', ace_crc32(body) & 0xFFFF, len(body)) + body
    def main(vol, multi):
        flags = (1 << 8) | ((1 << 11) if multi else 0)
        return hdr(struct.pack('<BH', 0, flags) + b'**ACE**' + struct.pack('<BBBBI', 20, 20, 2, vol, dt) + bytes(8) + b'\x00')
    def fhdr(name, part, orig, crc, flags):
        nb = name.encode('latin1')
        body = struct.pack('<BH', 1, 1 | flags) + struct.pack('<IIIIIBBHHH', len(part), orig, dt, 0x20, crc, 0, 0, 0x0A, 0, len(nb)) + nb
        return hdr(body)
    multi = volume_size is not None
    vols = [bytearray(main(0, multi))]
    for name, data in files.items():
        crc = ace_crc32(data); rest = data; first = True
        while True:
            cur = vols[-1]
            room = (volume_size - len(cur) - 40 - len(name)) if multi else len(rest)
            if multi and room <= 0:
                vols.append(bytearray(main(len(vols), multi))); continue
            part, rest2 = rest[:room], rest[room:]
            flags = (0 if first else (1 << 12)) | ((1 << 13) if rest2 else 0)
            cur += fhdr(name, part, len(data), crc, flags) + part
            first = False; rest = rest2
            if not rest: break
            vols.append(bytearray(main(len(vols), multi)))
    return [bytes(v) for v in vols] if multi else bytes(vols[0])
