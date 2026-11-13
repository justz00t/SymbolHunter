using System;
using System.Collections.Generic;
using System.Linq;

namespace SymbolHunter.Core
{
    /// <summary>Identifies archives, disk images and executables and knows how to open them.</summary>
    public static class Sniffer
    {
        static readonly HashSet<string> cdExts = new HashSet<string> { ".iso", ".bin", ".img", ".mdf", ".nrg", ".cdi", ".raw", ".b5i", ".pdi", ".ccd", ".ima", ".cue", ".toc", ".dao", ".tao", ".gi", ".bwi", ".c2d", ".udf" };

        static FormatInfo Arc(string id, string desc, Func<DataSource, string, ISiblingProvider, Container> open)
        { return new FormatInfo { Kind = FormatKind.Archive, Id = id, Description = desc, Open = open }; }
        static FormatInfo Img(string id, string desc, Func<DataSource, string, ISiblingProvider, Container> open)
        { return new FormatInfo { Kind = FormatKind.Image, Id = id, Description = desc, Open = open }; }
        static FormatInfo Unsupported(FormatKind k, string id, string desc, string why)
        { return new FormatInfo { Kind = k, Id = id, Description = desc, Supported = false, UnsupportedReason = why }; }

        public static FormatInfo Identify(DataSource s, string name)
        {
            long len = s.Length;
            if (len < 4) return null;
            var h = s.ReadBytes(0, (int)Math.Min(len, 65536));
            string ext = PathUtil.Ext(name);

            // ---------------- archives
            if (ZipContainer.Probe(h)) return Arc("ZIP", "ZIP archive", (d, n, sib) => new ZipContainer(d));
            if (h[0] == 0x60 && h[1] == 0xEA && ArjContainer.Probe(s)) return Arc("ARJ", "ARJ archive", (d, n, sib) => new ArjContainer(d, n, sib));
            if (h.Length > 21 && h[2] == '-' && h[6] == '-' && LzhContainer.ValidHeader(s, 0)) return Arc("LZH", "LHA/LZH archive", (d, n, sib) => new LzhContainer(d));
            if (RarContainer.Probe(h)) return Arc("RAR", "RAR archive", (d, n, sib) => new RarContainer(d, n, sib));
            if (Rar14Container.Probe(h)) return Arc("RAR13", "RAR 1.3 archive", (d, n, sib) => new Rar14Container(d, n, sib));
            if (SevenZipContainer.Probe(h)) return Arc("7Z", "7-Zip archive", (d, n, sib) => new SevenZipContainer(d));
            if (CabContainer.Probe(h)) return Arc("CAB", "Microsoft CAB", (d, n, sib) => new CabContainer(d, n, sib));
            if (ZooContainer.Probe(h)) return Arc("ZOO", "ZOO archive", (d, n, sib) => new ZooContainer(d));
            if (MsCompressContainer.Probe(h)) return Arc("SZDD", "MS-DOS COMPRESS file", (d, n, sib) => new MsCompressContainer(d, n));
            var single = SingleStreamContainer.Probe(h);
            if (single != null) return Arc(single.ToUpperInvariant(), single + " compressed file", (d, n, sib) => new SingleStreamContainer(d, n, single));
            if (TarContainer.Probe(h)) return Arc("TAR", "tar archive", (d, n, sib) => new TarContainer(d));
            if (h.Length > 14 && Bin.Match(h, 7, "**ACE**")) return Arc("ACE", "ACE archive", (d, n, sib) => new AceContainer(d, n, sib));
            if (Bin.Match(h, 0, "HLSQZ")) return Unsupported(FormatKind.Archive, "SQZ", "SQZ archive", "SQZ compression is not supported");
            if (h.Length > 8 && h[0] == 0x13 && h[1] == 0x5D && h[2] == 0x65 && h[3] == 0x8C) return Arc("IS3", "InstallShield 3 archive", (d, n, sib) => new InstallShield3Container(d));
            if (Bin.Match(h, 0, "HA") && (ext == ".ha") && h.Length > 4) return Unsupported(FormatKind.Archive, "HA", "HA archive", "HA compression is not supported");
            if (Bin.Match(h, 0, "DMS!")) return Unsupported(FormatKind.Image, "DMS", "Amiga DMS image", "Amiga DMS is not supported");
            if (ArcContainer.Probe(h) && (ext == ".arc" || ext == ".pak" || ext == ".ark" || ext == ".sdn" || LooksLikeArcChain(s))) return Arc("ARC", "ARC/PAK archive", (d, n, sib) => new ArcContainer(d));

            if (!Bin.Match(h, 0, "MZ") && !Bin.Match(h, 0, "ZM") && (ext == ".zip" || ext == ".exe" || ext == ".z01" || len < 64L * 1024 * 1024) && ZipContainer.ProbeEndRecord(s))
                return Arc("ZIP", "ZIP archive (data before the first entry)", (d, n, sib) => new ZipContainer(d));

            // ---------------- floppy dumps and virtual disks
            var fd = FloppyDumpContainer.Probe(h);
            if (fd != null) return Img(fd.ToUpperInvariant(), fd + " floppy image", (d, n, sib) => new FloppyDumpContainer(d, fd));
            if (Bin.Match(h, 0, "HXCPICFE") || Bin.Match(h, 0, "HXCHFEV3")) return Unsupported(FormatKind.Image, "HFE", "HxC HFE bitstream image", "convert HFE to IMG first (HxC Floppy Emulator software)");
            if (Bin.Match(h, 0, "SCP")) { if (ext == ".scp") return Unsupported(FormatKind.Image, "SCP", "SuperCard Pro flux image", "flux images need decoding to IMG first"); }
            if (Bin.Match(h, 0, "CAPS")) return Unsupported(FormatKind.Image, "IPF", "IPF image", "IPF images need conversion first");
            if (VhdContainer.Probe(s)) return Img("VHD", "Virtual PC disk", (d, n, sib) => new VhdContainer(d));
            if (ChdFile.Probe(h)) return Img("CHD", "MAME CHD (hard disk / CD-ROM)", (d, n, sib) => new ChdContainer(d, n, sib));

            // ---------------- optical
            if (len >= 17 * 2048)
            {
                var pvd = s.ReadBytes(16 * 2048, 8);
                if (pvd.Length == 8 && pvd[1] == 'C' && Bin.Match(pvd, 1, "CD001")) return Img("ISO", "ISO 9660 CD image", (d, n, sib) => new IsoContainer(d, null));
                if (IsoContainer.ProbeHsf(s)) return Img("HSF", "High Sierra CD image", (d, n, sib) => new IsoContainer(d, null));
                bool sync = h.Length > 12 && h[0] == 0 && h[1] == 0xFF && h[10] == 0xFF && h[11] == 0;
                if (sync || cdExts.Contains(ext) || len > 40L * 1024 * 1024)
                {
                    string layout;
                    if (!FatContainer.LooksLikeBpb(h) && MbrContainer.Parse(s).Count == 0 && IsoContainer.Locate(s, out layout) != null)
                        return Img("ISO", "CD image (" + layout + ")", (d, n, sib) => new IsoContainer(d, null));
                }
            }

            // ---------------- FAT and partitioned disks
            if (h.Length >= 512 && FatContainer.LooksLikeBpb(h)) return Img("FAT", "FAT disk image", (d, n, sib) => new FatContainer(d));
            if (h.Length >= 1024 && FatContainer.LooksLikeDos1(s, h)) return Img("FAT", "DOS 1.x disk image (no BPB)", (d, n, sib) => new FatContainer(d));
            if (h.Length >= 512 && MbrContainer.Parse(s).Count > 0) return Img("MBR", "hard disk image", (d, n, sib) => new MbrContainer(d));

            // ---------------- executables (debug scan) and self-extractors
            if (h.Length >= 64 && (Bin.Match(h, 0, "MZ") || Bin.Match(h, 0, "ZM")))
            {
                var sfx = FindSfx(s, h);
                if (sfx != null) return sfx;
                return new FormatInfo { Kind = FormatKind.Executable, Id = "EXE", Description = "executable" };
            }

            // ---------------- diskette images with a header in front (DiskDupe, IBM SaveDskF, Anex86, DIM, emulator formats ...)
            if (h.Length >= 2 && h[0] == 0xAA && h[1] == 0x5A)
                return Unsupported(FormatKind.Image, "DSKF", "IBM SaveDskF compressed diskette image", "compressed IBM SaveDskF images are not supported; expand with LOADDSKF or SAVEDSKF /D first");
            long hdrOff = FatContainer.FindBehindHeader(s, h);
            if (hdrOff > 0)
                return new FormatInfo { Kind = FormatKind.Image, Id = "FAT", Description = "FAT diskette image behind a " + hdrOff + "-byte header", Open = (d, n, sib) => new FatContainer(d.Slice(hdrOff, -1)) };

            // ---------------- cabinets inside other data (installer data files, dumps)
            if (Bin.IndexOf(h, "MSCF", 0, h.Length) >= 0 || len > h.Length)
            {
                var cabs = CabContainer.FindEmbedded(s, 32L << 20);
                if (cabs.Count == 1 && cabs[0].Key == 0) return Arc("CAB", "Microsoft CAB", (d, n, sib) => new CabContainer(d, n, sib));
                if (cabs.Count > 0)
                    return new FormatInfo { Kind = FormatKind.Archive, Id = "CAB-EMB", ScanSelf = true, Description = cabs.Count == 1 ? "Microsoft CAB inside other data" : cabs.Count + " Microsoft CABs inside other data",
                                            Open = (d, n, sib) => new CarvedContainer(d, CabContainer.FindEmbedded(d, 32L << 20), "cabinet", ".cab") };
            }
            return null;
        }

        static bool LooksLikeArcChain(DataSource s)
        {
            // two consecutive valid ARC headers, or one header followed by the end marker
            var h = s.ReadBytes(0, 29);
            int m = h[1];
            long cs = Bin.U32(h, 15);
            long next = (m == 1 ? 25 : 29) + cs;
            var n = s.ReadBytes(next, 29);
            if (n.Length >= 2 && n[0] == 0x1A && n[1] == 0) return true;
            return ArcContainer.Probe(n);
        }

        /// <summary>Looks for an archive appended to an EXE stub (PKSFX, ARJ SFX, LHA SFX, RAR SFX).</summary>
        static FormatInfo FindSfx(DataSource s, byte[] h)
        {
            int cblp = Bin.U16(h, 2), cp = Bin.U16(h, 4);
            long imageEnd = (long)cp * 512 - (cblp != 0 && cblp < 512 ? 512 - cblp : 0);
            if (imageEnd <= 0 || imageEnd > s.Length) imageEnd = Math.Min(s.Length, 0x200);
            if (ZipContainer.HasEndRecord(s))
            {
                try { var z = new ZipContainer(s); if (z.Entries().Any()) return new FormatInfo { Kind = FormatKind.Archive, Id = "ZIP-SFX", Description = "self-extracting ZIP", Open = (d, n, sib) => new ZipContainer(d) }; }
                catch { }
            }
            long scanFrom = Math.Max(0, Math.Min(imageEnd, s.Length) - 16);
            long arj = ArjContainer.FindArchive(s, scanFrom, 2 * 1024 * 1024);
            if (arj < 0 && imageEnd > 0x4000) arj = ArjContainer.FindArchive(s, 0x200, Math.Min(s.Length, 512 * 1024));
            if (arj >= 0) return new FormatInfo { Kind = FormatKind.Archive, Id = "ARJ-SFX", Description = "self-extracting ARJ", PayloadOffset = arj, Open = (d, n, sib) => new ArjContainer(d, n, sib) };
            long lzh = LzhContainer.FindArchive(s, scanFrom, 2 * 1024 * 1024);
            if (lzh < 0) lzh = LzhContainer.FindArchive(s, 0x200, Math.Min(s.Length, 128 * 1024));
            if (lzh >= 0) return new FormatInfo { Kind = FormatKind.Archive, Id = "LZH-SFX", Description = "self-extracting LHA", PayloadOffset = lzh, Open = (d, n, sib) => new LzhContainer(d) };
            var ov = s.ReadBytes(scanFrom, (int)Math.Min(s.Length - scanFrom, 4 * 1024 * 1024));
            int z7 = Bin.IndexOf(ov, new byte[] { (byte)'7', (byte)'z', 0xBC, 0xAF, 0x27, 0x1C }, 0, ov.Length);
            if (z7 >= 0) { long off7 = scanFrom + z7; return new FormatInfo { Kind = FormatKind.Archive, Id = "7Z-SFX", Description = "self-extracting 7-Zip", PayloadOffset = off7, Open = (d, n, sib) => new SevenZipContainer(d.Slice(off7, -1)) }; }
            for (int i = Bin.IndexOf(ov, "MSCF", 0, ov.Length); i >= 0; i = Bin.IndexOf(ov, "MSCF", i + 4, ov.Length))
            {
                var hb = s.ReadBytes(scanFrom + i, 40);
                if (CabContainer.Probe(hb) && Bin.U32(hb, 8) <= s.Length - scanFrom - i + 16) { long offc = scanFrom + i; return new FormatInfo { Kind = FormatKind.Archive, Id = "CAB-SFX", Description = "self-extracting CAB", PayloadOffset = offc, Open = (d, n, sib) => new CabContainer(d.Slice(offc, -1), n, sib) }; }
            }
            long ace = AceContainer.FindMainHeader(s, Math.Min(s.Length, 2 * 1024 * 1024));
            if (ace > 0) { long offa = ace; return new FormatInfo { Kind = FormatKind.Archive, Id = "ACE-SFX", Description = "self-extracting ACE", PayloadOffset = offa, Open = (d, n, sib) => new AceContainer(d, n, sib) }; }
            long rar = RarContainer.FindArchive(s, scanFrom, 2 * 1024 * 1024);
            if (rar >= 0) return new FormatInfo { Kind = FormatKind.Archive, Id = "RAR-SFX", Description = "self-extracting RAR", PayloadOffset = rar, Open = (d, n, sib) => new RarContainer(d, n, sib) };
            return null;
        }
    }
}
