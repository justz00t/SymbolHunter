using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SymbolHunter.Core;

namespace SymbolHunter.Cli
{
    /// <summary>Developer entry points used by the test harness (invoked through PowerShell on .NET 8).</summary>
    public static class DevTools
    {
        public static void ScanFile(string path)
        {
            using (var src = new FileSource(path))
            {
                var r = DebugScanner.Scan(src, Path.GetFileName(path));
                Console.WriteLine(Path.GetFileName(path) + " [" + r.FileType + (r.Packer != null ? ", packed " + r.Packer : "") + "]");
                foreach (var f in r.Findings) Console.WriteLine("   " + f.Strength + "  " + f);
            }
        }

        /// <summary>Scans a folder and writes JSON results (the test runner compares them with expectations).</summary>
        /// <summary>Checks that results arrive while the folder walk is still going.</summary>
        public static void StreamCheck(string root)
        {
            var sc = new Scanner(new ScanOptions { Threads = 2 });
            var sw = System.Diagnostics.Stopwatch.StartNew();
            string first = null;
            sc.ItemFinished += it => { if (first == null) first = "first item finished at " + sw.ElapsedMilliseconds + " ms while still walking folders: " + sc.Stats.Discovering + " (" + sc.Stats.Folders + " folders so far): " + it.RelPath; };
            var res = sc.Run(root);
            Console.WriteLine(first);
            Console.WriteLine("total " + sw.ElapsedMilliseconds + " ms, folders " + sc.Stats.Folders + ", items " + sc.Stats.TopItems + ", done " + sc.Stats.TopDone + ", results " + res.Count);
        }

        public static void Scan(string root, string json, string threads)
        {
            var opt = new ScanOptions { Threads = int.Parse(threads), ItemTimeout = TimeSpan.FromMinutes(5) };
            var sc = new Scanner(opt);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var res = sc.Run(root);
            Export.WriteJson(json, root, res, sc.Stats);
            Console.WriteLine("scanned " + res.Count + " items, " + sc.Stats.Files + " files, " + sc.Stats.Containers + " containers, " + sc.Stats.Hits + " findings in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s");
        }

        /// <summary>Dumps each entry of a CHD (logical disk or cooked CD tracks) to outPrefix.N.</summary>
        public static void ChdDump(string path, string outPrefix)
        {
            var sib = new DirSiblings(System.IO.Directory.GetFiles(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))));
            using (var fs = new FileSource(path))
            {
                var c = new ChdContainer(fs, System.IO.Path.GetFileName(path), sib);
                Console.WriteLine("#" + c.Description);
                foreach (var w in c.Warnings) Console.WriteLine("!" + w);
                int i = 0;
                foreach (var e in c.Entries())
                {
                    var d = e.Open();
                    using (var o = System.IO.File.Create(outPrefix + "." + i))
                    {
                        var buf = new byte[1 << 20];
                        for (long pos = 0; pos < d.Length; ) { int n = d.Read(pos, buf, 0, (int)Math.Min(buf.Length, d.Length - pos)); if (n <= 0) break; o.Write(buf, 0, n); pos += n; }
                    }
                    Console.WriteLine(e.Name + "|" + d.Length + "|" + e.Method);
                    i++;
                }
                if (outPrefix.EndsWith("+raw"))
                {
                    var chd = new ChdFile(fs);
                    var d = new ChdSource(chd);
                    using (var o = System.IO.File.Create(outPrefix + ".raw"))
                    {
                        var buf = new byte[1 << 20];
                        for (long pos = 0; pos < d.Length; ) { int n = d.Read(pos, buf, 0, (int)Math.Min(buf.Length, d.Length - pos)); if (n <= 0) break; o.Write(buf, 0, n); pos += n; }
                    }
                    foreach (var t in chd.CdTracks()) Console.WriteLine("track " + t.Number + " " + t.Type + " frames " + t.Frames + " chdframe " + t.ChdFrameStart);
                    Console.WriteLine("raw failed hunks: " + chd.FailedHunks + " unsupported: " + string.Join(",", chd.UnsupportedCodecs));
                }
                Console.WriteLine("failed hunks: " + c.FailedHunks);
            }
        }

        /// <summary>Scan with user YARA rules (rules: files or folders separated by ';').</summary>
        public static void ScanYara(string root, string json, string rules, string onContainers)
        {
            var msgs = new List<YaraMessage>();
            var set = YaraRuleSet.Compile(rules.Split(';'), msgs);
            foreach (var m in msgs) Console.WriteLine("  " + m);
            Console.WriteLine(set == null ? "no usable rules" : set.RuleCount + " rules from " + set.Files.Count + " files, libyara " + YaraRuleSet.Version);
            var opt = new ScanOptions { Threads = 2, Yara = set, YaraOnContainers = onContainers == "1" };
            var sc = new Scanner(opt);
            var res = sc.Run(root);
            Export.WriteJson(json, root, res, sc.Stats);
            foreach (var it in res.OrderBy(i => i.RelPath, StringComparer.OrdinalIgnoreCase))
                foreach (var h in it.Hits.Where(h => h.Finding.Kind == Kinds.Yara))
                    Console.WriteLine(it.RelPath + " | " + h.InnerPath + " | " + h.Finding.Strength + " | " + h.Finding.Label + " | " + h.Finding.Detail + " | " + string.Join("; ", h.Finding.Samples.Take(2)));
            if (set != null) set.Dispose();
        }

        /// <summary>Like Scan, with a per-item time limit in seconds (fuzz testing finds hangs this way).</summary>
        public static void ScanT(string root, string json, string threads, string seconds)
        {
            var opt = new ScanOptions { Threads = int.Parse(threads), ItemTimeout = TimeSpan.FromSeconds(int.Parse(seconds)) };
            var sc = new Scanner(opt);
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var res = sc.Run(root);
            Export.WriteJson(json, root, res, sc.Stats);
            Console.WriteLine("scanned " + res.Count + " items, " + sc.Stats.Files + " files, " + sc.Stats.Containers + " containers, " + sc.Stats.Hits + " findings in " + sw.Elapsed.TotalSeconds.ToString("0.0") + " s");
        }

        /// <summary>Lists a container's entries with size and CRC32 of the extracted data ("name|size|crc|note").</summary>
        public static void List(string path, string outFile)
        {
            using (var w = new StreamWriter(outFile))
            using (var src = new FileSource(path))
            {
                var fi = Sniffer.Identify(src, Path.GetFileName(path));
                if (fi == null || fi.Open == null) { w.WriteLine("!not a container: " + (fi == null ? "unknown" : fi.Description + " " + fi.UnsupportedReason)); return; }
                Container c;
                var sib = new ListSiblings(Path.GetDirectoryName(Path.GetFullPath(path)));
                try { c = fi.Open(src, Path.GetFileName(path), sib); }
                catch (Exception ex) { w.WriteLine("!open failed: " + ex.GetType().Name + ": " + ex.Message); return; }
                using (c)
                {
                    w.WriteLine("#" + c.Description);
                    foreach (var x in c.Warnings) w.WriteLine("#warning " + x);
                    foreach (var e in c.Entries())
                    {
                        if (e.IsDirectory) continue;
                        string line = e.Name + "|";
                        try
                        {
                            using (var d = e.Open())
                                line += d.Length + "|" + Crc.Crc32(d).ToString("x8") + "|" + (e.Note ?? "");
                        }
                        catch (Exception ex) { line += "-1|ERROR|" + ex.GetType().Name + ": " + ex.Message; }
                        w.WriteLine(line);
                    }
                }
            }
        }

        sealed class ListSiblings : ISiblingProvider
        {
            readonly string dir;
            public ListSiblings(string d) { dir = d; }
            public DataSource GetSibling(string name)
            {
                foreach (var f in Directory.GetFiles(dir))
                    if (Path.GetFileName(f).Equals(PathUtil.FileName(name), StringComparison.OrdinalIgnoreCase)) return new FileSource(f);
                return null;
            }
            public IEnumerable<string> SiblingNames { get { return Directory.GetFiles(dir).Select(Path.GetFileName); } }
        }

        public static void Lzhuf(string inFile, string outFile, string size)
        {
            using (var src = new FileSource(inFile))
            using (var sink = new Sink(-1, -1))
            {
                try { new Lzhuf(new BitReaderMsb(new ByteInput(src, 0, -1))).Run(sink, long.Parse(size)); } catch (Exception ex) { Console.WriteLine("stopped: " + ex.Message); }
                File.WriteAllBytes(outFile, sink.ToArray());
            }
        }

        /// <summary>Extracts all entries of a container into a folder (one level).</summary>
        public static void Extract(string path, string outDir)
        {
            using (var src = new FileSource(path))
            {
                var fi = Sniffer.Identify(src, Path.GetFileName(path));
                using (var c = fi.Open(src, Path.GetFileName(path), new ListSiblings(Path.GetDirectoryName(Path.GetFullPath(path)))))
                    foreach (var e in c.Entries())
                    {
                        if (e.IsDirectory) continue;
                        var dest = Path.Combine(outDir, e.Name.Replace('/', Path.DirectorySeparatorChar));
                        Directory.CreateDirectory(Path.GetDirectoryName(dest));
                        try { using (var d = e.Open()) File.WriteAllBytes(dest, d.ReadAll()); }
                        catch (Exception ex) { Console.WriteLine("ERROR " + e.Name + ": " + ex.Message); }
                    }
            }
        }
    }
}
