using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;

namespace SymbolHunter.Core
{
    public sealed class ScanOptions
    {
        public int MaxDepth = 12;
        public int Threads = Math.Max(1, Math.Min(8, Environment.ProcessorCount));
        public bool Recurse = true;
        public TimeSpan ItemTimeout = TimeSpan.FromMinutes(30);
        public bool IncludeDeleted = true;
        public bool CrossImageVolumes = true;
        public YaraRuleSet Yara;                // user YARA rules (null = none)
        public bool YaraOnContainers;           // also run them on archive and disk image files themselves
    }

    /// <summary>Multi-volume naming conventions.</summary>
    public static class VolumeSets
    {
        static readonly Regex reArjCont = new Regex(@"^(.*)\.a(\d\d)$", RegexOptions.IgnoreCase);
        static readonly Regex reRarOld = new Regex(@"^(.*)\.([r-z])(\d\d)$", RegexOptions.IgnoreCase);
        static readonly Regex reRarNew = new Regex(@"^(.*\.part)(\d+)\.rar$", RegexOptions.IgnoreCase);
        static readonly Regex reZipSplit = new Regex(@"^(.*)\.z(\d\d)$", RegexOptions.IgnoreCase);
        static readonly Regex reSplit = new Regex(@"^(.*)\.(\d{3})$", RegexOptions.IgnoreCase);
        static readonly Regex reAce = new Regex(@"^(.*)\.c(\d\d)$", RegexOptions.IgnoreCase);

        /// <summary>If the name looks like a continuation volume, returns possible first-volume names.</summary>
        public static string[] FirstVolumeCandidates(string fileName)
        {
            Match m;
            if ((m = reArjCont.Match(fileName)).Success) return new[] { m.Groups[1].Value + ".arj" };
            if ((m = reRarNew.Match(fileName)).Success)
            {
                int n = int.Parse(m.Groups[2].Value);
                if (n <= 1) return null;
                int w = m.Groups[2].Value.Length;
                return new[] { m.Groups[1].Value + "1".PadLeft(w, '0') + ".rar", m.Groups[1].Value + "1.rar", m.Groups[1].Value + "01.rar", m.Groups[1].Value + "001.rar" };
            }
            if ((m = reZipSplit.Match(fileName)).Success) return new[] { m.Groups[1].Value + ".zip", m.Groups[1].Value + ".rar" };
            if ((m = reRarOld.Match(fileName)).Success) return new[] { m.Groups[1].Value + ".rar" };
            if ((m = reSplit.Match(fileName)).Success) { if (int.Parse(m.Groups[2].Value) <= 1) return null; return new[] { m.Groups[1].Value + ".001", m.Groups[1].Value + ".000" }; }
            if ((m = reAce.Match(fileName)).Success) return new[] { m.Groups[1].Value + ".ace" };
            return null;
        }

        /// <summary>For "X.001" (or X.000) returns the stem X and the ordered list of existing parts.</summary>
        public static List<string> SplitParts(string firstName, Func<string, bool> exists, out string stem)
        {
            stem = null;
            var m = reSplit.Match(firstName);
            if (!m.Success) return null;
            int start = int.Parse(m.Groups[2].Value);
            if (start > 1) return null;
            stem = m.Groups[1].Value;
            var parts = new List<string> { firstName };
            for (int i = start + 1; i < 1000; i++)
            {
                string n = stem + "." + i.ToString("000");
                if (!exists(n)) break;
                parts.Add(n);
            }
            return parts.Count > 1 ? parts : null;
        }

        static readonly Regex reNumbered = new Regex(@"^(.*?)(\d+)(\.[A-Za-z0-9]{1,4})$");

        /// <summary>"GAME1.ARJ" with k=1 gives "GAME2.ARJ" (keeps zero padding). Null if the name has no number.</summary>
        public static string NumberedNext(string fileName, int k)
        {
            var m = reNumbered.Match(fileName);
            if (!m.Success) return null;
            string digits = m.Groups[2].Value;
            long n;
            if (!long.TryParse(digits, out n)) return null;
            return m.Groups[1].Value + (n + k).ToString().PadLeft(digits.Length, '0') + m.Groups[3].Value;
        }

        /// <summary>Groups names like ABC1.ZIP, ABC2.ZIP ... (same stem and extension, consecutive numbers).</summary>
        public static List<List<string>> NumberedGroups(IEnumerable<string> fileNames)
        {
            var groups = new Dictionary<string, SortedDictionary<long, string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var fn in fileNames)
            {
                var m = reNumbered.Match(fn);
                if (!m.Success) continue;
                long n; if (!long.TryParse(m.Groups[2].Value, out n)) continue;
                string key = m.Groups[1].Value + "|" + m.Groups[3].Value;
                SortedDictionary<long, string> g;
                if (!groups.TryGetValue(key, out g)) groups[key] = g = new SortedDictionary<long, string>();
                if (!g.ContainsKey(n)) g[n] = fn;
            }
            var res = new List<List<string>>();
            foreach (var g in groups.Values)
            {
                if (g.Count < 2) continue;
                var run = new List<string>(); long prev = -10;
                foreach (var kv in g)
                {
                    if (kv.Key != prev + 1 && run.Count > 0) { if (run.Count > 1) res.Add(run); run = new List<string>(); }
                    run.Add(kv.Value); prev = kv.Key;
                }
                if (run.Count > 1) res.Add(run);
            }
            return res;
        }

        public static List<string> ZipSplitParts(string zipName, Func<string, bool> exists)
        {
            int dot = zipName.LastIndexOf('.');
            if (dot < 0 || !zipName.Substring(dot).Equals(".zip", StringComparison.OrdinalIgnoreCase)) return null;
            string stem = zipName.Substring(0, dot);
            bool upper = zipName.Substring(dot) == ".ZIP";
            var parts = new List<string>();
            for (int i = 1; i < 100; i++)
            {
                string n = stem + (upper ? ".Z" : ".z") + i.ToString("00");
                if (!exists(n)) { string alt = stem + (upper ? ".z" : ".Z") + i.ToString("00"); if (exists(alt)) n = alt; else break; }
                parts.Add(n);
            }
            return parts.Count > 0 ? parts : null;
        }
    }

    /// <summary>Provides other files next to an archive (for multi-volume sets).</summary>
    public abstract class SiblingBase : ISiblingProvider, IDisposable
    {
        protected readonly List<IDisposable> opened = new List<IDisposable>();
        public SiblingBase Parent;         // provider one level up (for volumes spread across disk images)
        public string SelfName;            // the image we are inside of (excluded from cross-image search)
        public abstract IEnumerable<string> SiblingNames { get; }
        protected abstract DataSource OpenLocal(string name);
        public abstract IEnumerable<Tuple<string, Func<DataSource>>> Candidates();

        public DataSource GetSibling(string name)
        {
            var d = OpenLocal(name);
            if (d != null) return d;
            if (Parent != null) return Parent.FindInImages(PathUtil.FileName(name), SelfName);
            return null;
        }

        readonly Dictionary<string, Tuple<Container, List<Entry>>> conCache = new Dictionary<string, Tuple<Container, List<Entry>>>(StringComparer.OrdinalIgnoreCase);

        static string Stem(string n)
        {
            var f = PathUtil.FileName(n); int dot = f.LastIndexOf('.'); if (dot > 0) f = f.Substring(0, dot);
            return f.TrimEnd('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '_', '-', ' ').ToUpperInvariant();
        }

        Tuple<Container, List<Entry>> OpenContainer(string key, Func<DataSource> open, string name)
        {
            Tuple<Container, List<Entry>> c;
            if (conCache.TryGetValue(key, out c)) return c;
            c = null;
            try
            {
                var ds = open();
                var fi = Sniffer.Identify(ds, name);
                if (fi != null && fi.Supported && fi.Open != null && fi.Kind != FormatKind.Executable && !(fi.Id == "RAR" || fi.Id == "7Z"))
                {
                    var con = fi.Open(ds, name, null);
                    var list = con.Entries().ToList();
                    opened.Add(con); opened.Add(ds);
                    c = Tuple.Create(con, list);
                }
                else ds.Dispose();
            }
            catch { c = null; }
            conCache[key] = c;
            return c;
        }

        DataSource SearchIn(string key, Tuple<Container, List<Entry>> c, string fileName, int depth)
        {
            if (c == null) return null;
            var hit = c.Item2.FirstOrDefault(e => !e.IsDirectory && !e.IsDeleted && e.Open != null && PathUtil.FileName(e.Name).Equals(fileName, StringComparison.OrdinalIgnoreCase));
            if (hit != null) { try { var d = hit.Open(); opened.Add(d); return d; } catch { } }
            if (depth <= 0) return null;
            foreach (var e in c.Item2)
            {
                if (e.IsDirectory || e.IsDeleted || e.Open == null || e.Size < 1024 || e.Size > 1024L * 1024 * 1024) continue;
                if (!LikelyContainer(e.Name, e.Size)) continue;
                var ee = e;
                var sub = OpenContainer(key + "|" + e.Name, () => ee.Open(), PathUtil.FileName(e.Name));
                var r = SearchIn(key + "|" + e.Name, sub, fileName, depth - 1);
                if (r != null) return r;
            }
            return null;
        }

        static readonly HashSet<string> containerExts = new HashSet<string> { ".zip", ".arj", ".lzh", ".lha", ".arc", ".pak", ".zoo", ".cab", ".img", ".ima", ".imz", ".dsk", ".vfd", ".flp", ".td0", ".imd", ".cqm", ".360", ".720", ".144", ".12m", ".dmf", ".xdf", ".iso", ".bin", ".vhd", ".exe", ".raw", ".ddi", ".gz", ".tar", ".tgz" };
        static bool LikelyContainer(string name, long size)
        {
            string ext = PathUtil.Ext(name);
            if (containerExts.Contains(ext)) return ext != ".exe" || size > 20000;
            return size == 368640 || size == 737280 || size == 1228800 || size == 1474560 || size == 2949120 || size == 163840 || size == 184320 || size == 327680;
        }

        /// <summary>Searches sibling archives and disk images (and one level inside them) for a file with the given name.</summary>
        public DataSource FindInImages(string fileName, string exclude)
        {
            string want = Stem(exclude ?? fileName);
            var cands = Candidates().Where(c => exclude == null || !c.Item1.Equals(exclude, StringComparison.OrdinalIgnoreCase))
                                    .OrderBy(c => Stem(c.Item1) == want ? 0 : 1).ThenBy(c => c.Item1, StringComparer.OrdinalIgnoreCase).ToList();
            foreach (var c in cands)
            {
                var con = OpenContainer(c.Item1, c.Item2, PathUtil.FileName(c.Item1));
                var r = SearchIn(c.Item1, con, fileName, 2);
                if (r != null) return r;
            }
            // not here: try the level above (e.g. the next disk image inside the next numbered ZIP)
            if (Parent != null && searchDepth < 3)
            {
                searchDepth++;
                try { return Parent.FindInImages(fileName, SelfName); } finally { searchDepth--; }
            }
            return null;
        }
        int searchDepth;

        public void Dispose() { for (int i = opened.Count - 1; i >= 0; i--) { try { opened[i].Dispose(); } catch { } } opened.Clear(); conCache.Clear(); }
    }

    public sealed class DirSiblings : SiblingBase, IFolderSiblings
    {
        readonly Dictionary<string, string> files;
        public string FolderPath { get { var f = files.Values.FirstOrDefault(); return f != null ? Path.GetDirectoryName(f) : null; } }
        static readonly HashSet<string> imageExts = new HashSet<string> { ".img", ".ima", ".imz", ".dsk", ".vfd", ".flp", ".td0", ".imd", ".cqm", ".360", ".720", ".144", ".12m", ".dmf", ".xdf", ".iso", ".bin", ".ddi", ".fdi", ".hdm", ".vhd", ".raw" };
        static readonly HashSet<string> ArchiveExts = new HashSet<string> { ".zip", ".arj", ".lzh", ".lha", ".arc", ".pak", ".zoo", ".cab", ".exe", ".gz", ".tar", ".tgz" };
        public DirSiblings(IEnumerable<string> paths)
        {
            files = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in paths) { var fn = Path.GetFileName(p); if (!files.ContainsKey(fn)) files[fn] = p; }
        }
        public override IEnumerable<string> SiblingNames { get { return files.Keys; } }
        protected override DataSource OpenLocal(string name)
        {
            string p;
            if (!files.TryGetValue(PathUtil.FileName(name), out p)) return null;
            var s = new FileSource(p); opened.Add(s); return s;
        }
        public override IEnumerable<Tuple<string, Func<DataSource>>> Candidates()
        {
            foreach (var kv in files.OrderBy(k => k.Key))
                if (imageExts.Contains(PathUtil.Ext(kv.Key)) || ArchiveExts.Contains(PathUtil.Ext(kv.Key)))
                {
                    var p = kv.Value;
                    yield return Tuple.Create(kv.Key, (Func<DataSource>)(() => new FileSource(p)));
                }
        }
    }

    sealed class EntrySiblings : SiblingBase
    {
        readonly List<Entry> entries; readonly string dir;
        public EntrySiblings(List<Entry> entries, string dir) { this.entries = entries; this.dir = dir; }
        public override IEnumerable<string> SiblingNames { get { return entries.Where(e => !e.IsDirectory && PathUtil.Dir(e.Name) == dir).Select(e => PathUtil.FileName(e.Name)); } }
        protected override DataSource OpenLocal(string name)
        {
            string fn = PathUtil.FileName(name);
            var e = entries.FirstOrDefault(x => !x.IsDirectory && !x.IsDeleted && PathUtil.Dir(x.Name) == dir && PathUtil.FileName(x.Name).Equals(fn, StringComparison.OrdinalIgnoreCase))
                 ?? entries.FirstOrDefault(x => !x.IsDirectory && !x.IsDeleted && PathUtil.FileName(x.Name).Equals(fn, StringComparison.OrdinalIgnoreCase));
            if (e == null || e.Open == null) return null;
            try { var d = e.Open(); opened.Add(d); return d; } catch { return null; }
        }
        public override IEnumerable<Tuple<string, Func<DataSource>>> Candidates()
        {
            foreach (var e in entries)
            {
                if (e.IsDirectory || e.Open == null || e.Size < 1024) continue;
                var ee = e;
                yield return Tuple.Create(e.Name, (Func<DataSource>)(() => ee.Open()));
            }
        }
    }

    /// <summary>Re-opens a file found during a scan (for extraction from the GUI).</summary>
    public static class ChainOpener
    {
        /// <summary>Opens the innermost file of a hit chain. Dispose the returned list when done (it includes the data).</summary>
        public static DataSource Open(ItemResult item, List<string> chain, List<IDisposable> keep)
        {
            string dir = Path.GetDirectoryName(item.FullPath);
            var sib = new DirSiblings(Directory.GetFiles(dir)); keep.Add(sib);
            DataSource cur;
            string curName = Path.GetFileName(item.FullPath);
            if (item.Format.StartsWith("spanned ZIP"))
            {
                var parts = new List<string> { curName }; parts.AddRange(item.Volumes);
                var srcs = parts.Select(p => (DataSource)new FileSource(Path.Combine(dir, p))).ToList();
                keep.AddRange(srcs);
                var con = new ZipContainer(srcs[srcs.Count - 1], srcs.Take(srcs.Count - 1).ToList()); keep.Add(con);
                return Walk(con, chain, 1, keep, sib);
            }
            if (item.Note.StartsWith("split file"))
            {
                var parts = new List<string> { curName }; parts.AddRange(item.Volumes);
                cur = new ConcatSource(parts.Select(p => (DataSource)new FileSource(Path.Combine(dir, p))).ToList(), true);
                string stem; VolumeSets.SplitParts(curName, x => true, out stem); curName = stem ?? curName;
            }
            else cur = new FileSource(item.FullPath);
            keep.Add(cur);
            for (int i = 1; i < chain.Count; i++)
            {
                var fi = Sniffer.Identify(cur, curName);
                if (fi == null || fi.Open == null) throw new FormatException2("cannot reopen " + curName);
                var con = fi.Open(cur, curName, sib); keep.Add(con);
                string want = chain[i];
                bool deleted = want.EndsWith(" (deleted)");
                if (deleted) want = want.Substring(0, want.Length - 10);
                var e = con.Entries().FirstOrDefault(x => x.Name == want && x.IsDeleted == deleted && x.Open != null);
                if (e == null) throw new FormatException2("entry not found: " + want);
                cur = e.Open(); keep.Add(cur);
                curName = PathUtil.FileName(want);
                sib = null;
            }
            return cur;
        }

        static DataSource Walk(Container con, List<string> chain, int i, List<IDisposable> keep, ISiblingProvider sib)
        {
            string want = chain[i];
            bool deleted = want.EndsWith(" (deleted)");
            if (deleted) want = want.Substring(0, want.Length - 10);
            var e = con.Entries().FirstOrDefault(x => x.Name == want && x.Open != null);
            if (e == null) throw new FormatException2("entry not found: " + want);
            var cur = e.Open(); keep.Add(cur);
            if (i == chain.Count - 1) return cur;
            string name = PathUtil.FileName(want);
            var fi = Sniffer.Identify(cur, name);
            var c2 = fi.Open(cur, name, null); keep.Add(c2);
            return Walk(c2, chain, i + 1, keep, null);
        }
    }

    /// <summary>Identifies a folder by volume serial number and file index, so a folder reached through a junction
    /// or symbolic link is recognised as one already visited. Falls back to the full path elsewhere.</summary>
    static class FolderId
    {
        [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
        struct BY_HANDLE_FILE_INFORMATION
        {
            public uint Attributes; public long Created, Accessed, Written;
            public uint VolumeSerial, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode, SetLastError = true)]
        static extern Microsoft.Win32.SafeHandles.SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr sec, uint disp, uint flags, IntPtr tmpl);
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        static extern bool GetFileInformationByHandle(Microsoft.Win32.SafeHandles.SafeFileHandle h, out BY_HANDLE_FILE_INFORMATION info);
        static readonly bool windows = Environment.OSVersion.Platform == PlatformID.Win32NT;

        public static string Get(string dir)
        {
            string full;
            try { full = Path.GetFullPath(dir).TrimEnd('\\', '/'); } catch { full = dir; }
            if (!windows)
            {
                // test builds on other systems: resolve symbolic links to their final folder (.NET 6+ only)
                try
                {
                    var di = new DirectoryInfo(full);
                    var m = typeof(FileSystemInfo).GetMethod("ResolveLinkTarget", new[] { typeof(bool) });
                    if (m != null && (di.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        var target = m.Invoke(di, new object[] { true }) as FileSystemInfo;
                        if (target != null) return Get(target.FullName);
                    }
                    var parent = Path.GetDirectoryName(full);
                    if (parent != null && parent != full) return Path.Combine(Get(parent), Path.GetFileName(full));
                }
                catch { }
                return full;
            }
            try
            {
                // FILE_READ_ATTRIBUTES, share all, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS (needed to open a folder)
                using (var h = CreateFileW(dir, 0x80, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero))
                {
                    BY_HANDLE_FILE_INFORMATION info;
                    if (!h.IsInvalid && GetFileInformationByHandle(h, out info) && (info.IndexHigh | info.IndexLow) != 0)
                        return info.VolumeSerial.ToString("X8") + ":" + info.IndexHigh.ToString("X8") + info.IndexLow.ToString("X8");
                }
            }
            catch { }
            return full;
        }
    }

    /// <summary>Walks a folder, opens every archive and disk image recursively and collects debug findings.</summary>
    public sealed class Scanner
    {
        public readonly ScanOptions Options;
        public readonly ScanStats Stats = new ScanStats();
        public event Action<ItemResult> ItemStarted, ItemFinished;
        public event Action<string> Log;
        volatile bool cancelled;
        public bool Cancelled { get { return cancelled; } }
        public void Cancel() { cancelled = true; }
        public readonly List<ItemResult> Results = new List<ItemResult>();
        string outputDir;

        public Scanner(ScanOptions o) { Options = o ?? new ScanOptions(); }

        sealed class Job { public ItemResult Item; public List<string> SplitParts; public List<string> SpanParts; public List<string> DirFiles; }

        /// <summary>Scans a folder (or a single file). Blocks until finished or cancelled.
        /// Folders are walked on a separate thread and files are handed to the workers as soon as they are found,
        /// so results appear while the rest of the tree is still being listed.</summary>
        public List<ItemResult> Run(string root, string excludeDir = null)
        {
            outputDir = excludeDir != null ? Path.GetFullPath(excludeDir) : null;
            var queue = new ConcurrentQueue<Job>();
            discoveryDone = false;
            Stats.Discovering = true;
            Exception discoveryError = null;
            var discovery = new Thread(() =>
            {
                try { Discover(root, queue); }
                catch (Exception ex) { discoveryError = ex; Emit("ERROR while listing folders: " + ex.Message); }
                finally { Stats.Discovering = false; discoveryDone = true; }
            }) { IsBackground = true, Name = "discover" };
            discovery.Start();
            RunJobs(queue);
            if (discoveryError != null && Stats.TopItems == 0) throw new IOException("Could not list " + root + ": " + discoveryError.Message, discoveryError);
            return Results;
        }

        volatile bool discoveryDone;

        void AddJob(ConcurrentQueue<Job> queue, Job j)
        {
            lock (Results) Results.Add(j.Item);
            lock (Stats) { Stats.TopItems++; Stats.BytesTop += j.Item.Size; }
            queue.Enqueue(j);
        }

        void Discover(string root, ConcurrentQueue<Job> queue)
        {
            if (File.Exists(root))
            {
                var fp = Path.GetFullPath(root);
                AddJob(queue, new Job { Item = new ItemResult { FullPath = fp, RelPath = Path.GetFileName(fp), Size = new FileInfo(fp).Length }, DirFiles = Directory.GetFiles(Path.GetDirectoryName(fp)).ToList() });
                return;
            }
            string baseDir = Path.GetFullPath(root);
            if (!Directory.Exists(baseDir)) throw new DirectoryNotFoundException("folder not found: " + baseDir);
            bool recurse = Options.Recurse;
            if (!recurse)
            {
                // "Include subfolders" is off but the chosen folder only has subfolders: scanning nothing would look broken
                bool hasFiles = true;
                try { hasFiles = Directory.EnumerateFiles(baseDir).Any(); } catch { }
                if (!hasFiles) { recurse = true; Emit("The chosen folder has no files of its own, so its subfolders are scanned too."); }
            }
            foreach (var dir in EnumerateDirs(baseDir, recurse))
            {
                if (cancelled) break;
                lock (Stats) { Stats.Folders++; Stats.DiscoverDir = dir; }
                try { DiscoverFolder(baseDir, dir, queue); }
                catch (Exception ex) { Emit("skipped folder " + dir + ": " + ex.Message); }
            }
        }

        void DiscoverFolder(string baseDir, string dir, ConcurrentQueue<Job> queue)
        {
            string[] files;
            try { files = Directory.GetFiles(dir); } catch (Exception ex) { Emit("cannot list " + dir + ": " + ex.Message); return; }
            files = files.Where(f => { try { return !Directory.Exists(f); } catch { return true; } }).ToArray();   // links to folders are walked as folders
            if (files.Length == 0) return;
            Array.Sort(files, StringComparer.OrdinalIgnoreCase);
            var names = new HashSet<string>(files.Select(Path.GetFileName), StringComparer.OrdinalIgnoreCase);
            var consumedBy = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            // continuation volumes are scanned as part of their first volume
            foreach (var f in files)
            {
                var fn = Path.GetFileName(f);
                string[] cands;
                try { cands = VolumeSets.FirstVolumeCandidates(fn); } catch { continue; }
                if (cands == null) continue;
                var first = cands.FirstOrDefault(c => names.Contains(c));
                if (first != null) consumedBy[fn] = first;
            }
            var spanSets = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            var rawSplits = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            List<List<string>> groups;
            try { groups = VolumeSets.NumberedGroups(files.Select(Path.GetFileName)).ToList(); } catch { groups = new List<List<string>>(); }
            foreach (var grp in groups)
            {
                if (grp.Any(g => consumedBy.ContainsKey(g))) continue;
                try
                {
                    string ext = PathUtil.Ext(grp[0]);
                    var paths = grp.Select(g => Path.Combine(dir, g)).ToList();
                    bool set = false;
                    if (ext == ".zip")
                    {
                        int dl, d0;
                        using (var last = new FileSource(paths[paths.Count - 1])) dl = ZipContainer.DiskNumber(last);
                        using (var first = new FileSource(paths[0])) d0 = ZipContainer.DiskNumber(first);
                        if (dl > 0 && dl == grp.Count - 1 && d0 < 0) { spanSets[grp[0]] = grp; set = true; }
                        else if (dl == 0 && d0 < 0) { rawSplits[grp[0]] = grp; set = true; }
                    }
                    else if (ext == ".arj")
                    {
                        using (var first = new FileSource(paths[0])) { var h = first.ReadBytes(0, 16); set = h.Length > 9 && h[0] == 0x60 && h[1] == 0xEA && (h[8] & 0x04) != 0; }
                    }
                    else if (ext == ".rar")
                    {
                        using (var first = new FileSource(paths[0])) { var h = first.ReadBytes(0, 16); set = RarContainer.Probe(h) && h.Length > 11 && h[6] == 0 && (Bin.U16(h, 10) & 1) != 0; }
                    }
                    if (set) for (int i = 1; i < grp.Count; i++) consumedBy[grp[i]] = grp[0];
                }
                catch { }
            }
            var dirFiles = files.ToList();
            foreach (var f in files)
            {
                var fn = Path.GetFileName(f);
                long size = 0; try { size = new FileInfo(f).Length; } catch { }
                var it = new ItemResult { FullPath = f, RelPath = MakeRel(baseDir, f), Size = size };
                string first;
                if (consumedBy.TryGetValue(fn, out first)) { it.Status = ItemStatus.PartOfSet; it.Note = "part of " + first; lock (Results) Results.Add(it); continue; }
                string stem;
                List<string> split = null;
                try { split = VolumeSets.SplitParts(fn, n => names.Contains(n), out stem); } catch { }
                List<string> span, raw;
                if (spanSets.TryGetValue(fn, out span)) AddJob(queue, new Job { Item = it, SpanParts = span, DirFiles = dirFiles });
                else if (rawSplits.TryGetValue(fn, out raw)) AddJob(queue, new Job { Item = it, SplitParts = raw, DirFiles = dirFiles });
                else AddJob(queue, new Job { Item = it, SplitParts = split, DirFiles = dirFiles });
            }
        }

        static string MakeRel(string baseDir, string f)
        {
            if (f.StartsWith(baseDir, StringComparison.OrdinalIgnoreCase)) return f.Substring(baseDir.Length).TrimStart('\\', '/');
            return f;
        }

        /// <summary>Depth-first walk of every subfolder. A folder reached through a junction or symbolic link that leads
        /// back to a folder already walked is skipped, so link loops cannot make the walk endless.</summary>
        IEnumerable<string> EnumerateDirs(string root, bool recurse)
        {
            var stack = new Stack<Tuple<string, int, bool>>();   // folder, depth, reached through a link
            var seenPaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var seenIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            stack.Push(Tuple.Create(root, 0, false));
            while (stack.Count > 0)
            {
                var top = stack.Pop();
                var d = top.Item1;
                string full;
                try { full = Path.GetFullPath(d).TrimEnd('\\', '/'); } catch { full = d; }
                if (outputDir != null && full.Equals(outputDir.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase)) continue;
                if (!seenPaths.Add(full)) continue;
                bool viaLink = top.Item3;
                if (top.Item2 > 0) { try { if ((File.GetAttributes(d) & FileAttributes.ReparsePoint) != 0) viaLink = true; } catch { } }
                string id = FolderId.Get(d);
                // only trust the id to detect a loop when a link is involved (some network drives reuse ids)
                if (!seenIds.Add(id) && viaLink) { Emit("skipped " + d + ": it is a link back to a folder that was already scanned"); continue; }
                yield return d;
                if (!recurse) continue;
                if (top.Item2 >= 200) { Emit("skipped the subfolders of " + d + ": folders are nested too deeply"); continue; }
                string[] subs;
                try { subs = Directory.GetDirectories(d); } catch (Exception ex) { Emit("cannot list subfolders of " + d + ": " + ex.Message); continue; }
                Array.Sort(subs, StringComparer.OrdinalIgnoreCase);
                for (int i = subs.Length - 1; i >= 0; i--) stack.Push(Tuple.Create(subs[i], top.Item2 + 1, viaLink));
            }
        }

        sealed class WorkerState { public Thread Thread; public volatile ItemResult Current; public DateTime Started; public volatile bool Abandoned; }

        void RunJobs(ConcurrentQueue<Job> queue)
        {
            var workers = new List<WorkerState>();
            int n = Math.Max(1, Options.Threads);
            for (int i = 0; i < n; i++) workers.Add(StartWorker(queue));
            while (true)
            {
                Thread.Sleep(100);
                bool anyAlive = false;
                foreach (var w in workers.ToList())
                {
                    if (w.Abandoned) continue;
                    if (w.Thread.IsAlive) anyAlive = true;
                    var cur = w.Current;
                    if (cur != null && DateTime.UtcNow - w.Started > Options.ItemTimeout)
                    {
                        w.Abandoned = true;
                        cur.Status = ItemStatus.TimedOut;
                        lock (cur.Problems) cur.Problems.Add(new Problem { Where = cur.RelPath, Kind = "timeout", Message = "gave up after " + Options.ItemTimeout.TotalMinutes + " minutes" });
                        try { AbortThread(w.Thread); } catch { }
                        FinishItem(cur);
                        workers.Add(StartWorker(queue));
                        anyAlive = true;
                    }
                }
                if (!anyAlive && queue.IsEmpty && discoveryDone) break;
                if (!anyAlive && !queue.IsEmpty && !cancelled) { workers.Add(StartWorker(queue)); }
                if (cancelled && workers.All(w => w.Abandoned || !w.Thread.IsAlive)) break;
            }
        }

        static void AbortThread(Thread t)
        {
            // Thread.Abort exists on .NET Framework; on other runtimes the thread is simply abandoned
            var m = typeof(Thread).GetMethod("Abort", Type.EmptyTypes);
            if (m != null) { try { m.Invoke(t, null); } catch { } }
        }

        WorkerState StartWorker(ConcurrentQueue<Job> queue)
        {
            var w = new WorkerState();
            w.Thread = new Thread(() =>
            {
                Job j;
                while (!cancelled && !w.Abandoned)
                {
                    if (!queue.TryDequeue(out j))
                    {
                        if (discoveryDone && queue.IsEmpty) break;
                        Thread.Sleep(30);   // the folder walk is still finding files
                        continue;
                    }
                    w.Current = j.Item; w.Started = DateTime.UtcNow;
                    try { ProcessTop(j, w); }
                    catch (Exception ex)
                    {
                        if (w.Abandoned) return;
                        j.Item.Status = ItemStatus.Error;
                        string msg; string kind = Classify(ex, out msg);
                        lock (j.Item.Problems) j.Item.Problems.Add(new Problem { Where = j.Item.RelPath, Kind = kind, Message = msg });
                    }
                    if (w.Abandoned) return;
                    w.Current = null;
                    FinishItem(j.Item);
                }
            });
            w.Thread.IsBackground = true;
            w.Thread.Start();
            return w;
        }

        void FinishItem(ItemResult it)
        {
            lock (Stats)
            {
                Stats.TopDone++;
                Stats.BytesDone += it.Size;
            }
            var h = ItemFinished; if (h != null) h(it);
        }

        void Emit(string s) { var l = Log; if (l != null) l(s); }

        sealed class ItemCtx
        {
            public ItemResult Item; public WorkerState Worker; public HashSet<string> Seen = new HashSet<string>();
        }

        void ProcessTop(Job j, WorkerState w)
        {
            var it = j.Item;
            var sw = System.Diagnostics.Stopwatch.StartNew();
            it.Status = ItemStatus.Scanning;
            var hs = ItemStarted; if (hs != null) hs(it);
            var ctx = new ItemCtx { Item = it, Worker = w };
            using (var sib = new DirSiblings(j.DirFiles))
            {
                DataSource src;
                string name = Path.GetFileName(it.FullPath);
                if (j.SpanParts != null)
                {
                    string dir = Path.GetDirectoryName(it.FullPath);
                    var srcs = j.SpanParts.Select(p => (DataSource)new FileSource(Path.Combine(dir, p))).ToList();
                    try
                    {
                        var con = new ZipContainer(srcs[srcs.Count - 1], srcs.Take(srcs.Count - 1).ToList());
                        it.Format = "spanned ZIP (" + srcs.Count + " parts)";
                        it.Volumes.AddRange(j.SpanParts.Skip(1));
                        it.Note = "spanned ZIP set: " + string.Join(", ", j.SpanParts);
                        ctx.Item.ContainersOpened++;
                        foreach (var wmsg in con.Warnings) AddProblem(ctx, new List<string> { it.RelPath }, "warning", wmsg);
                        VisitContainer(ctx, con, new List<string> { it.RelPath }, 0, sib);
                        con.Dispose();
                    }
                    catch (Exception ex) { AddProblem(ctx, new List<string> { it.RelPath }, "corrupt", "spanned ZIP: " + ex.Message); }
                    finally { foreach (var x in srcs) x.Dispose(); }
                    it.Elapsed = sw.Elapsed;
                    if (it.Status == ItemStatus.Scanning) it.Status = ItemStatus.Done;
                    return;
                }
                if (j.SplitParts != null)
                {
                    string dir = Path.GetDirectoryName(it.FullPath);
                    var parts = j.SplitParts.Select(p => (DataSource)new FileSource(Path.Combine(dir, p))).ToList();
                    src = new ConcatSource(parts, true);
                    it.Volumes.AddRange(j.SplitParts.Skip(1));
                    string stem; VolumeSets.SplitParts(name, x => true, out stem);
                    name = stem ?? name;
                    it.Note = "split file: " + j.SplitParts.Count + " parts joined (" + string.Join(", ", j.SplitParts) + ")";
                }
                else src = new FileSource(it.FullPath);
                using (src)
                {
                    Visit(ctx, src, new List<string> { it.RelPath }, name, 0, sib, false, true);
                }
            }
            it.Elapsed = sw.Elapsed;
            if (it.Status == ItemStatus.Scanning) it.Status = ItemStatus.Done;
        }

        /// <summary>Maps an exception raised while reading data to a problem kind the user can act on.</summary>
        public static string Classify(Exception ex, out string message)
        {
            if (ex is System.Reflection.TargetInvocationException && ex.InnerException != null) ex = ex.InnerException;
            message = ex.Message;
            if (ex is UnsupportedException || ex is NotImplementedException || ex is NotSupportedException) return "unsupported";
            if (ex is FormatException2) return "corrupt";
            if (ex is System.IO.FileNotFoundException || ex is System.IO.DirectoryNotFoundException || ex is UnauthorizedAccessException ||
                ex is System.IO.PathTooLongException || (ex is System.IO.IOException && !(ex is System.IO.EndOfStreamException) && !(ex is System.IO.InvalidDataException)))
            { message = "could not read the file: " + ex.Message; return "unreadable"; }
            if (ex is IndexOutOfRangeException || ex is ArgumentException || ex is System.IO.EndOfStreamException || ex is System.IO.InvalidDataException ||
                ex is OverflowException || ex is InvalidOperationException || ex is NullReferenceException || ex is InvalidCastException ||
                ex is DivideByZeroException || ex is KeyNotFoundException || ex is FormatException || ex is OutOfMemoryException ||
                ex.GetType().Name.IndexOf("DataError", StringComparison.OrdinalIgnoreCase) >= 0 ||
                ex.GetType().Name.IndexOf("Crc", StringComparison.OrdinalIgnoreCase) >= 0 ||
                (ex.GetType().Namespace ?? "").StartsWith("SharpCompress", StringComparison.Ordinal))
            { message = "damaged or non-standard data (" + ex.GetType().Name + ": " + ex.Message + ")"; return "corrupt"; }
            message = ex.GetType().Name + ": " + ex.Message;
            return "error";
        }

        /// <summary>Container warnings that mean data was lost are reported as damage, the rest as notes.</summary>
        static string WarningKind(string msg)
        {
            string m = msg.ToLowerInvariant();
            if (m.Contains("cannot read (") || m.Contains("compression symbol hunter cannot")) return "unsupported";
            if (m.Contains("missing next") || m.Contains("missing volume") || m.Contains("next volume") || m.Contains("disks missing") || m.Contains("disks not found")) return "missing-volume";
            if (m.Contains("truncated") || m.Contains("damaged") || m.Contains("cannot find the end") || m.Contains("data blocks missing") || m.Contains("bad header") ||
                m.Contains("bad directory") || m.Contains("bad volume") || m.Contains("ends without") || m.Contains("unknown header level") || m.StartsWith("rar: ")) return "corrupt";
            return "warning";
        }

        void AddProblem(ItemCtx ctx, List<string> chain, Exception ex, string prefix)
        {
            string msg; string kind = Classify(ex, out msg);
            AddProblem(ctx, chain, kind, prefix + msg);
        }

        void AddProblem(ItemCtx ctx, List<string> chain, string kind, string msg)
        {
            lock (ctx.Item.Problems) ctx.Item.Problems.Add(new Problem { Where = string.Join(" > ", chain), Kind = kind, Message = msg });
            lock (Stats) Stats.Problems++;
        }

        void Visit(ItemCtx ctx, DataSource data, List<string> chain, string name, int depth, SiblingBase sib, bool deleted, bool top)
        {
            if (cancelled || ctx.Worker.Abandoned) return;
            ctx.Item.FilesExamined++;
            lock (Stats) { Stats.Files++; Stats.Current = string.Join(" > ", chain); }
            FormatInfo fi = null;
            try { fi = Sniffer.Identify(data, name); }
            catch (ThreadAbortException) { throw; }
            catch (Exception ex) { AddProblem(ctx, chain, ex, "could not identify: "); }

            if (top && fi != null) ctx.Item.Format = fi.Description;
            if (top && fi == null) ctx.Item.Format = "file";

            if (fi != null && fi.Kind != FormatKind.Executable)
            {
                if (!fi.Supported)
                {
                    AddProblem(ctx, chain, "unsupported", fi.Description + ": " + fi.UnsupportedReason);
                    return;
                }
                if (depth >= Options.MaxDepth) { AddProblem(ctx, chain, "depth", "nesting limit reached; not opened"); return; }
                // skip exact duplicates of containers already scanned in this item
                string key = ContentKey(data);
                if (key != null && !ctx.Seen.Add(key)) { return; }
                bool isSfx = fi.Id.EndsWith("-SFX") || fi.ScanSelf;
                if (isSfx) ScanLeaf(ctx, data, chain, name, deleted);
                else if (Options.YaraOnContainers) ScanYara(ctx, data, chain, deleted, fi.Description);
                Container con = null;
                try
                {
                    var arcData = data;
                    if (fi.Id == "ZIP")
                    {
                        // split ZIP: .Z01, .Z02 ... + .ZIP
                        var zparts = sib != null ? VolumeSets.ZipSplitParts(name, n => sib.SiblingNames.Contains(n, StringComparer.OrdinalIgnoreCase)) : null;
                        if (zparts != null && ZipContainer.IsMultiDisk(data))
                        {
                            var vols = new List<DataSource>();
                            foreach (var zp in zparts) { var v = sib.GetSibling(zp); if (v == null) break; vols.Add(v); }
                            if (vols.Count == zparts.Count) { con = new ZipContainer(data, vols); foreach (var zp in zparts) ctx.Item.Volumes.Add(zp); }
                        }
                    }
                    if (con == null) con = fi.Open(arcData, name, sib);
                    ctx.Item.ContainersOpened++;
                    if (fi.Kind == FormatKind.Image) ctx.Item.ImagesOpened++;
                    lock (Stats) Stats.Containers++;
                    foreach (var wmsg in con.Warnings) AddProblem(ctx, chain, WarningKind(wmsg), wmsg);
                    int reported = con.Warnings.Count;
                    foreach (var v in con.ConsumedVolumes) if (!ctx.Item.Volumes.Contains(v)) ctx.Item.Volumes.Add(v);
                    try { VisitContainer(ctx, con, chain, depth, sib); }
                    finally
                    {
                        foreach (var wmsg in con.Warnings.Skip(reported).ToList()) AddProblem(ctx, chain, WarningKind(wmsg), wmsg);
                        var chd = con as ChdContainer;
                        if (chd != null && chd.FailedHunks > 0) AddProblem(ctx, chain, "corrupt", chd.FailedHunks + " CHD hunk(s) could not be decompressed and were read as empty");
                    }
                }
                catch (UnsupportedException ex) { AddProblem(ctx, chain, "unsupported", ex.Message); if (!isSfx) ScanLeaf(ctx, data, chain, name, deleted); }
                catch (FormatException2 ex) { AddProblem(ctx, chain, "corrupt", fi.Description + ": " + ex.Message); if (!isSfx) ScanLeaf(ctx, data, chain, name, deleted); }
                catch (ThreadAbortException) { throw; }
                catch (Exception ex) { AddProblem(ctx, chain, ex, fi.Description + ": "); if (!isSfx) ScanLeaf(ctx, data, chain, name, deleted); }
                finally { if (con != null) try { con.Dispose(); } catch { } }
                return;
            }
            ScanLeaf(ctx, data, chain, name, deleted);
        }

        static string ContentKey(DataSource d)
        {
            if (d.Length < 64 * 1024) return null;
            var a = d.ReadBytes(0, 65536); var b = d.ReadBytes(d.Length - 65536, 65536);
            return d.Length + ":" + Crc.Crc32(0, a, 0, a.Length) + ":" + Crc.Crc32(0, b, 0, b.Length);
        }

        /// <summary>Runs the user's YARA rules over data and records the matches as findings.</summary>
        void ScanYara(ItemCtx ctx, DataSource data, List<string> chain, bool deleted, string fileType)
        {
            if (Options.Yara == null) return;
            YaraRuleSet.ScanOutcome res;
            try { res = Options.Yara.Scan(data); }
            catch (ThreadAbortException) { throw; }
            catch (Exception ex) { AddProblem(ctx, chain, "warning", "YARA scan failed: " + ex.Message); return; }
            if (res.Error != null) AddProblem(ctx, chain, "warning", res.Error);
            if (res.Matches.Count == 0) return;
            var found = new List<Finding>();
            foreach (var m in res.Matches)
            {
                string st, desc;
                Strength strength = Strength.Medium;
                if (m.Meta.TryGetValue("strength", out st))
                {
                    st = st.Trim().ToLowerInvariant();
                    strength = st.StartsWith("strong") || st == "high" ? Strength.Strong : st.StartsWith("weak") || st == "low" ? Strength.Weak : Strength.Medium;
                }
                m.Meta.TryGetValue("description", out desc);
                var where = m.Strings.Take(6).Select(x => x.Id + " at 0x" + x.Offset.ToString("X")).ToList();
                string detail = (string.IsNullOrEmpty(desc) ? "" : desc + " ") + "[rule file: " + m.Namespace + (m.Tags.Length > 0 ? ", tags: " + m.Tags : "") + "]" +
                                (where.Count > 0 ? " matched " + string.Join(", ", where) + (m.Strings.Count > 6 ? ", ..." : "") : "");
                var f = new Finding(Kinds.Yara, detail, strength, "YARA: " + m.Rule);
                foreach (var sh in m.Strings.Take(8))
                {
                    var sb = new System.Text.StringBuilder();
                    foreach (byte b in sh.Data) sb.Append(b >= 32 && b < 127 ? (char)b : '.');
                    f.Samples.Add(sh.Id + ": " + sb);
                }
                if (m.Strings.Count > 0) f.Offset = m.Strings[0].Offset;
                found.Add(f);
            }
            lock (ctx.Item.Hits)
                foreach (var f in found)
                    ctx.Item.Hits.Add(new Hit { Chain = new List<string>(chain), FileType = fileType, FileSize = data.Length, Deleted = deleted, Finding = f });
            lock (Stats) Stats.Hits += found.Count;
        }

        void ScanLeaf(ItemCtx ctx, DataSource data, List<string> chain, string name, bool deleted)
        {
            ScanResult r;
            try { r = DebugScanner.Scan(data, name); }
            catch (ThreadAbortException) { throw; }
            catch (Exception ex) { AddProblem(ctx, chain, ex, "debug scan failed: "); return; }
            ScanYara(ctx, data, chain, deleted, r.FileType);
            if (r.Findings.Count == 0) return;
            lock (ctx.Item.Hits)
                foreach (var f in r.Findings)
                    ctx.Item.Hits.Add(new Hit { Chain = new List<string>(chain), FileType = r.FileType, Packer = r.Packer, FileSize = data.Length, Deleted = deleted, Finding = f });
            lock (Stats) Stats.Hits += r.Findings.Count;
        }

        void VisitContainer(ItemCtx ctx, Container con, List<string> chain, int depth, SiblingBase parentSib)
        {
            bool random = !(con is RarContainer) && !(con is SevenZipContainer);
            IEnumerable<Entry> seq = con.Entries();
            List<Entry> list = null;
            if (random)
            {
                // keep whatever could be listed before damage (truncated downloads are common)
                list = new List<Entry>();
                try { foreach (var e in seq) list.Add(e); }
                catch (ThreadAbortException) { throw; }
                catch (UnsupportedException) { if (list.Count == 0) throw; }
                catch (Exception ex)
                {
                    if (list.Count == 0) throw;
                    string msg; string kind = Classify(ex, out msg);
                    AddProblem(ctx, chain, kind == "error" ? "error" : "corrupt", "listing stopped after " + list.Count + " entries: " + msg);
                }
            }
            var names = list != null ? new HashSet<string>(list.Where(e => !e.IsDirectory).Select(e => e.Name), StringComparer.OrdinalIgnoreCase) : null;
            // continuation volumes inside this container
            var consumed = new HashSet<string>(con.ConsumedVolumes, StringComparer.OrdinalIgnoreCase);
            if (list != null)
                foreach (var e in list)
                {
                    if (e.IsDirectory) continue;
                    var cands = VolumeSets.FirstVolumeCandidates(PathUtil.FileName(e.Name));
                    if (cands == null) continue;
                    string dir = PathUtil.Dir(e.Name);
                    if (cands.Any(c => names.Contains((dir.Length > 0 ? dir + "/" : "") + c))) consumed.Add(PathUtil.FileName(e.Name) + "|" + dir);
                }
            string selfName = chain[chain.Count - 1];
            foreach (var e in (IEnumerable<Entry>)list ?? seq)
            {
                if (cancelled || ctx.Worker.Abandoned) return;
                if (e.IsDirectory) continue;
                if (e.IsDeleted && !Options.IncludeDeleted) continue;
                string fn = PathUtil.FileName(e.Name), dir = PathUtil.Dir(e.Name);
                if (consumed.Contains(fn + "|" + dir)) continue;
                var child = new List<string>(chain) { e.Name + (e.IsDeleted ? " (deleted)" : "") };
                if (e.IsEncrypted) { AddProblem(ctx, child, "encrypted", "encrypted entry, password required"); continue; }
                if (e.Open == null) continue;
                DataSource d = null;
                EntrySiblings sib = null;
                try
                {
                    try { d = e.Open(); }
                    catch (UnsupportedException ex) { AddProblem(ctx, child, "unsupported", ex.Message); continue; }
                    catch (FormatException2 ex) { AddProblem(ctx, child, "corrupt", ex.Message); continue; }
                    catch (ThreadAbortException) { throw; }
                    catch (Exception ex) { AddProblem(ctx, child, ex, ""); continue; }
                    if (!string.IsNullOrEmpty(e.Note)) AddProblem(ctx, child, e.Note.Contains("CRC") ? "crc" : e.Note.StartsWith("damaged", StringComparison.OrdinalIgnoreCase) || e.Note.Contains("truncated") ? "corrupt" : "warning", e.Note);
                    if (list != null) { sib = new EntrySiblings(list, dir) { Parent = parentSib, SelfName = PathUtil.FileName(selfName) }; }
                    Visit(ctx, d, child, fn, depth + 1, sib, e.IsDeleted, false);
                    if (!string.IsNullOrEmpty(e.Note) && e.Note.Contains("CRC") == false && e.Note.Length == 0) { }
                }
                finally
                {
                    if (sib != null) sib.Dispose();
                    if (d != null) try { d.Dispose(); } catch { }
                }
            }
        }
    }
}
