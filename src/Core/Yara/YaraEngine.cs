using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace SymbolHunter.Core
{
    public sealed class YaraMessage
    {
        public bool Warning; public string File; public int Line; public string Text;
        public override string ToString() { return (Warning ? "warning: " : "error: ") + File + (Line > 0 ? "(" + Line + ")" : "") + ": " + Text; }
    }

    public sealed class YaraStringHit { public string Id; public long Offset; public int Length; public byte[] Data; }

    public sealed class YaraMatch
    {
        public string Namespace, Rule, Tags;
        public Dictionary<string, string> Meta = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        public List<YaraStringHit> Strings = new List<YaraStringHit>();
    }

    /// <summary>
    /// User YARA rules, run on every file Symbol Hunter examines (also inside archives and disk images).
    /// Uses libyara through a small native library (shyara) that ships inside the exe.
    /// </summary>
    public sealed class YaraRuleSet : IDisposable
    {
        public const int MaxConcurrentScans = 30;            // libyara allows 32 threads per rule set
        const long SingleScanLimit = 128L * 1024 * 1024;     // larger data is scanned in overlapping windows
        const int WindowSize = 64 * 1024 * 1024, WindowOverlap = 1024 * 1024;

        IntPtr rules;
        public int RuleCount { get; private set; }
        public List<string> Files = new List<string>();
        public List<YaraMessage> Messages = new List<YaraMessage>();
        public int TimeoutSeconds = 120;
        readonly System.Threading.SemaphoreSlim gate = new System.Threading.SemaphoreSlim(MaxConcurrentScans);

        // ------------------------------------------------------------------ native library

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void ErrorCb(int isWarning, IntPtr file, int line, IntPtr message);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)] delegate void MatchCb(IntPtr ns, IntPtr rule, IntPtr tags, IntPtr metas, IntPtr strings);

        static class N
        {
            const string Lib = "shyara";
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int sh_init();
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr sh_version();
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr sh_compiler_new();
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int sh_compiler_add(IntPtr c, byte[] source, byte[] ns, byte[] baseDir, byte[] displayName, ErrorCb cb);
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern IntPtr sh_compiler_rules(IntPtr c);
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void sh_compiler_free(IntPtr c);
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern void sh_rules_free(IntPtr r);
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int sh_rules_count(IntPtr r);
            [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)] public static extern int sh_scan(IntPtr rules, IntPtr buffer, long length, int timeout, MatchCb cb);
        }

        [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr LoadLibraryW(string path);

        static readonly object initLock = new object();
        static bool initDone;
        static string initError;
        public static string Version { get; private set; }

        /// <summary>Loads the native YARA library once. Returns null when ready, otherwise the reason it is unavailable.</summary>
        public static string EnsureLoaded()
        {
            lock (initLock)
            {
                if (initDone) return initError;
                initDone = true;
                try
                {
                    bool windows = Path.DirectorySeparatorChar == '\\';
                    if (windows)
                    {
                        string arch = Environment.Is64BitProcess ? (IsArm64() ? "arm64" : "x64") : "x86";
                        string res = "SymbolHunter.native.shyara-" + arch + ".dll";
                        using (var st = typeof(YaraRuleSet).Assembly.GetManifestResourceStream(res))
                        {
                            if (st == null) { initError = "YARA is not available for this processor (" + arch + ")"; return initError; }
                            var ms = new MemoryStream(); st.CopyTo(ms);
                            var bytes = ms.ToArray();
                            string hash = Crc.Crc32(0, bytes, 0, bytes.Length).ToString("x8");
                            string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SymbolHunter", "native", hash + "-" + arch);
                            Directory.CreateDirectory(dir);
                            string dll = Path.Combine(dir, "shyara.dll");
                            if (!File.Exists(dll) || new FileInfo(dll).Length != bytes.Length) { string tmp = dll + "." + Guid.NewGuid().ToString("N") + ".tmp"; File.WriteAllBytes(tmp, bytes); try { File.Copy(tmp, dll, true); } finally { try { File.Delete(tmp); } catch { } } }
                            if (LoadLibraryW(dll) == IntPtr.Zero) { initError = "could not load the YARA library (error " + Marshal.GetLastWin32Error() + ")"; return initError; }
                        }
                    }
                    int rc = N.sh_init();
                    if (rc != 0) { initError = "YARA failed to start (error " + rc + ")"; return initError; }
                    Version = Utf8(N.sh_version());
                    return null;
                }
                catch (Exception ex) { initError = "YARA library could not be loaded: " + ex.Message; return initError; }
            }
        }

        static bool IsArm64()
        {
            try { return RuntimeInformation.ProcessArchitecture == Architecture.Arm64; } catch { return false; }
        }

        static string Utf8(IntPtr p)
        {
            if (p == IntPtr.Zero) return "";
            int n = 0;
            while (Marshal.ReadByte(p, n) != 0) n++;
            var b = new byte[n];
            Marshal.Copy(p, b, 0, n);
            return Encoding.UTF8.GetString(b);
        }

        static byte[] Z(string s) { var b = Encoding.UTF8.GetBytes(s ?? ""); Array.Resize(ref b, b.Length + 1); return b; }

        // ------------------------------------------------------------------ compiling

        /// <summary>Expands files and folders into .yar/.yara files (folders are searched recursively).</summary>
        public static List<string> ExpandPaths(IEnumerable<string> paths)
        {
            var res = new List<string>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in paths)
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                try
                {
                    if (Directory.Exists(p))
                    {
                        foreach (var f in Directory.EnumerateFiles(p, "*", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
                        {
                            string e = Path.GetExtension(f).ToLowerInvariant();
                            if ((e == ".yar" || e == ".yara") && seen.Add(Path.GetFullPath(f))) res.Add(Path.GetFullPath(f));
                        }
                    }
                    else if (File.Exists(p) && seen.Add(Path.GetFullPath(p))) res.Add(Path.GetFullPath(p));
                }
                catch { }
            }
            return res;
        }

        /// <summary>
        /// Compiles the given rule files and folders. Files with errors are left out (their messages are kept);
        /// returns null when nothing usable was compiled (see messages).
        /// </summary>
        public static YaraRuleSet Compile(IEnumerable<string> paths, List<YaraMessage> messages)
        {
            string err = EnsureLoaded();
            if (err != null) { messages.Add(new YaraMessage { File = "YARA", Text = err }); return null; }
            var files = ExpandPaths(paths);
            if (files.Count == 0) return null;
            var good = new List<Tuple<string, string, string>>();   // path, text, namespace
            var nsUsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var f in files)
            {
                string text;
                try { text = File.ReadAllText(f); }
                catch (Exception ex) { messages.Add(new YaraMessage { File = f, Text = "cannot read: " + ex.Message }); continue; }
                string ns = Path.GetFileNameWithoutExtension(f);
                for (int i = 2; !nsUsed.Add(ns); i++) ns = Path.GetFileNameWithoutExtension(f) + "_" + i;
                var local = new List<YaraMessage>();
                int errors = AddSource(IntPtr.Zero, text, ns, f, local);
                messages.AddRange(local);
                if (errors == 0) good.Add(Tuple.Create(f, text, ns));
            }
            if (good.Count == 0) return null;
            IntPtr c = N.sh_compiler_new();
            if (c == IntPtr.Zero) { messages.Add(new YaraMessage { File = "YARA", Text = "could not create a compiler" }); return null; }
            try
            {
                var set = new YaraRuleSet();
                foreach (var g in good)
                {
                    var ignored = new List<YaraMessage>();
                    if (AddSource(c, g.Item2, g.Item3, g.Item1, ignored) != 0)
                    {
                        messages.AddRange(ignored.Where(m => !m.Warning));
                        return null;   // the compiler cannot be used after an error
                    }
                    set.Files.Add(g.Item1);
                }
                set.rules = N.sh_compiler_rules(c);
                if (set.rules == IntPtr.Zero) { messages.Add(new YaraMessage { File = "YARA", Text = "could not build the rule set" }); return null; }
                set.RuleCount = N.sh_rules_count(set.rules);
                set.Messages = messages;
                return set;
            }
            finally { N.sh_compiler_free(c); }
        }

        /// <summary>Compiles one source into compiler c (or a throw-away compiler when c is zero); returns the error count.</summary>
        static int AddSource(IntPtr c, string text, string ns, string path, List<YaraMessage> sink)
        {
            bool own = c == IntPtr.Zero;
            if (own) c = N.sh_compiler_new();
            if (c == IntPtr.Zero) { sink.Add(new YaraMessage { File = path, Text = "could not create a compiler" }); return 1; }
            try
            {
                ErrorCb cb = (w, file, line, msg) =>
                {
                    string fn = Utf8(file);
                    sink.Add(new YaraMessage { Warning = w != 0, File = fn.Length > 0 ? fn : path, Line = line, Text = Utf8(msg) });
                };
                string dir = Path.GetDirectoryName(Path.GetFullPath(path)) ?? ".";
                int n = N.sh_compiler_add(c, Z(text), Z(ns), Z(dir), Z(path), cb);
                GC.KeepAlive(cb);
                return n;
            }
            finally { if (own) N.sh_compiler_free(c); }
        }

        // ------------------------------------------------------------------ scanning

        public sealed class ScanOutcome { public List<YaraMatch> Matches = new List<YaraMatch>(); public string Error; }

        /// <summary>Runs the rules over a data source (large data in overlapping windows).</summary>
        public ScanOutcome Scan(DataSource data)
        {
            var res = new ScanOutcome();
            if (rules == IntPtr.Zero || data == null) return res;
            long len = data.Length;
            gate.Wait();
            try
            {
                if (len <= SingleScanLimit)
                {
                    var buf = data.ReadBytes(0, (int)len);
                    ScanBuffer(buf, buf.Length, 0, res);
                }
                else
                {
                    var seen = new HashSet<string>();
                    var buf = new byte[WindowSize];
                    for (long pos = 0; pos < len; pos += WindowSize - WindowOverlap)
                    {
                        int n = data.Read(pos, buf, 0, (int)Math.Min(WindowSize, len - pos));
                        if (n <= 0) break;
                        var part = new ScanOutcome();
                        ScanBuffer(buf, n, pos, part);
                        foreach (var m in part.Matches) if (seen.Add(m.Namespace + ":" + m.Rule)) res.Matches.Add(m);
                        if (part.Error != null) res.Error = part.Error;
                        if (pos + n >= len) break;
                    }
                }
            }
            finally { gate.Release(); }
            return res;
        }

        void ScanBuffer(byte[] buf, int length, long baseOffset, ScanOutcome res)
        {
            MatchCb cb = (ns, rule, tags, metas, strings) =>
            {
                var m = new YaraMatch { Namespace = Utf8(ns), Rule = Utf8(rule), Tags = Utf8(tags) };
                foreach (var line in Utf8(metas).Split('\n'))
                {
                    int eq = line.IndexOf('=');
                    if (eq > 0 && !m.Meta.ContainsKey(line.Substring(0, eq))) m.Meta[line.Substring(0, eq)] = line.Substring(eq + 1);
                }
                foreach (var line in Utf8(strings).Split('\n'))
                {
                    var p = line.Split('\t');
                    if (p.Length < 4) continue;
                    long off; int l; long.TryParse(p[1], out off); int.TryParse(p[2], out l);
                    var data = new byte[p[3].Length / 2];
                    for (int i = 0; i < data.Length; i++) data[i] = Convert.ToByte(p[3].Substring(i * 2, 2), 16);
                    m.Strings.Add(new YaraStringHit { Id = p[0], Offset = off + baseOffset, Length = l, Data = data });
                }
                res.Matches.Add(m);
            };
            var h = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                int rc = N.sh_scan(rules, h.AddrOfPinnedObject(), length, TimeoutSeconds, cb);
                if (rc != 0) res.Error = rc == 26 ? "YARA scan timed out" : "YARA scan error " + rc;
            }
            finally { h.Free(); GC.KeepAlive(cb); }
        }

        public void Dispose()
        {
            if (rules != IntPtr.Zero) { N.sh_rules_free(rules); rules = IntPtr.Zero; }
        }

        /// <summary>Writes the built-in 1990s/2000s rule file to the local application data folder and returns its path (null on failure).</summary>
        public static string BuiltinLaterRules()
        {
            try
            {
                using (var st = typeof(YaraRuleSet).Assembly.GetManifestResourceStream("SymbolHunter.debug_symbols_90s_00s.yar"))
                {
                    if (st == null) return null;
                    var ms = new MemoryStream(); st.CopyTo(ms); var bytes = ms.ToArray();
                    string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SymbolHunter", "builtin-rules");
                    Directory.CreateDirectory(dir);
                    string path = Path.Combine(dir, "debug_symbols_90s_00s.yar");
                    bool same = false;
                    try { same = File.Exists(path) && File.ReadAllBytes(path).SequenceEqual(bytes); } catch { }
                    if (!same) File.WriteAllBytes(path, bytes);
                    return path;
                }
            }
            catch { return null; }
        }

        /// <summary>Default folder for rule files: "rules" next to the program.</summary>
        public static string ProgramRulesFolder
        {
            get { try { return Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "rules"); } catch { return null; } }
        }
    }
}
