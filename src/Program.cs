using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using SymbolHunter.Core;

namespace SymbolHunter
{
    static class Program
    {
        [DllImport("kernel32.dll")] static extern bool AttachConsole(int pid);

        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 3 && args[0] == "/selftest")
            {
                Application.EnableVisualStyles();
                var f = new Gui.MainForm();
                f.RunSelfTest(args[1], args[2]);
                Application.Run(f);
                return 0;
            }
            if (args.Length == 2 && args[0] == "/selftest-options")
            {
                // shows the Options dialog with sample YARA rule paths for a screenshot, then closes
                Application.EnableVisualStyles();
                var st = new Gui.Settings();
                st.YaraRules.Add(@"C:\Tools\yara-rules\dos_debug_symbols.yar");
                st.YaraRules.Add(@"C:\Tools\yara-rules\my_rules");
                var dlg = new Gui.OptionsForm(st);
                var t = new Timer { Interval = 3000 };
                int phase = 0;
                t.Tick += (o, e) => { if (phase++ == 0) { try { File.WriteAllText(args[1] + ".txt", "options shown"); } catch { } } else { t.Stop(); dlg.Close(); } };
                dlg.Shown += (o, e) => t.Start();
                Application.Run(dlg);
                return 0;
            }
            if (args.Length > 0 && !args[0].StartsWith("/") && !args[0].StartsWith("-")) return RunConsole(args);
            if (args.Length > 0 && (args[0] == "/?" || args[0] == "-h" || args[0] == "--help" || args[0].Equals("/yara", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-yara", StringComparison.OrdinalIgnoreCase))) return RunConsole(args);
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.ThreadException += (s, e) => MessageBox.Show("Unexpected error:\n" + e.Exception, AppInfo.Name, MessageBoxButtons.OK, MessageBoxIcon.Error);
            Application.Run(new Gui.MainForm());
            Limits.Cleanup();
            return 0;
        }

        static int RunConsole(string[] args)
        {
            try { AttachConsole(-1); } catch { }
            Console.WriteLine();
            if (args[0] == "/?" || args[0] == "-h" || args[0] == "--help")
            {
                Console.WriteLine(AppInfo.Name + " " + AppInfo.Version + " - finds debug symbols inside DOS-era archives and disk images");
                Console.WriteLine("usage: SymbolHunter <folder or file> [/html report.html] [/csv out.csv] [/json out.json] [/txt list.txt]");
                Console.WriteLine("                   [/min strong|medium|weak] [/threads N] [/depth N] [/nosub]");
                Console.WriteLine("                   [/rules file.yar or folder] (repeatable) [/yaracontainers]");
                Console.WriteLine("       SymbolHunter /yara rules.yar     (writes the built-in YARA rules for loose files)");
                Console.WriteLine("Without arguments the window opens.");
                return 0;
            }
            if (args[0].Equals("/yara", StringComparison.OrdinalIgnoreCase) || args[0].Equals("-yara", StringComparison.OrdinalIgnoreCase))
            {
                string outPath = args.Length > 1 ? args[1] : "dos_debug_symbols.yar";
                YaraRules.Write(outPath);
                Console.WriteLine("YARA rules written to " + Path.GetFullPath(outPath));
                return 0;
            }
            string root = args[0], html = null, csv = null, json = null, txt = null;
            var rules = new System.Collections.Generic.List<string>();
            var min = Strength.Medium;
            var opt = new ScanOptions();
            for (int i = 1; i < args.Length; i++)
            {
                string a = args[i].TrimStart('/', '-').ToLowerInvariant();
                string v = i + 1 < args.Length ? args[i + 1] : null;
                switch (a)
                {
                    case "html": html = v; i++; break;
                    case "csv": csv = v; i++; break;
                    case "json": json = v; i++; break;
                    case "txt": txt = v; i++; break;
                    case "min": min = v == "strong" ? Strength.Strong : v == "weak" ? Strength.Weak : Strength.Medium; i++; break;
                    case "threads": opt.Threads = Math.Max(1, int.Parse(v)); i++; break;
                    case "depth": opt.MaxDepth = Math.Max(2, int.Parse(v)); i++; break;
                    case "nosub": opt.Recurse = false; break;
                    case "rules": rules.Add(v); i++; break;
                    case "yaracontainers": opt.YaraOnContainers = true; break;
                }
            }
            if (!Directory.Exists(root) && !File.Exists(root)) { Console.WriteLine("not found: " + root); return 2; }
            { var later = YaraRuleSet.BuiltinLaterRules(); if (later != null) rules.Insert(0, later); }
            if (Directory.Exists(YaraRuleSet.ProgramRulesFolder ?? "")) rules.Add(YaraRuleSet.ProgramRulesFolder);
            if (rules.Count > 0)
            {
                var msgs = new System.Collections.Generic.List<YaraMessage>();
                opt.Yara = YaraRuleSet.Compile(rules, msgs);
                foreach (var m in msgs) Console.WriteLine("YARA " + m);
                Console.WriteLine(opt.Yara != null ? "YARA: " + opt.Yara.RuleCount + " rules from " + opt.Yara.Files.Count + " file(s)" : "YARA: no usable rules");
            }
            var sc = new Scanner(opt);
            sc.ItemFinished += it =>
            {
                var labels = it.KindLabels(min);
                if (labels.Count > 0) Console.WriteLine("[" + it.Best + "] " + it.RelPath + " : " + string.Join(", ", labels));
            };
            var res = sc.Run(root);
            var hits = Export.WithHits(res, min).ToList();
            Console.WriteLine();
            Console.WriteLine(hits.Count + " archive(s)/file(s) with debug information; " + sc.Stats.Files + " files examined, " + sc.Stats.Containers + " archives/images opened, " + res.Sum(r => r.Problems.Count(p => p.Kind != "warning")) + " problems.");
            if (html != null) Export.WriteHtml(html, root, res, min, sc.Stats);
            if (csv != null) Export.WriteCsv(csv, res, min);
            if (json != null) Export.WriteJson(json, root, res, sc.Stats);
            if (txt != null) Export.WriteText(txt, res, min);
            Limits.Cleanup();
            return 0;
        }
    }
}
