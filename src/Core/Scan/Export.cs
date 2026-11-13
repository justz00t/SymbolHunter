using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;

namespace SymbolHunter.Core
{
    public static class Export
    {
        public static string Json(string s)
        {
            if (s == null) return "null";
            var sb = new StringBuilder("\"");
            foreach (char c in s)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default: if (c < 0x20) sb.Append("\\u" + ((int)c).ToString("x4")); else sb.Append(c); break;
                }
            }
            return sb.Append('"').ToString();
        }

        static string Csv(string s)
        {
            s = s ?? "";
            if (s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0) return "\"" + s.Replace("\"", "\"\"") + "\"";
            return s;
        }

        public static IEnumerable<ItemResult> WithHits(IEnumerable<ItemResult> items, Strength min)
        {
            return items.Where(i => i.HitsAtLeast(min).Any()).OrderByDescending(i => i.Best).ThenBy(i => i.RelPath, StringComparer.OrdinalIgnoreCase);
        }

        public static void WriteJson(string path, string root, IEnumerable<ItemResult> items, ScanStats stats)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                w.WriteLine("{");
                w.WriteLine("  \"tool\": " + Json("Symbol Hunter " + AppInfo.Version) + ",");
                w.WriteLine("  \"root\": " + Json(root) + ",");
                w.WriteLine("  \"generated\": " + Json(DateTime.Now.ToString("s", CultureInfo.InvariantCulture)) + ",");
                w.WriteLine("  \"items\": [");
                bool firstItem = true;
                foreach (var it in items.OrderBy(i => i.RelPath, StringComparer.OrdinalIgnoreCase))
                {
                    if (!firstItem) w.WriteLine(",");
                    firstItem = false;
                    w.Write("    {\"path\": " + Json(it.RelPath) + ", \"size\": " + it.Size + ", \"status\": " + Json(it.Status.ToString()) + ", \"format\": " + Json(it.Format) +
                            ", \"best\": " + Json(it.Best.ToString()) + ", \"note\": " + Json(it.Note) + ", \"volumes\": [" + string.Join(", ", it.Volumes.Select(Json)) + "]");
                    w.Write(", \"files\": " + it.FilesExamined + ", \"containers\": " + it.ContainersOpened + ", \"images\": " + it.ImagesOpened);
                    w.Write(", \"hits\": [");
                    bool fh = true;
                    foreach (var h in it.Hits.ToList())
                    {
                        if (!fh) w.Write(", ");
                        fh = false;
                        w.Write("{\"where\": " + Json(h.InnerPath) + ", \"kind\": " + Json(h.Finding.Kind) + ", \"label\": " + Json(h.Finding.Label) +
                                ", \"strength\": " + Json(h.Finding.Strength.ToString()) + ", \"detail\": " + Json(h.Finding.Detail) + ", \"fileType\": " + Json(h.FileType) +
                                ", \"samples\": [" + string.Join(", ", h.Finding.Samples.Take(12).Select(Json)) + "]" + (h.Deleted ? ", \"deleted\": true" : "") + "}");
                    }
                    w.Write("], \"problems\": [");
                    bool fp = true;
                    foreach (var p in it.Problems.ToList())
                    {
                        if (!fp) w.Write(", ");
                        fp = false;
                        w.Write("{\"where\": " + Json(p.Where) + ", \"kind\": " + Json(p.Kind) + ", \"message\": " + Json(p.Message) + "}");
                    }
                    w.Write("]}");
                }
                w.WriteLine();
                w.WriteLine("  ]");
                w.WriteLine("}");
            }
        }

        public static void WriteCsv(string path, IEnumerable<ItemResult> items, Strength min)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(true)))
            {
                w.WriteLine("Archive,Strength,Debug info,File inside archive,File type,Details,Samples");
                foreach (var it in WithHits(items, min))
                    foreach (var h in it.HitsAtLeast(min).OrderByDescending(x => x.Finding.Strength))
                        w.WriteLine(string.Join(",", new[] { Csv(it.RelPath), h.Finding.Strength.ToString(), Csv(h.Finding.Label), Csv(h.InnerPath + (h.Deleted ? " (deleted)" : "")), Csv(h.FileType), Csv(h.Finding.Detail), Csv(string.Join("; ", h.Finding.Samples.Take(10))) }));
            }
        }

        public static void WriteText(string path, IEnumerable<ItemResult> items, Strength min)
        {
            using (var w = new StreamWriter(path, false, new UTF8Encoding(false)))
            {
                foreach (var it in WithHits(items, min))
                    w.WriteLine(it.RelPath + "\t" + it.Best + "\t" + string.Join("; ", it.KindLabels(min)));
            }
        }

        static string H(string s) { return WebUtility.HtmlEncode(s ?? ""); }

        public static void WriteHtml(string path, string root, IEnumerable<ItemResult> all, Strength min, ScanStats stats)
        {
            var items = all.ToList();
            var hits = WithHits(items, min).ToList();
            var problems = items.Where(i => i.Problems.Any(p => p.Kind != "warning")).ToList();
            var sb = new StringBuilder();
            sb.Append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Symbol Hunter report</title><style>");
            sb.Append(@":root{--bg:#f7f6f3;--card:#fff;--ink:#1c1c1a;--mute:#6a6964;--line:#e4e2dc;--strong:#b4271f;--medium:#9a5b00;--weak:#4f5d6e}
@media(prefers-color-scheme:dark){:root{--bg:#151514;--card:#1e1e1c;--ink:#ebeae5;--mute:#9b9a93;--line:#33332f;--strong:#ff6b5d;--medium:#eba13d;--weak:#9fb0c5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 'Segoe UI',system-ui,sans-serif}main{max-width:1200px;margin:0 auto;padding:20px 16px 60px}
h1{font-size:24px;margin:0}h2{font-size:17px;margin:28px 0 8px}.mute{color:var(--mute)}.stats{display:flex;flex-wrap:wrap;gap:10px;margin:14px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px 12px;min-width:120px}.stat b{display:block;font-size:20px}
.card{background:var(--card);border:1px solid var(--line);border-left:5px solid var(--weak);border-radius:8px;padding:10px 14px;margin:10px 0}
.card.Strong{border-left-color:var(--strong)}.card.Medium{border-left-color:var(--medium)}.path{font-family:Consolas,Menlo,monospace;font-size:13px;word-break:break-all}
.tag{display:inline-block;font-size:12px;font-weight:600;padding:1px 7px;border-radius:10px;margin:2px 4px 2px 0;border:1px solid var(--line)}
.Strong .tag.s,.tag.Strong{color:var(--strong)}.tag.Medium{color:var(--medium)}.tag.Weak{color:var(--weak)}
table{border-collapse:collapse;width:100%;font-size:13px;margin-top:6px}td,th{text-align:left;vertical-align:top;border-bottom:1px solid var(--line);padding:4px 6px}th{color:var(--mute);font-weight:600}
.mono{font-family:Consolas,Menlo,monospace;font-size:12px;word-break:break-all}a{color:inherit}a:hover{color:#0b63c4}");
            sb.Append("</style></head><body><main>");
            sb.Append("<h1>Symbol Hunter report</h1><div class=mute>" + H(root) + " &middot; " + H(DateTime.Now.ToString("yyyy-MM-dd HH:mm")) + "</div>");
            sb.Append("<div class=stats>");
            Action<object, string> stat = (v, l) => sb.Append("<div class=stat><b>" + H(v.ToString()) + "</b><span class=mute>" + H(l) + "</span></div>");
            stat(hits.Count, "archives with debug info");
            stat(hits.Count(i => i.Best == Strength.Strong), "with real symbol tables");
            stat(items.Count(i => i.Status != ItemStatus.PartOfSet), "items scanned");
            if (stats != null) { stat(stats.Files, "files examined"); stat(stats.Containers, "archives/images opened"); }
            stat(problems.Count, "items with problems");
            sb.Append("</div>");
            sb.Append("<h2>Archives with debug information</h2>");
            if (hits.Count == 0) sb.Append("<p class=mute>Nothing found at this strength level.</p>");
            foreach (var it in hits)
            {
                string folderUrl = "";
                try { folderUrl = new Uri(System.IO.Path.GetDirectoryName(it.FullPath) + System.IO.Path.DirectorySeparatorChar).AbsoluteUri; } catch { }
                sb.Append("<div class=\"card " + it.Best + "\"><div class=path><b><a href=\"" + H(folderUrl) + "\" title=\"Open the folder\">" + H(it.RelPath) + "</a></b></div>");
                sb.Append("<div class=mute>" + H(it.Format) + (it.Volumes.Count > 0 ? " &middot; volumes: " + H(string.Join(", ", it.Volumes)) : "") + "</div><div>");
                foreach (var k in it.HitsAtLeast(min).GroupBy(h => h.Finding.Label).OrderByDescending(g => g.Max(h => h.Finding.Strength)))
                    sb.Append("<span class=\"tag " + k.Max(h => h.Finding.Strength) + "\">" + H(k.Key) + (k.Count() > 1 ? " &times;" + k.Count() : "") + "</span>");
                sb.Append("</div><table><tr><th>File</th><th>Debug info</th><th>Details</th></tr>");
                foreach (var h in it.HitsAtLeast(min).OrderByDescending(x => x.Finding.Strength).Take(200))
                    sb.Append("<tr><td class=mono>" + H(h.InnerPath.Length > 0 ? h.InnerPath : PathUtil.FileName(it.RelPath)) + (h.Deleted ? " <i>(deleted)</i>" : "") + "</td><td><span class=\"tag " + h.Finding.Strength + "\">" + H(h.Finding.Label) + "</span></td><td>" + H(h.Finding.Detail) +
                              (h.Finding.Samples.Count > 0 ? "<div class=mono>" + H(string.Join(", ", h.Finding.Samples.Take(10))) + "</div>" : "") + "</td></tr>");
                sb.Append("</table></div>");
            }
            if (problems.Count > 0)
            {
                sb.Append("<h2>Could not be fully examined</h2><table><tr><th>Where</th><th>Problem</th></tr>");
                foreach (var it in problems)
                    foreach (var p in it.Problems.Where(p => p.Kind != "warning").Take(50))
                        sb.Append("<tr><td class=mono>" + H(p.Where) + "</td><td>" + H(p.Kind + ": " + p.Message) + "</td></tr>");
                sb.Append("</table>");
            }
            sb.Append("<h2>What the labels mean</h2><table>");
            foreach (var k in Kinds.All.Values.OrderByDescending(k => k.Strength))
                sb.Append("<tr><td><span class=\"tag " + k.Strength + "\">" + H(k.Label) + "</span></td><td>" + H(k.Explain) + "</td></tr>");
            sb.Append("</table></main></body></html>");
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
        }
    }

    /// <summary>The YARA rules built into the program, for scanning loose files with YARA itself.</summary>
    public static class YaraRules
    {
        public static string Text()
        {
            using (var st = typeof(YaraRules).Assembly.GetManifestResourceStream("SymbolHunter.dos_debug_symbols.yar"))
            {
                if (st == null) return "// YARA rules resource missing from this build\n";
                using (var r = new StreamReader(st)) return r.ReadToEnd();
            }
        }

        public static void Write(string path) { File.WriteAllText(path, Text().Replace("\r\n", "\n").Replace("\n", "\r\n"), new UTF8Encoding(false)); }
    }

    public static class AppInfo
    {
        public const string Version = "1.0";
        public const string Name = "Symbol Hunter";
    }
}
