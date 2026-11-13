using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Emit;

public static class SHBuilder
{
    // Compiles all .cs files under srcDirs against .NET Framework 4.8 reference assemblies.
    public static int Build(string[] srcDirs, string refDir, string outPath, string kind, string manifestPath,
                            string iconPath, string[] embed, string[] defines, bool optimize)
    {
        var parse = new CSharpParseOptions(LanguageVersion.CSharp12, preprocessorSymbols: defines);
        var trees = new List<SyntaxTree>();
        foreach (var d in srcDirs)
            foreach (var f in Directory.GetFiles(d, "*.cs", SearchOption.AllDirectories).OrderBy(x => x, StringComparer.Ordinal))
                trees.Add(CSharpSyntaxTree.ParseText(File.ReadAllText(f), parse, f, System.Text.Encoding.UTF8));
        string[] refNames = { "mscorlib.dll", "System.dll", "System.Core.dll", "System.Drawing.dll",
            "System.Windows.Forms.dll", "System.Xml.dll", "System.Xml.Linq.dll", "System.Numerics.dll",
            "System.IO.Compression.dll", "System.Web.Extensions.dll", "Microsoft.CSharp.dll", "Facades/System.Runtime.dll",
            "Facades/netstandard.dll", "Facades/System.ValueTuple.dll" };
        var refs = new List<MetadataReference>();
        foreach (var r in refNames)
        {
            var p = Path.Combine(refDir, r);
            if (File.Exists(p)) refs.Add(MetadataReference.CreateFromFile(p));
        }
        OutputKind ok = kind == "exe" ? OutputKind.ConsoleApplication : kind == "dll" ? OutputKind.DynamicallyLinkedLibrary : OutputKind.WindowsApplication;
        var opts = new CSharpCompilationOptions(ok)
            .WithOptimizationLevel(optimize ? OptimizationLevel.Release : OptimizationLevel.Debug)
            .WithPlatform(Platform.AnyCpu)
            .WithAllowUnsafe(true)
            .WithOverflowChecks(false)
            .WithNullableContextOptions(NullableContextOptions.Disable)
            .WithDeterministic(true);
        var name = Path.GetFileNameWithoutExtension(outPath);
        var comp = CSharpCompilation.Create(name, trees, refs, opts);
        Stream manifest = manifestPath != null && File.Exists(manifestPath) ? File.OpenRead(manifestPath) : null;
        Stream icon = iconPath != null && File.Exists(iconPath) ? File.OpenRead(iconPath) : null;
        var res = comp.CreateDefaultWin32Resources(true, manifest == null, manifest, icon);
        var mres = new List<ResourceDescription>();
        if (embed != null)
            foreach (var e in embed)
            {
                var parts = e.Split('=');
                string resName = parts[0], file = parts[1];
                mres.Add(new ResourceDescription(resName, () => File.OpenRead(file), true));
            }
        using (var fs = File.Create(outPath))
        {
            EmitResult er = comp.Emit(fs, null, null, res, mres.Count > 0 ? mres : null);
            int errs = 0;
            foreach (var d in er.Diagnostics.Where(x => x.Severity == DiagnosticSeverity.Error || (x.Severity == DiagnosticSeverity.Warning && x.WarningLevel <= 1)))
            {
                if (d.Severity == DiagnosticSeverity.Error) errs++;
                if (errs < 60 || d.Severity != DiagnosticSeverity.Error) Console.Error.WriteLine(d.ToString());
            }
            if (!er.Success) { Console.Error.WriteLine("BUILD FAILED: " + errs + " error(s)"); return 1; }
        }
        Console.WriteLine("built " + outPath + " (" + new FileInfo(outPath).Length + " bytes)");
        return 0;
    }
}
