using System.Reflection;
using System.Runtime.Versioning;

// Without this attribute .NET Framework would run the program in 4.0 compatibility mode (legacy 260-character path handling).
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyTitle("Symbol Hunter")]
[assembly: AssemblyDescription("Finds debug symbols inside DOS-era archives and disk images")]
[assembly: AssemblyProduct("Symbol Hunter")]
[assembly: AssemblyCopyright("Includes SharpCompress (MIT license)")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: AssemblyInformationalVersion("1.0")]
