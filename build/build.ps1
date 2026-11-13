param([string]$Out = "out/SymbolHunter.exe", [string]$Kind = "winexe", [string[]]$Src = @("src"),
      [string[]]$Embed = @(), [string[]]$Define = @(), [switch]$NoOptimize)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root
$ca = Join-Path $PSHOME "Microsoft.CodeAnalysis.dll"; $cs = Join-Path $PSHOME "Microsoft.CodeAnalysis.CSharp.dll"
if (-not ("SHBuilder" -as [type])) {
  Add-Type -Path (Join-Path $PSScriptRoot "Builder.cs") -WarningAction SilentlyContinue -IgnoreWarnings -ReferencedAssemblies @($ca, $cs, "System.Collections", "System.Linq", "System.Runtime", "System.Console", "System.Text.Encoding.Extensions", "System.Collections.Immutable", "netstandard")
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
$srcDirs = $Src | ForEach-Object { (Resolve-Path $_).Path }
# YARA rules shipped inside the program (File > Export YARA Rules, or /yara on the command line)
$Embed = @($Embed) + @("SymbolHunter.dos_debug_symbols.yar=" + (Join-Path $root "build/dos_debug_symbols.yar"))
$Embed = @($Embed) + @("SymbolHunter.debug_symbols_90s_00s.yar=" + (Join-Path $root "build/debug_symbols_90s_00s.yar"))
# native YARA library (libyara + shim) for each Windows architecture that has been built
foreach ($a in @("x64", "x86", "arm64")) {
  $dll = Join-Path $root "native/bin/shyara-$a.dll"
  if (Test-Path $dll) { $Embed += @("SymbolHunter.native.shyara-$a.dll=" + $dll) }
}
$rc = [SHBuilder]::Build($srcDirs, "/opt/tools/refasm/v4.8", (Join-Path $root $Out), $Kind,
  (Join-Path $root "build/app.manifest"), (Join-Path $root "build/app.ico"), $Embed, $Define, -not $NoOptimize)
exit $rc
