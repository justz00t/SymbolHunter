#!/bin/bash
export LD_LIBRARY_PATH=/opt/work/native/linux${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
# usage: dev.sh Method arg1 arg2 ...   -> calls [SymbolHunter.Cli.DevTools]::Method(args...)
m=$1; shift
args=""
for a in "$@"; do args="$args,'${a//\'/\'\'}'"; done
args=${args#,}
export POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off
exec /opt/tools/pwsh/pwsh -NoProfile -NonInteractive -c "\$null=[Reflection.Assembly]::LoadFrom('/home/claude/symhunt/out/SymbolHunter.exe'); [SymbolHunter.Cli.DevTools]::$m($args)"
