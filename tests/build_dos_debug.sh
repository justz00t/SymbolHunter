#!/bin/bash
# Builds real DOS executables with and without debug information using period compilers under emu2.
# Output: /opt/work/dbg/<toolchain>/ with built files; a log of what was produced.
EMU=/opt/tools/src/emu2/emu2
DC=/opt/tools/src/dos_compilers
OUT=/opt/work/dbg
rm -rf $OUT; mkdir -p $OUT
export EMU2_DEFAULT_DRIVE=D

crlf() { sed 's/$/\r/' > "$1"; }

write_sources() {
cat <<'EOF' | crlf "$1/GAME.C"
#include <stdio.h>
#include <assert.h>
int player_score = 0;
static int helper_add(int a, int b) { return a + b; }
void update_player(int pts) { player_score = helper_add(player_score, pts); assert(player_score >= 0); }
int main(void) { update_player(42); printf("score %d\n", player_score); return 0; }
EOF
cat <<'EOF' | crlf "$1/GAME.PAS"
program Game;
var PlayerScore: Integer;
procedure UpdatePlayer(Pts: Integer);
begin
  PlayerScore := PlayerScore + Pts;
end;
begin
  UpdatePlayer(42);
  WriteLn('score ', PlayerScore);
end.
EOF
cat <<'EOF' | crlf "$1/GAMEU.PAS"
unit GameU;
interface
procedure HelloWorld;
implementation
procedure HelloWorld;
begin
  WriteLn('hello');
end;
end.
EOF
cat <<'EOF' | crlf "$1/GAME.ASM"
        .MODEL SMALL
        .STACK 100h
        .DATA
msg     DB 'hello$'
        .CODE
start:  mov ax, @data
        mov ds, ax
        call PrintMsg
        mov ax, 4C00h
        int 21h
PrintMsg PROC
        mov dx, OFFSET msg
        mov ah, 9
        int 21h
        ret
PrintMsg ENDP
        END start
EOF
cat <<'EOF' | crlf "$1/GAME.BAS"
DECLARE SUB UpdatePlayer (pts%)
COMMON SHARED PlayerScore%
CALL UpdatePlayer(42)
PRINT "score"; PlayerScore%
END
SUB UpdatePlayer (pts%)
PlayerScore% = PlayerScore% + pts%
END SUB
EOF
}

dos() {  # dos <compiler-root> <workdir> <exe path relative to compiler root> args... [-- env...]
    local root="$1" work="$2" exe="$3"; shift 3
    ( cd "$work" && EMU2_DRIVE_C="$root" EMU2_DRIVE_D="$work" timeout 120 $EMU "$root/$exe" "$@" ) >> "$work/build.log" 2>&1
    echo "rc=$? : $exe $*" >> "$work/build.log"
}

# ---------------- Turbo C 2.0
W=$OUT/tc20; mkdir -p $W; write_sources $W; R="$DC/Borland Turbo C v2"
dos "$R" $W TCC.EXE -v -M -IC:\\INCLUDE -LC:\\LIB -eTC20DBG.EXE GAME.C
dos "$R" $W TCC.EXE -IC:\\INCLUDE -LC:\\LIB -eTC20REL.EXE GAME.C
dos "$R" $W TCC.EXE -c -v -IC:\\INCLUDE -oGAMEDBG.OBJ GAME.C
dos "$R" $W TCC.EXE -c -IC:\\INCLUDE -oGAMEREL.OBJ GAME.C

# ---------------- Turbo C++ 1.0
W=$OUT/tcpp10; mkdir -p $W; write_sources $W; R="$DC/Borland Turbo C++ v1"
dos "$R" $W BIN/TCC.EXE -v -M -IC:\\INCLUDE -LC:\\LIB -eTCPPDBG.EXE GAME.C -- PATH=C:\\BIN
dos "$R" $W BIN/TCC.EXE -IC:\\INCLUDE -LC:\\LIB -eTCPPREL.EXE GAME.C -- PATH=C:\\BIN

# ---------------- Turbo Pascal 5.5
W=$OUT/tp55; mkdir -p $W; write_sources $W; R="$DC/Borland Turbo Pascal v55"
dos "$R" $W TPC.EXE /V /GD GAME.PAS
cp $W/GAME.EXE $W/TP55DBG.EXE 2>/dev/null; cp $W/GAME.MAP $W/TP55DBG.MAP 2>/dev/null
dos "$R" $W TPC.EXE GAMEU.PAS
mkdir -p $W/rel; write_sources $W/rel
dos "$R" $W/rel TPC.EXE GAME.PAS
cp $W/rel/GAME.EXE $W/TP55REL.EXE 2>/dev/null

# ---------------- Turbo Pascal 7.0
W=$OUT/tp70; mkdir -p $W; write_sources $W; R="$DC/Borland Turbo Pascal v7"
dos "$R" $W BIN/TPC.EXE /V /GD /TC:\\BIN /UC:\\UNITS GAME.PAS
cp $W/GAME.EXE $W/TP70DBG.EXE 2>/dev/null; cp $W/GAME.MAP $W/TP70DBG.MAP 2>/dev/null
dos "$R" $W BIN/TPC.EXE /TC:\\BIN /UC:\\UNITS GAMEU.PAS
mkdir -p $W/rel; write_sources $W/rel
dos "$R" $W/rel BIN/TPC.EXE /TC:\\BIN /UC:\\UNITS GAME.PAS
cp $W/rel/GAME.EXE $W/TP70REL.EXE 2>/dev/null

# ---------------- Turbo Assembler 3.2 + its TLINK
W=$OUT/tasm; mkdir -p $W; write_sources $W; R="$DC/Borland Turbo Assembler v32"
dos "$R" $W TASM.EXE /zi GAME.ASM
dos "$R" $W TLINK.EXE /v /m GAME.OBJ, TASMDBG.EXE, TASMDBG.MAP
dos "$R" $W TASM.EXE GAME.ASM, GAMEREL.OBJ
dos "$R" $W TLINK.EXE /x GAMEREL.OBJ, TASMREL.EXE

# ---------------- Microsoft C 5.1
W=$OUT/msc51; mkdir -p $W; write_sources $W; R="$DC/Microsoft C v5"
dos "$R" $W CL.EXE /Zi /Od /FmMSC5DBG.MAP /FeMSC5DBG.EXE GAME.C /link /CO /MAP -- PATH=C:\\ LIB=C:\\LIB INCLUDE=C:\\INC TMP=D:\\
dos "$R" $W CL.EXE /FeMSC5REL.EXE GAME.C -- PATH=C:\\ LIB=C:\\LIB INCLUDE=C:\\INC TMP=D:\\
dos "$R" $W CL.EXE /c /Zi /FoGAMEDBG.OBJ GAME.C -- PATH=C:\\ LIB=C:\\LIB INCLUDE=C:\\INC TMP=D:\\

# ---------------- Microsoft C 6.0
W=$OUT/msc60; mkdir -p $W; write_sources $W; R="$DC/Microsoft C v6ax"
dos "$R" $W BIN/CL.EXE /Zi /Od /FeMSC6DBG.EXE GAME.C /link /CO /MAP -- PATH=C:\\BIN\;C:\\BINB LIB=C:\\LIB INCLUDE=C:\\INCLUDE TMP=D:\\
dos "$R" $W BIN/CL.EXE /FeMSC6REL.EXE GAME.C -- PATH=C:\\BIN\;C:\\BINB LIB=C:\\LIB INCLUDE=C:\\INCLUDE TMP=D:\\

# ---------------- MASM 5.1 + LINK
W=$OUT/masm; mkdir -p $W; write_sources $W; R="$DC/Microsoft MASM v5"
dos "$R" $W BIN/MASM.EXE /Zi GAME.ASM\;
dos "$R" $W BIN/LINK.EXE /CO /MAP GAME.OBJ,MASMDBG.EXE,MASMDBG.MAP\;
dos "$R" $W BIN/MASM.EXE GAME.ASM,GAMEREL.OBJ\;
dos "$R" $W BIN/LINK.EXE GAMEREL.OBJ,MASMREL.EXE,NUL\;

# ---------------- QuickC 2.51
W=$OUT/qc25; mkdir -p $W; write_sources $W; R="$DC/Microsoft QuickC v251"
dos "$R" $W BIN/QCL.EXE /Zi /FeQCDBG.EXE GAME.C /link /CO -- PATH=C:\\BIN LIB=C:\\LIB INCLUDE=C:\\INCLUDE TMP=D:\\

# ---------------- QuickBASIC 4.5 (BC + LINK)
W=$OUT/qb45; mkdir -p $W; write_sources $W; R="$DC/Microsoft QuickBASIC v45"
dos "$R" $W BC.EXE /Zi GAME.BAS\;
dos "$R" $W LINK.EXE /CO GAME.OBJ,QBDBG.EXE,,C:\\BCOM45.LIB\;

# ---------------- Zortech C++ 3.0
W=$OUT/ztc30; mkdir -p $W; write_sources $W; R="$DC/Zortech C++ v30r1"
dos "$R" $W BIN/ZTC.COM -g -oZTCDBG.EXE GAME.C -- PATH=C:\\BIN INCLUDE=C:\\INCLUDE LIB=C:\\LIB

for d in $OUT/*/; do echo "== $(basename $d): $(ls $d | grep -i -E '\.(exe|map|obj|tpu|tds|sym)$' | tr '\n' ' ')"; done
