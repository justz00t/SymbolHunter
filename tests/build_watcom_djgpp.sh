#!/bin/bash
# Open Watcom (16-bit DOS, DOS/4GW LE, Phar Lap, Win16) and DJGPP builds with/without debug info
export WATCOM=/opt/tools/ow PATH=/opt/tools/ow/binl64:/opt/tools/ow/binl:$PATH INCLUDE=/opt/tools/ow/h
W=/opt/work/dbg/watcom; rm -rf $W; mkdir -p $W; cd $W
cp /opt/work/dbg/tc20/GAME.C game.c
L=build.log
wcc -bt=dos -ms -d2 -fo=g16.obj game.c >>$L 2>&1
wcc -bt=dos -ms -fo=g16rel.obj game.c >>$L 2>&1
wlink system dos debug watcom all option map=w16wat.map name w16wat.exe file g16.obj >>$L 2>&1
wlink system dos debug codeview all name w16cv.exe file g16.obj >>$L 2>&1
wlink system dos debug dwarf all name w16dw.exe file g16.obj >>$L 2>&1
wlink system dos name w16rel.exe file g16rel.obj >>$L 2>&1
wcc386 -bt=dos -d2 -fo=g32.obj game.c >>$L 2>&1
wcc386 -bt=dos -fo=g32rel.obj game.c >>$L 2>&1
wlink system dos4g debug watcom all option map=w4gwat.map name w4gwat.exe file g32.obj >>$L 2>&1
wlink system dos4g debug codeview all name w4gcv.exe file g32.obj >>$L 2>&1
wlink system dos4g debug dwarf all name w4gdw.exe file g32.obj >>$L 2>&1
wlink system dos4g name w4grel.exe file g32rel.obj >>$L 2>&1
wlink system pharlap debug watcom all name wplwat.exp file g32.obj >>$L 2>&1
wlink system windows debug codeview all name wwincv.exe file g16.obj >>$L 2>&1
wlib -q -n w16dbg.lib +g16.obj >>$L 2>&1
wlib -q -n w16rel.lib +g16rel.obj >>$L 2>&1
ls
D=/opt/work/dbg/djgpp; rm -rf $D; mkdir -p $D; cd $D
cp /opt/work/dbg/tc20/GAME.C game.c
DJ=/opt/tools/djgpp/djgpp; ls $DJ/bin | head -3 > /dev/null
$DJ/bin/i586-pc-msdosdjgpp-gcc -g -O0 -o djdbg.exe game.c >>$L 2>&1
$DJ/bin/i586-pc-msdosdjgpp-gcc -O2 -o djsym.exe game.c >>$L 2>&1
$DJ/bin/i586-pc-msdosdjgpp-gcc -O2 -s -o djrel.exe game.c >>$L 2>&1
$DJ/bin/i586-pc-msdosdjgpp-gcc -g -gstabs -O0 -o djstabs.exe game.c >>$L 2>&1
$DJ/bin/i586-pc-msdosdjgpp-gcc -g -c -o djdbg.o game.c >>$L 2>&1
ls; tail -3 $L
