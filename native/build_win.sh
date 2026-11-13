#!/bin/bash
# Cross-compiles libyara + shyara.c into shyara-<arch>.dll with clang/lld and a mingw-w64 sysroot.
ARCH=${1:-x86_64}
T=$ARCH-w64-mingw32
CC=/opt/work/xbuild/bin/$T-clang
Y=/opt/work/xbuild/yara-win64
OUT=/opt/work/native/win-$ARCH
mkdir -p $OUT/obj
DEFS="-DUSE_WINDOWS_PROC -DMACHO_MODULE -DDEX_MODULE -DDOTNET_MODULE -DHASH_MODULE -DHAVE_WINCRYPT_H -DBUCKETS_128=1 -DCHECKSUM_1B=1 -DHAVE_STDBOOL_H=1 -DNDEBUG=1 -D_CRT_SECURE_NO_WARNINGS"
INC="-I$Y/libyara/include -I$Y/libyara -I$Y"
SRCS="ahocorasick arena atoms base64 bitmask compiler endian exec exefiles filemap grammar hash hex_grammar hex_lexer lexer libyara mem modules notebook object parser proc re re_grammar re_lexer rules scan scanner simple_str sizedstr stack stopwatch stream strutils threading
modules/console/console modules/dex/dex modules/dotnet/dotnet modules/elf/elf modules/macho/macho modules/math/math modules/pe/pe modules/pe/pe_utils modules/string/string modules/tests/tests modules/time/time modules/hash/hash
proc/windows tlshc/tlsh tlshc/tlsh_impl tlshc/tlsh_util"
OBJS=""; FAIL=0
for s in $SRCS; do
  o=$OUT/obj/$(echo $s | tr / _).o
  $CC -O2 -w $DEFS $INC -c $Y/libyara/$s.c -o $o 2>> $OUT/errors.log || { echo "FAILED $s"; FAIL=1; }
  OBJS="$OBJS $o"
done
$CC -O2 -w $DEFS $INC -c /home/claude/symhunt/native/shyara.c -o $OUT/obj/shyara.o || FAIL=1
case $ARCH in x86_64) N=x64;; i686) N=x86;; aarch64) N=arm64;; esac
$CC -shared -s -o $OUT/shyara-$N.dll $OUT/obj/shyara.o $OBJS -ladvapi32 -lcrypt32 -Wl,--no-insert-timestamp && echo "built $OUT/shyara-$N.dll"
exit $FAIL
