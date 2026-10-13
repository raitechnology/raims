#!/bin/sh
# dist-strip.sh <unstripped> <dist-file> <debug-dir>
# The Windows equivalent of an rpm debuginfo split: keep the DWARF in
# <debug-dir>/<name>.debug, strip the shipped file and point it at the
# .debug with a gnu_debuglink (name + CRC), so gdb/addr2line find it when the
# -debug.zip is unpacked into the same directory as the exe/dll.
set -e
src=$1 dst=$2 dbgd=$3
name=$(basename "$dst")
mkdir -p "$dbgd"
x86_64-w64-mingw32-objcopy --only-keep-debug "$src" "$dbgd/$name.debug"
x86_64-w64-mingw32-strip -o "$dst" "$src"
x86_64-w64-mingw32-objcopy --add-gnu-debuglink="$dbgd/$name.debug" "$dst"
