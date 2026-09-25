#!/usr/bin/env bash
# build_engine.sh — 将运行期汇编 VM 引擎构建为位置无关 blob
#
# 用法: build_engine.sh <x64|x86> [输出目录]
#   x64: as --64 + ld -Ttext=0      x86: as --32 + ld -m elf_i386 -Ttext=0
#
# 产物: <输出目录>/engine_<arch>.bin
#
# blob 契约：入口符号 kbox_vm_selfcheck 必须位于 blob 偏移 0
# （packer 以 base + KboxConfig.vm_engine_rva 直接定位入口），本脚本校验之。
# 引擎仅含代码与只读偏移表，无绝对指针，故可平铺为裸二进制并置于任意基址。

set -euo pipefail

ARCH="${1:?usage: build_engine.sh <x64|x86> [outdir]}"
OUT="${2:-$(dirname "$0")/build}"
SRC="$(dirname "$0")/vm_engine_${ARCH}.S"
OBJ="$OUT/engine_${ARCH}.o"
ELF="$OUT/engine_${ARCH}.elf"
BLOB="$OUT/engine_${ARCH}.bin"

mkdir -p "$OUT"

case "$ARCH" in
  x64) ASFLAGS=(--64); LDEMU=() ;;
  x86) ASFLAGS=(--32); LDEMU=(-m elf_i386) ;;
  *)   echo "bad arch: $ARCH (x64|x86)" >&2; exit 1 ;;
esac

as "${ASFLAGS[@]}" "$SRC" -o "$OBJ"
ld "${LDEMU[@]}" -o "$ELF" -Ttext=0 -e kbox_vm_run "$OBJ"
objcopy -O binary "$ELF" "$BLOB"

ENTRY_OFF=$(nm -n "$ELF" | awk '$3=="kbox_vm_run" && !f {print $1; f=1}')
BLOB_SIZE=$(stat -c%s "$BLOB")
if [ "${ENTRY_OFF:-x}" != "0000000000000000" ] && [ "${ENTRY_OFF:-x}" != "00000000" ]; then
  echo "[engine/$ARCH] ERROR: entry not at blob offset 0 (entry=$ENTRY_OFF)" >&2
  exit 1
fi
echo "[engine/$ARCH] $BLOB ($BLOB_SIZE bytes, entry=0x$ENTRY_OFF)"
