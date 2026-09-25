#!/usr/bin/env bash
# build_stub.sh — 将 stub 汇编源构建为 blob 二进制，并生成布局头 stub_layout_<arch>.h
#
# 用法: build_stub.sh <x64|x86> [输出目录]
#   x64: as --64 + ld -Ttext=0          x86: as --32 + ld -Ttext=0
#
# 产物:
#   <输出目录>/blob_<arch>.bin            平铺 blob（VMA 从 0 起）
#   <输出目录>/stub_layout_<arch>.h       packer 需要的符号偏移/尺寸
#
# blob 布局契约（见 include/kbox_format.h）:
#   [0x000..0x100) KboxConfig（packer 填充）
#   [0x100 ...]    入口代码 + kbox_chacha
#   [ ...  ]       .iat 段（stub 自身 IAT，loader 回填）

set -euo pipefail

ARCH="${1:?usage: build_stub.sh <x64|x86> [outdir]}"
OUT="${2:-$(dirname "$0")/build}"
SRC="$(dirname "$0")/stub_${ARCH}.S"
OBJ="$OUT/stub_${ARCH}.o"
ELF="$OUT/stub_${ARCH}.elf"
BLOB="$OUT/blob_${ARCH}.bin"
HDR="$OUT/stub_layout_${ARCH}.h"

mkdir -p "$OUT"

case "$ARCH" in
  x64) ASFLAGS=(--64); LDEMU="" ;;
  x86) ASFLAGS=(--32); LDEMU="-m elf_i386" ;;
  *)   echo "bad arch: $ARCH (x64|x86)" >&2; exit 1 ;;
esac

as "${ASFLAGS[@]}" "$SRC" -o "$OBJ"
ld $LDEMU -o "$ELF" -Ttext=0 -e kbox_entry "$OBJ"
objcopy -O binary "$ELF" "$BLOB"

# 从链接后 ELF 取符号 VMA（blob 内偏移）
ENTRY_OFF=$(nm -n "$ELF" | awk '$3=="kbox_entry"  {print "0x"$1; exit}')
IAT_OFF=$(nm -n "$ELF"   | awk '$3=="kbox_iat"    {print "0x"$1; exit}')
CHACHA_OFF=$(nm -n "$ELF"| awk '$3=="kbox_chacha" {print "0x"$1; exit}')
DISPATCH_OFF=$(nm -n "$ELF" | awk '$3=="kbox_vm_dispatch" {print "0x"$1; exit}')
STRPOOL_OFF=$(nm -n "$ELF" | awk '$3=="kbox_strpool_start" {print "0x"$1; exit}')
DEFEND_OFF=$(nm -n "$ELF"  | awk '$3=="kbox_defense_end"   {print "0x"$1; exit}')
CFGROOT_OFF=$(nm -n "$ELF" | awk '$3=="kbox_cfg_root"      {print "0x"$1; exit}')
JUNK_START_OFF=$(nm -n "$ELF" | awk '$3=="kbox_junk_start" {print "0x"$1; exit}')
JUNK_END_OFF=$(nm -n "$ELF"   | awk '$3=="kbox_junk_end"   {print "0x"$1; exit}')
BLOB_SIZE=$(stat -c%s "$BLOB")

cat > "$HDR" <<EOF
// stub_layout_${ARCH}.h — 由 build_stub.sh 生成，勿手改
// blob 符号偏移（VMA = blob 内偏移，packer 用它构造节目录/导入目录）
#pragma once
namespace kbox {
namespace layout${ARCH} {
constexpr uint32_t BLOB_ENTRY_OFF   = ${ENTRY_OFF}u;   // AddressOfEntryPoint = stub_rva + 此值
constexpr uint32_t BLOB_CHACHA_OFF  = ${CHACHA_OFF}u;  // kbox_chacha 内部例程（调试/校验用）
constexpr uint32_t BLOB_IAT_OFF     = ${IAT_OFF}u;     // stub 自身 IAT（loader 回填目标）
constexpr uint32_t BLOB_DISPATCH_OFF = ${DISPATCH_OFF:-0}u; // kbox_vm_dispatch（虚拟化函数跳转目标）
constexpr uint32_t BLOB_STRPOOL_OFF = ${STRPOOL_OFF:-0}u; // G2：防御字符串池起始偏移
constexpr uint32_t BLOB_DEFENSE_END_OFF = ${DEFEND_OFF:-0}u; // G2：防御字符串池结束偏移
constexpr uint32_t BLOB_CFGROOT_OFF = ${CFGROOT_OFF:-0}u; // 方案A：配置区加密种子槽偏移
constexpr uint32_t BLOB_JUNK_START_OFF = ${JUNK_START_OFF:-0}u; // 方案E：随机填充区起始
constexpr uint32_t BLOB_JUNK_END_OFF = ${JUNK_END_OFF:-0}u;     // 方案E：随机填充区结束
constexpr uint32_t BLOB_SIZE        = ${BLOB_SIZE}u;   // blob 总字节数（payload 紧随其后）
} // namespace layout${ARCH}
} // namespace kbox
EOF

echo "[stub/$ARCH] $BLOB ($BLOB_SIZE bytes) -> $HDR"
echo "  entry=${ENTRY_OFF} chacha=${CHACHA_OFF} iat=${IAT_OFF} dispatch=${DISPATCH_OFF:-0}"
