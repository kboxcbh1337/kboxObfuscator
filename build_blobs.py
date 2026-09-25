#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_blobs.py — 重新生成 kboXShield 的 4 个汇编 blob 资产

产物（直接写入 kbox-core 资源目录）:
  kbox-core/src/main/resources/shield/blob_x64.bin     —— 解壳 stub（x86-64）
  kbox-core/src/main/resources/shield/blob_x86.bin     —— 解壳 stub（x86）
  kbox-core/src/main/resources/shield/engine_x64.bin   —— 运行期汇编 VM 引擎（x86-64）
  kbox-core/src/main/resources/shield/engine_x86.bin   —— 运行期汇编 VM 引擎（x86）

同时把 stub 符号布局头写到 kbox-shield/stub/build/ 供比对（Java 侧对应
com.kbox.core.shield.BlobLayout）。

前置条件:
  * MSYS2 mingw-w64 binutils（as / ld / objcopy / objdump / nm），默认路径
    C:\\msys64\\mingw64\\bin，可用 MSYS2_BIN 环境变量覆盖。

说明:
  原始 stub/vm_engine 的 .S 面向 ELF（Linux GNU as）。本脚本在汇编前剥离 ELF
  专有指示符（.type / .note.GNU-stack），并把 .iat 段声明改写为 COFF 可接受形式；
  其余指令字节完全一致。构建流程与原始 build_stub.sh / build_engine.sh 一致：
  as -> ld -Ttext=0 -e <entry> -> objcopy -O binary。
  ld 是必需步骤：stub 里 `leaq kbox_iat(%rip)` 等跨段引用在 .o 中仍是未解析
  重定位，跳过链接直接抽段会得到位移为 0 的指令，运行期从空 IAT 取 API
  → 加壳产物加载即 AV。PE 目标额外附带 .rdata/.idata（CRT 伪重定位表），
  用 -j 过滤掉，并以 --image-base 0x0 让段 VMA 直接等于 blob 内偏移。

blob 契约:
  [0x000..0x100) KboxConfig（packer 填充）
  [0x100 ...]    入口 kbox_entry（= AddressOfEntryPoint 相对节首偏移）+ 数据
  [ 4096 对齐 ]  .iat（stub 自身 IAT，loader 回填）
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
MSYS_BIN = os.environ.get("MSYS2_BIN", r"C:\msys64\mingw64\bin")
AS = os.path.join(MSYS_BIN, "as.exe")
LD = os.path.join(MSYS_BIN, "ld.exe")
OBJCOPY = os.path.join(MSYS_BIN, "objcopy.exe")
OBJDUMP = os.path.join(MSYS_BIN, "objdump.exe")
NM = os.path.join(MSYS_BIN, "nm.exe")

STUB_SRC = os.path.join(HERE, "kbox-shield", "stub")
ENGINE_OUT = os.path.join(HERE, "kbox-core", "src", "main", "resources", "shield")
LAYOUT_OUT = os.path.join(STUB_SRC, "build")
# mingw as 无法处理含非 ASCII 字符的路径，中间文件统一放到 ASCII 临时目录
WORK = os.path.join(tempfile.gettempdir(), "kbox_blobs")


def run(args):
    # as/nm 的诊断信息可能是本地编码（GBK），一律容错解码
    p = subprocess.run(args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode != 0:
        sys.stderr.write("FAILED: %s\n%s\n%s\n" % (" ".join(args), p.stdout, p.stderr))
        raise SystemExit(1)
    return p.stdout


def preprocess(src, dst):
    """剥离 ELF 专有指示符，改写 .iat 段声明为 COFF 形式。"""
    out = []
    with open(src, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            s = line.strip()
            if re.match(r"^\.type\s", s):
                continue
            if re.match(r"^\.section\s+\.note\.GNU-stack", s):
                continue
            if re.match(r"^\.section\s+\.iat", s):
                out.append('    .section .iat,"w"\n')
                continue
            out.append(line)
    with open(dst, "w", encoding="utf-8") as f:
        f.writelines(out)


def symbols(elf):
    """取链接后 ELF 的符号偏移（已减去镜像基址，等于 blob 内偏移）。"""
    base = image_base(elf)
    syms = {}
    for line in run([NM, elf]).splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                syms[parts[2]] = int(parts[0], 16) - base
            except ValueError:
                pass
    return syms


def image_base(elf):
    """ld 的 PE 目标会加默认镜像基址（x64 常见 0x200000000）。
    本脚本统一传 --image-base 0x0，此处再按最低非空段 VMA 归一，双保险。"""
    base = None
    for line in run([OBJDUMP, "-h", elf]).splitlines():
        m = re.match(r"\s*\d+\s+(\S+)\s+([0-9a-f]{8,16})\s+([0-9a-f]{8,16})", line)
        if not m:
            continue
        if int(m.group(2), 16) == 0:      # 空段（size=0）不参与
            continue
        vma = int(m.group(3), 16)
        if base is None or vma < base:
            base = vma
    return base or 0


def link_elf(arch, obj, elf, entry):
    """as 产物必须经 ld 解析跨段重定位后才能抽段。

    stub_x64.S 中 `leaq kbox_iat(%rip)` / `movl $kbox_iat, ...` 等 9 处
    跨段引用在 .o 里是未解析的 IMAGE_REL_AMD64_REL32 / ADDR32 重定位。
    若跳过 ld 直接 `objcopy -j .text` 抽段，这些位移保持为 0，stub 运行期
    从空 IAT 取 API 指针 → 加壳产物一加载就 AV。原始 build_stub.sh /
    build_engine.sh 同样走 as → ld → objcopy 三步。"""
    args = [LD]
    if arch == "x86":
        args += ["-m", "i386pe"]
    args += ["--image-base", "0x0", "-Ttext=0", "-e", entry, "-o", elf, obj]
    p = subprocess.run(args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    if p.returncode != 0:
        sys.stderr.write("FAILED: %s\n%s\n%s\n" % (" ".join(args), p.stdout, p.stderr))
        raise SystemExit(1)
    if p.stderr.strip():
        # "section below image base" 之类仅告警，不影响产物
        print("[ld/%s] warn: %s" % (arch, p.stderr.strip().replace("\n", " | ")))


def build_engine(arch):
    src = os.path.join(STUB_SRC, "vm_engine_%s.S" % arch)
    pp = os.path.join(WORK, "vm_engine_%s_coff.S" % arch)
    obj = os.path.join(WORK, "engine_%s.o" % arch)
    elf = os.path.join(WORK, "engine_%s.elf" % arch)
    tmp_bin = os.path.join(WORK, "engine_%s.bin" % arch)
    binout = os.path.join(ENGINE_OUT, "engine_%s.bin" % arch)
    preprocess(src, pp)
    run([AS, "--64" if arch == "x64" else "--32", "-o", obj, pp])
    link_elf(arch, obj, elf, "kbox_vm_run")
    # 仅取 .text：ld 的 PE 目标会附带 .rdata/.idata（CRT 伪重定位/延迟导入表），
    # 引擎不使用，剔除后与原始 Linux 构建产物等长。
    # binutils 处理不了非 ASCII 路径，先落 ASCII 临时目录再拷回。
    run([OBJCOPY, "-O", "binary", "-j", ".text", elf, tmp_bin])
    shutil.copyfile(tmp_bin, binout)
    syms = symbols(elf)
    if syms.get("kbox_vm_run") != 0:
        raise SystemExit("engine/%s: kbox_vm_run 不在 blob 偏移 0" % arch)
    print("[engine/%s] engine_%s.bin = %d bytes (kbox_meta_run@0x%X)"
          % (arch, arch, os.path.getsize(binout), syms.get("kbox_meta_run", 0)))


def build_stub(arch):
    src = os.path.join(STUB_SRC, "stub_%s.S" % arch)
    pp = os.path.join(WORK, "stub_%s_coff.S" % arch)
    obj = os.path.join(WORK, "stub_%s.o" % arch)
    elf = os.path.join(WORK, "stub_%s.elf" % arch)
    tmp_bin = os.path.join(WORK, "stub_%s.bin" % arch)
    binout = os.path.join(ENGINE_OUT, "blob_%s.bin" % arch)
    preprocess(src, pp)
    run([AS, "--64" if arch == "x64" else "--32", "-o", obj, pp])
    link_elf(arch, obj, elf, "kbox_entry")
    # 只取 .text/.iat：.iat 由 ld 按 4096 页对齐（x64/x86 均落在 0x5000），
    # 故链接产物天生满足 blob 契约，无需在 Python 里手工补对齐填充。
    # binutils 处理不了非 ASCII 路径，先落 ASCII 临时目录再拷回。
    run([OBJCOPY, "-O", "binary", "-j", ".text", "-j", ".iat", elf, tmp_bin])
    shutil.copyfile(tmp_bin, binout)
    blob = open(binout, "rb").read()

    syms = symbols(elf)
    iat_off = syms.get("kbox_iat", 0)
    layout = [
        ("BLOB_ENTRY_OFF", syms.get("kbox_entry", 0)),
        ("BLOB_CHACHA_OFF", syms.get("kbox_chacha", 0)),
        ("BLOB_IAT_OFF", iat_off),
        ("BLOB_CODE_END_OFF", syms.get("kbox_code_end", 0)),
        ("BLOB_DISPATCH_OFF", syms.get("kbox_vm_dispatch", 0)),
        ("BLOB_STRPOOL_OFF", syms.get("kbox_strpool_start", 0)),
        ("BLOB_DEFENSE_END_OFF", syms.get("kbox_defense_end", 0)),
        ("BLOB_CFGROOT_OFF", syms.get("kbox_cfg_root", 0)),
        ("BLOB_JUNK_START_OFF", syms.get("kbox_junk_start", 0)),
        ("BLOB_JUNK_END_OFF", syms.get("kbox_junk_end", 0)),
        ("BLOB_SIZE", len(blob)),
    ]
    hdr = os.path.join(LAYOUT_OUT, "stub_layout_%s.h" % arch)
    with open(hdr, "w", encoding="utf-8") as f:
        f.write("// stub_layout_%s.h - 由 build_blobs.py 生成，勿手改\n" % arch)
        f.write("// Java 侧对应 com.kbox.core.shield.BlobLayout.%s\n" % arch.upper())
        f.write("#pragma once\n#include <cstdint>\n")
        f.write("namespace kbox { namespace layout%s {\n" % arch)
        for k, v in layout:
            f.write("constexpr uint32_t %s = %du;\n" % (k, v))
        f.write("} } // namespace kbox::layout%s\n" % arch)

    print("[stub/%s] blob_%s.bin = %d bytes  entry=0x%X  .iat@0x%X"
          % (arch, arch, len(blob), syms.get("kbox_entry", 0), iat_off))


def main():
    for tool in (AS, LD, OBJCOPY, OBJDUMP, NM):
        if not os.path.exists(tool):
            raise SystemExit("缺少 binutils: %s（可用 MSYS2_BIN 环境变量覆盖）" % tool)
    for d in (ENGINE_OUT, LAYOUT_OUT, WORK):
        os.makedirs(d, exist_ok=True)
    for arch in ("x64", "x86"):
        build_engine(arch)
        build_stub(arch)
    print("done -> %s" % ENGINE_OUT)


if __name__ == "__main__":
    main()
