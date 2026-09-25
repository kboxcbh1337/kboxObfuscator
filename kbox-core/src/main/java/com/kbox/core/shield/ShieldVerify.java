package com.kbox.core.shield;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/**
 * ShieldVerify — 加壳产物的静态自检（PE 结构 + KboxConfig 可解密性）。
 *
 * <p>动机：加壳失败有两种表现——明确报错，或「产出能写出来但 Windows 直接拒载」。
 * 后者排查成本高（例如资源节被加密会让 {@code CreateProcess} 返回
 * {@code ERROR_BAD_EXE_FORMAT(193)}，因为进程创建阶段就要解析 manifest）。
 * 因此在打包后立刻做一遍结构自检，把结论回显到 CLI / GUI，避免产出静默不可用的 exe。</p>
 *
 * <p>只做只读校验，不修改产物；不加载、不执行。</p>
 */
public final class ShieldVerify {

    private ShieldVerify() {
    }

    /** 单条结论。level ∈ {"ok","warn","fail"}。 */
    public static final class Finding {
        public final String level;
        public final String msg;

        Finding(String level, String msg) {
            this.level = level;
            this.msg = msg;
        }

        @Override
        public String toString() {
            return "[" + level.toUpperCase() + "] " + msg;
        }
    }

    public static final class Report {
        public final List<Finding> findings = new ArrayList<>();
        public boolean ok = true;

        void add(String level, String msg) {
            findings.add(new Finding(level, msg));
            if ("fail".equals(level)) {
                ok = false;
            }
        }

        public int count(String level) {
            int n = 0;
            for (Finding f : findings) {
                if (f.level.equals(level)) {
                    n++;
                }
            }
            return n;
        }

        /** 多行文本报告（CLI 日志 / GUI 文本区直接用）。 */
        public String toText() {
            StringBuilder sb = new StringBuilder();
            sb.append("PE 自检：").append(ok ? "通过" : "发现致命问题")
                    .append("（ok=").append(count("ok"))
                    .append(" warn=").append(count("warn"))
                    .append(" fail=").append(count("fail")).append("）");
            for (Finding f : findings) {
                sb.append('\n').append("  ").append(f);
            }
            return sb.toString();
        }
    }

    /** 被清除的数据目录（与 packer 的 clear_dirs 一致）。 */
    private static final int[] CLEARED_DIRS = {
            PeImage.DIR_SECURITY, PeImage.DIR_BASERELOC, PeImage.DIR_TLS,
            PeImage.DIR_LOADCONFIG, PeImage.DIR_BOUNDIMPORT, PeImage.DIR_IAT,
            PeImage.DIR_DELAYIMPORT, PeImage.DIR_CLR
    };

    private static final String[] CLEARED_NAMES = {
            "SECURITY", "BASERELOC", "TLS", "LOADCONFIG", "BOUNDIMPORT", "IAT",
            "DELAYIMPORT", "CLR"
    };

    /**
     * 校验加壳产物。
     *
     * @param outPath 产物路径
     * @param opts    打包时使用的选项（用于回显期望值；可为 null）
     */
    public static Report verify(String outPath, ShieldOptions opts) {
        Report r = new Report();
        Path p = Paths.get(outPath);
        byte[] d;
        try {
            d = Files.readAllBytes(p);
        } catch (Exception e) {
            r.add("fail", "无法读取产物: " + e);
            return r;
        }
        r.add("ok", "产物大小 " + d.length + " 字节");

        PeImage img = new PeImage();
        StringBuilder err = new StringBuilder();
        if (!img.parse(d, d.length, err)) {
            r.add("fail", "PE 解析失败: " + err);
            return r;
        }
        r.add("ok", "PE 解析通过：arch=" + (img.is64Bit() ? "x64(PE32+)" : "x86(PE32)")
                + " sections=" + img.numberOfSections()
                + " SizeOfImage=0x" + Integer.toHexString(img.sizeOfImage())
                + " SizeOfHeaders=0x" + Integer.toHexString(img.sizeOfHeaders()));

        // ---- 1) 节表几何 ----
        int hdrEnd = 0;
        for (PeImage.SectionInfo s : img.sections()) {
            if (s.rawSize > 0) {
                if (Integer.compareUnsigned(s.rawPtr + s.rawSize, d.length) > 0) {
                    r.add("fail", "节 " + s.name + " 的 raw 区越过文件末尾（rptr=0x"
                            + Integer.toHexString(s.rawPtr) + " raw=0x"
                            + Integer.toHexString(s.rawSize) + "）");
                }
                if ((s.rawPtr % img.fileAlignment()) != 0) {
                    r.add("fail", "节 " + s.name + " 的 PointerToRawData 未按 FileAlignment 对齐");
                }
            }
            if (Integer.compareUnsigned(s.virtualAddress + Math.max(s.virtualSize, s.rawSize),
                    img.sizeOfImage()) > 0) {
                r.add("fail", "节 " + s.name + " 的虚拟区间越过 SizeOfImage");
            }
            int end = s.virtualAddress + Math.max(s.virtualSize, s.rawSize);
            if (end > hdrEnd) {
                hdrEnd = end;
            }
        }
        if (hdrEnd != 0) {
            r.add("ok", "节表几何检查完成（末节末尾 = SizeOfImage 前提已核对）");
        }

        // ---- 2) 入口点必须落在可执行节内 ----
        int ep = img.entryRva();
        PeImage.SectionInfo epSec = img.sectionByRva(ep);
        if (epSec == null) {
            r.add("fail", "入口点 RVA 0x" + Integer.toHexString(ep) + " 不在任何节内");
        } else if ((epSec.characteristics & PeImage.SCN_MEM_EXECUTE) == 0) {
            r.add("fail", "入口点所在节 " + epSec.name + " 未标记可执行");
        } else {
            r.add("ok", "入口点 0x" + Integer.toHexString(ep) + " 位于可执行节 " + epSec.name);
        }

        // ---- 3) 导入目录存在且落在节内 ----
        int impRva = img.directoryRva(PeImage.DIR_IMPORT);
        int impSize = img.directorySize(PeImage.DIR_IMPORT);
        if (impRva == 0 || impSize == 0) {
            r.add("fail", "Import Directory 为空：stub 无法取得 API（loader 不会回填 IAT）");
        } else if (img.sectionByRva(impRva) == null) {
            r.add("fail", "Import Directory RVA 0x" + Integer.toHexString(impRva) + " 不在任何节内");
        } else {
            r.add("ok", "合成导入表 rva=0x" + Integer.toHexString(impRva)
                    + " size=0x" + Integer.toHexString(impSize));
        }

        // ---- 4) 必须清零的目录 ----
        StringBuilder notCleared = new StringBuilder();
        for (int i = 0; i < CLEARED_DIRS.length; i++) {
            if (img.directoryRva(CLEARED_DIRS[i]) != 0 || img.directorySize(CLEARED_DIRS[i]) != 0) {
                // G3：sv>=7 镜像会注入明文 LoadConfig（位于 stub 前两节），loader 可直接读取，属预期
                if (CLEARED_DIRS[i] == PeImage.DIR_LOADCONFIG) {
                    PeImage.SectionInfo ls = img.sectionByRva(img.directoryRva(PeImage.DIR_LOADCONFIG));
                    if (ls != null && img.numberOfSections() >= 2
                            && ls == img.sections().get(1)) {
                        r.add("ok", "LOADCONFIG 指向 stub 明文节（sv>=7 loader 校验 SecurityCookie）");
                        continue;
                    }
                }
                if (notCleared.length() > 0) {
                    notCleared.append(", ");
                }
                notCleared.append(CLEARED_NAMES[i]);
            }
        }
        if (notCleared.length() > 0) {
            r.add("warn", "以下目录未清零（loader 可能读取密文）：" + notCleared);
        } else {
            r.add("ok", "SECURITY/BASERELOC/TLS/LOADCONFIG/BOUNDIMPORT/IAT/DELAYIMPORT/CLR 均已清零或指向明文区");
        }

        // ---- 5) 资源目录必须保留（进程创建阶段要解析 manifest） ----
        if (img.directoryRva(PeImage.DIR_RESOURCE) == 0) {
            r.add("warn", "Resource Directory 为空：应用清单/图标在运行期将不可用");
        } else {
            r.add("ok", "Resource Directory 保留 rva=0x"
                    + Integer.toHexString(img.directoryRva(PeImage.DIR_RESOURCE)));
        }

        // ---- 6) KboxConfig 可解密性（与 stub 的 .Lcfg_loop 同一 LCG 算法） ----
        int[] epOff = new int[1];
        if (epSec != null && epSec.rawSize > 0 && img.rvaToOffset(ep, epOff)) {
            // blob 契约：入口位于 blob 偏移 entry_off；配置区在 blob[0,0x100)
            // ⇒ 配置区文件偏移 = 入口文件偏移 − entry_off
            final int entryOff = BlobLayout.entryOff(img.is64Bit());
            final int cfgRoot = BlobLayout.cfgRootOff(img.is64Bit());
            final int entryDelta = ep - epSec.virtualAddress;
            final int cfgBase = epOff[0] - entryDelta;
            if (entryDelta != entryOff) {
                r.add("warn", "入口相对节首偏移 0x" + Integer.toHexString(entryDelta)
                        + " 与 blob 契约 entry_off=0x" + Integer.toHexString(entryOff) + " 不一致");
            }
            // cfgRoot 是「blob 内」的种子槽偏移（不在 0x100 配置区内），故按 blob 基址取。
            if (cfgBase >= 0
                    && cfgBase + 0x100 <= d.length
                    && cfgBase + cfgRoot + 4 <= d.length) {
                int seed = Bin.i32(d, cfgBase + cfgRoot);
                byte[] cfg = Bin.slice(d, cfgBase, 0x100);
                int st = seed;
                for (int i = 0; i < 0x100; i++) {
                    st = st * 1664525 + 1013904223;
                    cfg[i] ^= (byte) (st >>> 16);
                }
                int magic = Bin.i32(cfg, KboxFormat.CFG_MAGIC);
                int version = Bin.i32(cfg, KboxFormat.CFG_VERSION);
                int stubRva = Bin.i32(cfg, KboxFormat.CFG_STUB_RVA);
                int oepRva = Bin.i32(cfg, KboxFormat.CFG_OEP_RVA);
                int dflags = Bin.i32(cfg, KboxFormat.CFG_DEF_FLAGS);
                int dpolicy = Bin.i32(cfg, KboxFormat.CFG_DEF_POLICY);
                int vmCount = Bin.i32(cfg, KboxFormat.CFG_VM_COUNT);
                int payRva = Bin.i32(cfg, KboxFormat.CFG_PAY_RVA);
                if (magic != KboxFormat.KBOX_MAGIC) {
                    r.add("fail", "KboxConfig 解密后魔数不符（0x"
                            + Integer.toHexString(magic) + "，期望 0x"
                            + Integer.toHexString(KboxFormat.KBOX_MAGIC) + "）——配置区种子/布局不匹配");
                } else if (version != KboxFormat.KBOX_VERSION) {
                    r.add("fail", "KboxConfig 版本不符：" + version);
                } else if (stubRva != epSec.virtualAddress) {
                    r.add("fail", "KboxConfig.stub_rva=0x" + Integer.toHexString(stubRva)
                            + " 与入口所在节 0x" + Integer.toHexString(epSec.virtualAddress) + " 不一致");
                } else {
                    r.add("ok", "KboxConfig 解密通过：magic=KBOX ver=" + version
                            + " stub_rva=0x" + Integer.toHexString(stubRva)
                            + " oep_rva=0x" + Integer.toHexString(oepRva)
                            + " payload_rva=0x" + Integer.toHexString(payRva)
                            + " vm_count=" + vmCount);
                    r.add("ok", "运行期防御：def_flags=0x" + Integer.toHexString(dflags)
                            + " def_policy=" + dpolicy
                            + (opts != null
                            ? "（期望 0x" + Integer.toHexString(opts.defFlags)
                            + " / " + opts.defPolicy + "）"
                            : ""));
                    if (opts != null && dflags != opts.defFlags) {
                        r.add("warn", "def_flags 与本次选项不一致");
                    }
                    if (dflags == 0) {
                        r.add("warn", "def_flags=0：运行期防御全部关闭");
                    }
                }
            } else {
                r.add("warn", "无法定位配置区（stub 节几何异常），跳过 KboxConfig 自检");
            }
        }

        return r;
    }
}
