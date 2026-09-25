package com.kbox.core.shield;

/**
 * KboxFormat — kboXShield 共享布局契约（由 include/kbox_format.h 移植）。
 *
 * <p>定义打包产物（打壳后 PE）内部各数据结构的二进制布局。所有多字节字段
 * 均为小端；结构体按 pack(1) 排列，packer 与 stub（汇编）两侧必须按精确偏移访问。</p>
 */
public final class KboxFormat {

    private KboxFormat() {
    }

    // ---- 魔数与版本 ----
    public static final int KBOX_MAGIC = 0x584F424B;      // "KBOX"
    public static final int KBOX_VERSION = 1;
    public static final int PAYLOAD_MAGIC = 0x5941504B;   // "KPAY"

    // ---- Blob（stub 节）内固定偏移 ----
    public static final int BLOB_OFF_CONFIG = 0x000;
    public static final int BLOB_OFF_CODE = 0x100;
    public static final int BLOB_ENTRY_DELTA = 0x100;
    public static final int BLOB_IAT_COUNT = 3;

    // ---- 解密后 payload 内部布局 ----
    public static final int PAYLOAD_FLAG_SKIP_DECRYPT = 0x1;

    // ---- 节权限（PAGE_*） ----
    public static final int PAGE_READONLY = 0x02;
    public static final int PAGE_READWRITE = 0x04;
    public static final int PAGE_EXECUTE = 0x10;
    public static final int PAGE_EXECUTE_READ = 0x20;
    public static final int PAGE_EXECUTE_READWRITE = 0x40;

    // ---- KboxIat 槽位索引（stub 自身导入） ----
    public static final int IAT_LOADLIBRARYA = 0;
    public static final int IAT_GETPROCADDRESS = 1;
    public static final int IAT_VIRTUALPROTECT = 2;

    // ---- VM 镜像标记 ----
    public static final int VM_FLAG_PRESENT = 0x1;

    // ---- 运行期防御：检测位 ----
    public static final int KBOX_DEF_PEB_DEBUG = 0x00000001;
    public static final int KBOX_DEF_NTGLOBALFLAG = 0x00000002;
    public static final int KBOX_DEF_HEAPFLAGS = 0x00000004;
    public static final int KBOX_DEF_ISDEBUGGER = 0x00000008;
    public static final int KBOX_DEF_REMOTEDEBUG = 0x00000010;
    public static final int KBOX_DEF_PORTPROC = 0x00000020;
    public static final int KBOX_DEF_HWBP = 0x00000040;
    public static final int KBOX_DEF_TIMING = 0x00000080;
    public static final int KBOX_DEF_INT3SCAN = 0x00000100;
    public static final int KBOX_DEF_CPUID_HV = 0x00000200;
    public static final int KBOX_DEF_CPUID_VENDOR = 0x00000400;
    public static final int KBOX_DEF_IAT_HOOK = 0x00000800;
    public static final int KBOX_DEF_INLINE_HOOK = 0x00001000;
    public static final int KBOX_DEF_INTEGRITY = 0x00002000;
    public static final int KBOX_DEF_INJECT = 0x00004000;
    public static final int KBOX_DEF_THREAD_HIDE = 0x00008000;

    /** 强信号：任一命中 → level >= 2。 */
    public static final int KBOX_DEF_CRITICAL =
            KBOX_DEF_PEB_DEBUG | KBOX_DEF_ISDEBUGGER | KBOX_DEF_REMOTEDEBUG
                    | KBOX_DEF_PORTPROC | KBOX_DEF_HWBP | KBOX_DEF_IAT_HOOK
                    | KBOX_DEF_INLINE_HOOK | KBOX_DEF_THREAD_HIDE;

    /** 终局信号：命中 → 直接 level 3。 */
    public static final int KBOX_DEF_FATAL = KBOX_DEF_INJECT | KBOX_DEF_INTEGRITY;

    // ---- 分级响应级别 ----
    public static final int KBOX_LVL_OK = 0;
    public static final int KBOX_LVL_WEAK = 1;
    public static final int KBOX_LVL_DECOY = 2;
    public static final int KBOX_LVL_FATAL = 3;

    // ---- 报告块魔数与诱饵标记 ----
    public static final int DEF_REPORT_MAGIC = 0x5246444B;  // "KDFR"
    public static final int DEF_DECOY_MARK = 0x4F434544;    // "DECO"

    // ================= 结构体字段偏移（pack(1)） =================

    // ---- KboxDefenseReport（64 字节） ----
    public static final int DR_MAGIC = 0;
    public static final int DR_FLAGS = 4;
    public static final int DR_LEVEL = 8;
    public static final int DR_CHECKS_RUN = 12;
    public static final int DR_TIMING_DELTA = 16;
    public static final int DR_INTEG_CRC = 20;
    public static final int DR_MODULE_COUNT = 24;
    public static final int DR_HB_FAIL = 28;
    public static final int DR_RESERVED = 32;      // u32[8]
    public static final int DEFENSE_REPORT_SIZE = 64;

    // ---- KboxSectionRec（32 字节） ----
    public static final int SR_RVA = 0;
    public static final int SR_RAW_SIZE = 4;
    public static final int SR_CHACHA_BLOCK = 8;
    public static final int SR_NONCE = 12;         // u32[3]
    public static final int SR_PERMS = 24;
    public static final int SR_FLAGS = 28;
    public static final int SECTION_REC_SIZE = 32;

    // ---- KboxImpDll（12 字节）+ KboxImpEntry（8 字节） ----
    public static final int ID_NAME_RVA = 0;
    public static final int ID_IAT_RVA = 4;
    public static final int ID_COUNT = 8;
    public static final int IMP_DLL_SIZE = 12;

    public static final int IE_ORDINAL = 0;
    public static final int IE_HINT = 2;
    public static final int IE_NAME_RVA = 4;
    public static final int IMP_ENTRY_SIZE = 8;

    // ---- KboxPayloadHdr（32 字节） ----
    public static final int PH_MAGIC = 0;
    public static final int PH_SECTION_COUNT = 4;
    public static final int PH_IMP_DLL_COUNT = 8;
    public static final int PH_IMP_TOTAL = 12;
    public static final int PH_RELOC_SIZE = 16;
    public static final int PH_RESERVED = 20;      // u32[3]
    public static final int PAYLOAD_HDR_SIZE = 32;

    // ---- KboxConfig（160 字节） ----
    public static final int CFG_MAGIC = 0;
    public static final int CFG_VERSION = 4;
    public static final int CFG_FLAGS = 8;
    public static final int CFG_IS64 = 12;
    public static final int CFG_STUB_RVA = 16;
    public static final int CFG_OEP_RVA = 20;
    public static final int CFG_IMG_LO = 24;
    public static final int CFG_IMG_HI = 28;
    public static final int CFG_PAY_RVA = 32;
    public static final int CFG_PAY_SIZE = 36;
    public static final int CFG_KEY = 40;          // u32[8]，32 字节
    public static final int CFG_NONCE = 72;        // u32[3]，12 字节
    public static final int CFG_VM_COUNT = 84;
    public static final int CFG_VM_RECS_RVA = 88;
    public static final int CFG_VM_FLAGS = 92;
    public static final int CFG_VM_ENGINE_RVA = 96;
    public static final int CFG_DEF_FLAGS = 100;
    public static final int CFG_DEF_POLICY = 104;
    public static final int CFG_DEF_REPORT_RVA = 108;
    public static final int CFG_DEF_INTEG_RVA = 112;
    public static final int CFG_DEF_INTEG_SIZE = 116;
    public static final int CFG_DEF_INTEG_CRC = 120;
    public static final int CFG_DEF_DECOY_RVA = 124;
    public static final int CFG_DEF_DELAY = 128;
    public static final int CFG_DEF_TICKS = 132;
    public static final int CFG_TLS_CB_RVA = 136;
    public static final int CFG_TLS_CB_COUNT = 140;
    public static final int CFG_DEF_RES0 = 144;    // u32[4]
    public static final int CFG_EP_PATCH = 148;    // 入口 trampoline 原始 5 字节（u32@148 + u8@152）
    public static final int CONFIG_SIZE = 160;

    // ---- KboxVmRec（20 字节） ----
    public static final int VMR_IMAGE_RVA = 0;
    public static final int VMR_IMAGE_SIZE = 4;
    public static final int VMR_TARGET_RVA = 8;
    public static final int VMR_SELF_IN = 12;
    public static final int VMR_SELF_EXPECT = 16;
    public static final int VM_REC_SIZE = 20;
}
