// kbox_format.h — kboXShield 共享布局契约（packer ↔ stub）
//
// 该文件定义打包产物（打壳后 PE）内部各数据结构的二进制布局。
// 所有多字节字段均为小端（x86/x64 原生）。结构体使用 pack(1)，
// 因为 packer 与 stub(汇编) 两侧都必须按精确偏移访问。
//
// 打壳后的 PE 布局（原地变换模型，与 Themida/UPX 同思路）：
//   1. 保留原 PE 全部节（代码节/数据节/资源节等，载荷数据被加密）
//   2. 末尾新增一个 stub 节（随机节名，RWX），节内顺序：
//        [KboxConfig][stub 代码(blob 其余)][加密 payload][合成导入表]
//        [VM 镜像][运行期汇编引擎 blob]
//   3. AddressOfEntryPoint → stub 节入口；Import Directory → 合成导入表
//   4. TLS/LoadConfig/BaseReloc 目录被清零（防 loader 读取加密数据）
//   5. 运行期 stub：取基址 → VM 自检 → 解密 payload → 解密各节 → 应用重定位
//      → IAT 重建 → 恢复节权限 → 跳转 OEP
#pragma once

#include <cstdint>

namespace kbox {

// 魔数与版本
constexpr uint32_t KBOX_MAGIC   = 0x584F424Bu; // "KBOX"
constexpr uint32_t KBOX_VERSION = 1u;
constexpr uint32_t PAYLOAD_MAGIC = 0x5941504Bu; // "KPAY"

// ---- Blob（stub 节）内固定偏移 ----
constexpr uint32_t BLOB_OFF_CONFIG  = 0x000u; // KboxConfig（packer 填充）
constexpr uint32_t BLOB_OFF_CODE    = 0x100u; // 入口代码（= AddressOfEntryPoint 相对 stub 节的偏移）
constexpr uint32_t BLOB_ENTRY_DELTA = 0x100u; // entry 运行时地址 - config 运行时地址
// KboxIat 槽位数量（stub 自身导入：LoadLibraryA/GetProcAddress/VirtualProtect）
constexpr uint32_t BLOB_IAT_COUNT   = 3u;
// kbox_iat 在 blob 中的偏移由 stub 构建脚本生成：stub_layout_{x86,x64}.h
// （asm 中 .iat 段置于 blob 末尾，nm 导出符号地址即为偏移）

// ---- 解密后 payload 内部布局 ----
// payload 解密后依次排列：
//   KboxPayloadHdr
//   KboxSectionRec[section_count]
//   KboxImpDll + entries  × dll_count
//   reloc 原始字节 [reloc_size]
constexpr uint32_t PAYLOAD_FLAG_SKIP_DECRYPT = 0x1u; // 节标记：不解密（预留）

// ---- 节权限（PAGE_*，解壳后恢复用） ----
constexpr uint32_t PAGE_READONLY          = 0x02u;
constexpr uint32_t PAGE_READWRITE         = 0x04u;
constexpr uint32_t PAGE_EXECUTE           = 0x10u;
constexpr uint32_t PAGE_EXECUTE_READ      = 0x20u;
constexpr uint32_t PAGE_EXECUTE_READWRITE = 0x40u;

// ---- KboxIat 槽位索引（stub 自身导入） ----
constexpr uint32_t IAT_LOADLIBRARYA   = 0u;
constexpr uint32_t IAT_GETPROCADDRESS = 1u;
constexpr uint32_t IAT_VIRTUALPROTECT = 2u;

// ---- VM 镜像标记（KboxConfig.vm_flags）----
constexpr uint32_t VM_FLAG_PRESENT = 0x1u; // stub 节内存在 VM 镜像

// ---- 运行期防御（Batch 5）：检测位（KboxDefenseReport.flags 与 def_flags 共用）----
// 低 16 位为「单次检测命中」；def_flags 用同一组位选择启用的检查。
constexpr uint32_t KBOX_DEF_PEB_DEBUG    = 0x00000001u; // L1 PEB.BeingDebugged
constexpr uint32_t KBOX_DEF_NTGLOBALFLAG = 0x00000002u; // L1 PEB.NtGlobalFlag
constexpr uint32_t KBOX_DEF_HEAPFLAGS    = 0x00000004u; // L1 堆 Flags/ForceFlags
constexpr uint32_t KBOX_DEF_ISDEBUGGER   = 0x00000008u; // L2 IsDebuggerPresent
constexpr uint32_t KBOX_DEF_REMOTEDEBUG  = 0x00000010u; // L2 CheckRemoteDebuggerPresent
constexpr uint32_t KBOX_DEF_PORTPROC     = 0x00000020u; // L2 NtQueryInformationProcess
constexpr uint32_t KBOX_DEF_HWBP         = 0x00000040u; // L3 硬件断点 Dr0-3
constexpr uint32_t KBOX_DEF_TIMING       = 0x00000080u; // L3 rdtsc 时间差
constexpr uint32_t KBOX_DEF_INT3SCAN     = 0x00000100u; // L1 int3(0xCC) 代码扫描
constexpr uint32_t KBOX_DEF_CPUID_HV     = 0x00000200u; // 反 VM：CPUID hypervisor 位
constexpr uint32_t KBOX_DEF_CPUID_VENDOR = 0x00000400u; // 反 VM：hypervisor vendor 串
constexpr uint32_t KBOX_DEF_IAT_HOOK     = 0x00000800u; // 反 hook：IAT 重解析比对
constexpr uint32_t KBOX_DEF_INLINE_HOOK  = 0x00001000u; // 反 hook：API 前缀跳转扫描
constexpr uint32_t KBOX_DEF_INTEGRITY    = 0x00002000u; // 完整性：CRC32 不符
constexpr uint32_t KBOX_DEF_INJECT       = 0x00004000u; // 反注入：可执行私有页
constexpr uint32_t KBOX_DEF_THREAD_HIDE  = 0x00008000u; // L2 NtSetInformationThread 失败
// 强信号（任一命中 → level >= 2；与 INJECT/INTEGRITY 组合 → level 3）
constexpr uint32_t KBOX_DEF_CRITICAL =
    KBOX_DEF_PEB_DEBUG | KBOX_DEF_ISDEBUGGER | KBOX_DEF_REMOTEDEBUG |
    KBOX_DEF_PORTPROC | KBOX_DEF_HWBP | KBOX_DEF_IAT_HOOK |
    KBOX_DEF_INLINE_HOOK | KBOX_DEF_THREAD_HIDE;
// 终局信号（命中 → 直接 level 3）
constexpr uint32_t KBOX_DEF_FATAL = KBOX_DEF_INJECT | KBOX_DEF_INTEGRITY;

// 分级响应级别
constexpr uint32_t KBOX_LVL_OK     = 0u; // 继续
constexpr uint32_t KBOX_LVL_WEAK   = 1u; // 弱信号：延迟后继续（记录）
constexpr uint32_t KBOX_LVL_DECOY  = 2u; // 确认被调试/篡改：诱饵路径
constexpr uint32_t KBOX_LVL_FATAL  = 3u; // 敌对：终止

// 报告块魔数与诱饵标记（KboxDefenseReport.reserved[0]）
constexpr uint32_t DEF_REPORT_MAGIC = 0x5246444Bu; // "KDFR"
constexpr uint32_t DEF_DECOY_MARK   = 0x4F434544u; // "DECO"

#pragma pack(push, 1)

// 运行期防御报告块（stub 节内，运行期写入；用于「检测体系 + 诱饵路径可观测」）
struct KboxDefenseReport {
    uint32_t magic;         // DEF_REPORT_MAGIC
    uint32_t flags;         // 命中的检测位（KBOX_DEF_*）
    uint32_t level;         // 响应级别（KBOX_LVL_*）
    uint32_t checks_run;    // 已执行的检查数
    uint32_t timing_delta;  // rdtsc 时间差（低 32 位）
    uint32_t integ_crc;     // 运行期计算的完整性 CRC32
    uint32_t module_count;  // PEB Ldr 模块数（反注入辅助）
    uint32_t hb_fail;       // 动态解析失败的函数数
    uint32_t reserved[8];   // reserved[0] 在诱饵路径写入 DEF_DECOY_MARK
};

// 节记录：描述一个需要解密/恢复权限的原始节
struct KboxSectionRec {
    uint32_t rva;          // 节 RVA（相对模块基址）
    uint32_t raw_size;     // 原始数据大小（加密区域 = 整个节 raw 区）
    uint32_t chacha_block; // 该节 ChaCha20 起始块计数
    uint32_t nonce[3];     // 12 字节 nonce（4B 节 ID + 8B 构建期随机）
    uint32_t perms;        // 解壳后目标保护属性（PAGE_*）
    uint32_t flags;        // PAYLOAD_FLAG_*
};

// 导入映射：一个 DLL 的导入条目
struct KboxImpDll {
    uint32_t name_rva;     // DLL 名（ASCII, '\0' 结尾）RVA
    uint32_t iat_rva;      // FirstThunk RVA（解析结果写入处，按指针宽度递增）
    uint32_t count;        // 条目数
    // 紧跟 count 个 KboxImpEntry
};

// 导入条目
struct KboxImpEntry {
    uint16_t ordinal;      // 0 = 按名导入；非 0 = 按序号
    uint16_t hint;         // 名称表 hint（仅按名时有效）
    uint32_t name_rva;     // 函数名 RVA（仅按名时有效）
};

// 解密后 payload 头（紧随其后的数据见上方注释）
struct KboxPayloadHdr {
    uint32_t magic;        // PAYLOAD_MAGIC
    uint32_t section_count;
    uint32_t imp_dll_count;
    uint32_t imp_total;    // 全部 DLL 的条目总数（含 ordinal，用于边界校验）
    uint32_t reloc_size;   // 重定位原始数据字节数（0 = 无）
    uint32_t reserved[3];
};

// 打包配置：位于 blob 起始处，由 packer 填充，stub 运行期读取
struct KboxConfig {
    uint32_t magic;            // KBOX_MAGIC
    uint32_t version;
    uint32_t flags;            // 预留
    uint32_t is_64bit;         // 1 = PE32+
    uint32_t stub_rva;         // stub 节 RVA（blob 起始）
    uint32_t oep_rva;          // 原始入口点 RVA
    uint32_t image_base_lo;    // 原始 ImageBase（低 32 位）
    uint32_t image_base_hi;    // 原始 ImageBase（高 32 位）
    uint32_t payload_rva;      // 加密 payload 的 RVA（位于 stub 节内）
    uint32_t payload_size;     // 加密 payload 字节数
    uint32_t chacha_key[8];    // 256-bit 会话密钥（构建期随机）
    uint32_t chacha_nonce[3];  // 96-bit payload nonce
    // ---- VM 元数据（Batch 4；vm_count == 0 表示无 VM 镜像）----
    uint32_t vm_count;         // 虚拟化镜像数（每个标记节一个；回退时含内置自检镜像）
    uint32_t vm_recs_rva;      // KboxVmRec[vm_count] 数组 RVA（位于 stub 节内）
    uint32_t vm_flags;         // VM_FLAG_*
    // ---- 运行期汇编引擎（Batch 4）----
    uint32_t vm_engine_rva;    // 汇编引擎 blob RVA（stub 节内，VM 镜像之后；0 = 无）
    // ---- 运行期防御（Batch 5）----
    uint32_t def_flags;        // 启用的检查位（KBOX_DEF_*）；0 = 关闭全部
    uint32_t def_policy;       // 分级响应策略位（bit0=弱信号延迟, bit1=诱饵, bit2=终止）
    uint32_t def_report_rva;   // KboxDefenseReport RVA（stub 节内）
    uint32_t def_integ_rva;    // 完整性覆盖区 RVA
    uint32_t def_integ_size;   // 完整性覆盖区字节数
    uint32_t def_integ_crc;    // 期望 CRC32（packer 计算）
    uint32_t def_decoy_rva;    // 诱饵入口 RVA（0 = 用内置 kbox_decoy）
    uint32_t def_delay_loops;  // 弱信号延迟：空转循环次数
    uint32_t def_timing_ticks; // 反调试/反 VM 的 rdtsc 阈值
    // ---- TLS 回调（Batch 6）----
    // DIR_TLS 被清零后，loader 不再调用 TLS 回调；packer 把原回调表（RVA 序列，
    // 0 结尾）复制到 stub 节，由 stub 在解壳完成后、跳 OEP 前代跑
    // （hinst=模块基址, reason=DLL_PROCESS_ATTACH, reserved=0）。
    uint32_t tls_cb_rva;       // 回调 RVA 数组（0 结尾）在 stub 节内的 RVA（0 = 无）
    uint32_t tls_cb_count;     // 回调个数
    uint32_t def_reserved[4];
};

// 单个虚拟化镜像记录（存于 stub 节内，packer 填充）
struct KboxVmRec {
    uint32_t image_rva;    // VM 镜像 RVA
    uint32_t image_size;   // VM 镜像字节数
    uint32_t target_rva;   // 被虚拟化函数 RVA（0 = 内置自检镜像，无分发桩）
    uint32_t self_in;      // VM 自检输入（写入 gprs[RAX]）
    uint32_t self_expect;  // VM 自检期望返回值（packer 以 C++ 引擎预演得出）
};

#pragma pack(pop)

// 供 packer 与 stub 共享的常量推导
constexpr uint32_t CONFIG_SIZE    = sizeof(KboxConfig);
constexpr uint32_t PAYLOAD_HDR_SIZE = sizeof(KboxPayloadHdr);
constexpr uint32_t SECTION_REC_SIZE = sizeof(KboxSectionRec);
constexpr uint32_t IMP_DLL_SIZE   = sizeof(KboxImpDll);
constexpr uint32_t IMP_ENTRY_SIZE = sizeof(KboxImpEntry);
constexpr uint32_t VM_REC_SIZE    = sizeof(KboxVmRec);

} // namespace kbox
