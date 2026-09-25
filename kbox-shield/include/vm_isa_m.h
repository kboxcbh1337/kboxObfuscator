// vm_isa_m.h — kboXShield 外层 Meta VM（嵌套虚拟化的外层）指令集架构
//
// 定位（Batch 4.4 嵌套虚拟化）：
//   内层 VM（Family A 栈式 / Family B 寄存器式）的**解释器本身**不再以明文
//   native 代码存在，而是被编译成 Meta VM 的字节码；Meta VM 解释器
//   （kbox_meta_run）是唯一残留的明文 native 循环，因此逆向一个内层族
//   不再直接得到内层引擎的取指/分派/语义。
//
// 与内层 A/B 族**刻意保持独立**（逆向其一不蕴含其二）：
//   - 自有魔数/版本/密钥派生填充/内部偏移；
//   - 自有 opcode 编号空间（M_*，与 SEM_*/REG_* 无对应关系）；
//   - 64 位寄存器机器（16 × u64），带显式调用栈（M_CALL/M_CALLR/M_RET）
//     与宿主逃逸（M_HOST）——A 无调用、B 无 64 位 ALU/调用，语义面不同；
//   - 定长 8 字节指令，就地解密 + 执行后回加密（与内层同机制、不同密钥）。
//
// 自由态安全：无全局/静态可写状态，全部执行状态位于调用方提供的 ctx。
#pragma once

#include <cstdint>
#include <cstddef>

namespace kbox {
namespace vm {

// ---- 魔数与版本（与内层 VM_IMAGE_MAGIC/’KBVM’ 不同）----
// 方案B：Meta 镜像魔数同样由密钥派生（构建期随机），无固定扫描值（F9.4）。
constexpr uint32_t M_IMAGE_VERSION = 1u;

inline uint32_t m_magic_of(const uint32_t key[4]) {
    uint32_t h = 0x4D56426Du;
    for (int i = 0; i < 4; ++i) {
        h ^= key[i];
        h *= 0x85EBCA6Bu;
        h ^= h >> 15;
    }
    return (h & 0x7FFFFFFFu) | 0x80000000u;
}

// ---- 指令格式：定长 8 字节 [op:1B][dst:1B][src:1B][aux:1B][imm32 小端] ----
constexpr uint32_t M_INSN_SIZE = 8u;

// ---- 寄存器 ----
constexpr uint32_t M_REGS = 16u; // m0..m15，均为 64 位

// ---- Meta 语义（自成一体的编号空间）----
enum : uint32_t {
    M_NOP = 0,
    M_MOVI,    // m[dst] = (u64)(u32)imm                零扩展
    M_SET64,   // m[dst] = (u64)(i64)(i32)imm           符号扩展
    M_MOV,     // m[dst] = m[src]
    M_ADD,     // m[dst] = m[src] <op> m[aux]（以下 9 条均 64 位）
    M_SUB,
    M_MUL,
    M_AND,
    M_OR,
    M_XOR,
    M_SHL,     // 64 位，位移量 = m[aux] & 63
    M_SHR,
    M_SAR,
    M_NEG,     // m[dst] = -m[src]
    M_NOT,     // m[dst] = ~m[src]
    M_DIV,     // m[dst] = m[src] / m[aux]（无符号 64 位；除零 → M_ERR_FAULT）
    M_MOD,     // m[dst] = m[src] % m[aux]（无符号 64 位；除零 → M_ERR_FAULT）
    M_LD,      // m[dst] = *(u64*)(m[src] + simm32(imm))
    M_LD32,    // m[dst] = (u64)*(u32*)(m[src] + simm32(imm))
    M_LD8,     // m[dst] = (u64)*(u8*)(m[src] + simm32(imm))
    M_ST,      // *(u64*)(m[dst] + simm32(imm)) = m[src]   （dst=基址, src=值）
    M_ST32,    // *(u32*)(m[dst] + simm32(imm)) = (u32)m[src]
    M_ST8,     // *(u8*)(m[dst] + simm32(imm))  = (u8)m[src]
    M_LEA,     // m[dst] = m[src] + simm32(imm)
    M_SETCC,   // m[dst] = (m[src] cc m[aux]) ? 1 : 0；cc = imm 低 8 位
    M_JMP,     // mip = imm（Meta 字节码内绝对偏移）
    M_JCC,     // (m[src] cc m[aux]) 则 mip = imm；cc = dst 字段
    M_CALL,    // push(mip+8); mip = imm
    M_CALLR,   // push(mip+8); mip = (u32)m[src]（绝对偏移，供 handler 表分发）
    M_JMPR,    // mip = (u32)m[src]
    M_RET,     // mip = pop()
    M_HOST,    // 宿主逃逸：prim = imm（见 M_HOST_*）
    M_HALT,    // 停机：status = (u32)m[dst]，retval = (u32)m[src]
    M_COUNT
};
static_assert(M_COUNT <= 256u, "opcode 单字节，Meta 语义数须 <= 256");

// 条件码沿用 VCC_*（数值与 ir.h IrCc 同序，仅作共享数值约定）
enum : uint32_t {
    M_CC_EQ = 0, M_CC_NE, M_CC_ULT, M_CC_UGE, M_CC_ULE, M_CC_UGT,
    M_CC_SLT, M_CC_SGE, M_CC_SLE, M_CC_SGT, M_CC_COUNT
};

// ---- 宿主逃逸原语（M_HOST imm）----
// 约定：原语经 m12..m15 收参、经 m12 回结果（见 vm_meta.h 的 MHostFn）。
enum : uint32_t {
    M_HOST_CHACHA = 0,       // m12=buf, m13=len, m14=key, m15=nonce, m11=counter
    M_HOST_INNER_NATIVE = 1, // m12=imm → 调内层 native_fn；m12=状态码
    M_HOST_COUNT
};

// ---- 解释器固定寄存器约定 ----
// m5 由 vm_meta_exec 置为"解密后的 handler 偏移表"地址（供 M_CALLR 分派）；
// 内层解释器程序的初始寄存器 m0..m4 由调用方设置（state/image/size/gprs/ks_fn）。
constexpr uint32_t M_HT_REG = 5u;

// ---- Meta 指令（构建器输入 / 解释器输出）----
struct MInsn {
    uint8_t  op;
    uint8_t  dst;
    uint8_t  src;
    uint8_t  aux;
    uint32_t imm;
};

// ---- Meta 镜像头（与内层 VmImageHeader 同形不同魔数；独立密钥填充）----
struct MImageHeader {
    uint32_t magic;         // m_magic_of(key)（构建期随机）
    uint32_t version;       // M_IMAGE_VERSION
    uint32_t flags;         // 预留
    uint32_t reserved0;
    uint32_t total_size;    // 镜像总字节数
    uint32_t bc_size;       // 字节码字节数（M_INSN_SIZE 的整数倍）
    uint32_t entry;         // 起始指令下标
    uint32_t map_iv;        // 方案B：opcode/handler 表加扰 nonce（见 m_derive_key2）
    uint32_t key[4];        // 128-bit 镜像密钥（生成期随机）
    uint32_t reserved[4];
};
constexpr uint32_t M_HEADER_SIZE      = sizeof(MImageHeader);        // 64
constexpr uint32_t M_OFF_OPCODE_MAP   = M_HEADER_SIZE;               // 64
// handler 偏移表：N 个 u32 绝对偏移（相对字节码起始），随镜像加密
constexpr uint32_t M_HANTAB_ENTRIES   = 64u;
constexpr uint32_t M_OFF_HANDLER_TAB  = M_OFF_OPCODE_MAP + M_COUNT;  // 64 + M_COUNT
constexpr uint32_t M_OFF_BYTECODE     = M_OFF_HANDLER_TAB + M_HANTAB_ENTRIES * 4u;

// ---- 执行状态码（与内层同值域，便于 stub 统一判定）----
enum : uint32_t {
    M_OK              = 0,
    M_ERR_FAULT       = 1,
    M_ERR_BAD_MAGIC   = 4,
    M_ERR_BAD_OPCODE  = 5,
    M_ERR_TOO_DEEP    = 7,
};

// ---- keystream 块生成（共享底层原语；实现见 vm_ks.cpp）----
// 与内层 VM 使用同一 ChaCha20 原语，但密钥经 m_derive_key 独立派生。
void vm_ks_block(const uint32_t k8[8], uint32_t counter, uint8_t out[64]);

// ---- 密钥派生（内层 vm_derive_key 的独立对照：不同固定填充）----
inline void m_derive_key(const uint32_t key[4], uint32_t out[8]) {
    out[0] = key[0];
    out[1] = key[1];
    out[2] = key[2];
    out[3] = key[3];
    // 固定填充（与内层 VM_KS_C4..C7 不同；仅共享派生约定，非秘密）
    out[4] = 0x4D42564Du; // "MBVM"
    out[5] = 0x6174654Du; // "Meta"
    out[6] = 0x6E72654Bu; // "Kern"
    out[7] = 0x00004C65u; // "el"
}

// 方案B：Meta 加扰第二密钥派生（与 m_derive_key 不同填充 + 混入 map_iv）。
// opcode_map 与 handler 表以「明文 ^ ks1 ^ ks2」存储；ks2 密钥即本函数。
inline void m_derive_key2(const uint32_t key[4], uint32_t iv, uint32_t out[8]) {
    out[0] = key[0] ^ (iv + 0x85EBCA6Bu);
    out[1] = key[1] ^ (iv * 0xC2B2AE35u);
    out[2] = key[2] ^ ((iv << 17) | (iv >> 15));
    out[3] = key[3] ^ ((iv >> 7) | (iv << 25));
    out[4] = 0x656D614Cu; // "Lame"
    out[5] = 0x614D6162u; // "baMa"
    out[6] = 0x65546369u; // "icTe"
    out[7] = 0x00617250u; // "Pra"
}

} // namespace vm
} // namespace kbox
