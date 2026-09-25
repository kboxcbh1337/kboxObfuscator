// vm_isa.h — kboXShield 多态虚拟机指令集架构（VM ISA）
//
// 三方共享契约：C++ 引擎（packer/vm/vm_engine.cpp）、字节码生成器
// （packer/vm/vm_builder.cpp）、汇编 stub（后续批次）共同遵循此布局。
//
// 设计要点：
//   1. 栈式架构：操作数隐式在栈上，指令只携带语义号 + 1 个立即数。
//   2. 固定指令长度（5 字节 = [opcode:1B][imm:4B]）：解密取指前无需
//      知道指令长度，这是"字节码加密 + 运行时解密取指"可行的前提。
//   3. opcode 随机重排：生成期将语义号（SEM_*）随机映射到 opcode
//      （0..SEM_COUNT-1 的排列），映射表随镜像加密存储。
//   4. handler 多态：每个语义拥有多个等价变体实现，生成期随机选定
//      变体序号写入镜像（variant_map）。
//   5. 调度混淆：镜像内选择 DISPATCH_TABLE（表驱动）或 DISPATCH_SWITCH
//      （集中 switch）两种分发方式。
//   6. 自由态安全（free-state safe）：引擎无任何全局/静态可写状态，
//      全部执行状态集中于 VmCtx，可重入、可多实例并发。
//
// 加密模型：镜像 = [VmImageHeader][opcode_map][variant_map][bytecode]
// 后三区整体加密。keystream 按绝对偏移生成（counter = pos>>6, 块内
// pos&63），builder 与 engine 使用同一算法保证加解密一致。
#pragma once

#include <cstdint>
#include <cstddef>

namespace kbox {
namespace vm {

// ---- 魔数与版本 ----
// 方案B：镜像魔数不再固定，由镜像密钥派生（每次构建随机）。
// 攻击者无法以常量魔数扫描定位镜像（F9.4）；引擎以 vm_magic_of(key) 校验。
constexpr uint32_t VM_IMAGE_VERSION = 2u;

// 镜像魔数由密钥派生：FNV-1a 变体 + 固定高位（非零、随 key 随机）。
// 密钥为构建期随机 -> 每镜像/每构建魔数不同。
inline uint32_t vm_magic_of(const uint32_t key[4]) {
    uint32_t h = 0x6B6F4269u;
    for (int i = 0; i < 4; ++i) {
        h ^= key[i];
        h *= 0x9E3779B1u;
        h ^= h >> 16;
    }
    return (h & 0x7FFFFFFFu) | 0x80000000u;
}

// ---- 数据宽度 ----
constexpr uint32_t VM_WORD_BITS = 32u;
constexpr uint32_t VM_WORD_BYTES = 4u;

// ---- 指令格式：固定 5 字节 ----
constexpr uint32_t VM_INSN_SIZE = 5u; // [opcode:1B][imm:4B 小端]
// 无立即数的指令，imm 字段由生成器填充随机字节（混淆）。

// ---- 语义编号（VM 逻辑指令集）----
// 生成期将每个语义号随机映射到唯一 opcode，构成 0..SEM_COUNT-1 的排列。
enum : uint32_t {
    SEM_NOP   = 0,  // 无操作
    SEM_PUSH,       // imm32 压栈
    SEM_LOAD,       // frame[imm & VM_FRAME_MASK] 压栈
    SEM_STORE,      // 弹栈写 frame[imm & VM_FRAME_MASK]
    SEM_DUP,        // 复制栈顶
    SEM_SWAP,       // 交换栈顶两元素
    SEM_POP,        // 弹栈丢弃
    SEM_ADD,        // a+b
    SEM_SUB,        // a-b
    SEM_MUL,        // a*b
    SEM_NEG,        // 0-a
    SEM_AND,        // a&b
    SEM_OR,         // a|b
    SEM_XOR,        // a^b
    SEM_NOT,        // ~a
    SEM_SHL,        // a << (b & 31)
    SEM_SHR,        // a >> (b & 31)  逻辑右移
    SEM_SAR,        // (int32)a >> (b & 31) 算术右移
    SEM_JMP,        // ip += imm32（相对下一条指令）
    SEM_JZ,         // 弹栈，为 0 则 ip += imm32
    SEM_JNZ,        // 弹栈，非 0 则 ip += imm32
    SEM_RET,        // 返回栈顶（弹栈）

    // ---- Batch 5：机器码虚拟化所需语义 ----
    // 64 位值（地址/指针）在栈上以两个字表示：先压 lo，再压 hi（hi 在栈顶）。
    // 通用寄存器 rax..r15 位于 frame[2g]（lo）与 frame[2g+1]（hi）。
    SEM_MEMRD,      // imm = 带符号位移：弹 base(hi,lo) → 压 *(u32*)(base+imm)（零扩展）
    SEM_MEMWR,      // imm = 带符号位移：弹 val、base(hi,lo) → *(u32*)(base+imm) = val
    SEM_ADDREL,     // imm = 带符号位移：弹 base(hi,lo) → 压 (base+imm) 的 (lo,hi)
    SEM_NATIVE,     // imm = 原生片段序号：退出到原生执行（混合模型，见 vm_engine.h）
    SEM_EQ,         // a == b  → 0/1
    SEM_NE,         // a != b
    SEM_ULT,        // 无符号 a <  b
    SEM_UGE,        // 无符号 a >= b
    SEM_ULE,        // 无符号 a <= b
    SEM_UGT,        // 无符号 a >  b
    SEM_SLT,        // 有符号 a <  b
    SEM_SGE,        // 有符号 a >= b
    SEM_SLE,        // 有符号 a <= b
    SEM_SGT,        // 有符号 a >  b
    SEM_COUNT
};
static_assert(SEM_COUNT <= 256u, "opcode 单字节，语义数须 <= 256");

// ---- x86-64 机器模型：通用寄存器编号（ModRM 顺序）----
enum : uint32_t {
    GPR_RAX = 0, GPR_RCX, GPR_RDX, GPR_RBX,
    GPR_RSP,     GPR_RBP, GPR_RSI, GPR_RDI,
    GPR_R8, GPR_R9, GPR_R10, GPR_R11,
    GPR_R12, GPR_R13, GPR_R14, GPR_R15,
    GPR_COUNT
};
// 每个通用寄存器占 2 个 frame 字：lo = 2g，hi = 2g + 1
constexpr uint32_t vm_gpr_slot(uint32_t g) { return g * 2u; }
// 机器寄存器块（引擎入口/出口用）：16 × u64
constexpr uint32_t VM_MACH_GPRS = GPR_COUNT;

// ---- 操作数栈 / 局部帧深度（2 的幂，便于掩码索引）----
// 操作数栈：32 字，容纳机器码提升后较深的表达式求值。
// 局部帧：128 字 =
//   0..31   16 个通用寄存器 × 2 字（lo/hi）
//   32..95  被虚拟化函数的静态栈帧（256 字节，[rbp/rsp ± disp] 静态分配）
//   96..127 16 个临时虚拟寄存器 × 2 字
constexpr uint32_t VM_STACK_WORDS = 32u;
constexpr uint32_t VM_STACK_MASK  = VM_STACK_WORDS - 1u;
constexpr uint32_t VM_FRAME_WORDS = 128u;
constexpr uint32_t VM_FRAME_MASK  = VM_FRAME_WORDS - 1u;
// 内层（Family A/B）解释器的单次执行步数上限（防失控）。
// C++ 引擎、x86 汇编引擎、被元编译进 Meta 字节码的内层解释器必须一致，
// 否则同一镜像在打包期预演与运行期会产生不同的 VM_ERR_TOO_DEEP 行为。
constexpr uint32_t VM_MAX_STEPS   = 131072u;
// 机器模型中通用寄存器占用的槽区间
constexpr uint32_t VM_MACH_SLOTS  = GPR_COUNT * 2u;      // 32
// 静态栈帧：起始槽与字数（256 字节）
constexpr uint32_t VM_STKFRM_SLOT0 = VM_MACH_SLOTS;      // 32
constexpr uint32_t VM_STKFRM_WORDS = 64u;                // 32..95
constexpr uint32_t VM_STKFRM_BYTES = VM_STKFRM_WORDS * 4u;
// 临时虚拟寄存器槽起点（16 个临时寄存器 × 2 字）
constexpr uint32_t VM_TMP_SLOT0   = VM_STKFRM_SLOT0 + VM_STKFRM_WORDS; // 96
constexpr uint32_t VM_TMP_VREGS   = 16u;

// ---- 调度器类型（生成期写入镜像）----
enum : uint32_t {
    DISPATCH_TABLE  = 0, // 表驱动：handler 表经 opcode 反查后索引
    DISPATCH_SWITCH = 1, // 集中式 switch
};
constexpr uint32_t VM_DISPATCH_TYPES = 2u;

// ---- handler 变体数 ----
constexpr uint32_t VM_VARIANTS = 3u; // 每语义最多变体数（单实现语义固定用 0）

// ---- VM 家族（镜像 header.flags 低 8 位）----
// Family A：栈式，5 字节定长 [op:1B][imm:4B]，操作数隐式在栈上。
// Family B：寄存器式，8 字节定长 [op:1B][rd:1B][ra:1B][rb:1B][imm:4B]，
//           32 个 64 位寄存器直接映射 frame 槽（lo/hi 对）。
enum : uint32_t {
    VM_FAMILY_STACK = 0, // A
    VM_FAMILY_REG   = 1, // B
};
constexpr uint32_t VM_FAMILY_MASK = 0xFFu;

// ---- Family B：寄存器式 ISA ----
// 指令 8 字节：[op][rd][ra][rb][imm32 小端]。
// 寄存器 r（0..31）→ frame 槽 lo = (r < 16) ? 2r : 2r + 64（hi = lo+1）：
//   r0..r15  = x86-64 通用寄存器（rax..r15）
//   r16..r31 = 临时寄存器（frame 96..127）
// 32 位运算写 lo 并清 hi；LD/LEA/MEM 使用完整 64 位。
// rd 为 cc 的条件类：REG_SETCC 用 imm 低 8 位、REG_JCC 用 rd 字段。
constexpr uint32_t VM_B_INSN_SIZE = 8u;

enum : uint32_t {
    REG_NOP = 0,
    REG_MOVI,   // rd = imm（零扩展，hi = 0）
    REG_SET64,  // rd = (int64)(int32)imm（符号扩展，hi = 符号）
    REG_MOV,    // rd = ra（取 lo，清 hi）
    REG_ADD, REG_SUB, REG_MUL, REG_AND, REG_OR, REG_XOR,
    REG_SHL, REG_SHR, REG_SAR,     // rd = ra <op> rb（32 位，清 hi）
    REG_NEG, REG_NOT,              // rd = <op> ra（32 位，清 hi）
    REG_FLD,    // rd.lo = frame[imm]（hi = 0）
    REG_FLD64,  // rd = frame[imm..imm+1]（64 位）
    REG_FST,    // frame[imm] = ra.lo
    REG_FST64,  // frame[imm..imm+1] = ra（64 位）
    REG_LD,     // rd.lo = *(u32*)(ra + imm)，hi = 0
    REG_ST,     // *(u32*)(ra + imm) = rb.lo
    REG_LEA,    // rd = ra + (int64)(int32)imm（64 位）
    REG_SETCC,  // rd.lo = (ra cc rb)，hi = 0；cc = imm 低 8 位
    REG_JCC,    // (ra cc rb) 则 ip = imm（绝对字节偏移）；cc = rd
    REG_JMP,    // ip = imm（绝对字节偏移）
    REG_RET,    // 返回 ra.lo
    REG_NATIVE, // 退出到原生执行（imm = 片段序号）
    REG_COUNT
};
static_assert(REG_COUNT <= 256u, "opcode 单字节，Family B 语义数须 <= 256");

// 条件码编号（与 ir.h 的 IrCc 同序，供 REG_SETCC/REG_JCC 使用）
enum : uint32_t {
    VCC_EQ = 0, VCC_NE, VCC_ULT, VCC_UGE, VCC_ULE, VCC_UGT,
    VCC_SLT, VCC_SGE, VCC_SLE, VCC_SGT, VCC_COUNT
};

// Family B 指令（编译器输出 / 构建器输入）
struct BInsn {
    uint8_t  op = REG_NOP;
    uint8_t  rd = 0;    // 目的寄存器（或 JCC 的条件码）
    uint8_t  ra = 0;
    uint8_t  rb = 0;
    uint32_t imm = 0;
};

// ---- 镜像内部偏移（header 之后依次排列）----
struct VmImageHeader {
    uint32_t magic;         // vm_magic_of(key)（构建期随机）
    uint32_t version;       // VM_IMAGE_VERSION
    uint32_t flags;         // 预留
    uint32_t dispatch;      // DISPATCH_*
    uint32_t total_size;    // 镜像总字节数（含 header，用于边界校验）
    uint32_t bc_size;       // 加密指令流字节数（VM_INSN_SIZE 的整数倍）
    uint32_t entry;         // 起始指令下标（相对 bc 起始）
    uint32_t stack_words;   // 实际栈深（<= VM_STACK_WORDS）
    uint32_t key[4];        // 128-bit 镜像密钥（生成期随机）
    // 方案B：reserved[0] = Meta 镜像相对本镜像字节增量；reserved[1] = Meta 镜像字节数
    //         reserved[2] = map_iv（opcode/variant 表加扰 nonce，见 vm_derive_key2）
    //         reserved[3] = 预留（0）
    uint32_t reserved[4];
};

constexpr uint32_t VM_HEADER_SIZE    = sizeof(VmImageHeader);
constexpr uint32_t VM_OFF_OPCODE_MAP = VM_HEADER_SIZE;
constexpr uint32_t VM_OFF_VARIANT_MAP = VM_OFF_OPCODE_MAP + SEM_COUNT;
constexpr uint32_t VM_OFF_BYTECODE   = VM_OFF_VARIANT_MAP + SEM_COUNT;

// 方案B：加扰表第二密钥派生（与 vm_derive_key 不同填充 + 混入 map_iv）。
// 镜像中 opcode/variant 表以「明文 ^ ks1 ^ ks2」存储（ks1 用主派生密钥、
// ks2 用本派生密钥），攻击者仅知主 keystream 时得到伪随机表，无法建立
// 「opcode -> 语义」映射（F3.2/F3.5）；完整算法在引擎（C++/汇编/Meta）内。
inline void vm_derive_key2(const uint32_t key[4], uint32_t iv, uint32_t out[8]) {
    out[0] = key[0] ^ (iv + 0x9E3779B9u);
    out[1] = key[1] ^ (iv * 0x85EBCA77u);
    out[2] = key[2] ^ ((iv << 13) | (iv >> 19));
    out[3] = key[3] ^ ((iv >> 5) | (iv << 27));
    out[4] = 0x4D646E41u; // "AndM"
    out[5] = 0x6F6D4F75u; // "uOmo"
    out[6] = 0x7068434Bu; // "KChp"
    out[7] = 0x78696649u; // "Ifix"
}

// Family B 镜像内部偏移（header 之后：[opcode_map][bytecode]）
constexpr uint32_t VM_B_OFF_OPCODE_MAP = VM_HEADER_SIZE;
constexpr uint32_t VM_B_OFF_BYTECODE   = VM_B_OFF_OPCODE_MAP + REG_COUNT;

// ---- 执行结果码 ----
enum : uint32_t {
    VM_OK            = 0,
    VM_ERR_FAULT     = 1, // 越界 / 非法指令指针
    VM_ERR_STACK_OVER  = 2,
    VM_ERR_STACK_UNDER = 3,
    VM_ERR_BAD_MAGIC   = 4,
    VM_ERR_BAD_OPCODE  = 5,
    VM_ERR_BAD_JUMP    = 6,
    VM_ERR_TOO_DEEP    = 7, // 循环/指令数超限（防失控）
};

// ---- keystream 派生 ----
// 由 header.key[4]（128-bit 会话密钥）派生出 256-bit 加密密钥
inline void vm_derive_key(const uint32_t key[4], uint32_t out[8]) {
    out[0] = key[0];
    out[1] = key[1];
    out[2] = key[2];
    out[3] = key[3];
    // 固定填充（仅共享派生约定，非秘密）
    out[4] = 0x6B626F58u;
    out[5] = 0x6E67696Eu;
    out[6] = 0x203A6F44u;
    out[7] = 0x2179654Bu;
}

// 按绝对偏移生成 64 字节 keystream 块：counter = pos>>6，块内偏移 pos&63。
// 由 vm_ks.cpp 实现（基于 ChaCha20，nonce 全 0）。builder 与 engine 共用。
void vm_ks_block(const uint32_t k8[8], uint32_t counter, uint8_t out[64]);

} // namespace vm
} // namespace kbox
