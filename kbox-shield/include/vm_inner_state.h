// vm_inner_state.h — 嵌套虚拟化的"内层执行状态"共享布局
//
// 外层 Meta VM 执行的内层解释器程序以**内存块**保存内层引擎执行状态
// （内层 ip/sp/栈/帧/映射表/keystream 缓存等），该块由引导程序 kbox_vm_run
// 在栈上分配（IS_SIZE 字节），指针经 m-state 寄存器传给 Meta 程序。
//
// 字段均为小端；下划线的偏移同时被 C++（Meta 程序生成器）与汇编（引导程序）
// 使用，两侧必须保持一致。
#pragma once

#include <cstdint>

namespace kbox {
namespace vm {

// 内层指令长度/字节码偏移（与 vm_isa.h 一致）
constexpr uint32_t IS_INSN_A       = 5u;
constexpr uint32_t IS_INSN_B       = 8u;
constexpr uint32_t IS_BCOFF_A      = 136u; // VM_OFF_BYTECODE
constexpr uint32_t IS_BCOFF_B      = 91u;  // VM_B_OFF_BYTECODE
constexpr uint32_t IS_SEM_A        = 36u;  // SEM_COUNT
constexpr uint32_t IS_SEM_B        = 27u;  // REG_COUNT
constexpr uint32_t IS_VERSION      = 2u;

// 内层状态块偏移
constexpr uint32_t IS_IP      = 0;    // u32 内层 ip（相对 bc）
constexpr uint32_t IS_SP      = 4;    // u32 内层操作数栈指针
constexpr uint32_t IS_RETVAL  = 8;    // u32 RET 值
constexpr uint32_t IS_STATUS  = 12;   // u32 错误码（0 = 正常）
constexpr uint32_t IS_STEPS   = 16;   // u32 已执行步数
constexpr uint32_t IS_FAMILY  = 20;   // u32 0=A / 1=B
constexpr uint32_t IS_BCSIZE  = 24;   // u32
constexpr uint32_t IS_BCOFF   = 28;   // u32
constexpr uint32_t IS_ILEN    = 32;   // u32
constexpr uint32_t IS_STACKW  = 36;   // u32 内层栈深上限
constexpr uint32_t IS_IPIMG   = 40;   // u32 当前指令在镜像内绝对偏移
constexpr uint32_t IS_KSCNT   = 44;   // u32 keystream 缓存块号（0xFFFFFFFF = 无效）
constexpr uint32_t IS_IMM     = 48;   // u32 当前指令 imm
constexpr uint32_t IS_RD      = 52;   // u32 当前指令 rd
constexpr uint32_t IS_RA      = 56;   // u32
constexpr uint32_t IS_RB      = 60;   // u32
constexpr uint32_t IS_SEM     = 64;   // u32 当前指令语义号
constexpr uint32_t IS_JUMPED  = 68;   // u32 B 族跳转已发生标志
constexpr uint32_t IS_NSEM    = 72;   // u32 本族语义数（A=36 / B=27）
constexpr uint32_t IS_RETC    = 76;   // u32 本族 RET 语义值（A=21 / B=25）
constexpr uint32_t IS_OPMAP   = 128;  // u8[64]  解密后 opcode_map
constexpr uint32_t IS_REV     = 192;  // u8[256] opcode -> 语义号（0xFF = 无效）
constexpr uint32_t IS_KSBLK   = 448;  // u8[64]  keystream 块缓存
constexpr uint32_t IS_KS5     = 512;  // u8[8]   当前指令 keystream（回加密）
constexpr uint32_t IS_KEY     = 520;  // u8[32]  派生密钥
constexpr uint32_t IS_NONCE   = 552;  // u8[16]  全零 nonce
// 方案B：加扰第二密钥（opcode_map 双 keystream 解密）与其块缓存计数
constexpr uint32_t IS_KEY2    = 568;  // u8[32]  加扰派生密钥（vm_derive_key2）
constexpr uint32_t IS_KSCNT2  = 600;  // u32    第二 keystream 缓存块号（0xFFFFFFFF=无效）
constexpr uint32_t IS_STACK   = 604;  // u32[32] 内层操作数栈
constexpr uint32_t IS_FRAME   = 732;  // u32[128] 内层帧（含 16 个 GPR 的 lo/hi 槽）
constexpr uint32_t IS_SIZE    = 1248; // 总字节数（8 对齐）

static_assert(IS_SIZE % 8u == 0u, "内层状态块须 8 字节对齐");

// 内层 VM 头部字段偏移（与 vm_isa.h VmImageHeader 一致）
constexpr uint32_t IH_MAGIC       = 0;
constexpr uint32_t IH_VERSION     = 4;
constexpr uint32_t IH_FLAGS       = 8;
constexpr uint32_t IH_DISPATCH    = 12;
constexpr uint32_t IH_TOTAL_SIZE  = 16;
constexpr uint32_t IH_BC_SIZE     = 20;
constexpr uint32_t IH_ENTRY       = 24;
constexpr uint32_t IH_STACK_WORDS = 28;
constexpr uint32_t IH_KEY         = 32;
constexpr uint32_t IH_RESERVED    = 48;  // reserved[0] = Meta 镜像相对本镜像的字节增量
constexpr uint32_t IH_MAGIC_VAL   = 0x4D56424Bu; // "KBVM"
constexpr uint32_t IH_SIZE        = 64;

} // namespace vm
} // namespace kbox
