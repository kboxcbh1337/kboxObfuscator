# vm_engine_x64.S — kboXShield 运行期汇编 VM 引擎（x86-64, PE32+）
#
# Batch 4.4 嵌套虚拟化：本 blob 不再包含内层（Family A/B）解释器的 native 实现，
# 只含
#   1) kbox_vm_run  —— 引导：校验内层镜像头、经 reserved[0] 定位外层 Meta 镜像、
#                       布置内层状态块（含机器寄存器 -> 帧槽）、调用 kbox_meta_run；
#   2) kbox_meta_run —— 外层 Meta VM 解释器（本文件主体）。
# 内层解释器的取指/反查/分派/语义/回加密/ip 推进全部以 Meta 字节码形式存在
# （由 packer 于打包期生成，见 packer/vm/meta_inner.cpp），随内层镜像头
# reserved[0]=相对字节增量 / reserved[1]=Meta 镜像字节数 定位。
#
# 与 packer/vm/vm_meta.cpp 的 C++ Meta 解释器逐条一致：
#   - 定长 8 字节指令 [op][dst][src][aux][imm32]，取指**就地**解密（写入镜像
#     缓冲），执行后立即用同一 keystream 回写密文（幂等：返回时逐字节不变）。
#   - opcode 随机重排（解密 opcode_map 后建反向表 rev[opcode]=语义号）。
#   - handler 偏移表（64 × u32 绝对字节偏移）随镜像加密存放。
#   - M_HOST：原语 0 = ChaCha（经 ks_fn），1 = 内层原生片段（无执行器 → FAULT）。
#
# 位置无关（PIC）：仅 RIP 相对寻址；分发表以"相对本地基准的 32 位偏移"存储。
# 自由态安全：无全局/静态可写状态，执行状态全在栈上（无堆分配）。
#
# 入口：kbox_vm_run(image, image_size, gprs, ks_fn)
#         Win64 式（rcx/rdx/r8/r9）→ eax=状态码，edx=结果
#       kbox_meta_run(params*) —— 见下方 MetaParams 布局
# blob 契约：入口符号 kbox_vm_run 位于 blob 偏移 0。

    .code64
    .section .text

# ================= 契约常量 =================
# ---- Meta ISA（同步 include/vm_isa_m.h）----
.set MX_MAGIC,       0x4D56424D
.set MX_VERSION,     1
.set MX_INSN,        8
.set MX_HDRSZ,       64
.set MX_COUNT,       33
.set MX_OFF_OPMAP,   64
.set MX_HANTAB_N,    64
.set MX_OFF_HANTAB,  97
.set MX_OFF_BC,      353

.set MX_NOP,0
.set MX_MOVI,1
.set MX_SET64,2
.set MX_MOV,3
.set MX_ADD,4
.set MX_SUB,5
.set MX_MUL,6
.set MX_AND,7
.set MX_OR,8
.set MX_XOR,9
.set MX_SHL,10
.set MX_SHR,11
.set MX_SAR,12
.set MX_NEG,13
.set MX_NOT,14
.set MX_DIV,15
.set MX_MOD,16
.set MX_LD,17
.set MX_LD32,18
.set MX_LD8,19
.set MX_ST,20
.set MX_ST32,21
.set MX_ST8,22
.set MX_LEA,23
.set MX_SETCC,24
.set MX_JMP,25
.set MX_JCC,26
.set MX_CALL,27
.set MX_CALLR,28
.set MX_JMPR,29
.set MX_RET,30
.set MX_HOST,31
.set MX_HALT,32

.set MX_CC_EQ,0
.set MX_CC_NE,1
.set MX_CC_ULT,2
.set MX_CC_UGE,3
.set MX_CC_ULE,4
.set MX_CC_UGT,5
.set MX_CC_SLT,6
.set MX_CC_SGE,7
.set MX_CC_SLE,8
.set MX_CC_SGT,9
.set MX_CC_COUNT,10

.set MX_OK,0
.set MX_ERR_FAULT,1
.set MX_ERR_BADMAGIC,4
.set MX_ERR_BADOP,5
.set MX_ERR_DEEP,7
.set MX_MAX_STEPS, 8388608

# ---- MetaCtx 布局（栈上；XSZ 须 ≡ 8 mod 16）----
.set X_IMG,     0
.set X_MSIZE,   8
.set X_KSFN,    16
.set X_INNIMG,  24
.set X_INNSZ,   32
.set X_STATE,   40
.set X_GPRS,    48
.set X_OUT,     56
.set X_IP,      64
.set X_STEPS,   68
.set X_CSP,     72
.set X_RETVAL,  76
.set X_BCSIZE,  80
.set X_INSOFF,  84
.set X_KSCTR,   88
.set X_OPC,     92
.set X_DST,     96
.set X_SRC,     100
.set X_AUX,     104
.set X_IMM,     108
.set X_JUMPED,  112
.set X_HALTED,  116
.set X_HALTST,  120
.set X_POS,     124
.set X_K8,      128
.set X_NONCE,   160
.set X_OPMAP,   176
.set X_REGS,    240
.set X_HANTAB,  368
.set X_REV,     624
.set X_KSBLK,   880
.set X_KS8,     944
.set X_CSTACK,  952
.set XSZ,       1464

# ---- 内层镜像头（同步 include/vm_isa.h）----
.set IH_MAGIC,   0
.set IH_VERSION, 4
.set IH_RSV0,    48
.set IH_RSV1,    52
.set IH_IV_MAGIC, 0x4D56424B
.set IH_IV_VER,   2

# ---- 内层状态块（同步 include/vm_inner_state.h）----
.set IS_SIZE,    1248
.set IS_FRAME,   732
.set IS_LOOPN,   16

# ================= 引导：kbox_vm_run =================
    .globl kbox_vm_run
    .type kbox_vm_run, @function
kbox_vm_run:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rsi
    subq $1344, %rsp                # [0,1248) 内层状态块；1248..1311 参数块；1312 出参
    movq %rcx, %r12                 # image
    movl %edx, %r13d                # image_size
    movq %r8, %r14                  # gprs
    movq %r9, %r15                  # ks_fn
    movq %rsp, %rbx                 # state

    movq %rbx, %rdi
    xorl %eax, %eax
    movl $(IS_SIZE/8), %ecx
    rep stosq

    cmpl $64, %r13d
    jb .Lvd_badmagic
    cmpl $IH_IV_MAGIC, IH_MAGIC(%r12)
    jne .Lvd_badmagic
    cmpl $IH_IV_VER, IH_VERSION(%r12)
    jne .Lvd_badmagic
    movl IH_RSV0(%r12), %eax        # Meta 镜像相对增量
    testl %eax, %eax
    jz .Lvd_badmagic
    movslq %eax, %rax
    leaq (%r12,%rax), %r8           # meta image
    movl IH_RSV1(%r12), %r9d        # meta size

    testq %r14, %r14
    jz .Lvd_nogpr
    xorl %edi, %edi
.Lvd_gi:
    movq (%r14,%rdi,8), %rax
    movl %eax, IS_FRAME(%rbx,%rdi,8)
    shrq $32, %rax
    movl %eax, IS_FRAME+4(%rbx,%rdi,8)
    incl %edi
    cmpl $16, %edi
    jb .Lvd_gi
.Lvd_nogpr:

    leaq 1248(%rsp), %rcx
    movq %r8, 0(%rcx)
    movl %r9d, 8(%rcx)
    movq %r12, 16(%rcx)
    movl %r13d, 24(%rcx)
    movq %r14, 32(%rcx)
    movq %r15, 40(%rcx)
    movq %rbx, 48(%rcx)
    leaq 1312(%rsp), %rax
    movq %rax, 56(%rcx)
    movl $0, 1312(%rsp)

    call kbox_meta_run

    movl %eax, %esi                 # status
    movl %edx, %edi                 # retval
    testl %esi, %esi
    jnz .Lvd_out
    testq %r14, %r14
    jz .Lvd_out
    xorl %ecx, %ecx
.Lvd_go:
    movl IS_FRAME(%rbx,%rcx,8), %eax
    movl IS_FRAME+4(%rbx,%rcx,8), %edx
    shlq $32, %rdx
    orq %rdx, %rax
    movq %rax, (%r14,%rcx,8)
    incl %ecx
    cmpl $16, %ecx
    jb .Lvd_go
.Lvd_out:
    movl %esi, %eax
    movl %edi, %edx
    addq $1344, %rsp
    popq %rsi
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret
.Lvd_badmagic:
    movl $MX_ERR_BADMAGIC, %eax
    xorl %edx, %edx
    jmp .Lvd_exit2
.Lvd_exit2:
    addq $1344, %rsp
    popq %rsi
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

# ================= 外层 Meta VM 解释器 =================
# 入参：rcx = MetaParams*
#   +0  meta_image   +8  meta_size(u32)  +16 inner_image  +24 inner_size(u32)
#   +32 gprs         +40 ks_fn           +48 inner_state  +56 out(u32*)
    .globl kbox_meta_run
    .type kbox_meta_run, @function
kbox_meta_run:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %rsi
    pushq %rdi
    subq $XSZ, %rsp
    movq %rsp, %rbx
    movq %rcx, %r12                 # params
    movq %rbx, %rdi
    xorl %eax, %eax
    movl $(XSZ/8), %ecx
    rep stosq

    movq 0(%r12), %rax;  movq %rax, X_IMG(%rbx)
    movl 8(%r12), %eax;  movl %eax, X_MSIZE(%rbx)
    movq 16(%r12), %rax; movq %rax, X_INNIMG(%rbx)
    movl 24(%r12), %eax; movl %eax, X_INNSZ(%rbx)
    movq 32(%r12), %rax; movq %rax, X_GPRS(%rbx)
    movq 40(%r12), %rax; movq %rax, X_KSFN(%rbx)
    movq 48(%r12), %rax; movq %rax, X_STATE(%rbx)
    movq 56(%r12), %rax; movq %rax, X_OUT(%rbx)

    # ---- 校验 Meta 镜像头 ----
    cmpl $MX_HDRSZ, X_MSIZE(%rbx)
    jb .Lmx_badmagic
    movq X_IMG(%rbx), %rsi
    cmpl $MX_MAGIC, 0(%rsi)
    jne .Lmx_badmagic
    cmpl $MX_VERSION, 4(%rsi)
    jne .Lmx_badmagic
    movl 16(%rsi), %eax
    testl %eax, %eax
    jz .Lmx_tot_ok
    cmpl X_MSIZE(%rbx), %eax
    ja .Lmx_fault_nw
.Lmx_tot_ok:
    movl 20(%rsi), %eax
    movl %eax, X_BCSIZE(%rbx)
    testl $7, %eax
    jnz .Lmx_fault_nw
    addl $MX_OFF_BC, %eax
    cmpl X_MSIZE(%rbx), %eax
    ja .Lmx_fault_nw
    cmpl $0, X_BCSIZE(%rbx)
    je .Lmx_fault_nw
    movl $0, X_IP(%rbx)

    # ---- 派生密钥：header.key[4] || 固定填充 ----
    movl 32(%rsi), %eax;  movl %eax, X_K8+0(%rbx)
    movl 36(%rsi), %eax;  movl %eax, X_K8+4(%rbx)
    movl 40(%rsi), %eax;  movl %eax, X_K8+8(%rbx)
    movl 44(%rsi), %eax;  movl %eax, X_K8+12(%rbx)
    movl $0x4D42564D, X_K8+16(%rbx)
    movl $0x6174654D, X_K8+20(%rbx)
    movl $0x6E72654B, X_K8+24(%rbx)
    movl $0x00004C65, X_K8+28(%rbx)
    movl $0xFFFFFFFF, X_KSCTR(%rbx)

    # ---- rev[0..255] = 0xFF ----
    movq $-1, %rax
    leaq X_REV(%rbx), %rdi
    movl $32, %ecx
    rep stosq

    # ---- 解密 opcode_map -> X_OPMAP ----
    xorl %esi, %esi
.Lmx_dmap:
    leal MX_OFF_OPMAP(%rsi), %r8d
    call .Lmx_ks_byte
    movq X_IMG(%rbx), %rcx
    leal MX_OFF_OPMAP(%rsi), %eax
    movzbl (%rcx,%rax), %eax
    xorb %dl, %al
    movb %al, X_OPMAP(%rbx,%rsi)
    incl %esi
    cmpl $MX_COUNT, %esi
    jb .Lmx_dmap

    # ---- 建反向表 rev[opcode] = 语义号（校验为排列）----
    xorl %esi, %esi
.Lmx_rb:
    movzbl X_OPMAP(%rbx,%rsi), %eax
    cmpl $MX_COUNT, %eax
    jae .Lmx_badmagic
    cmpb $0xFF, X_REV(%rbx,%rax)
    jne .Lmx_badmagic
    movb %sil, X_REV(%rbx,%rax)
    incl %esi
    cmpl $MX_COUNT, %esi
    jb .Lmx_rb

    # ---- 解密 handler 偏移表（64 × u32 = 256B）----
    xorl %esi, %esi
.Lmx_hb:
    leal MX_OFF_HANTAB(%rsi), %r8d
    call .Lmx_ks_byte
    movq X_IMG(%rbx), %rcx
    leal MX_OFF_HANTAB(%rsi), %eax
    movzbl (%rcx,%rax), %eax
    xorb %dl, %al
    movb %al, X_HANTAB(%rbx,%rsi)
    incl %esi
    cmpl $256, %esi
    jb .Lmx_hb

    # ---- 初始寄存器：m0=state m1=image m2=size m3=gprs m4=ksfn m5=&hantab ----
    movq X_STATE(%rbx), %rax;  movq %rax, X_REGS+0(%rbx)
    movq X_INNIMG(%rbx), %rax; movq %rax, X_REGS+8(%rbx)
    movl X_INNSZ(%rbx), %eax;  movq %rax, X_REGS+16(%rbx)
    movq X_GPRS(%rbx), %rax;   movq %rax, X_REGS+24(%rbx)
    movq X_KSFN(%rbx), %rax;   movq %rax, X_REGS+32(%rbx)
    leaq X_HANTAB(%rbx), %rax; movq %rax, X_REGS+40(%rbx)

    # ================= 主循环 =================
.Lmx_loop:
    movl X_STEPS(%rbx), %eax
    incl %eax
    movl %eax, X_STEPS(%rbx)
    cmpl $MX_MAX_STEPS, %eax
    ja .Lmx_toodeep_nw
    movl $0, X_JUMPED(%rbx)         # 每轮复位（跳转 handler 命中时置 1）

    movl X_IP(%rbx), %eax
    cmpl X_BCSIZE(%rbx), %eax
    ja .Lmx_fault_nw
    addl $MX_INSN, %eax
    cmpl X_BCSIZE(%rbx), %eax
    ja .Lmx_fault_nw

    movl X_IP(%rbx), %r12d
    addl $MX_OFF_BC, %r12d
    movl %r12d, X_INSOFF(%rbx)
    xorl %r13d, %r13d
.Lmx_fb:
    movl %r12d, %r8d
    addl %r13d, %r8d
    call .Lmx_ks_byte
    movq X_IMG(%rbx), %rcx
    movl %r12d, %eax
    addl %r13d, %eax
    movb %dl, X_KS8(%rbx,%r13)
    xorb %dl, (%rcx,%rax)           # 就地解密：密文 -> 明文
    incl %r13d
    cmpl $MX_INSN, %r13d
    jb .Lmx_fb

    movq X_IMG(%rbx), %rcx
    movl %r12d, %eax
    movzbl 0(%rcx,%rax), %edx; movl %edx, X_OPC(%rbx)
    movzbl 1(%rcx,%rax), %edx; movl %edx, X_DST(%rbx)
    movzbl 2(%rcx,%rax), %edx; movl %edx, X_SRC(%rbx)
    movzbl 3(%rcx,%rax), %edx; movl %edx, X_AUX(%rbx)
    movl   4(%rcx,%rax), %edx; movl %edx, X_IMM(%rbx)

    movl X_OPC(%rbx), %eax
    movzbl X_REV(%rbx,%rax), %eax
    cmpl $MX_COUNT, %eax
    jae .Lmx_badop
    leaq .Lmx_dtbase(%rip), %rcx
    movslq (%rcx,%rax,4), %rax
    addq %rcx, %rax
    jmp *%rax

.Lmx_after:
    # 回加密：当前指令明文 -> 密文
    movl X_INSOFF(%rbx), %eax
    movq X_IMG(%rbx), %rcx
    xorl %edx, %edx
.Lmx_re:
    movzbl X_KS8(%rbx,%rdx), %esi
    xorb %sil, (%rcx,%rax)
    incl %eax
    incl %edx
    cmpl $MX_INSN, %edx
    jb .Lmx_re
    cmpl $0, X_HALTED(%rbx)
    jne .Lmx_done
    cmpl $0, X_JUMPED(%rbx)
    jne .Lmx_loop
    addl $MX_INSN, X_IP(%rbx)
    jmp .Lmx_loop

.Lmx_done:
    movl X_RETVAL(%rbx), %edx
    movl X_HALTST(%rbx), %eax
    jmp .Lmx_exit

# ---- 错误出口 ----
.Lmx_fault:
    movl $MX_ERR_FAULT, X_HALTST(%rbx)
    movl $1, X_HALTED(%rbx)
    jmp .Lmx_after
.Lmx_badop:
    movl $MX_ERR_BADOP, X_HALTST(%rbx)
    movl $1, X_HALTED(%rbx)
    jmp .Lmx_after
.Lmx_toodeep:
    movl $MX_ERR_DEEP, X_HALTST(%rbx)
    movl $1, X_HALTED(%rbx)
    jmp .Lmx_after

.Lmx_fault_nw:
    movl $MX_ERR_FAULT, %eax
    xorl %edx, %edx
    jmp .Lmx_exit
.Lmx_toodeep_nw:
    movl $MX_ERR_DEEP, %eax
    xorl %edx, %edx
    jmp .Lmx_exit
.Lmx_badmagic:
    movl $MX_ERR_BADMAGIC, %eax
    xorl %edx, %edx

.Lmx_exit:
    testl %eax, %eax
    jnz .Lmx_exit2
    movq X_OUT(%rbx), %rcx
    testq %rcx, %rcx
    jz .Lmx_exit2
    movl %edx, (%rcx)
.Lmx_exit2:
    addq $XSZ, %rsp
    popq %rdi
    popq %rsi
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

# ================= keystream 单字节（pos 入 r8d，字节出 dl） =================
# 保留 rbx/r12/r13（供主循环与取指使用）；其余可破坏。
.Lmx_ks_byte:
    movl %r8d, X_POS(%rbx)
    movl %r8d, %eax
    shrl $6, %eax
    cmpl X_KSCTR(%rbx), %eax
    je .Lks_hit
    movl %eax, X_KSCTR(%rbx)
    xorl %eax, %eax
    movq %rax, X_KSBLK+0(%rbx)
    movq %rax, X_KSBLK+8(%rbx)
    movq %rax, X_KSBLK+16(%rbx)
    movq %rax, X_KSBLK+24(%rbx)
    movq %rax, X_KSBLK+32(%rbx)
    movq %rax, X_KSBLK+40(%rbx)
    movq %rax, X_KSBLK+48(%rbx)
    movq %rax, X_KSBLK+56(%rbx)
    leaq X_KSBLK(%rbx), %rcx
    movl $64, %edx
    leaq X_K8(%rbx), %r8
    leaq X_NONCE(%rbx), %r9
    movl X_KSCTR(%rbx), %r10d
    movq X_KSFN(%rbx), %rax
    call *%rax
.Lks_hit:
    movl X_POS(%rbx), %eax
    andl $63, %eax
    leaq X_KSBLK(%rbx), %rcx
    movzbl (%rcx,%rax), %edx
    ret

# ================= 条件码求值（cc 入 eax，a 入 r8，b 入 r9；出 edx=0/1） =================
.Lmx_cceval:
    cmpl $MX_CC_EQ, %eax
    je .Lcc_eq
    cmpl $MX_CC_NE, %eax
    je .Lcc_ne
    cmpl $MX_CC_ULT, %eax
    je .Lcc_ult
    cmpl $MX_CC_UGE, %eax
    je .Lcc_uge
    cmpl $MX_CC_ULE, %eax
    je .Lcc_ule
    cmpl $MX_CC_UGT, %eax
    je .Lcc_ugt
    cmpl $MX_CC_SLT, %eax
    je .Lcc_slt
    cmpl $MX_CC_SGE, %eax
    je .Lcc_sge
    cmpl $MX_CC_SLE, %eax
    je .Lcc_sle
    cmpl $MX_CC_SGT, %eax
    je .Lcc_sgt
    xorl %edx, %edx
    ret
.Lcc_eq:  cmpq %r9, %r8; sete  %dl; movzbl %dl, %edx; ret
.Lcc_ne:  cmpq %r9, %r8; setne %dl; movzbl %dl, %edx; ret
.Lcc_ult: cmpq %r9, %r8; setb  %dl; movzbl %dl, %edx; ret
.Lcc_uge: cmpq %r9, %r8; setae %dl; movzbl %dl, %edx; ret
.Lcc_ule: cmpq %r9, %r8; setbe %dl; movzbl %dl, %edx; ret
.Lcc_ugt: cmpq %r9, %r8; seta  %dl; movzbl %dl, %edx; ret
.Lcc_slt: cmpq %r9, %r8; setl  %dl; movzbl %dl, %edx; ret
.Lcc_sge: cmpq %r9, %r8; setge %dl; movzbl %dl, %edx; ret
.Lcc_sle: cmpq %r9, %r8; setle %dl; movzbl %dl, %edx; ret
.Lcc_sgt: cmpq %r9, %r8; setg  %dl; movzbl %dl, %edx; ret

# ================= Meta handler（按语义号） =================
.Lmh_nop:
    jmp .Lmx_after

.Lmh_movi:
    movl X_DST(%rbx), %ecx
    movl X_IMM(%rbx), %eax
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_set64:
    movl X_DST(%rbx), %ecx
    movslq X_IMM(%rbx), %rax
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_mov:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.macro MX_BIN op
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movl X_AUX(%rbx), %ecx
    \op X_REGS(%rbx,%rcx,8), %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after
.endm

.Lmh_add: MX_BIN addq
.Lmh_sub: MX_BIN subq
.Lmh_mul: MX_BIN imulq
.Lmh_and: MX_BIN andq
.Lmh_or:  MX_BIN orq
.Lmh_xor: MX_BIN xorq

.macro MX_SHIFT op
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movl X_AUX(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rcx
    \op %cl, %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after
.endm

.Lmh_shl: MX_SHIFT shlq
.Lmh_shr: MX_SHIFT shrq
.Lmh_sar: MX_SHIFT sarq

.Lmh_neg:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    negq %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_not:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    notq %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.macro MX_DIVMOD
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movl X_AUX(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rcx
    testq %rcx, %rcx
    jz .Lmx_fault
    xorl %edx, %edx
    divq %rcx
.endm

.Lmh_div:
    MX_DIVMOD
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_mod:
    MX_DIVMOD
    movl X_DST(%rbx), %ecx
    movq %rdx, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.macro MX_LOADADDR
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movslq X_IMM(%rbx), %rcx
    addq %rcx, %rax
.endm

.Lmh_ld:
    MX_LOADADDR
    movq (%rax), %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_ld32:
    MX_LOADADDR
    movl (%rax), %eax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_ld8:
    MX_LOADADDR
    movzbl (%rax), %eax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.macro MX_STOREADDR
    movl X_DST(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movslq X_IMM(%rbx), %rcx
    addq %rcx, %rax
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rcx
.endm

.Lmh_st:
    MX_STOREADDR
    movq %rcx, (%rax)
    jmp .Lmx_after

.Lmh_st32:
    MX_STOREADDR
    movl %ecx, (%rax)
    jmp .Lmx_after

.Lmh_st8:
    MX_STOREADDR
    movb %cl, (%rax)
    jmp .Lmx_after

.Lmh_lea:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    movslq X_IMM(%rbx), %rcx
    addq %rcx, %rax
    movl X_DST(%rbx), %ecx
    movq %rax, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_setcc:
    movl X_IMM(%rbx), %eax
    andl $0xFF, %eax
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %r8
    movl X_AUX(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %r9
    call .Lmx_cceval
    movl X_DST(%rbx), %ecx
    movq %rdx, X_REGS(%rbx,%rcx,8)
    jmp .Lmx_after

.Lmh_jmp:
    movl X_IMM(%rbx), %eax
    movl %eax, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_jcc:
    movl X_DST(%rbx), %eax
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %r8
    movl X_AUX(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %r9
    call .Lmx_cceval
    testl %edx, %edx
    jz .Lmx_after
    movl X_IMM(%rbx), %eax
    movl %eax, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_call:
    movl X_CSP(%rbx), %eax
    cmpl $64, %eax
    jae .Lmx_toodeep
    movl X_IP(%rbx), %ecx
    addl $MX_INSN, %ecx
    movq %rcx, X_CSTACK(%rbx,%rax,8)
    incl %eax
    movl %eax, X_CSP(%rbx)
    movl X_IMM(%rbx), %eax
    movl %eax, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_callr:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    cmpl X_BCSIZE(%rbx), %eax
    jae .Lmx_fault
    movl X_CSP(%rbx), %ecx
    cmpl $64, %ecx
    jae .Lmx_toodeep
    movl X_IP(%rbx), %edx
    addl $MX_INSN, %edx
    movq %rdx, X_CSTACK(%rbx,%rcx,8)
    incl %ecx
    movl %ecx, X_CSP(%rbx)
    movl %eax, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_jmpr:
    movl X_SRC(%rbx), %ecx
    movq X_REGS(%rbx,%rcx,8), %rax
    cmpl X_BCSIZE(%rbx), %eax
    jae .Lmx_fault
    movl %eax, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_ret:
    movl X_CSP(%rbx), %eax
    testl %eax, %eax
    jz .Lmx_fault
    decl %eax
    movl %eax, X_CSP(%rbx)
    movq X_CSTACK(%rbx,%rax,8), %rcx
    movl %ecx, X_IP(%rbx)
    movl $1, X_JUMPED(%rbx)
    jmp .Lmx_after

.Lmh_host:
    movl X_IMM(%rbx), %eax
    testl %eax, %eax
    jnz .Lmh_host_native
    movq X_REGS+96(%rbx), %rcx     # m12 = buf
    movq X_REGS+104(%rbx), %rdx    # m13 = len
    movq X_REGS+112(%rbx), %r8     # m14 = key
    movq X_REGS+120(%rbx), %r9     # m15 = nonce
    movl X_REGS+88(%rbx), %r10d    # m11 = counter
    movq X_KSFN(%rbx), %rax
    call *%rax
    jmp .Lmx_after
.Lmh_host_native:
    movq $MX_ERR_FAULT, X_REGS+96(%rbx)   # m12 = status（无内层原生执行器）
    jmp .Lmx_after

.Lmh_halt:
    movl X_SRC(%rbx), %ecx
    movl X_REGS(%rbx,%rcx,8), %eax
    movl %eax, X_RETVAL(%rbx)
    movl X_DST(%rbx), %ecx
    movl X_REGS(%rbx,%rcx,8), %eax
    movl %eax, X_HALTST(%rbx)
    movl $1, X_HALTED(%rbx)
    jmp .Lmx_after

# ---- 分发表（相对 .Lmx_dtbase 的 32 位偏移；顺序同 M_*）----
    .balign 4
.Lmx_dtbase:
    .long .Lmh_nop    - .Lmx_dtbase
    .long .Lmh_movi   - .Lmx_dtbase
    .long .Lmh_set64  - .Lmx_dtbase
    .long .Lmh_mov    - .Lmx_dtbase
    .long .Lmh_add    - .Lmx_dtbase
    .long .Lmh_sub    - .Lmx_dtbase
    .long .Lmh_mul    - .Lmx_dtbase
    .long .Lmh_and    - .Lmx_dtbase
    .long .Lmh_or     - .Lmx_dtbase
    .long .Lmh_xor    - .Lmx_dtbase
    .long .Lmh_shl    - .Lmx_dtbase
    .long .Lmh_shr    - .Lmx_dtbase
    .long .Lmh_sar    - .Lmx_dtbase
    .long .Lmh_neg    - .Lmx_dtbase
    .long .Lmh_not    - .Lmx_dtbase
    .long .Lmh_div    - .Lmx_dtbase
    .long .Lmh_mod    - .Lmx_dtbase
    .long .Lmh_ld     - .Lmx_dtbase
    .long .Lmh_ld32   - .Lmx_dtbase
    .long .Lmh_ld8    - .Lmx_dtbase
    .long .Lmh_st     - .Lmx_dtbase
    .long .Lmh_st32   - .Lmx_dtbase
    .long .Lmh_st8    - .Lmx_dtbase
    .long .Lmh_lea    - .Lmx_dtbase
    .long .Lmh_setcc  - .Lmx_dtbase
    .long .Lmh_jmp    - .Lmx_dtbase
    .long .Lmh_jcc    - .Lmx_dtbase
    .long .Lmh_call   - .Lmx_dtbase
    .long .Lmh_callr  - .Lmx_dtbase
    .long .Lmh_jmpr   - .Lmx_dtbase
    .long .Lmh_ret    - .Lmx_dtbase
    .long .Lmh_host   - .Lmx_dtbase
    .long .Lmh_halt   - .Lmx_dtbase

    .section .note.GNU-stack,"",@progbits
