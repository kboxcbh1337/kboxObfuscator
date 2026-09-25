# vm_engine_x86.S — kboXShield 运行期汇编 VM 引擎（IA-32, PE32）
#
# Batch 4.4 嵌套虚拟化（x86 侧）：与 vm_engine_x64.S 同构——本 blob 不再包含
# 内层（Family A）解释器的 native 实现，只含
#   1) kbox_vm_run  —— 引导：校验内层镜像头、经 reserved[0] 定位外层 Meta 镜像、
#                       布置内层状态块（含机器寄存器 -> 帧槽）、调用 kbox_meta_run；
#   2) kbox_meta_run —— 外层 Meta VM 解释器（本文件主体）。
# 内层解释器的取指/反查/分派/语义/回加密/ip 推进全部以 Meta 字节码形式存在
# （由 packer 于打包期生成，见 packer/vm/meta_inner.cpp），随内层镜像头
# reserved[0]=相对字节增量 / reserved[1]=Meta 镜像字节数 定位。x86 与 x64 共享
# 同一份 Meta 镜像（Meta ISA 与宿主机指针宽度无关）。
#
# Meta 机器为 64 位寄存器机；IA-32 无 64 位通用寄存器，故本解释器以"寄存器对
# (hi:lo)"实现全部 64 位语义：加减用 add/adc、sub/sbb，移位用 shld/shrd，
# 乘法用 32×32->64 部分积合成，除法用 64 轮移位-减法（软件除法），比较用
# 32 位指令 + CF/SF/OF 组合。语义与 packer/vm/vm_meta.cpp、vm_engine_x64.S
# 逐条一致。
#
# PIC：32 位无 RIP 相对寻址，引擎基址用 call-pop 取得（ebp），分发表以"相对
# .Lmbase 的 32 位偏移"存储。自由态安全：无全局/静态可写状态，执行状态全在
# 调用方栈上（无堆分配）。
#
# 入口（cdecl，与内层 native 引擎 ABI 相同）：
#   uint64_t kbox_vm_run(const uint8_t* image, uint32_t image_size,
#                        uint64_t* gprs, void* ks_fn)
#     gprs: 16 × u64 机器寄存器块（rax..r15），入参载入 / 出参写回；可传 0。
#   返回：eax = 状态码（VM_OK == 0 为成功），edx = VM 结果（仅 eax==0 有效）
#
# blob 契约：入口符号 kbox_vm_run 位于 blob 偏移 0。

    .code32
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

.set MX_OK,0
.set MX_ERR_FAULT,1
.set MX_ERR_BADMAGIC,4
.set MX_ERR_BADOP,5
.set MX_ERR_DEEP,7
.set MX_MAX_STEPS, 8388608

# ---- MetaCtx 布局（栈上；32 位字段）----
.set X_IMG,     0
.set X_MSIZE,   4
.set X_KSFN,    8
.set X_INNIMG,  12
.set X_INNSZ,   16
.set X_STATE,   20
.set X_GPRS,    24
.set X_OUT,     28
.set X_IP,      32
.set X_STEPS,   36
.set X_CSP,     40
.set X_RETVAL,  44
.set X_BCSIZE,  48
.set X_INSOFF,  52
.set X_KSCTR,   56
.set X_POS,     60
.set X_OPC,     64
.set X_DST,     68
.set X_SRC,     72
.set X_AUX,     76
.set X_IMM,     80
.set X_JUMPED,  84
.set X_HALTED,  88
.set X_HALTST,  92
.set X_CC,      96
.set X_T0,      100
.set X_T1,      104
.set X_T2,      108
.set X_T3,      112
.set X_T4,      116
.set X_T5,      120
.set X_SAV0,    124
.set X_SAV1,    128
.set X_K8,      132      # 32B 派生密钥
.set X_NONCE,   164      # 16B（12B 全零 nonce）
.set X_OPMAP,   180      # 64B
.set X_REGS,    244      # 16 × 8B = 128B（hi:lo 对）
.set X_HANTAB,  372      # 64 × 4B = 256B
.set X_REV,     628      # 256B
.set X_KSBLK,   884      # 64B keystream 块
.set X_CSTACK,  948      # 64 × 4B = 256B
.set XSZ,       1204

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

# ---- kbox_vm_run 栈帧 ----
.set VD_PARAMS,  1248    # 8 × u32
.set VD_OUT,     1280
.set VD_ALLOC,   1296

# ================= 引导：kbox_vm_run =================
    .globl kbox_vm_run
    .type kbox_vm_run, @function
kbox_vm_run:
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    subl $VD_ALLOC, %esp

    # 清零内层状态块（1208B）
    movl %esp, %edi
    xorl %eax, %eax
    movl $(IS_SIZE/4), %ecx
    rep stosl

    movl VD_ALLOC+20(%esp), %esi    # image
    movl VD_ALLOC+24(%esp), %edi    # image_size
    movl %esp, %ebx                 # state

    cmpl $64, %edi
    jb .Lvd_badmagic
    cmpl $IH_IV_MAGIC, IH_MAGIC(%esi)
    jne .Lvd_badmagic
    cmpl $IH_IV_VER, IH_VERSION(%esi)
    jne .Lvd_badmagic
    movl IH_RSV0(%esi), %eax        # Meta 镜像相对增量
    testl %eax, %eax
    jz .Lvd_badmagic
    leal (%esi,%eax), %ecx          # meta image
    movl IH_RSV1(%esi), %edx        # meta size

    movl %ecx, VD_PARAMS+0(%esp)    # meta_image
    movl %edx, VD_PARAMS+4(%esp)    # meta_size
    movl %esi, VD_PARAMS+8(%esp)    # inner_image
    movl %edi, VD_PARAMS+12(%esp)   # inner_size
    movl VD_ALLOC+28(%esp), %eax    # gprs
    movl %eax, VD_PARAMS+16(%esp)
    movl VD_ALLOC+32(%esp), %eax    # ks_fn
    movl %eax, VD_PARAMS+20(%esp)
    movl %ebx, VD_PARAMS+24(%esp)   # inner_state
    leal VD_OUT(%esp), %eax
    movl %eax, VD_PARAMS+28(%esp)   # out
    movl $0, VD_OUT(%esp)

    # ---- 机器寄存器块 -> frame 槽（lo = 2g，hi = 2g+1）----
    movl VD_ALLOC+28(%esp), %esi
    testl %esi, %esi
    jz .Lvd_nogpr
    xorl %edi, %edi
.Lvd_gi:
    movl (%esi,%edi,8), %eax
    movl %eax, IS_FRAME(%ebx,%edi,8)
    movl 4(%esi,%edi,8), %eax
    movl %eax, IS_FRAME+4(%ebx,%edi,8)
    incl %edi
    cmpl $16, %edi
    jb .Lvd_gi
.Lvd_nogpr:

    leal VD_PARAMS(%esp), %eax
    pushl %eax
    call kbox_meta_run
    addl $4, %esp

    movl %eax, VD_PARAMS+0(%esp)    # status
    movl %edx, VD_PARAMS+4(%esp)    # retval

    testl %eax, %eax
    jnz .Lvd_out
    movl VD_ALLOC+28(%esp), %ecx    # gprs
    testl %ecx, %ecx
    jz .Lvd_out
    xorl %edi, %edi
.Lvd_go:
    movl IS_FRAME(%ebx,%edi,8), %eax
    movl %eax, (%ecx,%edi,8)
    movl IS_FRAME+4(%ebx,%edi,8), %eax
    movl %eax, 4(%ecx,%edi,8)
    incl %edi
    cmpl $16, %edi
    jb .Lvd_go
.Lvd_out:
    movl VD_PARAMS+0(%esp), %eax
    movl VD_PARAMS+4(%esp), %edx
    addl $VD_ALLOC, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret
.Lvd_badmagic:
    movl $MX_ERR_BADMAGIC, %eax
    xorl %edx, %edx
    addl $VD_ALLOC, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret

# ================= 外层 Meta VM 解释器 =================
# 入参：参数块指针（cdecl 单参数），布局（32 位）：
#   +0  meta_image  +4 meta_size  +8 inner_image +12 inner_size
#   +16 gprs        +20 ks_fn      +24 inner_state +28 out
    .globl kbox_meta_run
    .type kbox_meta_run, @function
kbox_meta_run:
    pushl %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    call .Lmbase
.Lmbase:
    popl %ebp                       # ebp = .Lmbase（分发表/引擎基址）
    subl $XSZ, %esp
    movl %esp, %ebx                 # ebx = ctx

    movl %ebx, %edi
    xorl %eax, %eax
    movl $(XSZ/4), %ecx
    rep stosl

    movl XSZ+20(%esp), %ecx         # 参数块指针（4 pushes + ret + arg）
    movl 0(%ecx), %eax;  movl %eax, X_IMG(%ebx)
    movl 4(%ecx), %eax;  movl %eax, X_MSIZE(%ebx)
    movl 8(%ecx), %eax;  movl %eax, X_INNIMG(%ebx)
    movl 12(%ecx), %eax; movl %eax, X_INNSZ(%ebx)
    movl 16(%ecx), %eax; movl %eax, X_GPRS(%ebx)
    movl 20(%ecx), %eax; movl %eax, X_KSFN(%ebx)
    movl 24(%ecx), %eax; movl %eax, X_STATE(%ebx)
    movl 28(%ecx), %eax; movl %eax, X_OUT(%ebx)

    # ---- 校验 Meta 镜像头 ----
    cmpl $MX_HDRSZ, X_MSIZE(%ebx)
    jb .Lmx_badmagic
    movl X_IMG(%ebx), %esi
    cmpl $MX_MAGIC, 0(%esi)
    jne .Lmx_badmagic
    cmpl $MX_VERSION, 4(%esi)
    jne .Lmx_badmagic
    movl 16(%esi), %eax
    testl %eax, %eax
    jz .Lmx_tot_ok
    cmpl X_MSIZE(%ebx), %eax
    ja .Lmx_fault_nw
.Lmx_tot_ok:
    movl 20(%esi), %eax
    movl %eax, X_BCSIZE(%ebx)
    testl $7, %eax
    jnz .Lmx_fault_nw
    addl $MX_OFF_BC, %eax
    cmpl X_MSIZE(%ebx), %eax
    ja .Lmx_fault_nw
    cmpl $0, X_BCSIZE(%ebx)
    je .Lmx_fault_nw
    movl $0, X_IP(%ebx)

    # ---- 派生密钥：header.key[4] || 固定填充 ----
    movl 32(%esi), %eax;  movl %eax, X_K8+0(%ebx)
    movl 36(%esi), %eax;  movl %eax, X_K8+4(%ebx)
    movl 40(%esi), %eax;  movl %eax, X_K8+8(%ebx)
    movl 44(%esi), %eax;  movl %eax, X_K8+12(%ebx)
    movl $0x4D42564D, X_K8+16(%ebx)
    movl $0x6174654D, X_K8+20(%ebx)
    movl $0x6E72654B, X_K8+24(%ebx)
    movl $0x00004C65, X_K8+28(%ebx)
    movl $0xFFFFFFFF, X_KSCTR(%ebx)

    # ---- rev[0..255] = 0xFF ----
    leal X_REV(%ebx), %edi
    movl $-1, %eax
    movl $64, %ecx
    rep stosl

    # ---- 解密 opcode_map -> X_OPMAP ----
    xorl %esi, %esi
.Lmx_dmap:
    leal MX_OFF_OPMAP(%esi), %eax
    movl %eax, X_POS(%ebx)
    call .Lmx_ks_byte
    movl X_IMG(%ebx), %ecx
    leal MX_OFF_OPMAP(%esi), %eax
    movzbl (%ecx,%eax), %eax
    xorb %dl, %al
    movb %al, X_OPMAP(%ebx,%esi)
    incl %esi
    cmpl $MX_COUNT, %esi
    jb .Lmx_dmap

    # ---- 建反向表 rev[opcode] = 语义号（校验为排列）----
    xorl %esi, %esi
.Lmx_rb:
    movzbl X_OPMAP(%ebx,%esi), %eax
    cmpl $MX_COUNT, %eax
    jae .Lmx_badmagic
    cmpb $0xFF, X_REV(%ebx,%eax)
    jne .Lmx_badmagic
    movl %esi, %ecx
    movb %cl, X_REV(%ebx,%eax)
    incl %esi
    cmpl $MX_COUNT, %esi
    jb .Lmx_rb

    # ---- 解密 handler 偏移表（64 × u32 = 256B）----
    xorl %esi, %esi
.Lmx_hb:
    leal MX_OFF_HANTAB(%esi), %eax
    movl %eax, X_POS(%ebx)
    call .Lmx_ks_byte
    movl X_IMG(%ebx), %ecx
    leal MX_OFF_HANTAB(%esi), %eax
    movzbl (%ecx,%eax), %eax
    xorb %dl, %al
    movb %al, X_HANTAB(%ebx,%esi)
    incl %esi
    cmpl $256, %esi
    jb .Lmx_hb

    # ---- 初始寄存器：m0=state m1=image m2=size m3=gprs m4=ksfn m5=&hantab ----
    movl X_STATE(%ebx), %eax
    movl %eax, X_REGS+0(%ebx);  movl $0, X_REGS+4(%ebx)
    movl X_INNIMG(%ebx), %eax
    movl %eax, X_REGS+8(%ebx);  movl $0, X_REGS+12(%ebx)
    movl X_INNSZ(%ebx), %eax
    movl %eax, X_REGS+16(%ebx); movl $0, X_REGS+20(%ebx)
    movl X_GPRS(%ebx), %eax
    movl %eax, X_REGS+24(%ebx); movl $0, X_REGS+28(%ebx)
    movl X_KSFN(%ebx), %eax
    movl %eax, X_REGS+32(%ebx); movl $0, X_REGS+36(%ebx)
    leal X_HANTAB(%ebx), %eax
    movl %eax, X_REGS+40(%ebx); movl $0, X_REGS+44(%ebx)

    # ================= 主循环 =================
.Lmx_loop:
    movl X_STEPS(%ebx), %eax
    incl %eax
    movl %eax, X_STEPS(%ebx)
    cmpl $MX_MAX_STEPS, %eax
    ja .Lmx_toodeep_nw
    movl $0, X_JUMPED(%ebx)

    movl X_IP(%ebx), %eax
    cmpl X_BCSIZE(%ebx), %eax
    ja .Lmx_fault_nw
    addl $MX_INSN, %eax
    cmpl X_BCSIZE(%ebx), %eax
    ja .Lmx_fault_nw

    movl X_IP(%ebx), %eax
    addl $MX_OFF_BC, %eax
    movl %eax, X_INSOFF(%ebx)

    # ---- 取指：就地解密 8 字节 ----
    movl $0, X_T0(%ebx)
.Lmx_fb:
    movl X_INSOFF(%ebx), %eax
    addl X_T0(%ebx), %eax
    movl %eax, X_POS(%ebx)
    call .Lmx_ks_byte               # 出 dl
    movl X_IMG(%ebx), %ecx
    movl X_INSOFF(%ebx), %eax
    addl X_T0(%ebx), %eax
    xorb %dl, (%ecx,%eax)           # 就地解密：密文 -> 明文
    movl X_T0(%ebx), %eax
    incl %eax
    movl %eax, X_T0(%ebx)
    cmpl $MX_INSN, %eax
    jb .Lmx_fb

    # ---- 解码字段 ----
    movl X_IMG(%ebx), %ecx
    movl X_INSOFF(%ebx), %eax
    movzbl 0(%ecx,%eax), %edx; movl %edx, X_OPC(%ebx)
    movzbl 1(%ecx,%eax), %edx; movl %edx, X_DST(%ebx)
    movzbl 2(%ecx,%eax), %edx; movl %edx, X_SRC(%ebx)
    movzbl 3(%ecx,%eax), %edx; movl %edx, X_AUX(%ebx)
    movl   4(%ecx,%eax), %edx; movl %edx, X_IMM(%ebx)

    # ---- 分派（分发表项 = handler - .Lmbase）----
    movl X_OPC(%ebx), %eax
    movzbl X_REV(%ebx,%eax), %eax
    cmpl $MX_COUNT, %eax
    jae .Lmx_badop
    movl .Lmx_dtbase-.Lmbase(%ebp,%eax,4), %eax
    addl %ebp, %eax
    jmp *%eax

.Lmx_after:
    # ---- 回加密：当前指令明文 -> 密文 ----
    movl $0, X_T0(%ebx)
.Lmx_re:
    movl X_INSOFF(%ebx), %eax
    addl X_T0(%ebx), %eax
    movl %eax, X_POS(%ebx)
    call .Lmx_ks_byte
    movl X_IMG(%ebx), %ecx
    movl X_INSOFF(%ebx), %eax
    addl X_T0(%ebx), %eax
    xorb %dl, (%ecx,%eax)
    movl X_T0(%ebx), %eax
    incl %eax
    movl %eax, X_T0(%ebx)
    cmpl $MX_INSN, %eax
    jb .Lmx_re

    cmpl $0, X_HALTED(%ebx)
    jne .Lmx_done
    cmpl $0, X_JUMPED(%ebx)
    jne .Lmx_loop
    movl X_IP(%ebx), %eax
    addl $MX_INSN, %eax
    movl %eax, X_IP(%ebx)
    jmp .Lmx_loop

.Lmx_done:
    movl X_RETVAL(%ebx), %edx
    movl X_HALTST(%ebx), %eax
    jmp .Lmx_exit

# ---- 错误出口 ----
.Lmx_fault:
    movl $MX_ERR_FAULT, X_HALTST(%ebx)
    movl $1, X_HALTED(%ebx)
    jmp .Lmx_after
.Lmx_badop:
    movl $MX_ERR_BADOP, X_HALTST(%ebx)
    movl $1, X_HALTED(%ebx)
    jmp .Lmx_after
.Lmx_toodeep:
    movl $MX_ERR_DEEP, X_HALTST(%ebx)
    movl $1, X_HALTED(%ebx)
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
    movl X_OUT(%ebx), %ecx
    testl %ecx, %ecx
    jz .Lmx_exit2
    movl %edx, (%ecx)
.Lmx_exit2:
    addl $XSZ, %esp
    popl %edi
    popl %esi
    popl %ebx
    popl %ebp
    ret

# ================= keystream 单字节（X_POS 入，dl 出）=================
# 破坏 eax/ecx/edx；保存/恢复 esi/edi（其余调用方状态在 ebx 与内存）。
.Lmx_ks_byte:
    movl %esi, X_T1(%ebx)
    movl %edi, X_T2(%ebx)
    movl X_POS(%ebx), %ecx
    shrl $6, %ecx
    cmpl X_KSCTR(%ebx), %ecx
    je .Lks_hit
    movl %ecx, X_KSCTR(%ebx)
    xorl %eax, %eax
    movl %eax, X_KSBLK+0(%ebx)
    movl %eax, X_KSBLK+4(%ebx)
    movl %eax, X_KSBLK+8(%ebx)
    movl %eax, X_KSBLK+12(%ebx)
    movl %eax, X_KSBLK+16(%ebx)
    movl %eax, X_KSBLK+20(%ebx)
    movl %eax, X_KSBLK+24(%ebx)
    movl %eax, X_KSBLK+28(%ebx)
    movl %eax, X_KSBLK+32(%ebx)
    movl %eax, X_KSBLK+36(%ebx)
    movl %eax, X_KSBLK+40(%ebx)
    movl %eax, X_KSBLK+44(%ebx)
    movl %eax, X_KSBLK+48(%ebx)
    movl %eax, X_KSBLK+52(%ebx)
    movl %eax, X_KSBLK+56(%ebx)
    movl %eax, X_KSBLK+60(%ebx)
    # kbox_chacha：eax=buf, edx=len, ecx=key, esi=nonce, edi=counter
    leal X_KSBLK(%ebx), %eax
    movl $64, %edx
    leal X_K8(%ebx), %ecx
    leal X_NONCE(%ebx), %esi
    movl X_KSCTR(%ebx), %edi
    call *X_KSFN(%ebx)
.Lks_hit:
    movl X_T1(%ebx), %esi           # 恢复调用方的 esi/edi
    movl X_T2(%ebx), %edi
    movl X_POS(%ebx), %eax
    andl $63, %eax
    leal X_KSBLK(%ebx), %ecx
    movzbl (%ecx,%eax), %edx
    ret

# ================= 条件码求值（X_CC 入，X_SAV0/1=a，X_T0/1=b；出 eax=0/1）=================
# a-b 的 64 位标志由 sub/sbb 给出；UE/GT/LE/GT 用 CF 与"合并零"组合。
.macro CCSUB
    movl X_SAV0(%ebx), %eax
    movl X_SAV1(%ebx), %edx
    movl X_T0(%ebx), %esi
    movl X_T1(%ebx), %edi
    subl %esi, %eax
    sbbl %edi, %edx
.endm

.Lmx_cceval:
    movl X_CC(%ebx), %ecx
    cmpl $MX_CC_EQ, %ecx
    je .Lcc_eq
    cmpl $MX_CC_NE, %ecx
    je .Lcc_ne
    cmpl $MX_CC_ULT, %ecx
    je .Lcc_ult
    cmpl $MX_CC_UGE, %ecx
    je .Lcc_uge
    cmpl $MX_CC_ULE, %ecx
    je .Lcc_ule
    cmpl $MX_CC_UGT, %ecx
    je .Lcc_ugt
    cmpl $MX_CC_SLT, %ecx
    je .Lcc_slt
    cmpl $MX_CC_SGE, %ecx
    je .Lcc_sge
    cmpl $MX_CC_SLE, %ecx
    je .Lcc_sle
    cmpl $MX_CC_SGT, %ecx
    je .Lcc_sgt
    xorl %eax, %eax
    ret
.Lcc_eq:
    CCSUB
    orl %edx, %eax
    sete %al
    movzbl %al, %eax
    ret
.Lcc_ne:
    CCSUB
    orl %edx, %eax
    setne %al
    movzbl %al, %eax
    ret
.Lcc_ult:
    CCSUB
    setb %al
    movzbl %al, %eax
    ret
.Lcc_uge:
    CCSUB
    setae %al
    movzbl %al, %eax
    ret
.Lcc_ule:                            # (CF) || (combined ZF)
    CCSUB
    setc %cl
    orl %edx, %eax
    setz %dl
    orb %dl, %cl
    movzbl %cl, %eax
    ret
.Lcc_ugt:                            # !CF && !combined ZF
    CCSUB
    setc %cl
    orl %edx, %eax
    setz %dl
    xorb $1, %cl
    xorb $1, %dl
    andb %dl, %cl
    movzbl %cl, %eax
    ret
.Lcc_slt:
    CCSUB
    setl %al
    movzbl %al, %eax
    ret
.Lcc_sge:
    CCSUB
    setge %al
    movzbl %al, %eax
    ret
.Lcc_sle:                            # (SF!=OF) || combined ZF
    CCSUB
    setl %cl
    orl %edx, %eax
    setz %dl
    orb %dl, %cl
    movzbl %cl, %eax
    ret
.Lcc_sgt:                            # (SF==OF) && !combined ZF
    CCSUB
    setl %cl
    orl %edx, %eax
    setz %dl
    xorb $1, %cl
    xorb $1, %dl
    andb %dl, %cl
    movzbl %cl, %eax
    ret

# ================= 64 位无符号除法 =================
# 入：X_SRC 寄存器 = 被除数，X_AUX 寄存器 = 除数
# 出：X_T0/X_T1 = 商，X_T2/X_T3 = 余数；X_T4 = 1 表示除零
# 算法：64 轮移位-减法（恢复式长除法）。
.Lmx_div64:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi      # alo
    movl X_REGS+4(%ebx,%ecx,8), %edi    # ahi
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax      # blo
    movl X_REGS+4(%ebx,%ecx,8), %edx    # bhi
    movl %eax, %ecx
    orl %edx, %ecx
    jnz .Ldv_nonzero
    movl $1, X_T4(%ebx)
    ret
.Ldv_nonzero:
    movl %eax, X_SAV0(%ebx)             # divisor lo
    movl %edx, X_SAV1(%ebx)             # divisor hi
    movl $0, X_T0(%ebx)                 # quotient lo
    movl $0, X_T1(%ebx)                 # quotient hi
    movl $0, X_T2(%ebx)                 # remainder lo
    movl $0, X_T3(%ebx)                 # remainder hi
    movl $63, X_T5(%ebx)                # i
.Ldv_loop:
    shll $1, %esi                       # 被除数整体左移 1；CF = 当前位
    rcll $1, %edi
    movl X_T2(%ebx), %eax               # rem lo
    movl X_T3(%ebx), %edx               # rem hi
    rcll $1, %eax                       # rem = (rem<<1)|CF
    rcll $1, %edx
    movl %eax, X_T2(%ebx)               # 先按"不移除"暂存左移后的 rem
    movl %edx, X_T3(%ebx)
    movl X_SAV0(%ebx), %ecx
    subl %ecx, %eax                     # rem - divisor（低字，CF = 借位）
    movl X_SAV1(%ebx), %ecx
    sbbl %ecx, %edx                     # rem - divisor（高字）
    jc .Ldv_nosub                       # 借位 -> rem < divisor，保留暂存值
    movl %eax, X_T2(%ebx)               # rem 更新为差值
    movl %edx, X_T3(%ebx)
    movl X_T5(%ebx), %ecx
    btsl %ecx, X_T0(%ebx)               # 商置位 i（X_T0/X_T1 连续 64 位）
.Ldv_nosub:
    decl X_T5(%ebx)
    jns .Ldv_loop
    movl $0, X_T4(%ebx)
    ret

# ================= Meta handler（按语义号）=================
.Lmh_nop:
    jmp .Lmx_after

.Lmh_movi:
    movl X_DST(%ebx), %ecx
    movl X_IMM(%ebx), %eax
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl $0, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_set64:
    movl X_DST(%ebx), %ecx
    movl X_IMM(%ebx), %eax
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %eax, %edx
    sarl $31, %edx
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_mov:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.macro MXWORD op
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi
    movl X_REGS+4(%ebx,%ecx,8), %edi
    \op %esi, %eax
    \op %edi, %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after
.endm

.Lmh_add:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi
    movl X_REGS+4(%ebx,%ecx,8), %edi
    addl %esi, %eax
    adcl %edi, %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_sub:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi
    movl X_REGS+4(%ebx,%ecx,8), %edi
    subl %esi, %eax
    sbbl %edi, %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_mul:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax      # alo
    movl X_REGS+4(%ebx,%ecx,8), %edi    # ahi
    movl X_AUX(%ebx), %edx
    movl X_REGS(%ebx,%edx,8), %ecx      # blo
    movl X_REGS+4(%ebx,%edx,8), %esi    # bhi
    mull %ecx                           # edx:eax = alo*blo
    movl %eax, X_T0(%ebx)
    movl %edx, X_T1(%ebx)
    movl X_SRC(%ebx), %edx
    movl X_REGS(%ebx,%edx,8), %eax
    mull %esi                           # edx:eax = alo*bhi
    addl %eax, X_T1(%ebx)
    movl %edi, %eax
    mull %ecx                           # edx:eax = ahi*blo
    addl %eax, X_T1(%ebx)
    movl X_DST(%ebx), %ecx
    movl X_T0(%ebx), %eax
    movl X_T1(%ebx), %edx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_and: MXWORD andl
.Lmh_or:  MXWORD orl
.Lmh_xor: MXWORD xorl

.Lmh_shl:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %ecx
    andl $63, %ecx
    jz .Lshl_done
    cmpl $32, %ecx
    jb .Lshl_small
    subl $32, %ecx
    movl %eax, %edx
    shll %cl, %edx
    xorl %eax, %eax
    jmp .Lshl_done
.Lshl_small:
    shldl %cl, %eax, %edx
    shll %cl, %eax
.Lshl_done:
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_shr:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %ecx
    andl $63, %ecx
    jz .Lshr_done
    cmpl $32, %ecx
    jb .Lshr_small
    subl $32, %ecx
    movl %edx, %eax
    shrl %cl, %eax
    xorl %edx, %edx
    jmp .Lshr_done
.Lshr_small:
    shrdl %cl, %edx, %eax
    shrl %cl, %edx
.Lshr_done:
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_sar:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %ecx
    andl $63, %ecx
    jz .Lsar_done
    cmpl $32, %ecx
    jb .Lsar_small
    subl $32, %ecx
    movl %edx, %eax
    sarl %cl, %eax
    sarl $31, %edx
    jmp .Lsar_done
.Lsar_small:
    shrdl %cl, %edx, %eax
    sarl %cl, %edx
.Lsar_done:
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_neg:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    notl %eax
    notl %edx
    addl $1, %eax
    adcl $0, %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_not:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    notl %eax
    notl %edx
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_div:
    call .Lmx_div64
    cmpl $0, X_T4(%ebx)
    jne .Lmx_fault
    movl X_DST(%ebx), %ecx
    movl X_T0(%ebx), %eax
    movl X_T1(%ebx), %edx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_mod:
    call .Lmx_div64
    cmpl $0, X_T4(%ebx)
    jne .Lmx_fault
    movl X_DST(%ebx), %ecx
    movl X_T2(%ebx), %eax
    movl X_T3(%ebx), %edx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

# 64 位地址 = m[src] + simm32(imm)，结果 lo 入 eax / hi 入 edx
.macro MXADDR srcfield
    movl \srcfield(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl X_IMM(%ebx), %ecx
    movl %ecx, %esi
    sarl $31, %esi
    addl %ecx, %eax
    adcl %esi, %edx
.endm

.Lmh_ld:
    MXADDR X_SRC
    movl (%eax), %esi
    movl 4(%eax), %edi
    movl X_DST(%ebx), %ecx
    movl %esi, X_REGS(%ebx,%ecx,8)
    movl %edi, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_ld32:
    MXADDR X_SRC
    movl (%eax), %esi
    movl X_DST(%ebx), %ecx
    movl %esi, X_REGS(%ebx,%ecx,8)
    movl $0, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_ld8:
    MXADDR X_SRC
    movzbl (%eax), %esi
    movl X_DST(%ebx), %ecx
    movl %esi, X_REGS(%ebx,%ecx,8)
    movl $0, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_st:
    MXADDR X_DST
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi
    movl X_REGS+4(%ebx,%ecx,8), %edi
    movl %esi, (%eax)
    movl %edi, 4(%eax)
    jmp .Lmx_after

.Lmh_st32:
    MXADDR X_DST
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %esi
    movl %esi, (%eax)
    jmp .Lmx_after

.Lmh_st8:
    MXADDR X_DST
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %ecx
    movb %cl, (%eax)
    jmp .Lmx_after

.Lmh_lea:
    MXADDR X_SRC
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl %edx, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_setcc:
    movl X_IMM(%ebx), %eax
    andl $0xFF, %eax
    movl %eax, X_CC(%ebx)
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl %eax, X_SAV0(%ebx)
    movl %edx, X_SAV1(%ebx)
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl %eax, X_T0(%ebx)
    movl %edx, X_T1(%ebx)
    call .Lmx_cceval
    movl X_DST(%ebx), %ecx
    movl %eax, X_REGS(%ebx,%ecx,8)
    movl $0, X_REGS+4(%ebx,%ecx,8)
    jmp .Lmx_after

.Lmh_jmp:
    movl X_IMM(%ebx), %eax
    movl %eax, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_jcc:
    movl X_DST(%ebx), %eax
    andl $0xFF, %eax
    movl %eax, X_CC(%ebx)
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl %eax, X_SAV0(%ebx)
    movl %edx, X_SAV1(%ebx)
    movl X_AUX(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl X_REGS+4(%ebx,%ecx,8), %edx
    movl %eax, X_T0(%ebx)
    movl %edx, X_T1(%ebx)
    call .Lmx_cceval
    testl %eax, %eax
    jz .Lmx_after
    movl X_IMM(%ebx), %eax
    movl %eax, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_call:
    movl X_CSP(%ebx), %eax
    cmpl $64, %eax
    jae .Lmx_toodeep
    movl X_IP(%ebx), %ecx
    addl $MX_INSN, %ecx
    movl %ecx, X_CSTACK(%ebx,%eax,4)
    incl %eax
    movl %eax, X_CSP(%ebx)
    movl X_IMM(%ebx), %eax
    movl %eax, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_callr:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    cmpl X_BCSIZE(%ebx), %eax
    jae .Lmx_fault
    movl X_CSP(%ebx), %ecx
    cmpl $64, %ecx
    jae .Lmx_toodeep
    movl X_IP(%ebx), %edx
    addl $MX_INSN, %edx
    movl %edx, X_CSTACK(%ebx,%ecx,4)
    incl %ecx
    movl %ecx, X_CSP(%ebx)
    movl %eax, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_jmpr:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    cmpl X_BCSIZE(%ebx), %eax
    jae .Lmx_fault
    movl %eax, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_ret:
    movl X_CSP(%ebx), %eax
    testl %eax, %eax
    jz .Lmx_fault
    decl %eax
    movl %eax, X_CSP(%ebx)
    movl X_CSTACK(%ebx,%eax,4), %ecx
    movl %ecx, X_IP(%ebx)
    movl $1, X_JUMPED(%ebx)
    jmp .Lmx_after

.Lmh_host:
    movl X_IMM(%ebx), %eax
    testl %eax, %eax
    jnz .Lmh_host_native
    # m12=buf, m13=len, m14=key, m15=nonce, m11=counter（取 lo 32 位）
    movl X_REGS+96(%ebx), %eax
    movl X_REGS+104(%ebx), %edx
    movl X_REGS+112(%ebx), %ecx
    movl X_REGS+120(%ebx), %esi
    movl X_REGS+88(%ebx), %edi
    call *X_KSFN(%ebx)
    jmp .Lmx_after
.Lmh_host_native:
    movl $MX_ERR_FAULT, X_REGS+96(%ebx)   # m12 = status（无内层原生执行器）
    movl $0, X_REGS+100(%ebx)
    jmp .Lmx_after

.Lmh_halt:
    movl X_SRC(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl %eax, X_RETVAL(%ebx)
    movl X_DST(%ebx), %ecx
    movl X_REGS(%ebx,%ecx,8), %eax
    movl %eax, X_HALTST(%ebx)
    movl $1, X_HALTED(%ebx)
    jmp .Lmx_after

# ---- 分发表（相对 .Lmbase 的 32 位偏移；顺序同 M_*）----
    .balign 4
.Lmx_dtbase:
    .long .Lmh_nop    - .Lmbase
    .long .Lmh_movi   - .Lmbase
    .long .Lmh_set64  - .Lmbase
    .long .Lmh_mov    - .Lmbase
    .long .Lmh_add    - .Lmbase
    .long .Lmh_sub    - .Lmbase
    .long .Lmh_mul    - .Lmbase
    .long .Lmh_and    - .Lmbase
    .long .Lmh_or     - .Lmbase
    .long .Lmh_xor    - .Lmbase
    .long .Lmh_shl    - .Lmbase
    .long .Lmh_shr    - .Lmbase
    .long .Lmh_sar    - .Lmbase
    .long .Lmh_neg    - .Lmbase
    .long .Lmh_not    - .Lmbase
    .long .Lmh_div    - .Lmbase
    .long .Lmh_mod    - .Lmbase
    .long .Lmh_ld     - .Lmbase
    .long .Lmh_ld32   - .Lmbase
    .long .Lmh_ld8    - .Lmbase
    .long .Lmh_st     - .Lmbase
    .long .Lmh_st32   - .Lmbase
    .long .Lmh_st8    - .Lmbase
    .long .Lmh_lea    - .Lmbase
    .long .Lmh_setcc  - .Lmbase
    .long .Lmh_jmp    - .Lmbase
    .long .Lmh_jcc    - .Lmbase
    .long .Lmh_call   - .Lmbase
    .long .Lmh_callr  - .Lmbase
    .long .Lmh_jmpr   - .Lmbase
    .long .Lmh_ret    - .Lmbase
    .long .Lmh_host   - .Lmbase
    .long .Lmh_halt   - .Lmbase

    .section .note.GNU-stack,"",@progbits
