# stub_x64.S — kboXShield 解壳 Stub（x86-64, PE32+）
#
# 布局契约与 include/kbox_format.h 一一对应（.equ 常量须与其保持一致）。
# 该文件被汇编为 ELF 目标文件后经 ld 平铺为二进制 blob（VMA 从 0 起），
# 因此所有跨段引用都必须是位置无关的（RIP-relative / 基址相对）。
#
# blob 布局：
#   [0x000 .. 0x100)  KboxConfig（packer 填充）
#   [0x100 ...]       入口代码与数据
#   [....  ]          .iat 段（loader 回填 stub 自身 IAT）
#
# 运行期流程：
#   取基址 -> 校验 magic -> VM 自检（运行期汇编引擎）-> 取 API(IAT)
#   -> 解密 payload -> 校验 payload magic -> 逐个解密原始节 -> 重建 IAT
#   -> 应用重定位 -> 恢复节权限 -> 跳 OEP

    .code64
    .section .text

# ================= 固定偏移（同步 kbox_format.h） =================
# KboxConfig
.set CFG_MAGIC,    0
.set CFG_VERSION,  4
.set CFG_FLAGS,    8
.set CFG_IS64,     12
.set CFG_STUB_RVA, 16
.set CFG_OEP_RVA,  20
.set CFG_IMG_LO,   24
.set CFG_IMG_HI,   28
.set CFG_PAY_RVA,  32
.set CFG_PAY_SIZE, 36
.set CFG_KEY,      40
.set CFG_NONCE,    72
# VM 元数据（Batch 4，同步 kbox_format.h）
.set CFG_VM_COUNT,       84
.set CFG_VM_RECS_RVA,    88
.set CFG_VM_FLAGS,       92
.set CFG_VM_ENGINE_RVA,  96
# 运行期防御（Batch 5，同步 kbox_format.h）
.set CFG_DEF_FLAGS,       100
.set CFG_DEF_POLICY,      104
.set CFG_DEF_REPORT_RVA,  108
.set CFG_DEF_INTEG_RVA,   112
.set CFG_DEF_INTEG_SIZE,  116
.set CFG_DEF_INTEG_CRC,   120
.set CFG_DEF_DECOY_RVA,   124
.set CFG_DEF_DELAY,       128
.set CFG_DEF_TICKS,       132
.set CFG_TLS_CB_RVA,      136
.set CFG_TLS_CB_COUNT,    140
# G2 原生层多态：字符串池 XOR 键（0 = 未启用）
.set CFG_DEF_RES0,        144
# 入口 trampoline 原始字节（5 字节：u32@0x94 + u8@0x98，packer 写入）
.set CFG_EP_PATCH,        148
# 检测位（同 kbox_format.h KBOX_DEF_*）
.set KDEF_PEB_DEBUG,    0x0001
.set KDEF_NTGLOBALFLAG, 0x0002
.set KDEF_HEAPFLAGS,    0x0004
.set KDEF_ISDEBUGGER,   0x0008
.set KDEF_REMOTEDEBUG,  0x0010
.set KDEF_PORTPROC,     0x0020
.set KDEF_HWBP,         0x0040
.set KDEF_TIMING,       0x0080
.set KDEF_INT3SCAN,     0x0100
.set KDEF_CPUID_HV,     0x0200
.set KDEF_CPUID_VENDOR, 0x0400
.set KDEF_IAT_HOOK,     0x0800
.set KDEF_INLINE_HOOK,  0x1000
.set KDEF_INTEGRITY,    0x2000
.set KDEF_INJECT,       0x4000
.set KDEF_THREAD_HIDE,  0x8000
.set KDEF_SIDT,         0x00010000
.set KDEF_VMWARE,       0x00020000
.set KDEF_CRITICAL,     0x9879
.set KDEF_FATAL,        0x6000
.set LVL_WEAK,  1
.set LVL_DECOY, 2
.set LVL_FATAL, 3
.set DEF_REPORT_MAGIC, 0x5246444B
.set DEF_DECOY_MARK,   0x4F434544
# KboxVmRec
.set VMR_IMAGE_RVA,   0
.set VMR_IMAGE_SIZE,  4
.set VMR_TARGET_RVA,  8
.set VMR_SELF_IN,     12
.set VMR_SELF_EXPECT, 16
.set VMR_SIZE,        20
# KboxSectionRec
.set REC_RVA,     0
.set REC_RAWSIZE, 4
.set REC_BLOCK,   8
.set REC_NONCE,   12
.set REC_PERMS,   24
.set REC_FLAGS,   28
.set REC_SIZE,    32
# KboxPayloadHdr
.set PAY_MAGIC,       0
.set PAY_SECTION_CNT, 4
.set PAY_IMP_DLL_CNT, 8
.set PAY_IMP_TOTAL,   12
.set PAY_RELOC_SIZE,  16
.set PAY_HDR_SIZE,    32
# KboxImpDll / KboxImpEntry
.set DLL_NAME_RVA, 0
.set DLL_IAT_RVA,  4
.set DLL_COUNT,    8
.set DLL_SIZE,     12
.set ENT_ORD,      0
.set ENT_HINT,     2
.set ENT_NAME,     4
.set ENT_SIZE,     8
# 常量
.set IAT_LOADLIBRARYA,   0
.set IAT_GETPROCADDRESS, 1
.set IAT_VIRTUALPROTECT, 2
.set KBOX_MAGIC_VAL,     0x584F424B
.set PAYLOAD_MAGIC_VAL,  0x5941504B
.set PAGE_EXECUTE_READWRITE, 0x40
.set PAGE_EXECUTE_READ, 0x20
.set STUB_A_LEN, kbox_iat      # 方案D：stub 代码节长度 = blob[0, iat_off)（VMA 常量）
.set PAYLOAD_FLAG_SKIP_DECRYPT, 0x1
.set RELOC_HIGHLOW, 3
.set RELOC_DIR64,  10
.set VM_FLAG_PRESENT, 0x1

# ================= ChaCha20 四分之一轮宏 =================
# 操作 [rbx+\a..d]（work 状态缓冲区）
.macro QR a, b, c, d
    movl \a(%rbx), %eax
    movl \b(%rbx), %ecx
    movl \d(%rbx), %edx          # %edx 承担 d 角色
    movl \c(%rbx), %esi          # %esi 承担 c 角色
    addl %ecx, %eax
    xorl %eax, %edx
    roll $16, %edx
    addl %edx, %esi
    xorl %esi, %ecx
    roll $12, %ecx
    addl %ecx, %eax
    xorl %eax, %edx
    roll $8, %edx
    addl %edx, %esi
    xorl %esi, %ecx
    roll $7, %ecx
    movl %eax, \a(%rbx)
    movl %ecx, \b(%rbx)
    movl %edx, \d(%rbx)
    movl %esi, \c(%rbx)
.endm

.macro ROUND
    QR 0, 16, 32, 48
    QR 4, 20, 36, 52
    QR 8, 24, 40, 56
    QR 12, 28, 44, 60
    QR 0, 20, 40, 60
    QR 4, 24, 44, 48
    QR 8, 28, 32, 52
    QR 12, 16, 36, 56
.endm

# 生成一个块：work = orig，work[12] = counter(%r10d)
.macro BLOCK_GEN
    leaq 64(%rbx), %rsi
    movl 0(%rsi), %eax;  movl %eax, 0(%rbx)
    movl 4(%rsi), %eax;  movl %eax, 4(%rbx)
    movl 8(%rsi), %eax;  movl %eax, 8(%rbx)
    movl 12(%rsi), %eax; movl %eax, 12(%rbx)
    movl 16(%rsi), %eax; movl %eax, 16(%rbx)
    movl 20(%rsi), %eax; movl %eax, 20(%rbx)
    movl 24(%rsi), %eax; movl %eax, 24(%rbx)
    movl 28(%rsi), %eax; movl %eax, 28(%rbx)
    movl 32(%rsi), %eax; movl %eax, 32(%rbx)
    movl 36(%rsi), %eax; movl %eax, 36(%rbx)
    movl 40(%rsi), %eax; movl %eax, 40(%rbx)
    movl 44(%rsi), %eax; movl %eax, 44(%rbx)
    movl %r10d, 48(%rbx)          # counter
    movl %r10d, 112(%rbx)         # orig[12] 同步为该块计数（最终 work+orig 需要）
    movl 52(%rsi), %eax; movl %eax, 52(%rbx)
    movl 56(%rsi), %eax; movl %eax, 56(%rbx)
    movl 60(%rsi), %eax; movl %eax, 60(%rbx)
    # ROUND 宏 = 1 组双轮（列轮 + 对角轮）；ChaCha20 共 20 轮 = 10 组
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
    ROUND
.endm

# ================= 配置区（blob 偏移 0，packer 填充） =================
    .balign 1
    .space 0x100

# ================= 入口（blob 偏移 0x100） =================
    .globl kbox_entry
    .type kbox_entry, @function
kbox_entry:
    # 入口时 RSP%16 == 8（已压入返回地址）。减 184（≡8 mod 16）使 RSP%16 == 0，
    # 之后所有 call 满足 Win64 ABI 的 16 字节栈对齐（否则 ntdll 的
    # movdqa/movaps 在对齐敏感的路径上会触发 #GP）。
    subq $184, %rsp                # 栈帧：局部变量 + 入口寄存器保存区
    # 入口参数寄存器：EXE 入口不使用这些槽，但 **DLL 入口**的
    # _DllMainCRTStartup(hinstDLL, fdwReason, lpvReserved) 正是经 rcx/rdx/r8
    # 传入。stub 全程会破坏这些易失寄存器，必须在跳 OEP 前原样还原，
    # 否则 DllMain 拿到野指针（hinstDLL）会立即崩溃。
    movq %rcx, 88(%rsp)
    movq %rdx, 96(%rsp)
    movq %r8,  104(%rsp)
    movq %r9,  112(%rsp)
    # 非易失寄存器同样必须保留。EXE 入口无返回方，但 **DLL 入口是被 loader
    # 直接 call 的**（LdrpCallInitRoutine），ntdll 假定 rbx/rbp/rsi/rdi/r12-r15
    # 跨调用不变；stub 把 rbx 当模块基址、r12 当配置区指针用，若就此跳 OEP，
    # 返回后 loader 会在被污染的寄存器上继续跑，表现为静默 ExitProcess(0)。
    movq %rbx, 120(%rsp)
    movq %rbp, 128(%rsp)
    movq %rsi, 136(%rsp)
    movq %rdi, 144(%rsp)
    movq %r12, 152(%rsp)
    movq %r13, 160(%rsp)
    movq %r14, 168(%rsp)
    movq %r15, 176(%rsp)
    leaq kbox_entry(%rip), %rax
    subq $0x100, %rax              # %rax = config 运行时地址（= base + stub_rva）
    movq %rax, %r12                # %r12 = config（跨调用保留）

    # ---- 二次进入检测（DLL 特有）----
    # loader 对 DLL 入口点的调用不止一次：DLL_PROCESS_ATTACH 之后，
    # DLL_THREAD_ATTACH / DLL_PROCESS_DETACH（进程退出）都会再次 call 同一入口
    # 地址。stub 是非幂等的（配置区解密），二次进入会把**明文**配置再解一遍
    # → CFG_MAGIC 失配 → .Ldead 死循环，表现为 LoadLibrary 正常返回、进程退出
    # 时永久挂起（调试器里看到「加载成功」但普通运行 HANG）。
    # 判据：配置区已解密（magic+version 合法，首次进入时为密文，误判概率 2^-64）
    # 且 rcx(=hinstDLL) + stub_rva 恰等于配置区运行时地址。命中即直转原入口。
    movl CFG_MAGIC(%r12), %eax
    cmpl $KBOX_MAGIC_VAL, %eax
    jne .Lfirst_entry
    cmpl $1, CFG_VERSION(%r12)
    jne .Lfirst_entry
    movl CFG_STUB_RVA(%r12), %eax
    addq %rcx, %rax                # rcx = hinstDLL = 模块基址
    leaq kbox_entry(%rip), %rdx
    subq $0x100, %rdx
    cmpq %rdx, %rax
    jne .Lfirst_entry
    movq %rcx, %rbx                # %rbx = 模块基址
    movl CFG_OEP_RVA(%r12), %eax
    addq %rbx, %rax
    movq 88(%rsp), %rcx            # 与尾部跳 OEP 相同的还原序列
    movq 96(%rsp), %rdx
    movq 104(%rsp), %r8
    movq 112(%rsp), %r9
    movq 120(%rsp), %rbx
    movq 128(%rsp), %rbp
    movq 136(%rsp), %rsi
    movq 144(%rsp), %rdi
    movq 152(%rsp), %r12
    movq 160(%rsp), %r13
    movq 168(%rsp), %r14
    movq 176(%rsp), %r15
    addq $184, %rsp
    jmp *%rax

.Lfirst_entry:
    # ---- 方案D：stub 代码节文件态 RX；入口先置 RWX 以便就地解密配置 ----
    # 注：IAT 位于独立 RW 节（loader 回填）；此处经 kbox_iat 取 VirtualProtect。
    leaq kbox_iat(%rip), %rsi
    movq 8*IAT_VIRTUALPROTECT(%rsi), %rax
    testq %rax, %rax
    jz .Ldead
    movq %r12, %rcx
    movl $0x1000, %edx
    movl $PAGE_EXECUTE_READWRITE, %r8d
    movq %rsp, %r9
    call *%rax
    movq %r12, %rax              # 恢复 config 地址（call 已破坏 rax）
    # ---- 方案A：配置区解密（每构建随机 LCG 流密钥，种子取自 kbox_cfg_root）----
    # 配置区 [0,0x100) 在文件中为密文；此处就地还原，之后才可读 stub_rva 等字段。
    leaq kbox_cfg_root(%rip), %r8
    movl (%r8), %r9d
    movq %r12, %rdi
    movl $256, %ecx
.Lcfg_loop:
    imull $1664525, %r9d, %r9d
    addl $1013904223, %r9d
    movl %r9d, %r10d
    shrl $16, %r10d
    xorb %r10b, (%rdi)
    incq %rdi
    decl %ecx
    jnz .Lcfg_loop
    movl CFG_STUB_RVA(%r12), %ecx
    subq %rcx, %rax
    movq %rax, %rbx                # %rbx = 模块基址（跨调用保留）
    cmpl $KBOX_MAGIC_VAL, CFG_MAGIC(%r12)
    jne .Ldead
    # ---- 方案D：整个 stub 代码节置 RWX（字符串池就地解码等运行期写入）----
    leaq kbox_iat(%rip), %rsi
    movq 8*IAT_VIRTUALPROTECT(%rsi), %rax
    testq %rax, %rax
    jz .Ldead
    movq %r12, %rcx
    movl $STUB_A_LEN, %edx
    movl $PAGE_EXECUTE_READWRITE, %r8d
    movq %rsp, %r9
    call *%rax

    # ---- G2 原生层多态：防御字符串池就地解码（XOR） ----
    # packer 以每构建随机键加密 blob 内字符串池 [kbox_strpool_start, kbox_defense_end)；
    # 此处先行还原，使后续 API 解析/防御检查使用明文；因还原后与打包资产一致，
    # 完整性 CRC（覆盖同一区间）仍成立。
    movl CFG_DEF_RES0(%r12), %eax
    testl %eax, %eax
    jz .Lstr_ok
    movl %eax, %edx
    leaq kbox_strpool_start(%rip), %rdi
    leaq kbox_defense_end(%rip), %rcx
    subq %rdi, %rcx
.Lstr_loop:
    xorb %dl, (%rdi)
    incq %rdi
    decq %rcx
    jnz .Lstr_loop
.Lstr_ok:

    # ---- 运行期防御（第 5 项）：检测体系 + 分级响应 ----
    # kbox_defense 执行全部启用检查并写 KboxDefenseReport；返回值即响应级别。
    call kbox_defense
    cmpl $LVL_FATAL, %eax
    jae .Ldead                      # 敌对：直接终止
    cmpl $LVL_DECOY, %eax
    je .Ldecoy_path                 # 确认被调试/篡改：转诱饵路径

    # ---- VM 自检（运行期汇编引擎）----
    # 逐个虚拟化镜像：以 rec->self_in 为输入执行该镜像，结果须等于打包期
    # 预演的 rec->self_expect；任何一项不符即说明引擎/镜像被篡改，直接死锁。
    # 引擎接口：kbox_vm_run(image, image_size, gprs, ks_fn)；
    #           eax = 状态码（0 = VM_OK），edx = VM 结果。
    # gprs 为 16 × u64 机器寄存器块，本处仅填 rax（= VM 输入约定 frame[0]）。
    testl $VM_FLAG_PRESENT, CFG_VM_FLAGS(%r12)
    jz .Lvm_skip
    movl CFG_VM_COUNT(%r12), %r15d          # r15 = 镜像数
    testl %r15d, %r15d
    jz .Lvm_skip
    movl CFG_VM_RECS_RVA(%r12), %r14d
    addq %rbx, %r14                         # r14 = KboxVmRec 数组
    subq $160, %rsp                         # 128B gprs 块 + 32B 影子空间
    xorl %r13d, %r13d                       # r13 = 记录下标
.Lvm_loop:
    imull $VMR_SIZE, %r13d, %r10d           # r10 = 记录字节偏移
    movq %rsp, %rdi
    xorl %eax, %eax
    movl $16, %ecx
    rep stosq                               # 清零 gprs 块
    movl VMR_SELF_IN(%r14,%r10), %eax
    movq %rax, 0(%rsp)                      # gprs[RAX] = 自检输入
    movl VMR_IMAGE_RVA(%r14,%r10), %ecx
    addq %rbx, %rcx                         # rcx = VM 镜像基址
    movl VMR_IMAGE_SIZE(%r14,%r10), %edx    # rdx = 镜像字节数
    movq %rsp, %r8                          # r8 = gprs
    leaq kbox_chacha(%rip), %r9             # r9 = keystream 例程
    movl CFG_VM_ENGINE_RVA(%r12), %eax
    addq %rbx, %rax                         # rax = 引擎入口
    call *%rax
    testl %eax, %eax
    jnz .Lvm_fail
    imull $VMR_SIZE, %r13d, %r10d           # 引擎调用会破坏 r10，重算偏移
    cmpl VMR_SELF_EXPECT(%r14,%r10), %edx
    jne .Lvm_fail
    incl %r13d
    cmpl %r15d, %r13d
    jb .Lvm_loop
    addq $160, %rsp
    jmp .Lvm_skip
.Lvm_fail:
    addq $160, %rsp
    jmp .Ldead
.Lvm_skip:

    # ---- 取 stub 自身 API（loader 已回填 kbox_iat）----
    leaq kbox_iat(%rip), %rsi
    movq 8*IAT_LOADLIBRARYA(%rsi), %r13   # LoadLibraryA
    movq 8*IAT_GETPROCADDRESS(%rsi), %r14  # GetProcAddress
    movq 8*IAT_VIRTUALPROTECT(%rsi), %r15  # VirtualProtect
    testq %r13, %r13
    jz .Ldead
    testq %r14, %r14
    jz .Ldead
    testq %r15, %r15
    jz .Ldead

    # ---- 解密 payload（stub 节内，RWX，直接原地解密）----
    movl CFG_PAY_RVA(%r12), %ecx
    addq %rbx, %rcx
    movl CFG_PAY_SIZE(%r12), %edx
    leaq CFG_KEY(%r12), %r8
    leaq CFG_NONCE(%r12), %r9
    xorl %r10d, %r10d               # counter = 0
    call kbox_chacha

    movl CFG_PAY_RVA(%r12), %eax
    addq %rbx, %rax
    movq %rax, %rbp                 # %rbp = payload 基址（解密后）
    cmpl $PAYLOAD_MAGIC_VAL, PAY_MAGIC(%rbp)
    jne .Ldead

    # ---- 逐个解密原始节 ----
    movl PAY_SECTION_CNT(%rbp), %eax
    testl %eax, %eax
    jz .Lno_sections
    # 槽位必须避开 Win64 影子空间 [rsp, rsp+0x20)：被调用的 VirtualProtect 等
    # API 可自由改写该区域。此前放在 8/16(%rsp) 会被覆盖，导致解密到野地址而崩溃。
    movl %eax, 72(%rsp)             # 剩余节数
    leaq PAY_HDR_SIZE(%rbp), %rax
    movq %rax, 80(%rsp)             # 节记录指针
.Lsec_loop:
    movq 80(%rsp), %rsi
    movl REC_FLAGS(%rsi), %r8d
    testl $PAYLOAD_FLAG_SKIP_DECRYPT, %r8d
    jnz .Lsec_next
    # VirtualProtect(addr, size, RWX, &old)
    movl REC_RVA(%rsi), %eax
    addq %rbx, %rax
    movq %rax, %rcx
    movl REC_RAWSIZE(%rsi), %edx
    movl $PAGE_EXECUTE_READWRITE, %r8d
    movq %rsp, %r9
    call *%r15
    # kbox_chacha(addr, size, key, nonce, block)
    movq 80(%rsp), %rsi
    movl REC_RVA(%rsi), %ecx
    addq %rbx, %rcx
    movl REC_RAWSIZE(%rsi), %edx
    leaq CFG_KEY(%r12), %r8
    leaq REC_NONCE(%rsi), %r9
    movl REC_BLOCK(%rsi), %r10d
    call kbox_chacha
.Lsec_next:
    movq 80(%rsp), %rax
    addq $REC_SIZE, %rax
    movq %rax, 80(%rsp)
    decl 72(%rsp)                   # 32 位计数（与 movl 存入配对）
    jnz .Lsec_loop
.Lno_sections:

    # ---- 重建 IAT（此时各节仍为 RWX，可直接写入）----
    movl PAY_SECTION_CNT(%rbp), %eax
    imull $REC_SIZE, %eax, %eax
    leaq PAY_HDR_SIZE(%rbp), %rsi
    addq %rax, %rsi                 # %rsi = 导入区起始
    movl PAY_IMP_DLL_CNT(%rbp), %eax
    testl %eax, %eax
    jz .Lno_imports
    movl %eax, 32(%rsp)             # 剩余 DLL 数
    movq %rsi, 40(%rsp)             # DLL 描述符指针
.Limp_dll_loop:
    movq 40(%rsp), %rsi
    movl DLL_NAME_RVA(%rsi), %ecx
    addq %rbx, %rcx
    call *%r13                      # LoadLibraryA
    movq %rax, 24(%rsp)             # hLib
    testq %rax, %rax
    jz .Limp_dll_next
    movq 40(%rsp), %rsi
    movl DLL_COUNT(%rsi), %eax
    movl %eax, 48(%rsp)             # 条目剩余数
    movl DLL_IAT_RVA(%rsi), %eax
    addq %rbx, %rax
    movq %rax, 56(%rsp)             # IAT 写入地址
    leaq DLL_SIZE(%rsi), %rax
    movq %rax, 64(%rsp)             # 条目指针
.Limp_entry_loop:
    movl 48(%rsp), %r9d
    testl %r9d, %r9d
    jz .Limp_dll_next
    movq 64(%rsp), %r11
    movzwl ENT_ORD(%r11), %eax
    movq 24(%rsp), %rcx             # hLib
    testl %eax, %eax
    jz .Limp_by_name
    movq %rax, %rdx                 # 按序号：MAKEINTRESOURCE(ordinal)
    jmp .Limp_gpa
.Limp_by_name:
    movl ENT_NAME(%r11), %edx
    addq %rbx, %rdx
.Limp_gpa:
    call *%r14                      # GetProcAddress
    testq %rax, %rax
    jz .Limp_entry_next
    movq 56(%rsp), %r10
    movq %rax, (%r10)
.Limp_entry_next:
    movq 64(%rsp), %rax
    addq $ENT_SIZE, %rax
    movq %rax, 64(%rsp)
    movq 56(%rsp), %rax
    addq $8, %rax
    movq %rax, 56(%rsp)
    decl 48(%rsp)
    jmp .Limp_entry_loop
.Limp_dll_next:
    movq 40(%rsp), %rax
    movl DLL_COUNT(%rax), %ecx
    imull $ENT_SIZE, %ecx, %ecx
    addq $DLL_SIZE, %rcx
    addq %rcx, %rax
    movq %rax, 40(%rsp)
    decl 32(%rsp)
    jnz .Limp_dll_loop
.Lno_imports:

    # ---- 应用重定位（仅当 base != ImageBase；无调用，可用易失寄存器）----
    movq %rbx, %rdx
    movl CFG_IMG_LO(%r12), %eax
    movl CFG_IMG_HI(%r12), %ecx
    shlq $32, %rcx
    orq %rax, %rcx
    subq %rcx, %rdx                 # %rdx = delta
    jz .Lno_reloc
    movl PAY_RELOC_SIZE(%rbp), %ecx
    testl %ecx, %ecx
    jz .Lno_reloc
    # 定位 reloc 数据：节记录之后 -> 导入区 -> 跳过所有 DLL 数据
    movl PAY_SECTION_CNT(%rbp), %eax
    imull $REC_SIZE, %eax, %eax
    leaq PAY_HDR_SIZE(%rbp), %rsi
    addq %rax, %rsi
    movl PAY_IMP_DLL_CNT(%rbp), %edi
.Lreloc_imp_walk:
    testl %edi, %edi
    jz .Lreloc_imp_done
    movl DLL_COUNT(%rsi), %eax
    imull $ENT_SIZE, %eax, %eax
    addl $DLL_SIZE, %eax
    addq %rax, %rsi
    decl %edi
    jmp .Lreloc_imp_walk
.Lreloc_imp_done:
    # %rsi = reloc 数据；%ecx = 剩余字节；%rdx = delta
    movl PAY_RELOC_SIZE(%rbp), %ecx
.Lreloc_loop:
    testl %ecx, %ecx
    jz .Lreloc_done
    movl 0(%rsi), %r8d              # 块 VirtualAddress
    movl 4(%rsi), %r9d              # SizeOfBlock
    movl %r9d, %r10d
    subl $8, %r10d
    shrl $1, %r10d                  # 条目数
    addq $8, %rsi
.Lreloc_entry:
    testl %r10d, %r10d
    jz .Lreloc_block_done
    movzwl (%rsi), %r11d
    movl %r11d, %edi
    shrl $12, %edi                  # type
    andl $0xFFF, %r11d              # offset
    leal (%r8,%r11), %eax           # rva
    cmpl $RELOC_DIR64, %edi
    je .Lreloc_dir64
    cmpl $RELOC_HIGHLOW, %edi
    jne .Lreloc_entry_next
    movl %eax, %edi                 # HIGHLOW: *(u32*)(base+rva) += delta32
    addq %rbx, %rdi
    addl %edx, (%rdi)
    jmp .Lreloc_entry_next
.Lreloc_dir64:
    movl %eax, %edi                 # DIR64: *(u64*)(base+rva) += delta
    addq %rbx, %rdi
    addq %rdx, (%rdi)
.Lreloc_entry_next:
    addq $2, %rsi
    decl %r10d
    jmp .Lreloc_entry
.Lreloc_block_done:
    subl %r9d, %ecx
    jmp .Lreloc_loop
.Lreloc_done:
.Lno_reloc:

    # ---- 入口 trampoline 字节还原 ----
    # packer 把原入口前 5 字节替换为 `jmp stub`（位置无关，见 ShieldPacker），
    # 原始字节保存在配置区 CFG_EP_PATCH。时机：各节解密完成、恢复节权限前
    # （此时 .text 仍为 RWX）写回原始字节，使 OEP 处指令与原始一致。
    movl CFG_EP_PATCH(%r12), %eax
    movl CFG_OEP_RVA(%r12), %ecx
    addq %rbx, %rcx
    movb %al, 0(%rcx)
    shrl $8, %eax
    movb %al, 1(%rcx)
    shrl $8, %eax
    movb %al, 2(%rcx)
    shrl $8, %eax
    movb %al, 3(%rcx)
    movl CFG_EP_PATCH+4(%r12), %eax
    movb %al, 4(%rcx)

    # ---- 恢复各节权限 ----
    movl PAY_SECTION_CNT(%rbp), %eax
    testl %eax, %eax
    jz .Lno_restore
    movl %eax, 72(%rsp)             # 同上：避开影子空间
    leaq PAY_HDR_SIZE(%rbp), %rax
    movq %rax, 80(%rsp)
.Lrest_loop:
    movq 80(%rsp), %rsi
    movl REC_RVA(%rsi), %eax
    addq %rbx, %rax
    movq %rax, %rcx
    movl REC_RAWSIZE(%rsi), %edx
    movl REC_PERMS(%rsi), %r8d
    movq %rsp, %r9
    call *%r15                      # VirtualProtect
    movq 80(%rsp), %rax
    addq $REC_SIZE, %rax
    movq %rax, 80(%rsp)
    decl 72(%rsp)
    jnz .Lrest_loop
.Lno_restore:

    # ---- TLS 回调（第 6 项）----
    # DIR_TLS 已被清零，loader 不会调用 TLS 回调；此处按原回调表代跑一次
    # （hinst = 模块基址，reason = DLL_PROCESS_ATTACH(1)，reserved = 0），
    # 语义与 Windows loader 对主镜像的静态 TLS 处理一致。
    movl CFG_TLS_CB_COUNT(%r12), %r14d
    testl %r14d, %r14d
    jz .Lno_tls
    movl CFG_TLS_CB_RVA(%r12), %r13d
    testl %r13d, %r13d
    jz .Lno_tls
    addq %rbx, %r13                 # r13 = 回调 RVA 数组基址
.Ltls_loop:
    movl 0(%r13), %eax
    testl %eax, %eax
    jz .Lno_tls
    addq %rbx, %rax                 # 回调 VA
    movq %rbx, %rcx                 # hinst
    movl $1, %edx                   # DLL_PROCESS_ATTACH
    xorl %r8d, %r8d                 # reserved
    call *%rax
    addq $4, %r13
    decl %r14d
    jnz .Ltls_loop
.Lno_tls:

    # ---- 方案D：stub 代码节恢复只读（RX） ----
    leaq kbox_iat(%rip), %rsi
    movq 8*IAT_VIRTUALPROTECT(%rsi), %rax
    testq %rax, %rax
    jz .Ldead
    movq %r12, %rcx
    movl $STUB_A_LEN, %edx
    movl $PAGE_EXECUTE_READ, %r8d
    movq %rsp, %r9
    call *%rax
    # ---- 跳转 OEP ----
    # 先还原入口参数寄存器（DLL 入口的 hinstDLL/fdwReason/lpvReserved），
    # 再把 RSP 还原到入口值，使 OEP 看到的栈与寄存器与「它就是入口点」一致；
    # DLL 的 _DllMainCRTStartup 会 ret 回 loader，栈错位会直接 AV。
    movl CFG_OEP_RVA(%r12), %eax
    addq %rbx, %rax
    movq 88(%rsp), %rcx
    movq 96(%rsp), %rdx
    movq 104(%rsp), %r8
    movq 112(%rsp), %r9
    movq 120(%rsp), %rbx
    movq 128(%rsp), %rbp
    movq 136(%rsp), %rsi
    movq 144(%rsp), %rdi
    movq 152(%rsp), %r12
    movq 160(%rsp), %r13
    movq 168(%rsp), %r14
    movq 176(%rsp), %r15
    addq $184, %rsp                # 还原入口栈，OEP 期望 RSP 与进程入口一致
    jmp *%rax

.Ldead:
    jmp .Ldead

# 诱饵路径：kbox_decoy 写入 DECO 标记后进入伪终止循环（可观测）
.Ldecoy_path:
    call kbox_decoy
    jmp .Ldead

# ================= 虚拟化函数运行期分发桩 =================
# 由「每函数 trampoline」的 `jmp` 进入（见 packer：改写标记函数首字节为
# `E9 rel32` 跳到该函数的 trampoline；trampoline 压入镜像 RVA/大小后跳此）。
# 职责：把真实机器寄存器搬进 gprs 块 → 调 kbox_vm_run 执行对应 VM 镜像
#       → 以虚拟 rax 作为返回值返回调用方。
#
# 入口栈布局（trampoline 已压入两个 imm32）：
#     [rsp+0] = 镜像 RVA
#     [rsp+4] = 镜像 RVA 的高半（pushq imm32 符号扩展）
#     [rsp+8] = 镜像字节数
#     [rsp+16]= 返回地址
# 进入后立刻弹出这两个槽，使后续栈形与普通函数入口一致（rsp%16 == 8）。
#
# ABI 契约（关键）：调用方在编译期可能借助 IPA-RA 得知原函数的寄存器
# 破坏集合，从而把活跃值放在原函数“不破坏”的易失寄存器里跨调用存活
# （例：被测函数只用 rax/rcx/rdx，则调用方可把值放在 r8/r9 跨调用）。
# 因此分发桩必须把「除 rax 外的全部通用寄存器」原样保留：保留得比原函数
# 更多永远满足 ABI，少保留则会让调用方拿到被破坏的值。rax 承载返回值，
# 由 VM 结果覆写。
# ---- 方案A：配置区加密种子（每构建随机；packer 填充低 4 字节）----
    .balign 8
    .globl kbox_cfg_root
kbox_cfg_root:
    .space 8

    .globl kbox_vm_dispatch
    .type kbox_vm_dispatch, @function
kbox_vm_dispatch:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    pushq %rcx                      # 易失寄存器同样入栈保留（见上）
    pushq %rdx
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    # 注意：trampoline 压入的两个参数槽位于 [rbp+8]（镜像 RVA）与
    # [rbp+16]（镜像字节数）；必须**在保存全部寄存器之后**再读，否则会
    # 破坏函数入参（尤其 rdx 承载第 2 个参数）。
    subq $184, %rsp                 # 128B gprs 块 + 32B 影子 + 镜像 RVA/大小 + 对齐
    movl 8(%rbp), %eax              # 镜像 RVA
    movl %eax, 168(%rsp)
    movl 16(%rbp), %edx             # 镜像字节数
    movl %edx, 176(%rsp)
    # ---- 构造机器寄存器块（槽号 = 寄存器编号）----
    xorl %eax, %eax
    movq %rax, 0(%rsp)              # rax（返回时回读）
    movq -64(%rbp), %rax
    movq %rax, 8(%rsp)              # rcx（参数 1）
    movq -72(%rbp), %rax
    movq %rax, 16(%rsp)             # rdx（参数 2）
    movq -8(%rbp), %rax
    movq %rax, 24(%rsp)             # rbx（调用者值）
    leaq 24(%rbp), %rax
    movq %rax, 32(%rsp)             # rsp（普通函数入口值 = rbp + 24）
    movq 0(%rbp), %rax
    movq %rax, 40(%rsp)             # rbp（调用者值）
    movq -16(%rbp), %rax
    movq %rax, 48(%rsp)             # rsi
    movq -24(%rbp), %rax
    movq %rax, 56(%rsp)             # rdi
    movq -80(%rbp), %rax
    movq %rax, 64(%rsp)             # r8
    movq -88(%rbp), %rax
    movq %rax, 72(%rsp)             # r9
    movq -96(%rbp), %rax
    movq %rax, 80(%rsp)             # r10
    movq -104(%rbp), %rax
    movq %rax, 88(%rsp)             # r11
    movq -32(%rbp), %rax
    movq %rax, 96(%rsp)             # r12
    movq -40(%rbp), %rax
    movq %rax, 104(%rsp)            # r13
    movq -48(%rbp), %rax
    movq %rax, 112(%rsp)            # r14
    movq -56(%rbp), %rax
    movq %rax, 120(%rsp)            # r15
    # ---- 取 config / 模块基址（PIC）----
    leaq kbox_entry(%rip), %rax
    subq $0x100, %rax
    movq %rax, %r15                 # r15 = config
    movl CFG_STUB_RVA(%r15), %ecx
    movq %rax, %rbx
    subq %rcx, %rbx                 # rbx = 模块基址
    # ---- kbox_vm_run(image, image_size, gprs, ks_fn) ----
    movl 168(%rsp), %ecx            # 镜像 RVA（trampoline 传入）
    addq %rbx, %rcx                 # rcx = 镜像基址
    movl 176(%rsp), %edx            # rdx = 镜像字节数
    movq %rsp, %r8                  # r8 = gprs
    leaq kbox_chacha(%rip), %r9     # r9 = keystream 例程
    movl CFG_VM_ENGINE_RVA(%r15), %eax
    addq %rbx, %rax                 # rax = 引擎入口
    call *%rax
    testl %eax, %eax
    jnz .Lvd_dead
    movq 0(%rsp), %rax              # 返回值 = 虚拟 rax
    addq $184, %rsp
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rdx
    popq %rcx
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rdi
    popq %rsi
    popq %rbx
    popq %rbp
    addq $16, %rsp                  # 弹出 trampoline 压入的两个参数槽
    ret
.Lvd_dead:
    jmp .Lvd_dead

# ================= kbox_chacha（内部调用） =================
# 入口参数：rcx=buf, rdx=len, r8=key, r9=nonce, r10d=counter
# 原地 XOR keystream。保留 rbx/rsi/rdi/rbp/r12/r13。
    .globl kbox_chacha
    .type kbox_chacha, @function
kbox_chacha:
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r12
    pushq %r13
    subq $128, %rsp
    movq %rsp, %rbx                 # work 状态 at +0, orig 状态 at +64
    movq %rcx, %r12                 # buf
    movq %rdx, %r13                 # len
    # 构建初始 state（含 key/nonce/counter）
    movl $0x61707865, 0(%rbx)
    movl $0x3320646e, 4(%rbx)
    movl $0x79622d32, 8(%rbx)
    movl $0x6b206574, 12(%rbx)
    movq %r8, %rsi
    movl 0(%rsi), %eax;  movl %eax, 16(%rbx)
    movl 4(%rsi), %eax;  movl %eax, 20(%rbx)
    movl 8(%rsi), %eax;  movl %eax, 24(%rbx)
    movl 12(%rsi), %eax; movl %eax, 28(%rbx)
    movl 16(%rsi), %eax; movl %eax, 32(%rbx)
    movl 20(%rsi), %eax; movl %eax, 36(%rbx)
    movl 24(%rsi), %eax; movl %eax, 40(%rbx)
    movl 28(%rsi), %eax; movl %eax, 44(%rbx)
    movl %r10d, 48(%rbx)            # counter
    movq %r9, %rsi
    movl 0(%rsi), %eax;  movl %eax, 52(%rbx)
    movl 4(%rsi), %eax;  movl %eax, 56(%rbx)
    movl 8(%rsi), %eax;  movl %eax, 60(%rbx)
    # orig = work
    leaq 64(%rbx), %rdi
    movl 0(%rbx), %eax;  movl %eax, 0(%rdi)
    movl 4(%rbx), %eax;  movl %eax, 4(%rdi)
    movl 8(%rbx), %eax;  movl %eax, 8(%rdi)
    movl 12(%rbx), %eax; movl %eax, 12(%rdi)
    movl 16(%rbx), %eax; movl %eax, 16(%rdi)
    movl 20(%rbx), %eax; movl %eax, 20(%rdi)
    movl 24(%rbx), %eax; movl %eax, 24(%rdi)
    movl 28(%rbx), %eax; movl %eax, 28(%rdi)
    movl 32(%rbx), %eax; movl %eax, 32(%rdi)
    movl 36(%rbx), %eax; movl %eax, 36(%rdi)
    movl 40(%rbx), %eax; movl %eax, 40(%rdi)
    movl 44(%rbx), %eax; movl %eax, 44(%rdi)
    movl 48(%rbx), %eax; movl %eax, 48(%rdi)
    movl 52(%rbx), %eax; movl %eax, 52(%rdi)
    movl 56(%rbx), %eax; movl %eax, 56(%rdi)
    movl 60(%rbx), %eax; movl %eax, 60(%rdi)
    jmp .Lchacha_loop

.Lchacha_loop:
    cmpq $64, %r13
    jb .Lchacha_tail
    BLOCK_GEN
    # 输出：out[i] = work[i]+orig[i] ^ buf[i]
    xorl %edi, %edi
.Lchacha_out:
    movl 0(%rbx,%rdi,4), %eax
    addl 64(%rbx,%rdi,4), %eax
    xorl 0(%r12,%rdi,4), %eax
    movl %eax, 0(%r12,%rdi,4)
    incl %edi
    cmpl $16, %edi
    jb .Lchacha_out
    addq $64, %r12
    subq $64, %r13
    incl %r10d
    jmp .Lchacha_loop

.Lchacha_tail:
    testq %r13, %r13
    jz .Lchacha_done
    BLOCK_GEN
    # 按字节 XOR 剩余 r13 字节
    xorl %edi, %edi
.Lchacha_tail_byte:
    cmpq %r13, %rdi
    jae .Lchacha_done
    movl %edi, %eax
    shrl $2, %eax
    movl 0(%rbx,%rax,4), %ecx
    addl 64(%rbx,%rax,4), %ecx      # keystream 字
    movl %edi, %eax
    andl $3, %eax
    shll $3, %eax                   # 字节内偏移：0/8/16/24
    movl %ecx, %edx                 # 保留密钥流字（cl 将被移位数占用）
    movb %al, %cl
    shrl %cl, %edx                  # dl = keystream 字节
    movb (%r12,%rdi), %al
    xorb %dl, %al
    movb %al, (%r12,%rdi)
    incl %edi
    jmp .Lchacha_tail_byte

.Lchacha_done:
    addq $128, %rsp
    popq %r13
    popq %r12
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rbx
    ret

# ================= 运行期防御（第 5 项） =================
# kbox_defense：检测体系（三层反调试 / 反注入 / 完整性 / 反 VM / 反 hook），
# 结果写入 def_report_rva 指向的 KboxDefenseReport，并按分级响应返回级别。
#   入：r12 = config，rbx = 模块基址
#   出：eax = 响应级别（0 继续 / 1 弱信号已延迟 / 2 诱饵 / 3 终止）
#   保留 rbx/r12/rbp/rsi/rdi/r13-r15（Win64 ABI）。
# 本地帧（rbp 基准）：
.set LF_FLAGS,   0      # 命中位
.set LF_RUN,     4      # 已执行检查数
.set LF_LEVEL,   8
.set LF_HBFAIL,  12     # 动态解析失败数
.set LF_DELTA,   16     # rdtsc 时间差
.set LF_CRC,     20     # 运行期 CRC
.set LF_MODCNT,  24     # 模块数
.set LF_TMPBUF,  32     # 16B 通用缓冲（NtQueryInformationProcess 输出）
.set LF_SCAN,    56     # VirtualQuery 扫描地址
.set LF_REPORT,  64     # 报告块地址
.set LF_CURP,    72     # GetCurrentProcess 结果
.set LF_CURT,    80     # GetCurrentThread 结果
.set LF_RBXSAVE, 88     # cpuid 前保存 %rbx（模块基址；cpuid 破坏 ebx）
.set LF_MBI,     96     # MEMORY_BASIC_INFORMATION（48B）
.set LF_CTX,     160    # CONTEXT（含调试寄存器；0x4D0）
# 方案D：直接系统调用 SSN 缓存 + hook 扫描表
.set LF_SSN_QIP,  0x570  # NtQueryInformationProcess 系统调用号（0 = 不可用）
.set LF_SSN_TSIT, 0x578  # NtSetInformationThread 系统调用号
.set LF_SSN_QVM,  0x580  # NtQueryVirtualMemory 系统调用号
.set LF_HOOKTBL,  0x588  # hook 扫描表（24 × 8B，防御解析 API 地址）
.set LF_HOOKCNT,  0x648  # 表内条目数
.set LF_VEHADD,   0x650  # AddVectoredExceptionHandler 地址（0 = 不可用）
.set LF_VEHHDL,   0x658  # VEH 句柄
.set LF_HOOKMAX,  24
.set LF_END,      0x660
.set LF_SIZE,     0x660  # 16 的倍数

    .globl kbox_defense
    .type kbox_defense, @function
kbox_defense:
    pushq %rbp
    pushq %rbx
    pushq %rsi
    pushq %rdi
    pushq %r13
    pushq %r14
    pushq %r15
    subq $LF_SIZE, %rsp
    movq %rsp, %rbp                 # 局部帧基址（跨 call 稳定）
    movl $0, LF_FLAGS(%rbp)
    movl $0, LF_RUN(%rbp)
    movl $0, LF_HBFAIL(%rbp)
    movl $0, LF_DELTA(%rbp)
    movl $0, LF_CRC(%rbp)
    movl $0, LF_MODCNT(%rbp)
    movl $0, LF_CURP(%rbp)
    movl $0, LF_CURT(%rbp)
    movl $0, LF_HOOKCNT(%rbp)
    movq $0, LF_VEHADD(%rbp)
    movq $0, LF_VEHHDL(%rbp)
    movl CFG_DEF_REPORT_RVA(%r12), %eax
    testl %eax, %eax
    jz 1f
    addq %rbx, %rax
1:  movq %rax, LF_REPORT(%rbp)

    # ---- 特权指令探针的容错前置：安装 VEH ----
    # SIDT 在现代 Windows（CR4.UMIP=1，VBS/HVCI 默认开启）与 VMware 后门 IN 都是
    # CPL3 下的 #GP（STATUS_PRIVILEGED_INSTRUCTION）。裸执行会让进程直接死亡，
    # 而 stub 位于裸代码节、没有 .pdata/SEH 帧可挂。故此处先注册一个顶层
    # Vectored Exception Handler（VEH 在 SEH 之前运行），由它把探针处的故障
    # 转为「探针结果为否」并继续执行。注册失败则跳过全部特权探针。
    testl $(KDEF_SIDT|KDEF_VMWARE), CFG_DEF_FLAGS(%r12)
    jz .Ld_veh_done
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_addveh(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_veh_done
    movq %rax, LF_VEHADD(%rbp)
    movq $1, %rcx                   # First = 1（置于链首）
    leaq kbox_veh(%rip), %rdx
    call *%rax
    movq %rax, LF_VEHHDL(%rbp)
.Ld_veh_done:

    # ---- L1 反调试：PEB.BeingDebugged ----
    testl $KDEF_PEB_DEBUG, CFG_DEF_FLAGS(%r12)
    jz .Ld_ntgf
    incl LF_RUN(%rbp)
    movq %gs:0x60, %rax             # PEB
    cmpb $0, 2(%rax)
    je .Ld_ntgf
    orl $KDEF_PEB_DEBUG, LF_FLAGS(%rbp)

.Ld_ntgf:                            # ---- L1 反调试：PEB.NtGlobalFlag ----
    testl $KDEF_NTGLOBALFLAG, CFG_DEF_FLAGS(%r12)
    jz .Ld_heap
    incl LF_RUN(%rbp)
    movq %gs:0x60, %rax
    movl 0xBC(%rax), %eax
    testl %eax, %eax
    jz .Ld_heap
    orl $KDEF_NTGLOBALFLAG, LF_FLAGS(%rbp)

.Ld_heap:                            # ---- L1 反调试：堆 Flags/ForceFlags ----
    testl $KDEF_HEAPFLAGS, CFG_DEF_FLAGS(%r12)
    jz .Ld_isdbg
    incl LF_RUN(%rbp)
    movq %gs:0x60, %rax
    movq 0x30(%rax), %rax           # ProcessHeap
    testq %rax, %rax
    jz .Ld_isdbg
    movl 0x74(%rax), %ecx           # ForceFlags
    testl %ecx, %ecx
    jnz .Ld_heap_hit
    movl 0x70(%rax), %ecx           # Flags（正常为 2）
    andl $-3, %ecx
    jz .Ld_isdbg
.Ld_heap_hit:
    orl $KDEF_HEAPFLAGS, LF_FLAGS(%rbp)

.Ld_isdbg:                           # ---- L2 反调试：IsDebuggerPresent ----
    testl $KDEF_ISDEBUGGER, CFG_DEF_FLAGS(%r12)
    jz .Ld_remote
    incl LF_RUN(%rbp)
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_isdbg(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_isdbg_fail
    call *%rax
    testl %eax, %eax
    jz .Ld_remote
    orl $KDEF_ISDEBUGGER, LF_FLAGS(%rbp)
    jmp .Ld_remote
.Ld_isdbg_fail:
    incl LF_HBFAIL(%rbp)

.Ld_remote:                          # ---- L2 反调试：CheckRemoteDebuggerPresent ----
    testl $KDEF_REMOTEDEBUG, CFG_DEF_FLAGS(%r12)
    jz .Ld_port
    incl LF_RUN(%rbp)
    call .Ld_getcurp
    testq %rax, %rax
    jz .Ld_remote_fail
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_cremote(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_remote_fail
    movl $0, LF_TMPBUF(%rbp)
    movq LF_CURP(%rbp), %rcx
    leaq LF_TMPBUF(%rbp), %rdx
    call *%rax
    testl %eax, %eax
    jz .Ld_port
    cmpl $0, LF_TMPBUF(%rbp)
    je .Ld_port
    orl $KDEF_REMOTEDEBUG, LF_FLAGS(%rbp)
    jmp .Ld_port
.Ld_remote_fail:
    incl LF_HBFAIL(%rbp)

.Ld_port:                            # ---- L2 反调试：NtQueryInformationProcess ----
    testl $KDEF_PORTPROC, CFG_DEF_FLAGS(%r12)
    jz .Ld_thrhide
    incl LF_RUN(%rbp)
    call .Ld_getcurp
    testq %rax, %rax
    jz .Ld_port_fail
    leaq .Ld_s_ntdll(%rip), %rdi
    leaq .Ld_s_ntqip(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_port_fail
    movq %rax, %r15                 # pNtQueryInformationProcess
    movq %rax, %rsi
    call .Ld_ssn_of
    movl %eax, LF_SSN_QIP(%rbp)     # SSN（0 = 回退函数指针）
    movl $7, %r14d                  # ProcessDebugPort
    call .Ld_ntqip
    testl %eax, %eax
    jnz .Ld_port_fail
    cmpq $0, LF_TMPBUF(%rbp)
    jne .Ld_port_hit
    movl $0x1E, %r14d               # ProcessDebugObjectHandle
    call .Ld_ntqip
    testl %eax, %eax
    jnz .Ld_port_fail
    cmpq $0, LF_TMPBUF(%rbp)
    jne .Ld_port_hit
    movl $0x1F, %r14d               # ProcessDebugFlags（0 = 被调试）
    call .Ld_ntqip
    testl %eax, %eax
    jnz .Ld_port_fail
    cmpq $0, LF_TMPBUF(%rbp)
    jne .Ld_thrhide
.Ld_port_hit:
    orl $KDEF_PORTPROC, LF_FLAGS(%rbp)
    jmp .Ld_hwbp
.Ld_port_fail:
    incl LF_HBFAIL(%rbp)

.Ld_thrhide:                         # ---- L2 反调试：NtSetInformationThread 失败 ----
    testl $KDEF_THREAD_HIDE, CFG_DEF_FLAGS(%r12)
    jz .Ld_hwbp
    incl LF_RUN(%rbp)
    leaq .Ld_s_ntdll(%rip), %rdi
    leaq .Ld_s_ntsit(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_thr_fail
    movq %rax, %r15                 # pNtSetInformationThread
    movq %rax, %rsi
    call .Ld_ssn_of
    movl %eax, LF_SSN_TSIT(%rbp)
    movq $-2, %rcx                  # NtCurrentThread（伪句柄）
    movl $0x11, %edx                # ThreadHideFromDebugger
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $56, %rsp                  # 影子空间
    movl LF_SSN_TSIT(%rbp), %eax
    call .Ld_ntcall
    addq $56, %rsp
    testl %eax, %eax                # 非 STATUS_SUCCESS -> 被拦截/异常
    jz .Ld_hwbp
    orl $KDEF_THREAD_HIDE, LF_FLAGS(%rbp)
    jmp .Ld_hwbp
.Ld_thr_fail:
    incl LF_HBFAIL(%rbp)

.Ld_hwbp:                            # ---- L3 反调试：硬件断点（Dr0-3） ----
    testl $KDEF_HWBP, CFG_DEF_FLAGS(%r12)
    jz .Ld_timing
    incl LF_RUN(%rbp)
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_gcurt(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_hwbp_fail
    call *%rax
    movq %rax, LF_CURT(%rbp)
    leaq LF_CTX(%rbp), %rdi
    xorl %eax, %eax
    movl $(0x4D0/8), %ecx
    rep stosq
    movl $0x00100010, LF_CTX+0x30(%rbp)   # CONTEXT_AMD64|DEBUG_REGISTERS
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_gtc(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_hwbp_fail
    movq LF_CURT(%rbp), %rcx
    leaq LF_CTX(%rbp), %rdx
    call *%rax
    testl %eax, %eax
    jz .Ld_timing
    movq LF_CTX+0x48(%rbp), %rax    # Dr0..Dr3
    orq LF_CTX+0x50(%rbp), %rax
    orq LF_CTX+0x58(%rbp), %rax
    orq LF_CTX+0x60(%rbp), %rax
    jz .Ld_timing
    orl $KDEF_HWBP, LF_FLAGS(%rbp)
    jmp .Ld_timing
.Ld_hwbp_fail:
    incl LF_HBFAIL(%rbp)

.Ld_timing:                          # ---- L3 反调试：rdtsc 时间差 ----
    testl $KDEF_TIMING, CFG_DEF_FLAGS(%r12)
    jz .Ld_cpuid_hv
    incl LF_RUN(%rbp)
    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    movq %rax, %r14
    movl $128, %ecx
.Ld_tloop:
    pause
    decl %ecx
    jnz .Ld_tloop
    rdtsc
    shlq $32, %rdx
    orq %rdx, %rax
    subq %r14, %rax
    movl %eax, LF_DELTA(%rbp)
    movl CFG_DEF_TICKS(%r12), %ecx
    testl %ecx, %ecx
    jz .Ld_cpuid_hv
    cmpq %rcx, %rax
    jbe .Ld_cpuid_hv
    orl $KDEF_TIMING, LF_FLAGS(%rbp)

.Ld_cpuid_hv:                        # ---- 反 VM：CPUID hypervisor 位 ----
    testl $KDEF_CPUID_HV, CFG_DEF_FLAGS(%r12)
    jz .Ld_cpuid_v
    incl LF_RUN(%rbp)
    movq %rbx, LF_RBXSAVE(%rbp)     # cpuid 破坏 ebx（= 模块基址）
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    movl %ebx, %r9d                 # 结果先入 r9d
    movq LF_RBXSAVE(%rbp), %rbx
    testl $0x80000000, %ecx
    jz .Ld_cpuid_v
    orl $KDEF_CPUID_HV, LF_FLAGS(%rbp)

.Ld_cpuid_v:                         # ---- 反 VM：hypervisor vendor 串 ----
    testl $KDEF_CPUID_VENDOR, CFG_DEF_FLAGS(%r12)
    jz .Ld_sidt
    incl LF_RUN(%rbp)
    movq %rbx, LF_RBXSAVE(%rbp)
    movl $0x40000000, %eax
    xorl %ecx, %ecx
    cpuid
    movl %ebx, %r9d
    movl %ecx, %r8d
    movl %edx, %r10d
    movq LF_RBXSAVE(%rbp), %rbx
    movl %r9d, %eax
    orl %r8d, %eax
    orl %r10d, %eax
    testl %eax, %eax
    jz .Ld_sidt
    orl $KDEF_CPUID_VENDOR, LF_FLAGS(%rbp)

.Ld_sidt:                            # ---- 反 VM：SIDT（IDT 基址高字节）----
    # 非 CPUID 信号：IDTR 仅 ring-0 可改，用户态攻击者无法伪造（需 UMIP 关闭）。
    # 若 CR4.UMIP=1（Win10+ VBS/HVCI 默认开启）该指令在 CPL3 下 #GP，由 kbox_veh
    # 兜底：清零目标缓冲并跳过，等价于「无 VM 特征」。
    testl $KDEF_SIDT, CFG_DEF_FLAGS(%r12)
    jz .Ld_vmw
    incl LF_RUN(%rbp)
    cmpq $0, LF_VEHHDL(%rbp)        # 无 VEH 兜底时不得裸执行（会 #GP 杀进程）
    je .Ld_sidt_fail
    subq $16, %rsp
.Lveh_probe_sidt:
    sidt (%rsp)
.Lveh_after_sidt:
    movq 2(%rsp), %rax               # IDT 基址（10 字节：limit + base64）
    addq $16, %rsp
    shrq $56, %rax
    cmpq $0xFF, %rax                 # 经典 VM 特征：基址高字节 0xFF
    jne .Ld_vmw
    orl $KDEF_SIDT, LF_FLAGS(%rbp)
    jmp .Ld_vmw
.Ld_sidt_fail:
    incl LF_HBFAIL(%rbp)

.Ld_vmw:                             # ---- 反 VM：VMware I/O 后门 ----
    # 非 CPUID 信号：IN/OUT 为特权级敏感端口访问，用户态钩子无法拦截。
    # 注：CPL3 下 IN 恒 #GP（用户态并不存在 VMware 后门响应），故实测恒为「否」；
    # 由 kbox_veh 兜底跳过（true 只可能出现在 ring0 探针）。
    testl $KDEF_VMWARE, CFG_DEF_FLAGS(%r12)
    jz .Ld_iat
    incl LF_RUN(%rbp)
    cmpq $0, LF_VEHHDL(%rbp)
    je .Ld_vmw_fail
    movq %rbx, LF_RBXSAVE(%rbp)      # in 不破坏 rbx，此处仅为防御 cpuid 残留
    movl $0x564D5868, %eax           # 'VMXh'
    xorl %ebx, %ebx
    movl $0x0A, %ecx                 # getVMVersion
    movl $0x5658, %edx               # 'VX'
.Lveh_probe_in:
    inl %dx, %eax                    # VMware 后门：命中时 ebx 返回魔数
.Lveh_after_in:
    movl %ebx, %ecx
    movq LF_RBXSAVE(%rbp), %rbx
    cmpl $0x564D5868, %ecx
    jne .Ld_iat
    orl $KDEF_VMWARE, LF_FLAGS(%rbp)
    jmp .Ld_iat
.Ld_vmw_fail:
    incl LF_HBFAIL(%rbp)

.Ld_iat:                             # ---- 反 hook：IAT/解析 API + 内联前缀扫描 ----
    testl $(KDEF_IAT_HOOK|KDEF_INLINE_HOOK), CFG_DEF_FLAGS(%r12)
    jz .Ld_inject
    incl LF_RUN(%rbp)
    # 页属性经 NtQueryVirtualMemory 查询（直接 syscall；用户态 VirtualQuery 钩子无效）
    leaq .Ld_s_ntdll(%rip), %rdi
    leaq .Ld_s_ntqvm(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_iat_fail
    movq %rax, %r15                 # pNtQueryVirtualMemory
    movq %rax, %rsi
    call .Ld_ssn_of
    movl %eax, LF_SSN_QVM(%rbp)
    # 扫描 kbox_iat 3 槽 + 防御解析 API 表（.Ld_resolve 已记录）
    leaq kbox_iat(%rip), %r13
    xorl %r14d, %r14d
.Ld_iat_loop:
    cmpl $3, %r14d
    jae .Ld_iat_tbl
    movq (%r13,%r14,8), %rsi        # IAT 槽内实际函数地址
    jmp .Ld_iat_chk
.Ld_iat_tbl:
    movl LF_HOOKCNT(%rbp), %r10d    # 表条目数（快照）
    movl %r14d, %r11d
    subl $3, %r11d                  # 表下标
    cmpl %r10d, %r11d
    jae .Ld_inject
    movq LF_HOOKTBL(%rbp,%r11,8), %rsi
.Ld_iat_chk:
    testq %rsi, %rsi
    jz .Ld_iat_next
    testl $KDEF_INLINE_HOOK, CFG_DEF_FLAGS(%r12)
    jz .Ld_iat_vq
    movzbl (%rsi), %ecx
    cmpl $0xE9, %ecx                # jmp rel32
    je .Ld_iat_inline
    cmpl $0xFF, %ecx
    jne .Ld_iat_vq
    movzbl 1(%rsi), %ecx
    cmpl $0x25, %ecx                # jmp [rip+disp]
    je .Ld_iat_inline
.Ld_iat_vq:
    testl $KDEF_IAT_HOOK, CFG_DEF_FLAGS(%r12)
    jz .Ld_iat_next
    # NtQueryVirtualMemory(当前进程, addr, MemoryBasicInformation, &mbi, 48, &len)
    movq $-1, %rcx
    movq %rsi, %rdx
    xorl %r8d, %r8d
    leaq LF_MBI(%rbp), %r9
    subq $56, %rsp
    movl $48, 32(%rsp)
    leaq LF_TMPBUF(%rbp), %rax
    movq %rax, 40(%rsp)
    movl LF_SSN_QVM(%rbp), %eax
    call .Ld_ntcall
    addq $56, %rsp
    testl %eax, %eax
    jnz .Ld_iat_next
    cmpl $0x1000000, LF_MBI+40(%rbp)  # Type == MEM_IMAGE
    je .Ld_iat_next
    orl $KDEF_IAT_HOOK, LF_FLAGS(%rbp)
    jmp .Ld_iat_next
.Ld_iat_inline:
    orl $KDEF_INLINE_HOOK, LF_FLAGS(%rbp)
.Ld_iat_next:
    incl %r14d
    jmp .Ld_iat_loop
.Ld_iat_fail:
    incl LF_HBFAIL(%rbp)

.Ld_inject:                          # ---- 完整性校验（CRC32）+ 反注入 ----
    testl $KDEF_INTEGRITY, CFG_DEF_FLAGS(%r12)
    jz .Ld_int3
    incl LF_RUN(%rbp)
    movl CFG_DEF_INTEG_SIZE(%r12), %esi
    testl %esi, %esi
    jz .Ld_int3
    movl CFG_DEF_INTEG_RVA(%r12), %edi
    addq %rbx, %rdi
    call .Ld_crc32
    movl %eax, LF_CRC(%rbp)
    cmpl CFG_DEF_INTEG_CRC(%r12), %eax
    je .Ld_int3
    orl $KDEF_INTEGRITY, LF_FLAGS(%rbp)

.Ld_int3:                            # ---- 断点扫描：连续 0xCC ----
    testl $KDEF_INT3SCAN, CFG_DEF_FLAGS(%r12)
    jz .Ld_inj
    incl LF_RUN(%rbp)
    movl CFG_DEF_INTEG_SIZE(%r12), %ecx
    testl %ecx, %ecx
    jz .Ld_inj
    movl CFG_DEF_INTEG_RVA(%r12), %esi
    addq %rbx, %rsi
.Ld_i3loop:
    cmpb $0xCC, (%rsi)
    jne .Ld_i3next
    cmpb $0xCC, 1(%rsi)
    je .Ld_i3hit
.Ld_i3next:
    incq %rsi
    decl %ecx
    jnz .Ld_i3loop
    jmp .Ld_inj
.Ld_i3hit:
    orl $KDEF_INT3SCAN, LF_FLAGS(%rbp)

.Ld_inj:                             # ---- 反注入：可执行私有页扫描 ----
    testl $KDEF_INJECT, CFG_DEF_FLAGS(%r12)
    jz .Ld_finish
    incl LF_RUN(%rbp)
    # 模块数（PEB Ldr InMemoryOrderModuleList 计数）
    movq %gs:0x60, %rax
    movq 0x18(%rax), %rax           # PEB->Ldr
    testq %rax, %rax
    jz .Ld_inj_vq
    leaq 0x20(%rax), %rcx           # InMemoryOrderModuleList 头
    movq (%rcx), %rdx
    xorl %r8d, %r8d
.Ld_modloop:
    cmpq %rcx, %rdx
    je .Ld_moddone
    incl %r8d
    cmpl $1024, %r8d
    jae .Ld_moddone
    movq (%rdx), %rdx
    jmp .Ld_modloop
.Ld_moddone:
    movl %r8d, LF_MODCNT(%rbp)
.Ld_inj_vq:
    # 页属性经 NtQueryVirtualMemory（直接 syscall）扫描——用户态 VirtualQuery 钩子无效
    leaq .Ld_s_ntdll(%rip), %rdi
    leaq .Ld_s_ntqvm(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_finish
    movq %rax, %r15
    movq %rax, %rsi
    call .Ld_ssn_of
    movl %eax, LF_SSN_QVM(%rbp)
    movq $0, LF_SCAN(%rbp)
.Ld_vq_loop:
    movq $-1, %rcx
    movq LF_SCAN(%rbp), %rdx
    xorl %r8d, %r8d
    leaq LF_MBI(%rbp), %r9
    subq $56, %rsp
    movl $48, 32(%rsp)
    leaq LF_TMPBUF(%rbp), %rax
    movq %rax, 40(%rsp)
    movl LF_SSN_QVM(%rbp), %eax
    call .Ld_ntcall
    addq $56, %rsp
    testl %eax, %eax
    jnz .Ld_finish
    movq LF_MBI+24(%rbp), %rax      # RegionSize
    testq %rax, %rax
    jz .Ld_finish
    cmpl $0x1000, LF_MBI+32(%rbp)   # MEM_COMMIT
    jne .Ld_vq_next
    cmpl $0x20000, LF_MBI+40(%rbp)  # MEM_PRIVATE
    jne .Ld_vq_next
    movl LF_MBI+36(%rbp), %ecx      # Protect
    andl $0xF0, %ecx                # 执行位
    jz .Ld_vq_next
    orl $KDEF_INJECT, LF_FLAGS(%rbp)
.Ld_vq_next:
    addq %rax, LF_SCAN(%rbp)
    movq LF_SCAN(%rbp), %rcx
    shrq $47, %rcx                  # 达用户态上限即止
    jz .Ld_vq_loop

.Ld_finish:                          # ---- 分级响应 ----
    # ---- 卸载 VEH（必须早于返回：句柄不得跨 stub 生命周期存活）----
    movq LF_VEHHDL(%rbp), %rcx
    testq %rcx, %rcx
    jz .Ld_veh_off
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_rmveh(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz .Ld_veh_off
    movq LF_VEHHDL(%rbp), %rcx
    call *%rax
.Ld_veh_off:

    movl LF_FLAGS(%rbp), %eax
    xorl %edx, %edx                 # 建议级别
    testl %eax, %eax
    jz .Ld_lv_done
    movl $LVL_WEAK, %edx
    testl $KDEF_FATAL, %eax
    jnz .Ld_lv3
    movl %eax, %ecx
    andl $KDEF_CRITICAL, %ecx
    jz .Ld_lv_done
    movl $LVL_DECOY, %edx
    # 强信号计数 >= 3 → 终局
    xorl %r8d, %r8d
.Ld_pc:
    testl %ecx, %ecx
    jz .Ld_pc_done
    movl %ecx, %r9d
    andl $1, %r9d
    addl %r9d, %r8d
    shrl $1, %ecx
    jmp .Ld_pc
.Ld_pc_done:
    cmpl $3, %r8d
    jb .Ld_lv_done
.Ld_lv3:
    movl $LVL_FATAL, %edx
.Ld_lv_done:
    # 策略门控：bit1 关闭则 2→1；bit2 关闭则 3→2
    cmpl $LVL_DECOY, %edx
    jne 1f
    testl $2, CFG_DEF_POLICY(%r12)
    jnz 2f
    movl $LVL_WEAK, %edx
    jmp 2f
1:  cmpl $LVL_FATAL, %edx
    jne 2f
    testl $4, CFG_DEF_POLICY(%r12)
    jnz 2f
    movl $LVL_DECOY, %edx
2:
    movl %edx, LF_LEVEL(%rbp)
    # 写报告
    movq LF_REPORT(%rbp), %rdi
    testq %rdi, %rdi
    jz 3f
    movl $DEF_REPORT_MAGIC, 0(%rdi)
    movl LF_FLAGS(%rbp), %eax
    movl %eax, 4(%rdi)
    movl LF_LEVEL(%rbp), %eax
    movl %eax, 8(%rdi)
    movl LF_RUN(%rbp), %eax
    movl %eax, 12(%rdi)
    movl LF_DELTA(%rbp), %eax
    movl %eax, 16(%rdi)
    movl LF_CRC(%rbp), %eax
    movl %eax, 20(%rdi)
    movl LF_MODCNT(%rbp), %eax
    movl %eax, 24(%rdi)
    movl LF_HBFAIL(%rbp), %eax
    movl %eax, 28(%rdi)
3:
    # 弱信号延迟（策略 bit0）
    cmpl $LVL_WEAK, %edx
    jne 4f
    testl $1, CFG_DEF_POLICY(%r12)
    jz 4f
    movl CFG_DEF_DELAY(%r12), %ecx
    testl %ecx, %ecx
    jz 4f
5:  pause
    decl %ecx
    jnz 5b
4:
    movl %edx, %eax
    movq %rbp, %rsp
    addq $LF_SIZE, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %rdi
    popq %rsi
    popq %rbx
    popq %rbp
    ret

# ================= 特权指令探针的故障容错 VEH =================
# LONG CALLBACK kbox_veh(PEXCEPTION_POINTERS p)   —— rcx = p
# 仅接管本 stub 两条特权探针（SIDT / IN）产生的
# STATUS_PRIVILEGED_INSTRUCTION(0xC0000096)：把探针结果置为「否」、将 RIP 指到
# 对应的 .Lveh_after_* 并返回 CONTINUE_EXECUTION；其余异常一律 CONTINUE_SEARCH
# 交回系统（VEH 先于 SEH 运行，故不会被 loader 的 SEH 抢走）。
# 仅使用易失寄存器，无需栈帧（Win64）。
.set VEH_CONTINUE_EXECUTION, -1
.set EXC_CODE_OFF, 0
.set EXC_ADDR_OFF, 16
.set CTX_RAX, 0x78
.set CTX_RBX, 0x90
.set CTX_RSP, 0x98
.set CTX_RIP, 0xF8

    .globl kbox_veh
    .type kbox_veh, @function
kbox_veh:
    testq %rcx, %rcx
    jz .Lveh_search
    movq 0(%rcx), %rax              # p->ExceptionRecord
    testq %rax, %rax
    jz .Lveh_search
    cmpl $0xC0000096, EXC_CODE_OFF(%rax)   # STATUS_PRIVILEGED_INSTRUCTION
    jne .Lveh_search
    movq 8(%rcx), %r9               # p->ContextRecord
    testq %r9, %r9
    jz .Lveh_search
    movq EXC_ADDR_OFF(%rax), %rdx   # ExceptionAddress = 故障指令地址
    leaq .Lveh_probe_sidt(%rip), %r8
    cmpq %r8, %rdx
    jne .Lveh_in
    movq CTX_RSP(%r9), %r10         # SIDT 目标缓冲在 [rsp]
    movq $0, 0(%r10)                # 10 字节清零 → IDT 基址高字节 = 0 ≠ 0xFF
    movw $0, 8(%r10)
    leaq .Lveh_after_sidt(%rip), %r8
    movq %r8, CTX_RIP(%r9)
    movq $VEH_CONTINUE_EXECUTION, %rax
    ret
.Lveh_in:
    leaq .Lveh_probe_in(%rip), %r8
    cmpq %r8, %rdx
    jne .Lveh_search
    movq $0, CTX_RAX(%r9)           # IN 结果置 0（ebx 之后由 LF_RBXSAVE 还原）
    movq $0, CTX_RBX(%r9)
    leaq .Lveh_after_in(%rip), %r8
    movq %r8, CTX_RIP(%r9)
    movq $VEH_CONTINUE_EXECUTION, %rax
    ret
.Lveh_search:
    xorl %eax, %eax                 # EXCEPTION_CONTINUE_SEARCH
    ret

# ---- 动态解析：rdi = DLL 名，rsi = 函数名 → rax = 地址（0 = 失败） ----
# 破坏 rax/rcx/rdx/r8-r11；保留其余。
# 方案D：解析成功即记录到 hook 扫描表（.Ld_iat 复用）。
.Ld_resolve:
    subq $40, %rsp
    movq %rsi, 32(%rsp)
    leaq kbox_iat(%rip), %rax
    movq 0(%rax), %r10              # LoadLibraryA
    movq %rdi, %rcx
    call *%r10
    testq %rax, %rax
    jz .Ld_res_fail
    movq %rax, %rcx
    movq 32(%rsp), %rdx
    leaq kbox_iat(%rip), %rax
    movq 8(%rax), %r10              # GetProcAddress
    call *%r10
    movl LF_HOOKCNT(%rbp), %r10d
    cmpl $LF_HOOKMAX, %r10d
    jae .Ld_res_done
    movq %rax, LF_HOOKTBL(%rbp,%r10,8)
    incl %r10d
    movl %r10d, LF_HOOKCNT(%rbp)
.Ld_res_done:
    addq $40, %rsp
    ret
.Ld_res_fail:
    xorl %eax, %eax
    addq $40, %rsp
    ret

# ---- 解析 ntdll 桩的系统调用号：rsi = 函数地址 → eax = SSN（0 = 不可用）----
# 校验标准 x64 桩：`4C 8B D1 | B8 <SSN> | 0F 05`（mov r10,rcx; mov eax,SSN; syscall）
.Ld_ssn_of:
    cmpb $0x4C, 0(%rsi)
    jne 1f
    cmpb $0x8B, 1(%rsi)
    jne 1f
    cmpb $0xD1, 2(%rsi)
    jne 1f
    cmpb $0xB8, 3(%rsi)
    jne 1f
    cmpb $0x0F, 8(%rsi)
    jne 1f
    cmpb $0x05, 9(%rsi)
    jne 1f
    movl 4(%rsi), %eax
    ret
1:  xorl %eax, %eax
    ret

# ---- 直接系统调用（绕过用户态 Nt* 钩子）----
# 入：eax = SSN（0 = 回退函数指针 r15）；rcx/rdx/r8/r9 + [rsp+0x20]/[rsp+0x28] = 参数
# 出：eax = NTSTATUS。调用方按 Win64 ABI 摆好 5/6 号参数（32/40(%rsp)）。
.Ld_ntcall:
    testl %eax, %eax
    jz 1f
    movq %rcx, %r10                 # syscall 破坏 rcx；arg1 移至 r10
    syscall
    ret
1:  jmp *%r15

# ---- GetCurrentProcess（带缓存）→ rax ----
# 本子程序自身被 call 进入（rsp≡8）；为满足嵌套调用的 16 字节对齐，先降 8。
.Ld_getcurp:
    subq $8, %rsp
    movq LF_CURP(%rbp), %rax
    testq %rax, %rax
    jnz 1f
    leaq .Ld_s_k32(%rip), %rdi
    leaq .Ld_s_gcurp(%rip), %rsi
    call .Ld_resolve
    testq %rax, %rax
    jz 1f
    call *%rax
    movq %rax, LF_CURP(%rbp)
1:  addq $8, %rsp
    ret

# ---- NtQueryInformationProcess 单次调用：r15 = 函数，r14d = class → eax=状态 ----
# 方案D：经 .Ld_ntcall 走直接 syscall（SSN 已解析）或回退函数指针。
.Ld_ntqip:
    movq $0, LF_TMPBUF(%rbp)
    leaq LF_TMPBUF(%rbp), %r8
    movq LF_CURP(%rbp), %rcx
    movl %r14d, %edx
    movl $8, %r9d
    subq $56, %rsp
    leaq LF_TMPBUF(%rbp), %rax
    movq %rax, 32(%rsp)
    movl LF_SSN_QIP(%rbp), %eax
    call .Ld_ntcall
    addq $56, %rsp
    ret

# ---- CRC32（IEEE，表无关）：rdi = 指针，esi = 长度 → eax ----
.Ld_crc32:
    movl $0xFFFFFFFF, %eax
    testl %esi, %esi
    jz 2f
1:  movzbl (%rdi), %ecx
    xorl %ecx, %eax
    movl $8, %edx
3:  movl %eax, %ecx
    andl $1, %ecx
    negl %ecx
    andl $0xEDB88320, %ecx
    shrl $1, %eax
    xorl %ecx, %eax
    decl %edx
    jnz 3b
    incq %rdi
    decl %esi
    jnz 1b
2:  notl %eax
    ret

# ---- 诱饵路径：写入标记后进入伪终止循环（真实产品可替换为伪造主流程） ----
    .globl kbox_decoy
    .type kbox_decoy, @function
kbox_decoy:
    pushq %rbp
    movq %rsp, %rbp
    pushq %rbx
    pushq %r12
    movl CFG_DEF_REPORT_RVA(%r12), %eax
    testl %eax, %eax
    jz 1f
    addq %rbx, %rax
    movl $DEF_DECOY_MARK, 32(%rax)      # report.reserved[0] = "DECO"
1:  popq %r12
    popq %rbx
    popq %rbp
.Ld_decoy_loop:
    jmp .Ld_decoy_loop

# ---- 防御用字符串常量（位于代码区，纳入完整性校验；G2 下随构建 XOR 加密） ----
    .globl kbox_strpool_start
kbox_strpool_start:
.Ld_s_k32:      .asciz "kernel32.dll"
.Ld_s_ntdll:    .asciz "ntdll.dll"
.Ld_s_isdbg:    .asciz "IsDebuggerPresent"
.Ld_s_cremote:  .asciz "CheckRemoteDebuggerPresent"
.Ld_s_ntqip:     .asciz "NtQueryInformationProcess"
.Ld_s_ntsit:     .asciz "NtSetInformationThread"
.Ld_s_gcurp:    .asciz "GetCurrentProcess"
.Ld_s_gcurt:    .asciz "GetCurrentThread"
.Ld_s_gtc:      .asciz "GetThreadContext"
.Ld_s_ntqvm:    .asciz "NtQueryVirtualMemory"
.Ld_s_addveh:   .asciz "AddVectoredExceptionHandler"
.Ld_s_rmveh:    .asciz "RemoveVectoredExceptionHandler"
    .globl kbox_defense_end
kbox_defense_end:

# ---- 方案E：每构建随机化填充区（packer 逐构建填充随机字节）----
# 该区位于 .text 末尾（不可达），使 stub native 代码区的「字节指纹」跨构建失效，
# 抵抗基于固定代码签名的样本比对/差分。
    .balign 16
    .globl kbox_junk_start
kbox_junk_start:
    .space 0x1800
    .globl kbox_junk_end
kbox_junk_end:

# ================= stub 自身 IAT（loader 回填） =================
# "aw" 标志：必须可分配，ld --oformat binary 才会平铺进 blob
    .section .iat,"aw",@progbits
    .balign 4096
# secA（代码，RX）/ secB（数据，RWX）切分点：packer 以该偏移拆节。
# 置于 .iat 起始（= 原 IAT 页），保证切分点与页边界一致。
    .globl kbox_code_end
kbox_code_end:
# ---- 布局保护页（不可达填充）----
# 实测：若 stub 自身 IAT 恰好落在镜像 RVA 0x6000（= stub_rva + 0x5000），
# Windows loader 不会把解析后的 API 地址写入该页——页本身可写、同页其它内容
# 也未被清零（可见文件原值），但 IAT 槽恒为 0，导致 stub 首条取指针即得空值
# 并跳入 .Ldead。故在此插入一整页，把 .iat 顶到 0x6000（RVA 0x7000），实测正常。
    .space 0x1000
    .balign 4096
    .globl kbox_iat
kbox_iat:
    .space 24           # 3 × 8 字节：LoadLibraryA / GetProcAddress / VirtualProtect

    .section .note.GNU-stack,"",@progbits
