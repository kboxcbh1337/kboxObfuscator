# stub_x86.S — kboXShield 解壳 Stub（IA-32, PE32）
#
# 布局契约与 include/kbox_format.h 一一对应（.equ 常量须与其保持一致）。
# 该文件被汇编为 ELF32 目标文件后经 ld 平铺为二进制 blob（VMA 从 0 起），
# 因此所有跨段引用都必须是位置无关的（基址 + 立即偏移）。
#
# blob 布局（与 x64 版一致）：
#   [0x000 .. 0x100)  KboxConfig（packer 填充）
#   [0x100 ...]       入口代码与数据
#   [....  ]          .iat 段（loader 回填 stub 自身 IAT，3 × 4 字节）
#
# 寄存器/栈约定（所有 API 调用期间被调方保留 ebx/esi/edi/ebp）：
#   ebx = config 运行时地址（= base + stub_rva，blob 偏移 0）
#   ebp = 帧指针；局部变量全部存 [ebp-4 .. ebp-96]
#   [ebp-4]   payload 基址（解密后）
#   [ebp-8]   VirtualProtect
#   [ebp-12]  LoadLibraryA
#   [ebp-16]  GetProcAddress
#   [ebp-20]  模块基址
#   [ebp-24]  循环：剩余节数 / 剩余 DLL 数
#   [ebp-28]  循环：节记录指针 / DLL 描述符指针
#   [ebp-32]  临时（oldprot 槽 / hLib）
#   [ebp-36]  循环：导入条目剩余数
#   [ebp-40]  循环：IAT 写入地址
#   [ebp-44]  循环：条目指针
#   [ebp-48]  reloc delta
#   [ebp-52]  当前 reloc 块 SizeOfBlock
#   [ebp-56]  reloc 剩余字节数
#   [ebp-60]  恢复权限 oldprot 槽
#
# 运行期流程（与 x64 版一致）：
#   取基址 -> 校验 magic -> VM 自检（运行期汇编引擎）-> 取 API(IAT)
#   -> 解密 payload -> 校验 payload magic -> 逐个解密原始节 -> 重建 IAT
#   -> 应用重定位 -> 恢复节权限 -> 跳 OEP

    .code32
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
# 运行期防御 / TLS 回调（Batch 5/6，同步 kbox_format.h）
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
.set CFG_DEF_RES0,        144    # G2：字符串池 XOR 键
.set CFG_EP_PATCH,        148    # 入口 trampoline 原始字节（u32@0x94 + u8@0x98）
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
.set VM_FLAG_PRESENT, 0x1

# ================= ChaCha20 四分之一轮宏 =================
# 操作 [ebx+\a..d]（work 状态缓冲区）；临时用 eax/ecx/edx/esi
.macro QR a, b, c, d
    movl \a(%ebx), %eax
    movl \b(%ebx), %ecx
    movl \d(%ebx), %edx          # %edx 承担 d 角色
    movl \c(%ebx), %esi          # %esi 承担 c 角色
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
    movl %eax, \a(%ebx)
    movl %ecx, \b(%ebx)
    movl %edx, \d(%ebx)
    movl %esi, \c(%ebx)
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

# 生成一个块：work = orig；counter 从 kbox_chacha 栈槽 148(%esp) 读
.macro BLOCK_GEN
    leal 64(%ebx), %esi
    movl 0(%esi), %eax;  movl %eax, 0(%ebx)
    movl 4(%esi), %eax;  movl %eax, 4(%ebx)
    movl 8(%esi), %eax;  movl %eax, 8(%ebx)
    movl 12(%esi), %eax; movl %eax, 12(%ebx)
    movl 16(%esi), %eax; movl %eax, 16(%ebx)
    movl 20(%esi), %eax; movl %eax, 20(%ebx)
    movl 24(%esi), %eax; movl %eax, 24(%ebx)
    movl 28(%esi), %eax; movl %eax, 28(%ebx)
    movl 32(%esi), %eax; movl %eax, 32(%ebx)
    movl 36(%esi), %eax; movl %eax, 36(%ebx)
    movl 40(%esi), %eax; movl %eax, 40(%ebx)
    movl 44(%esi), %eax; movl %eax, 44(%ebx)
    movl 148(%esp), %eax
    movl %eax, 48(%ebx)          # counter
    movl %eax, 112(%ebx)         # orig[12] 同步为该块计数（最终 work+orig 需要）
    movl 52(%esi), %eax; movl %eax, 52(%ebx)
    movl 56(%esi), %eax; movl %eax, 56(%ebx)
    movl 60(%esi), %eax; movl %eax, 60(%ebx)
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
    pushl %ebp
    movl %esp, %ebp
    subl $96, %esp               # 局部变量区（[ebp-4..-96]）
    call .Lgetbase
.Lgetbase:
    popl %eax                    # eax = .Lgetbase 运行时地址
    .set LGETBASE_OFF, (.Lgetbase - kbox_entry) + 0x100
    subl $LGETBASE_OFF, %eax     # eax = config 运行时地址（= base + stub_rva）
    movl %eax, %ebx              # ebx = config（跨调用保留）

    # ---- 二次进入检测（DLL 特有）----
    # loader 对 DLL 入口点的调用不止一次：DLL_PROCESS_ATTACH 之后，
    # DLL_THREAD_ATTACH / DLL_PROCESS_DETACH（进程退出）都会再次 call 同一入口
    # 地址。stub 非幂等（配置区解密），二次进入会把**明文**配置再解一遍 →
    # CFG_MAGIC 失配 → .Ldead 死循环，表现为 LoadLibrary 正常返回、进程退出时
    # 永久挂起。判据：配置区已解密（magic+version 合法，首次为密文，误判 2^-64）
    # 且 hinstDLL(8(%ebp)) + stub_rva 恰等于配置区运行时地址。
    cmpl $KBOX_MAGIC_VAL, CFG_MAGIC(%ebx)
    jne .Lcr_first_entry
    cmpl $1, CFG_VERSION(%ebx)
    jne .Lcr_first_entry
    movl CFG_STUB_RVA(%ebx), %eax
    addl 8(%ebp), %eax           # 8(%ebp) = hinstDLL = 模块基址
    cmpl %ebx, %eax
    jne .Lcr_first_entry
    movl 8(%ebp), %eax
    movl %eax, -20(%ebp)         # 模块基址
    movl CFG_OEP_RVA(%ebx), %eax
    addl -20(%ebp), %eax
    leave                        # 与尾部跳 OEP 相同的还原序列
    jmp *%eax

.Lcr_first_entry:
    # ---- 方案D：stub 代码节文件态 RX；入口先置 RWX 以便就地解密配置 ----
    # 注：IAT 位于独立 RW 节（loader 回填）；此处经 kbox_iat 取 VirtualProtect。
    leal kbox_iat(%ebx), %eax
    movl 4*IAT_VIRTUALPROTECT(%eax), %ecx
    testl %ecx, %ecx
    jz .Ldead
    leal -32(%ebp), %edx              # &old（临时 oldprot 槽）
    pushl %edx
    pushl $PAGE_EXECUTE_READWRITE
    pushl $0x1000
    pushl %ebx                        # lpAddress = config（stub 代码节起始）
    call *%ecx                        # stdcall：被调方清 16 字节
    movl %ebx, %eax                   # 恢复 config 地址（call 已破坏 eax）
    # ---- 方案A：配置区解密（每构建随机 LCG 流密钥，种子取自 kbox_cfg_root）----
    # 配置区 [0,0x100) 在文件中为密文；此处就地还原，之后才可读 stub_rva 等字段。
    leal kbox_cfg_root(%ebx), %esi
    movl (%esi), %esi
    movl %ebx, %edi
    movl $256, %ecx
.Lcr_cfg_loop:
    imull $1664525, %esi, %esi
    addl $1013904223, %esi
    movl %esi, %edx
    shrl $16, %edx
    xorb %dl, (%edi)
    incl %edi
    decl %ecx
    jnz .Lcr_cfg_loop
    movl CFG_STUB_RVA(%ebx), %ecx
    subl %ecx, %eax
    movl %eax, -20(%ebp)         # 模块基址
    cmpl $KBOX_MAGIC_VAL, CFG_MAGIC(%ebx)
    jne .Ldead
    # ---- 方案D：整个 stub 代码节置 RWX（字符串池就地解码等运行期写入）----
    leal kbox_iat(%ebx), %eax
    movl 4*IAT_VIRTUALPROTECT(%eax), %ecx
    testl %ecx, %ecx
    jz .Ldead
    leal -32(%ebp), %edx
    pushl %edx
    pushl $PAGE_EXECUTE_READWRITE
    pushl $STUB_A_LEN
    pushl %ebx
    call *%ecx

    # ---- G2 原生层多态：防御字符串池就地解码（XOR） ----
    # packer 以每构建随机键加密 blob 内字符串池 [kbox_strpool_start, kbox_defense_end)；
    # 此处先行还原，使后续 API 解析/防御检查使用明文；因还原后与打包资产一致，
    # 完整性 CRC（覆盖同一区间）仍成立。
    movl CFG_DEF_RES0(%ebx), %eax
    testl %eax, %eax
    jz .Lcr_str_ok
    movl %eax, %edx
    leal kbox_strpool_start(%ebx), %edi
    leal kbox_defense_end(%ebx), %esi
    subl %edi, %esi
.Lcr_str_loop:
    xorb %dl, (%edi)
    incl %edi
    decl %esi
    jnz .Lcr_str_loop
.Lcr_str_ok:

    # ---- 运行期防御（第 5 项）：检测体系 + 分级响应 ----
    movl -20(%ebp), %esi
    call kbox_defense
    cmpl $LVL_FATAL, %eax
    jae .Ldead                      # 敌对：直接终止
    cmpl $LVL_DECOY, %eax
    je .Ldecoy_path                 # 确认被调试/篡改：转诱饵路径

    # ---- VM 自检（运行期汇编引擎）----
    # 逐个虚拟化镜像：以 rec->self_in 为输入执行该镜像，结果须等于打包期
    # 预演的 rec->self_expect；任何一项不符即说明引擎/镜像被篡改，直接死锁。
    # 引擎接口（cdecl）：image / image_size / gprs / ks_fn；
    # 返回 eax = 状态码（0 = VM_OK），edx = VM 结果。
    # gprs 为 16 × u64 机器寄存器块，本处仅填 rax（= VM 输入约定 frame[0]）。
    testl $VM_FLAG_PRESENT, CFG_VM_FLAGS(%ebx)
    jz .Lvm_skip
    movl CFG_VM_COUNT(%ebx), %eax
    testl %eax, %eax
    jz .Lvm_skip
    movl %eax, -8(%ebp)             # 镜像数
    movl $0, -4(%ebp)               # 记录下标
    movl CFG_VM_RECS_RVA(%ebx), %eax
    addl -20(%ebp), %eax
    movl %eax, -12(%ebp)            # KboxVmRec 数组基址
.Lvm_loop:
    movl -4(%ebp), %eax
    imull $VMR_SIZE, %eax
    addl -12(%ebp), %eax
    movl %eax, -16(%ebp)            # 当前记录指针
    subl $128, %esp                 # gprs 块
    movl %esp, %edi
    xorl %eax, %eax
    movl $32, %ecx
    rep stosl                       # 清零 gprs 块
    movl -16(%ebp), %eax
    movl VMR_SELF_IN(%eax), %eax
    movl %eax, 0(%esp)              # gprs[RAX].lo
    movl $0, 4(%esp)                # gprs[RAX].hi
    movl %esp, %esi                 # gprs 基址（压参不影响）
    # ks_fn = kbox_chacha 运行时地址（call-pop 取当前 IP 后加静态偏移）
    call .Lvm_getip
.Lvm_getip:
    popl %eax
    addl $(kbox_chacha - .Lvm_getip), %eax
    pushl %eax                      # ks_fn
    pushl %esi                      # gprs
    movl -16(%ebp), %eax
    movl VMR_IMAGE_SIZE(%eax), %eax
    pushl %eax                      # image_size
    movl -16(%ebp), %eax
    movl VMR_IMAGE_RVA(%eax), %eax
    addl -20(%ebp), %eax
    pushl %eax                      # image
    movl CFG_VM_ENGINE_RVA(%ebx), %eax
    addl -20(%ebp), %eax            # eax = 引擎入口
    call *%eax
    addl $16, %esp
    addl $128, %esp
    testl %eax, %eax
    jnz .Lvm_fail
    movl -16(%ebp), %eax
    cmpl VMR_SELF_EXPECT(%eax), %edx
    jne .Lvm_fail
    incl -4(%ebp)
    movl -4(%ebp), %eax
    cmpl -8(%ebp), %eax
    jb .Lvm_loop
    jmp .Lvm_skip
.Lvm_fail:
    jmp .Ldead
.Lvm_skip:

    # ---- 取 stub 自身 API（loader 已回填 kbox_iat）----
    leal kbox_iat(%ebx), %eax
    movl 4*IAT_LOADLIBRARYA(%eax), %ecx
    movl 4*IAT_GETPROCADDRESS(%eax), %edx
    movl 4*IAT_VIRTUALPROTECT(%eax), %esi
    testl %ecx, %ecx
    jz .Ldead
    testl %edx, %edx
    jz .Ldead
    testl %esi, %esi
    jz .Ldead
    movl %ecx, -12(%ebp)         # LoadLibraryA
    movl %edx, -16(%ebp)         # GetProcAddress
    movl %esi, -8(%ebp)          # VirtualProtect

    # ---- 解密 payload（stub 节内，RWX，直接原地解密）----
    movl CFG_PAY_RVA(%ebx), %eax
    addl -20(%ebp), %eax
    movl CFG_PAY_SIZE(%ebx), %edx
    leal CFG_KEY(%ebx), %ecx
    leal CFG_NONCE(%ebx), %esi
    xorl %edi, %edi              # counter = 0
    call kbox_chacha

    movl CFG_PAY_RVA(%ebx), %eax
    addl -20(%ebp), %eax
    movl %eax, -4(%ebp)          # payload 基址（解密后）
    cmpl $PAYLOAD_MAGIC_VAL, PAY_MAGIC(%eax)
    jne .Ldead

    # ---- 逐个解密原始节 ----
    movl -4(%ebp), %eax
    movl PAY_SECTION_CNT(%eax), %eax
    testl %eax, %eax
    jz .Lno_sections
    movl %eax, -24(%ebp)         # 剩余节数
    movl -4(%ebp), %eax
    addl $PAY_HDR_SIZE, %eax
    movl %eax, -28(%ebp)         # 节记录指针
.Lsec_loop:
    movl -28(%ebp), %ecx
    movl REC_FLAGS(%ecx), %eax
    testl $PAYLOAD_FLAG_SKIP_DECRYPT, %eax
    jnz .Lsec_next
    # VirtualProtect(addr, size, PAGE_EXECUTE_READWRITE, &old)
    movl REC_RVA(%ecx), %eax
    addl -20(%ebp), %eax
    movl REC_RAWSIZE(%ecx), %edx
    leal -32(%ebp), %ecx
    pushl %ecx                   # &old
    pushl $PAGE_EXECUTE_READWRITE
    pushl %edx                   # size
    pushl %eax                   # addr
    call *-8(%ebp)               # VirtualProtect (stdcall, callee 清栈)
    # kbox_chacha(buf, len, key, nonce, counter)
    movl -28(%ebp), %eax
    movl REC_RVA(%eax), %ecx
    addl -20(%ebp), %ecx
    movl %ecx, %eax              # buf
    movl -28(%ebp), %ecx
    movl REC_RAWSIZE(%ecx), %edx # len
    movl REC_BLOCK(%ecx), %edi   # counter
    leal REC_NONCE(%ecx), %esi   # nonce
    leal CFG_KEY(%ebx), %ecx     # key
    call kbox_chacha
.Lsec_next:
    addl $REC_SIZE, -28(%ebp)
    decl -24(%ebp)
    jnz .Lsec_loop
.Lno_sections:

    # ---- 重建 IAT（此时各节仍为 RWX，可直接写入；指针宽度 4）----
    movl -4(%ebp), %eax
    movl PAY_IMP_DLL_CNT(%eax), %eax
    testl %eax, %eax
    jz .Lno_imports
    movl %eax, -24(%ebp)         # 剩余 DLL 数
    movl -4(%ebp), %eax
    movl PAY_SECTION_CNT(%eax), %eax
    imull $REC_SIZE, %eax
    movl -4(%ebp), %ecx
    addl $PAY_HDR_SIZE, %ecx
    addl %ecx, %eax
    movl %eax, -28(%ebp)         # DLL 描述符指针
.Limp_dll_loop:
    movl -28(%ebp), %ecx
    movl DLL_NAME_RVA(%ecx), %eax
    addl -20(%ebp), %eax
    pushl %eax                   # LoadLibraryA(name)
    call *-12(%ebp)
    movl %eax, -32(%ebp)         # hLib
    testl %eax, %eax
    jz .Limp_dll_next
    movl -28(%ebp), %ecx
    movl DLL_COUNT(%ecx), %eax
    movl %eax, -36(%ebp)         # 条目剩余数
    movl DLL_IAT_RVA(%ecx), %eax
    addl -20(%ebp), %eax
    movl %eax, -40(%ebp)         # IAT 写入地址
    leal DLL_SIZE(%ecx), %eax
    movl %eax, -44(%ebp)         # 条目指针
.Limp_entry_loop:
    movl -36(%ebp), %eax
    testl %eax, %eax
    jz .Limp_dll_next
    movl -44(%ebp), %ecx
    movzwl ENT_ORD(%ecx), %eax
    testl %eax, %eax
    jz .Limp_by_name
    pushl %eax                   # 按序号：MAKEINTRESOURCE(ordinal)
    jmp .Limp_gpa
.Limp_by_name:
    movl ENT_NAME(%ecx), %eax
    addl -20(%ebp), %eax
    pushl %eax
.Limp_gpa:
    pushl -32(%ebp)              # hLib
    call *-16(%ebp)              # GetProcAddress
    testl %eax, %eax
    jz .Limp_entry_next
    movl -40(%ebp), %ecx
    movl %eax, 0(%ecx)           # *(u32*)iat = proc
.Limp_entry_next:
    addl $ENT_SIZE, -44(%ebp)
    addl $4, -40(%ebp)
    decl -36(%ebp)
    jmp .Limp_entry_loop
.Limp_dll_next:
    movl -28(%ebp), %ecx
    movl DLL_COUNT(%ecx), %eax
    imull $ENT_SIZE, %eax
    addl $DLL_SIZE, %eax
    addl %eax, -28(%ebp)
    decl -24(%ebp)
    jnz .Limp_dll_loop
.Lno_imports:

    # ---- 应用重定位（仅当 base != ImageBase；x86 仅 HIGHLOW）----
    movl -20(%ebp), %edx
    subl CFG_IMG_LO(%ebx), %edx  # delta
    jz .Lno_reloc
    movl -4(%ebp), %eax
    movl PAY_RELOC_SIZE(%eax), %eax
    movl %eax, -56(%ebp)         # 剩余字节
    testl %eax, %eax
    jz .Lno_reloc
    movl %edx, -48(%ebp)         # 保存 delta
    # 定位 reloc 数据：节记录之后 -> 跳过所有 DLL 记录
    movl -4(%ebp), %eax
    movl PAY_SECTION_CNT(%eax), %eax
    imull $REC_SIZE, %eax
    movl -4(%ebp), %esi
    addl $PAY_HDR_SIZE, %esi
    addl %eax, %esi
    movl -4(%ebp), %edi
    movl PAY_IMP_DLL_CNT(%edi), %edi
.Lreloc_imp_walk:
    testl %edi, %edi
    jz .Lreloc_imp_done
    movl DLL_COUNT(%esi), %eax
    imull $ENT_SIZE, %eax
    addl $DLL_SIZE, %eax
    addl %eax, %esi
    decl %edi
    jmp .Lreloc_imp_walk
.Lreloc_imp_done:
    # %esi = reloc 数据
.Lreloc_loop:
    movl -56(%ebp), %eax
    testl %eax, %eax
    jz .Lreloc_done
    movl 0(%esi), %eax           # 块 VirtualAddress
    movl 4(%esi), %ecx           # SizeOfBlock
    movl %ecx, -52(%ebp)
    addl $8, %esi
    subl $8, %ecx
    shrl $1, %ecx                # 条目数
.Lreloc_entry:
    testl %ecx, %ecx
    jz .Lreloc_block_done
    movzwl 0(%esi), %edx
    movl %edx, %edi
    shrl $12, %edi               # type
    andl $0xFFF, %edx            # offset
    addl %eax, %edx              # rva
    cmpl $RELOC_HIGHLOW, %edi
    jne .Lreloc_entry_next
    movl %edx, %edi              # addr = base + rva
    addl -20(%ebp), %edi
    movl -48(%ebp), %edx         # delta
    addl %edx, 0(%edi)           # *(u32*)addr += delta
.Lreloc_entry_next:
    addl $2, %esi
    decl %ecx
    jmp .Lreloc_entry
.Lreloc_block_done:
    movl -52(%ebp), %eax
    subl %eax, -56(%ebp)
    jmp .Lreloc_loop
.Lreloc_done:
.Lno_reloc:

    # ---- 入口 trampoline 字节还原 ----
    # 与 x64 侧一致：把配置区 CFG_EP_PATCH 保存的原始 5 字节写回入口点，
    # 时机在恢复节权限前（各节仍为 RWX，可写）。
    movl CFG_EP_PATCH(%ebx), %eax
    movl CFG_OEP_RVA(%ebx), %ecx
    addl -20(%ebp), %ecx
    movb %al, 0(%ecx)
    shrl $8, %eax
    movb %al, 1(%ecx)
    shrl $8, %eax
    movb %al, 2(%ecx)
    shrl $8, %eax
    movb %al, 3(%ecx)
    movl CFG_EP_PATCH+4(%ebx), %eax
    movb %al, 4(%ecx)

    # ---- 恢复各节权限 ----
    movl -4(%ebp), %eax
    movl PAY_SECTION_CNT(%eax), %eax
    testl %eax, %eax
    jz .Lno_restore
    movl %eax, -24(%ebp)
    movl -4(%ebp), %eax
    addl $PAY_HDR_SIZE, %eax
    movl %eax, -28(%ebp)
.Lrest_loop:
    movl -28(%ebp), %ecx
    movl REC_RVA(%ecx), %eax
    addl -20(%ebp), %eax
    movl REC_RAWSIZE(%ecx), %edx
    movl REC_PERMS(%ecx), %esi
    leal -60(%ebp), %ecx
    pushl %ecx                   # &old
    pushl %esi                   # perms
    pushl %edx                   # size
    pushl %eax                   # addr
    call *-8(%ebp)               # VirtualProtect
    addl $REC_SIZE, -28(%ebp)
    decl -24(%ebp)
    jnz .Lrest_loop
.Lno_restore:

    # ---- TLS 回调（第 6 项）----
    # DIR_TLS 已被清零，loader 不会调用 TLS 回调；此处按原回调表代跑一次
    # （hinst = 模块基址，reason = DLL_PROCESS_ATTACH(1)，reserved = 0）。
    movl CFG_TLS_CB_COUNT(%ebx), %ecx
    testl %ecx, %ecx
    jz .Lno_tls
    movl CFG_TLS_CB_RVA(%ebx), %esi
    testl %esi, %esi
    jz .Lno_tls
    addl -20(%ebp), %esi            # 回调 RVA 数组基址
.Ltls_loop:
    movl 0(%esi), %eax
    testl %eax, %eax
    jz .Lno_tls
    addl -20(%ebp), %eax            # 回调 VA
    pushl $0                        # reserved
    pushl $1                        # DLL_PROCESS_ATTACH
    pushl -20(%ebp)                 # hinst
    call *%eax                      # stdcall：被调方清理 12 字节参数
    addl $4, %esi
    decl %ecx
    jnz .Ltls_loop
.Lno_tls:

    # ---- 方案D：stub 代码节恢复只读（RX） ----
    leal kbox_iat(%ebx), %eax
    movl 4*IAT_VIRTUALPROTECT(%eax), %ecx
    testl %ecx, %ecx
    jz .Ldead
    leal -60(%ebp), %edx              # &old（复用恢复权限 oldprot 槽）
    pushl %edx
    pushl $PAGE_EXECUTE_READ
    pushl $STUB_A_LEN
    pushl %ebx
    call *%ecx
    # ---- 跳转 OEP ----
    movl CFG_OEP_RVA(%ebx), %eax
    addl -20(%ebp), %eax
    leave                          # 还原 esp/ebp，OEP 期望入口栈布局
    jmp *%eax

.Ldead:
    jmp .Ldead

# 诱饵路径（可观测：kbox_decoy 写 DECO 标记后进入伪终止循环）
.Ldecoy_path:
    movl -20(%ebp), %esi
    call kbox_decoy
    jmp .Ldead

# ================= 运行期防御（第 5 项）——x86 =================
# 与 stub_x64.S 的 kbox_defense 语义一致：检测体系（三层反调试 / 反注入 /
# 完整性 / 反 VM / 反 hook）+ 分级响应，结果写入 KboxDefenseReport。
#   入：ebx = config，esi = 模块基址
#   出：eax = 响应级别（0 继续 / 1 弱信号已延迟 / 2 诱饵 / 3 终止）
#   保留 ebx/esi/edi/ebp（Win32 ABI）。
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

.set LF_CFG,    -4
.set LF_BASE,   -8
.set LF_FLAGS,  -12
.set LF_RUN,    -16
.set LF_LEVEL,  -20
.set LF_HBFAIL, -24
.set LF_DELTA,  -28
.set LF_CRC,    -32
.set LF_MODCNT, -36
.set LF_SCAN,   -40
.set LF_REPORT, -44
.set LF_CURP,   -48
.set LF_CURT,   -52
.set LF_PFN,    -56
.set LF_CLASS,  -60
.set LF_TMPBUF, -72
.set LF_MBI,    -128
.set LF_CTX,    -0x500
# 方案D：直接系统调用 SSN 缓存 + hook 扫描表
.set LF_SSN_QIP,  -0x504  # NtQueryInformationProcess 系统调用号（0 = 不可用）
.set LF_SSN_TSIT, -0x508  # NtSetInformationThread 系统调用号
.set LF_SSN_QVM,  -0x50C  # NtQueryVirtualMemory 系统调用号
.set LF_HOOKTBL,  -0x510  # hook 扫描表（24 × 4B，防御解析 API 地址）
.set LF_HOOKCNT,  -0x570  # 表内条目数
.set LF_VEHADD,   -0x574  # AddVectoredExceptionHandler 地址（0 = 不可用）
.set LF_VEHHDL,   -0x578  # VEH 句柄
.set LF_HOOKMAX,  24
.set LF_SIZE,     0x590

# ---- 方案A：配置区加密种子（每构建随机；packer 填充低 4 字节）----
    .balign 8
    .globl kbox_cfg_root
kbox_cfg_root:
    .space 8

    .globl kbox_defense
    .type kbox_defense, @function
kbox_defense:
    pushl %ebp
    movl %esp, %ebp
    subl $LF_SIZE, %esp
    movl %ebx, LF_CFG(%ebp)
    movl %esi, LF_BASE(%ebp)
    movl $0, LF_FLAGS(%ebp)
    movl $0, LF_RUN(%ebp)
    movl $0, LF_HBFAIL(%ebp)
    movl $0, LF_DELTA(%ebp)
    movl $0, LF_CRC(%ebp)
    movl $0, LF_MODCNT(%ebp)
    movl $0, LF_CURP(%ebp)
    movl $0, LF_CURT(%ebp)
    movl $0, LF_HOOKCNT(%ebp)
    movl $0, LF_VEHADD(%ebp)
    movl $0, LF_VEHHDL(%ebp)
    movl CFG_DEF_REPORT_RVA(%ebx), %eax
    testl %eax, %eax
    jz 1f
    addl LF_BASE(%ebp), %eax
1:  movl %eax, LF_REPORT(%ebp)

    # ---- 特权指令探针的容错前置：安装 VEH ----
    # SIDT 在现代 Windows（CR4.UMIP=1，VBS/HVCI 默认开启）与 VMware 后门 IN 都是
    # CPL3 下的 #GP（STATUS_PRIVILEGED_INSTRUCTION）。裸执行会让进程直接死亡，
    # 而 stub 位于裸代码节、没有 .pdata/SEH 帧可挂。故此处先注册顶层 Vectored
    # Exception Handler（VEH 在 SEH 之前运行），由它把探针故障转为「结果为否」并
    # 继续执行。注册失败则跳过全部特权探针。
    testl $(KDEF_SIDT|KDEF_VMWARE), CFG_DEF_FLAGS(%ebx)
    jz .Lcr_veh_done
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_addveh(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_veh_done
    movl %eax, LF_VEHADD(%ebp)
    leal kbox_veh(%ebx), %eax
    pushl %eax                       # Handler
    pushl $1                         # First = 1（置于链首）
    call *LF_VEHADD(%ebp)            # stdcall，清 8
    movl %eax, LF_VEHHDL(%ebp)
.Lcr_veh_done:

    # ---- L1 反调试：PEB.BeingDebugged ----
    testl $KDEF_PEB_DEBUG, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_ntgf
    incl LF_RUN(%ebp)
    movl %fs:0x30, %eax
    cmpb $0, 2(%eax)
    je .Lcr_ntgf
    orl $KDEF_PEB_DEBUG, LF_FLAGS(%ebp)

.Lcr_ntgf:                           # ---- L1 反调试：PEB.NtGlobalFlag ----
    testl $KDEF_NTGLOBALFLAG, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_heap
    incl LF_RUN(%ebp)
    movl %fs:0x30, %eax
    movl 0x68(%eax), %eax
    testl %eax, %eax
    jz .Lcr_heap
    orl $KDEF_NTGLOBALFLAG, LF_FLAGS(%ebp)

.Lcr_heap:                           # ---- L1 反调试：堆 Flags/ForceFlags ----
    testl $KDEF_HEAPFLAGS, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_isdbg
    incl LF_RUN(%ebp)
    movl %fs:0x30, %eax
    movl 0x18(%eax), %eax            # ProcessHeap
    testl %eax, %eax
    jz .Lcr_isdbg
    movl 0x10(%eax), %ecx            # ForceFlags
    testl %ecx, %ecx
    jnz .Lcr_heap_hit
    movl 0x0C(%eax), %ecx            # Flags（正常为 2）
    andl $-3, %ecx
    jz .Lcr_isdbg
.Lcr_heap_hit:
    orl $KDEF_HEAPFLAGS, LF_FLAGS(%ebp)

.Lcr_isdbg:                          # ---- L2 反调试：IsDebuggerPresent ----
    testl $KDEF_ISDEBUGGER, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_remote
    incl LF_RUN(%ebp)
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_isdbg(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_isdbg_fail
    call *%eax
    testl %eax, %eax
    jz .Lcr_remote
    orl $KDEF_ISDEBUGGER, LF_FLAGS(%ebp)
    jmp .Lcr_remote
.Lcr_isdbg_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_remote:                         # ---- L2 反调试：CheckRemoteDebuggerPresent ----
    testl $KDEF_REMOTEDEBUG, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_port
    incl LF_RUN(%ebp)
    call .Lcr_getcurp
    testl %eax, %eax
    jz .Lcr_remote_fail
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_cremote(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_remote_fail
    movl %eax, LF_PFN(%ebp)
    movl $0, LF_TMPBUF(%ebp)
    leal LF_TMPBUF(%ebp), %eax
    pushl %eax                       # &b
    pushl LF_CURP(%ebp)              # hProcess
    call *LF_PFN(%ebp)
    testl %eax, %eax
    jz .Lcr_port
    cmpl $0, LF_TMPBUF(%ebp)
    je .Lcr_port
    orl $KDEF_REMOTEDEBUG, LF_FLAGS(%ebp)
    jmp .Lcr_port
.Lcr_remote_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_port:                           # ---- L2 反调试：NtQueryInformationProcess ----
    testl $KDEF_PORTPROC, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_thrhide
    incl LF_RUN(%ebp)
    call .Lcr_getcurp
    testl %eax, %eax
    jz .Lcr_port_fail
    leal .Lcr_s_ntdll(%ebx), %edi
    leal .Lcr_s_ntqip(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_port_fail
    movl %eax, LF_PFN(%ebp)
    movl %eax, %esi
    call .Lcr_ssn_of
    movl %eax, LF_SSN_QIP(%ebp)      # SSN（0 = 回退函数指针）
    movl $7, LF_CLASS(%ebp)          # ProcessDebugPort
    call .Lcr_ntqip
    testl %eax, %eax
    jnz .Lcr_port_fail
    cmpl $0, LF_TMPBUF(%ebp)
    jne .Lcr_port_hit
    movl $0x1E, LF_CLASS(%ebp)       # ProcessDebugObjectHandle
    call .Lcr_ntqip
    testl %eax, %eax
    jnz .Lcr_port_fail
    cmpl $0, LF_TMPBUF(%ebp)
    jne .Lcr_port_hit
    movl $0x1F, LF_CLASS(%ebp)       # ProcessDebugFlags（0 = 被调试）
    call .Lcr_ntqip
    testl %eax, %eax
    jnz .Lcr_port_fail
    cmpl $0, LF_TMPBUF(%ebp)
    jne .Lcr_thrhide
.Lcr_port_hit:
    orl $KDEF_PORTPROC, LF_FLAGS(%ebp)
    jmp .Lcr_hwbp
.Lcr_port_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_thrhide:                        # ---- L2 反调试：NtSetInformationThread 失败 ----
    testl $KDEF_THREAD_HIDE, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_hwbp
    incl LF_RUN(%ebp)
    leal .Lcr_s_ntdll(%ebx), %edi
    leal .Lcr_s_ntsit(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_thr_fail
    movl %eax, LF_PFN(%ebp)
    movl %eax, %esi
    call .Lcr_ssn_of
    movl %eax, LF_SSN_TSIT(%ebp)
    pushl $0                         # ThreadInformationLength
    pushl $0                         # ThreadInformation
    pushl $0x11                      # ThreadHideFromDebugger
    pushl $-2                        # NtCurrentThread（伪句柄）
    movl LF_SSN_TSIT(%ebp), %eax
    call .Lcr_ntcall_tsit            # 直接 sysenter 或 jmp *LF_PFN
    testl %eax, %eax                 # 非 STATUS_SUCCESS -> 被拦截/异常
    jz .Lcr_hwbp
    orl $KDEF_THREAD_HIDE, LF_FLAGS(%ebp)
    jmp .Lcr_hwbp
.Lcr_thr_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_hwbp:                           # ---- L3 反调试：硬件断点（Dr0-3） ----
    testl $KDEF_HWBP, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_timing
    incl LF_RUN(%ebp)
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_gcurt(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_hwbp_fail
    call *%eax
    movl %eax, LF_CURT(%ebp)
    movl %eax, LF_TMPBUF(%ebp)
    leal LF_CTX(%ebp), %edi
    xorl %eax, %eax
    movl $(0x2CC/4), %ecx
    rep stosl                        # 清零 CONTEXT
    movl $0x00010010, LF_CTX+0(%ebp) # CONTEXT_i386|DEBUG_REGISTERS
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_gtc(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_hwbp_fail
    movl %eax, LF_PFN(%ebp)
    leal LF_CTX(%ebp), %eax
    pushl %eax                       # &ctx
    pushl LF_CURT(%ebp)              # hThread
    call *LF_PFN(%ebp)
    testl %eax, %eax
    jz .Lcr_timing
    movl LF_CTX+4(%ebp), %eax        # Dr0..Dr3
    orl LF_CTX+8(%ebp), %eax
    orl LF_CTX+12(%ebp), %eax
    orl LF_CTX+16(%ebp), %eax
    jz .Lcr_timing
    orl $KDEF_HWBP, LF_FLAGS(%ebp)
    jmp .Lcr_timing
.Lcr_hwbp_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_timing:                         # ---- L3 反调试：rdtsc 时间差 ----
    testl $KDEF_TIMING, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_cpuid_hv
    incl LF_RUN(%ebp)
    rdtsc
    movl %eax, LF_TMPBUF(%ebp)
    movl %edx, LF_TMPBUF+4(%ebp)
    movl $128, %ecx
.Lcr_tloop:
    pause
    decl %ecx
    jnz .Lcr_tloop
    rdtsc
    subl LF_TMPBUF(%ebp), %eax
    sbbl LF_TMPBUF+4(%ebp), %edx
    movl %eax, LF_DELTA(%ebp)
    testl %edx, %edx
    jnz .Lcr_t_hit                  # 高 32 位非 0 => 差值巨大
    movl CFG_DEF_TICKS(%ebx), %ecx
    testl %ecx, %ecx
    jz .Lcr_cpuid_hv
    cmpl %ecx, %eax
    jbe .Lcr_cpuid_hv
.Lcr_t_hit:
    orl $KDEF_TIMING, LF_FLAGS(%ebp)

.Lcr_cpuid_hv:                       # ---- 反 VM：CPUID hypervisor 位 ----
    testl $KDEF_CPUID_HV, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_cpuid_v
    incl LF_RUN(%ebp)
    movl %ebx, LF_PFN(%ebp)          # cpuid 破坏 ebx（= config），先存
    movl $1, %eax
    xorl %ecx, %ecx
    cpuid
    movl %ebx, %edi
    movl LF_PFN(%ebp), %ebx
    testl $0x80000000, %ecx
    jz .Lcr_cpuid_v
    orl $KDEF_CPUID_HV, LF_FLAGS(%ebp)

.Lcr_cpuid_v:                        # ---- 反 VM：hypervisor vendor 串 ----
    testl $KDEF_CPUID_VENDOR, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_sidt
    incl LF_RUN(%ebp)
    movl %ebx, LF_PFN(%ebp)
    movl $0x40000000, %eax
    xorl %ecx, %ecx
    cpuid
    movl %ebx, %edi
    movl %ecx, %esi
    movl LF_PFN(%ebp), %ebx
    movl %edi, %eax
    orl %esi, %eax
    orl %edx, %eax
    testl %eax, %eax
    jz .Lcr_sidt
    orl $KDEF_CPUID_VENDOR, LF_FLAGS(%ebp)

.Lcr_sidt:                           # ---- 反 VM：SIDT（IDT 基址高字节）----
    # 非 CPUID 信号：IDTR 仅 ring-0 可改，用户态攻击者无法伪造（需 UMIP 关闭）。
    # 若 CR4.UMIP=1 该指令在 CPL3 下 #GP，由 kbox_veh 清零缓冲并跳过。
    testl $KDEF_SIDT, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_vmw
    incl LF_RUN(%ebp)
    cmpl $0, LF_VEHHDL(%ebp)         # 无 VEH 兜底时不得裸执行（会 #GP 杀进程）
    je .Lcr_sidt_fail
    subl $8, %esp
.Lcr_veh_probe_sidt:
    sidt (%esp)                      # 6 字节：limit + base32
.Lcr_veh_after_sidt:
    movl 2(%esp), %eax
    addl $8, %esp
    shrl $24, %eax
    cmpl $0xFF, %eax                 # 经典 VM 特征：基址高字节 0xFF
    jne .Lcr_vmw
    orl $KDEF_SIDT, LF_FLAGS(%ebp)
    jmp .Lcr_vmw
.Lcr_sidt_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_vmw:                            # ---- 反 VM：VMware I/O 后门 ----
    # 非 CPUID 信号：IN/OUT 为特权级敏感端口访问，用户态钩子无法拦截。
    # 注：CPL3 下 IN 恒 #GP（用户态不存在 VMware 后门响应），由 kbox_veh 兜底跳过。
    testl $KDEF_VMWARE, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_iat
    incl LF_RUN(%ebp)
    cmpl $0, LF_VEHHDL(%ebp)
    je .Lcr_vmw_fail
    movl %ebx, LF_PFN(%ebp)          # 保存 config（防御性）
    movl $0x564D5868, %eax           # 'VMXh'
    xorl %ebx, %ebx
    movl $0x0A, %ecx                 # getVMVersion
    movl $0x5658, %edx               # 'VX'
.Lcr_veh_probe_in:
    inl %dx, %eax                    # VMware 后门：命中时 ebx 返回魔数
.Lcr_veh_after_in:
    movl %ebx, %ecx
    movl LF_PFN(%ebp), %ebx
    cmpl $0x564D5868, %ecx
    jne .Lcr_iat
    orl $KDEF_VMWARE, LF_FLAGS(%ebp)
    jmp .Lcr_iat
.Lcr_vmw_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_iat:                            # ---- 反 hook：IAT/解析 API + 内联前缀 ----
    testl $(KDEF_IAT_HOOK|KDEF_INLINE_HOOK), CFG_DEF_FLAGS(%ebx)
    jz .Lcr_integrity
    incl LF_RUN(%ebp)
    # 页属性经 NtQueryVirtualMemory 查询（直接 syscall；用户态 VirtualQuery 钩子无效）
    leal .Lcr_s_ntdll(%ebx), %edi
    leal .Lcr_s_ntqvm(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_iat_fail
    movl %eax, LF_PFN(%ebp)
    movl %eax, %esi
    call .Lcr_ssn_of
    movl %eax, LF_SSN_QVM(%ebp)
    # 扫描 kbox_iat 3 槽 + 防御解析 API 表（.Lcr_resolve 已记录）
    movl $0, LF_SCAN(%ebp)
.Lcr_iat_loop:
    cmpl $3, LF_SCAN(%ebp)
    jae .Lcr_iat_tbl
    leal kbox_iat(%ebx), %eax
    movl LF_SCAN(%ebp), %ecx
    movl 0(%eax,%ecx,4), %edi        # IAT 槽内实际函数地址
    jmp .Lcr_iat_chk
.Lcr_iat_tbl:
    movl LF_HOOKCNT(%ebp), %edx      # 表条目数（快照）
    movl LF_SCAN(%ebp), %ecx
    subl $3, %ecx                    # 表下标
    cmpl %edx, %ecx
    jae .Lcr_integrity
    movl LF_HOOKTBL(%ebp,%ecx,4), %edi
.Lcr_iat_chk:
    testl %edi, %edi
    jz .Lcr_iat_next
    testl $KDEF_INLINE_HOOK, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_iat_vq
    movzbl (%edi), %eax
    cmpl $0xE9, %eax
    je .Lcr_iat_inline
    cmpl $0xFF, %eax
    jne .Lcr_iat_vq
    movzbl 1(%edi), %eax
    cmpl $0x25, %eax
    je .Lcr_iat_inline
.Lcr_iat_vq:
    testl $KDEF_IAT_HOOK, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_iat_next
    # NtQueryVirtualMemory(NtCurrentProcess, addr, MemoryBasicInformation, &mbi, 28, &len)
    leal LF_TMPBUF(%ebp), %eax
    pushl %eax                       # arg5 = &retlen
    pushl $28                        # arg4 = sizeof(MBI)（x86）
    leal LF_MBI(%ebp), %eax
    pushl %eax                       # arg3 = &mbi
    pushl $0                         # arg2 = MemoryBasicInformation
    pushl %edi                       # arg1 = BaseAddress
    pushl $-1                        # arg0 = NtCurrentProcess（伪句柄）
    movl LF_SSN_QVM(%ebp), %eax
    call .Lcr_ntcall_qvm             # 直接 sysenter 或 jmp *LF_PFN
    testl %eax, %eax
    jnz .Lcr_iat_next
    cmpl $0x1000000, LF_MBI+24(%ebp) # Type == MEM_IMAGE（x86 布局）
    je .Lcr_iat_next
    orl $KDEF_IAT_HOOK, LF_FLAGS(%ebp)
    jmp .Lcr_iat_next
.Lcr_iat_inline:
    orl $KDEF_INLINE_HOOK, LF_FLAGS(%ebp)
.Lcr_iat_next:
    incl LF_SCAN(%ebp)
    jmp .Lcr_iat_loop
.Lcr_iat_fail:
    incl LF_HBFAIL(%ebp)

.Lcr_integrity:                      # ---- 完整性校验（CRC32） ----
    testl $KDEF_INTEGRITY, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_int3
    incl LF_RUN(%ebp)
    movl CFG_DEF_INTEG_SIZE(%ebx), %ecx
    testl %ecx, %ecx
    jz .Lcr_int3
    movl CFG_DEF_INTEG_RVA(%ebx), %edi
    addl LF_BASE(%ebp), %edi
    call .Lcr_crc32
    movl %eax, LF_CRC(%ebp)
    cmpl CFG_DEF_INTEG_CRC(%ebx), %eax
    je .Lcr_int3
    orl $KDEF_INTEGRITY, LF_FLAGS(%ebp)

.Lcr_int3:                           # ---- 断点扫描：连续 0xCC ----
    testl $KDEF_INT3SCAN, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_inj
    incl LF_RUN(%ebp)
    movl CFG_DEF_INTEG_SIZE(%ebx), %ecx
    testl %ecx, %ecx
    jz .Lcr_inj
    movl CFG_DEF_INTEG_RVA(%ebx), %edi
    addl LF_BASE(%ebp), %edi
.Lcr_i3loop:
    cmpb $0xCC, (%edi)
    jne .Lcr_i3next
    cmpb $0xCC, 1(%edi)
    je .Lcr_i3hit
.Lcr_i3next:
    incl %edi
    decl %ecx
    jnz .Lcr_i3loop
    jmp .Lcr_inj
.Lcr_i3hit:
    orl $KDEF_INT3SCAN, LF_FLAGS(%ebp)

.Lcr_inj:                            # ---- 反注入：可执行私有页扫描 ----
    testl $KDEF_INJECT, CFG_DEF_FLAGS(%ebx)
    jz .Lcr_finish
    incl LF_RUN(%ebp)
    movl %fs:0x30, %eax
    movl 0x0C(%eax), %eax            # PEB->Ldr
    testl %eax, %eax
    jz .Lcr_inj_vq
    leal 0x14(%eax), %ecx            # InMemoryOrderModuleList 头
    movl (%ecx), %edx
    xorl %edi, %edi
.Lcr_modloop:
    cmpl %ecx, %edx
    je .Lcr_moddone
    incl %edi
    cmpl $1024, %edi
    jae .Lcr_moddone
    movl (%edx), %edx
    jmp .Lcr_modloop
.Lcr_moddone:
    movl %edi, LF_MODCNT(%ebp)
.Lcr_inj_vq:
    # 页属性经 NtQueryVirtualMemory（直接 syscall）扫描——用户态 VirtualQuery 钩子无效
    leal .Lcr_s_ntdll(%ebx), %edi
    leal .Lcr_s_ntqvm(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_finish
    movl %eax, LF_PFN(%ebp)
    movl %eax, %esi
    call .Lcr_ssn_of
    movl %eax, LF_SSN_QVM(%ebp)
    movl $0, LF_SCAN(%ebp)
.Lcr_vq_loop:
    leal LF_TMPBUF(%ebp), %eax
    pushl %eax                       # arg5 = &retlen
    pushl $28                        # arg4 = sizeof(MBI)（x86）
    leal LF_MBI(%ebp), %eax
    pushl %eax                       # arg3 = &mbi
    pushl $0                         # arg2 = MemoryBasicInformation
    pushl LF_SCAN(%ebp)              # arg1 = BaseAddress
    pushl $-1                        # arg0 = NtCurrentProcess
    movl LF_SSN_QVM(%ebp), %eax
    call .Lcr_ntcall_qvm             # 直接 sysenter 或 jmp *LF_PFN
    testl %eax, %eax
    jnz .Lcr_finish
    movl LF_MBI+12(%ebp), %eax       # RegionSize（x86 布局）
    testl %eax, %eax
    jz .Lcr_finish
    cmpl $0x1000, LF_MBI+16(%ebp)    # MEM_COMMIT
    jne .Lcr_vq_next
    cmpl $0x20000, LF_MBI+24(%ebp)   # MEM_PRIVATE
    jne .Lcr_vq_next
    movl LF_MBI+20(%ebp), %ecx       # Protect
    andl $0xF0, %ecx                 # 执行位
    jz .Lcr_vq_next
    orl $KDEF_INJECT, LF_FLAGS(%ebp)
.Lcr_vq_next:
    addl %eax, LF_SCAN(%ebp)
    js .Lcr_finish                   # 越过用户态上限（符号位）
    jmp .Lcr_vq_loop

.Lcr_finish:                         # ---- 分级响应 ----
    # ---- 卸载 VEH（必须早于返回：句柄不得跨 stub 生命周期存活）----
    cmpl $0, LF_VEHHDL(%ebp)
    je .Lcr_veh_off
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_rmveh(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz .Lcr_veh_off
    pushl LF_VEHHDL(%ebp)
    call *%eax
.Lcr_veh_off:

    movl LF_FLAGS(%ebp), %eax
    xorl %edx, %edx
    testl %eax, %eax
    jz .Lcr_lv_done
    movl $LVL_WEAK, %edx
    testl $KDEF_FATAL, %eax
    jnz .Lcr_lv3
    movl %eax, %ecx
    andl $KDEF_CRITICAL, %ecx
    jz .Lcr_lv_done
    movl $LVL_DECOY, %edx
    xorl %edi, %edi
.Lcr_pc:
    testl %ecx, %ecx
    jz .Lcr_pc_done
    movl %ecx, %esi
    andl $1, %esi
    addl %esi, %edi
    shrl $1, %ecx
    jmp .Lcr_pc
.Lcr_pc_done:
    cmpl $3, %edi
    jb .Lcr_lv_done
.Lcr_lv3:
    movl $LVL_FATAL, %edx
.Lcr_lv_done:
    cmpl $LVL_DECOY, %edx
    jne 1f
    testl $2, CFG_DEF_POLICY(%ebx)
    jnz 2f
    movl $LVL_WEAK, %edx
    jmp 2f
1:  cmpl $LVL_FATAL, %edx
    jne 2f
    testl $4, CFG_DEF_POLICY(%ebx)
    jnz 2f
    movl $LVL_DECOY, %edx
2:
    movl %edx, LF_LEVEL(%ebp)
    movl LF_REPORT(%ebp), %edi
    testl %edi, %edi
    jz 3f
    movl $DEF_REPORT_MAGIC, 0(%edi)
    movl LF_FLAGS(%ebp), %eax
    movl %eax, 4(%edi)
    movl LF_LEVEL(%ebp), %eax
    movl %eax, 8(%edi)
    movl LF_RUN(%ebp), %eax
    movl %eax, 12(%edi)
    movl LF_DELTA(%ebp), %eax
    movl %eax, 16(%edi)
    movl LF_CRC(%ebp), %eax
    movl %eax, 20(%edi)
    movl LF_MODCNT(%ebp), %eax
    movl %eax, 24(%edi)
    movl LF_HBFAIL(%ebp), %eax
    movl %eax, 28(%edi)
3:
    cmpl $LVL_WEAK, %edx
    jne 4f
    testl $1, CFG_DEF_POLICY(%ebx)
    jz 4f
    movl CFG_DEF_DELAY(%ebx), %ecx
    testl %ecx, %ecx
    jz 4f
5:  pause
    decl %ecx
    jnz 5b
4:
    movl %edx, %eax
    movl LF_BASE(%ebp), %esi         # 恢复调用者 esi（模块基址）
    movl LF_CFG(%ebp), %ebx          # 恢复 config（防御内 cpuid 已单独处理）
    leave
    ret

# ================= 特权指令探针的故障容错 VEH =================
# LONG WINAPI kbox_veh(PEXCEPTION_POINTERS p)  —— __stdcall，arg 在 [esp+4]
# 仅接管本 stub 两条特权探针（SIDT / IN）产生的
# STATUS_PRIVILEGED_INSTRUCTION(0xC0000096)：把探针结果置为「否」、将 Eip 指到
# 对应的 .Lcr_veh_after_* 并返回 CONTINUE_EXECUTION；其余异常 CONTINUE_SEARCH。
# 处理器由系统直接调用，ebx 不再持有 config，故先用 call/pop 自定位。
.set VEH_CONTINUE_EXECUTION, -1
.set XEXC_CODE_OFF, 0x00         # EXCEPTION_RECORD.ExceptionCode
.set XEXC_ADDR_OFF, 0x0C         # EXCEPTION_RECORD.ExceptionAddress
.set XCTX_EAX, 0xB0
.set XCTX_EBX, 0xA4
.set XCTX_EIP, 0xB8
.set XCTX_ESP, 0xC4

    .globl kbox_veh
    .type kbox_veh, @function
kbox_veh:
    pushl %ebx
    call .Lcr_veh_base
.Lcr_veh_base:
    popl %ebx
    subl $LVEHBASE_OFF, %ebx         # ebx = config（= base + stub_rva）
    movl 8(%esp), %ecx               # p
    testl %ecx, %ecx
    jz .Lcr_veh_search
    movl 0(%ecx), %edx               # p->ExceptionRecord
    testl %edx, %edx
    jz .Lcr_veh_search
    cmpl $0xC0000096, XEXC_CODE_OFF(%edx)
    jne .Lcr_veh_search
    movl 4(%ecx), %ecx               # p->ContextRecord
    testl %ecx, %ecx
    jz .Lcr_veh_search
    movl XEXC_ADDR_OFF(%edx), %eax   # ExceptionAddress = 故障指令地址
    leal .Lcr_veh_probe_sidt(%ebx), %edx
    cmpl %edx, %eax
    jne .Lcr_veh_in
    movl XCTX_ESP(%ecx), %edx        # SIDT 目标缓冲在 [esp]
    movl $0, 0(%edx)                 # 清零 → IDT 基址高字节 = 0 ≠ 0xFF
    movl $0, 4(%edx)
    leal .Lcr_veh_after_sidt(%ebx), %edx
    movl %edx, XCTX_EIP(%ecx)
    movl $VEH_CONTINUE_EXECUTION, %eax
    popl %ebx
    ret $4
.Lcr_veh_in:
    leal .Lcr_veh_probe_in(%ebx), %edx
    cmpl %edx, %eax
    jne .Lcr_veh_search
    movl $0, XCTX_EAX(%ecx)          # IN 结果置 0（ebx 之后由 LF_PFN 还原）
    movl $0, XCTX_EBX(%ecx)
    leal .Lcr_veh_after_in(%ebx), %edx
    movl %edx, XCTX_EIP(%ecx)
    movl $VEH_CONTINUE_EXECUTION, %eax
    popl %ebx
    ret $4
.Lcr_veh_search:
    xorl %eax, %eax                  # EXCEPTION_CONTINUE_SEARCH
    popl %ebx
    ret $4
.set LVEHBASE_OFF, (.Lcr_veh_base - kbox_entry) + 0x100

# ---- 动态解析：edi = DLL 名，esi = 函数名 → eax = 地址（0 = 失败） ----
# 方案D：解析成功即记录到 hook 扫描表（.Lcr_iat 复用）。
.Lcr_resolve:
    pushl %esi                       # 暂存函数名
    leal kbox_iat(%ebx), %eax
    pushl %edi                       # dll 名
    call *0(%eax)                    # LoadLibraryA（stdcall，清 4）
    testl %eax, %eax
    jz 1f
    movl %eax, %ecx                  # hLib
    popl %edx                        # 函数名
    pushl %edx
    pushl %ecx
    leal kbox_iat(%ebx), %eax
    call *4(%eax)                    # GetProcAddress（stdcall，清 8）
    movl LF_HOOKCNT(%ebp), %ecx
    cmpl $LF_HOOKMAX, %ecx
    jae 2f
    movl %eax, LF_HOOKTBL(%ebp,%ecx,4)
    incl %ecx
    movl %ecx, LF_HOOKCNT(%ebp)
2:  ret
1:  addl $4, %esp
    xorl %eax, %eax
    ret

# ---- 解析 ntdll 桩的系统调用号：esi = 函数地址 → eax = SSN（0 = 不可用）----
# 校验标准 x86 桩：`B8 <SSN> | (BA imm32)? | 0F 34`（mov eax,SSN; mov edx,ret; sysenter）
.Lcr_ssn_of:
    cmpb $0xB8, 0(%esi)
    jne 1f
    cmpb $0x0F, 5(%esi)
    jne 2f
    cmpb $0x34, 6(%esi)
    jne 2f
    movl 1(%esi), %eax
    ret
2:  cmpb $0x0F, 10(%esi)
    jne 1f
    cmpb $0x34, 11(%esi)
    jne 1f
    movl 1(%esi), %eax
    ret
1:  xorl %eax, %eax
    ret

# ---- 直接系统调用（绕过用户态 Nt* 钩子）——x86 sysenter ----
# 入：eax = SSN（0 = 回退 LF_PFN）；参数已压栈（call 进入，args 在 [esp+4..]）
# 出：eax = NTSTATUS。每个变体对应参数个数（stdcall 清栈量）。
.Lcr_ntcall_qip:                     # 5 参数（NtQueryInformationProcess）
    testl %eax, %eax
    jz 1f
    movl $.Lcr_ntcall_qip_ret, %edx
    sysenter
.Lcr_ntcall_qip_ret:
    ret $20
1:  jmp *LF_PFN(%ebp)
.Lcr_ntcall_tsit:                    # 4 参数（NtSetInformationThread）
    testl %eax, %eax
    jz 1f
    movl $.Lcr_ntcall_tsit_ret, %edx
    sysenter
.Lcr_ntcall_tsit_ret:
    ret $16
1:  jmp *LF_PFN(%ebp)
.Lcr_ntcall_qvm:                     # 6 参数（NtQueryVirtualMemory）
    testl %eax, %eax
    jz 1f
    movl $.Lcr_ntcall_qvm_ret, %edx
    sysenter
.Lcr_ntcall_qvm_ret:
    ret $24
1:  jmp *LF_PFN(%ebp)

# ---- GetCurrentProcess（带缓存）→ eax ----
.Lcr_getcurp:
    movl LF_CURP(%ebp), %eax
    testl %eax, %eax
    jnz 1f
    leal .Lcr_s_k32(%ebx), %edi
    leal .Lcr_s_gcurp(%ebx), %esi
    call .Lcr_resolve
    testl %eax, %eax
    jz 1f
    call *%eax
    movl %eax, LF_CURP(%ebp)
1:  ret

# ---- NtQueryInformationProcess 单次调用：LF_PFN/LF_CLASS → eax = 状态 ----
# 方案D：经 .Lcr_ntcall_qip 走直接 sysenter（SSN 已解析）或回退函数指针。
.Lcr_ntqip:
    movl $0, LF_TMPBUF(%ebp)
    movl $0, LF_TMPBUF+4(%ebp)
    leal LF_TMPBUF+4(%ebp), %eax
    pushl %eax                       # &retlen
    pushl $8                         # len
    leal LF_TMPBUF(%ebp), %eax
    pushl %eax                       # &buf
    pushl LF_CLASS(%ebp)             # class
    pushl LF_CURP(%ebp)              # h
    movl LF_SSN_QIP(%ebp), %eax
    call .Lcr_ntcall_qip
    ret

# ---- CRC32（IEEE，表无关）：edi = 指针，ecx = 长度 → eax ----
.Lcr_crc32:
    movl $0xFFFFFFFF, %eax
    testl %ecx, %ecx
    jz 2f
1:  movzbl (%edi), %edx
    xorl %edx, %eax
    movl $8, %esi
3:  movl %eax, %edx
    andl $1, %edx
    negl %edx
    andl $0xEDB88320, %edx
    shrl $1, %eax
    xorl %edx, %eax
    decl %esi
    jnz 3b
    incl %edi
    decl %ecx
    jnz 1b
2:  notl %eax
    ret

# ---- 诱饵路径：写入标记后进入伪终止循环 ----
    .globl kbox_decoy
    .type kbox_decoy, @function
kbox_decoy:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    movl CFG_DEF_REPORT_RVA(%ebx), %eax
    testl %eax, %eax
    jz 1f
    addl %esi, %eax
    movl $DEF_DECOY_MARK, 32(%eax)
1:  popl %esi
    popl %ebx
    popl %ebp
.Lcr_decoy_loop:
    jmp .Lcr_decoy_loop

# ---- 防御用字符串常量（位于代码区；G2 下随构建 XOR 加密） ----
    .globl kbox_strpool_start
kbox_strpool_start:
.Lcr_s_k32:     .asciz "kernel32.dll"
.Lcr_s_ntdll:   .asciz "ntdll.dll"
.Lcr_s_isdbg:   .asciz "IsDebuggerPresent"
.Lcr_s_cremote: .asciz "CheckRemoteDebuggerPresent"
.Lcr_s_ntqip:    .asciz "NtQueryInformationProcess"
.Lcr_s_ntsit:    .asciz "NtSetInformationThread"
.Lcr_s_gcurp:   .asciz "GetCurrentProcess"
.Lcr_s_gcurt:   .asciz "GetCurrentThread"
.Lcr_s_gtc:     .asciz "GetThreadContext"
.Lcr_s_ntqvm:   .asciz "NtQueryVirtualMemory"
.Lcr_s_addveh:  .asciz "AddVectoredExceptionHandler"
.Lcr_s_rmveh:   .asciz "RemoveVectoredExceptionHandler"
    .globl kbox_defense_end
kbox_defense_end:

# ================= kbox_chacha（内部调用） =================
# 入口参数：eax=buf, edx=len, ecx=key, esi=nonce, edi=counter
# 原地 XOR keystream。保留 ebx/esi/edi/ebp（调用者依赖 ebx=config）。
    .globl kbox_chacha
    .type kbox_chacha, @function
kbox_chacha:
    pushl %ebx
    pushl %esi
    pushl %edi
    pushl %ebp
    subl $160, %esp
    movl %esp, %ebx              # work 状态 at +0, orig 状态 at +64
    movl %eax, 128(%esp)         # buf
    movl %edx, 132(%esp)         # len
    movl %ecx, 136(%esp)         # key
    movl %esi, 140(%esp)         # nonce
    movl %edi, 148(%esp)         # counter
    # 构建初始 state
    movl $0x61707865, 0(%ebx)
    movl $0x3320646e, 4(%ebx)
    movl $0x79622d32, 8(%ebx)
    movl $0x6b206574, 12(%ebx)
    movl 136(%esp), %esi
    movl 0(%esi), %eax;  movl %eax, 16(%ebx)
    movl 4(%esi), %eax;  movl %eax, 20(%ebx)
    movl 8(%esi), %eax;  movl %eax, 24(%ebx)
    movl 12(%esi), %eax; movl %eax, 28(%ebx)
    movl 16(%esi), %eax; movl %eax, 32(%ebx)
    movl 20(%esi), %eax; movl %eax, 36(%ebx)
    movl 24(%esi), %eax; movl %eax, 40(%ebx)
    movl 28(%esi), %eax; movl %eax, 44(%ebx)
    movl 148(%esp), %eax
    movl %eax, 48(%ebx)          # counter
    movl 140(%esp), %esi
    movl 0(%esi), %eax;  movl %eax, 52(%ebx)
    movl 4(%esi), %eax;  movl %eax, 56(%ebx)
    movl 8(%esi), %eax;  movl %eax, 60(%ebx)
    # orig = work
    leal 64(%ebx), %edi
    movl 0(%ebx), %eax;  movl %eax, 0(%edi)
    movl 4(%ebx), %eax;  movl %eax, 4(%edi)
    movl 8(%ebx), %eax;  movl %eax, 8(%edi)
    movl 12(%ebx), %eax; movl %eax, 12(%edi)
    movl 16(%ebx), %eax; movl %eax, 16(%edi)
    movl 20(%ebx), %eax; movl %eax, 20(%edi)
    movl 24(%ebx), %eax; movl %eax, 24(%edi)
    movl 28(%ebx), %eax; movl %eax, 28(%edi)
    movl 32(%ebx), %eax; movl %eax, 32(%edi)
    movl 36(%ebx), %eax; movl %eax, 36(%edi)
    movl 40(%ebx), %eax; movl %eax, 40(%edi)
    movl 44(%ebx), %eax; movl %eax, 44(%edi)
    movl 48(%ebx), %eax; movl %eax, 48(%edi)
    movl 52(%ebx), %eax; movl %eax, 52(%edi)
    movl 56(%ebx), %eax; movl %eax, 56(%edi)
    movl 60(%ebx), %eax; movl %eax, 60(%edi)
    jmp .Lchacha_loop

.Lchacha_loop:
    movl 132(%esp), %eax
    cmpl $64, %eax
    jb .Lchacha_tail
    BLOCK_GEN
    # 输出：out[i] = work[i]+orig[i] ^ buf[i]
    xorl %edi, %edi
.Lchacha_out:
    movl 0(%ebx,%edi,4), %eax
    addl 64(%ebx,%edi,4), %eax
    movl 128(%esp), %ecx
    xorl 0(%ecx,%edi,4), %eax
    movl %eax, 0(%ecx,%edi,4)
    incl %edi
    cmpl $16, %edi
    jb .Lchacha_out
    addl $64, 128(%esp)          # buf += 64
    subl $64, 132(%esp)          # len -= 64
    incl 148(%esp)               # counter++
    jmp .Lchacha_loop

.Lchacha_tail:
    movl 132(%esp), %eax
    testl %eax, %eax
    jz .Lchacha_done
    BLOCK_GEN
    # 按字节 XOR 剩余 len 字节
    xorl %edi, %edi
.Lchacha_tail_byte:
    movl 132(%esp), %eax
    cmpl %eax, %edi
    jae .Lchacha_done
    movl %edi, %eax
    shrl $2, %eax
    movl 0(%ebx,%eax,4), %ecx
    addl 64(%ebx,%eax,4), %ecx   # keystream 字
    movl %edi, %eax
    andl $3, %eax
    shll $3, %eax
    movl %ecx, %edx              # 保留密钥流字（cl 将被移位数占用）
    movb %al, %cl
    shrl %cl, %edx              # dl = keystream 字节
    movl 128(%esp), %eax
    movb (%eax,%edi), %al
    xorb %dl, %al
    movb %al, (%eax,%edi)
    incl %edi
    jmp .Lchacha_tail_byte

.Lchacha_done:
    addl $160, %esp
    popl %ebp
    popl %edi
    popl %esi
    popl %ebx
    ret

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
    .section .iat,"aw",@progbits
    .balign 4096
# secA（代码，RX）/ secB（数据，RWX）切分点：packer 以该偏移拆节。
    .globl kbox_code_end
kbox_code_end:
# ---- 布局保护页（不可达填充）----
# 实测：IAT 若恰落在镜像 RVA 0x6000（= stub_rva + 0x5000），loader 不回填该页，
# IAT 槽恒为 0 → stub 取到空指针跳 .Ldead。插一页把 .iat 顶到 RVA 0x7000。
    .space 0x1000
    .balign 4096
    .globl kbox_iat
kbox_iat:
    .space 12           # 3 × 4 字节：LoadLibraryA / GetProcAddress / VirtualProtect

    .section .note.GNU-stack,"",@progbits
