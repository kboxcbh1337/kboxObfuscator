package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * MetaInner — 嵌套虚拟化：把内层 VM 引擎编译成外层 Meta 字节码程序
 * （由 packer/vm/meta_inner.cpp 移植）。
 *
 * <p>本类在<b>打包期</b>生成一段 Meta VM 程序（MInsn 流 + handler 偏移表），该
 * 程序实现内层 A（栈式）/ B（寄存器式）两族的完整解释器：</p>
 *
 * <p>取指（就地解密，缓存 keystream）→ opcode 反查语义 → 分派 handler →
 * 执行语义 → 回写密文 → 依 jumped/RET 推进 ip</p>
 *
 * <p>内层执行状态（ip/sp/栈/帧/映射表/key/keystream 缓存）保存在 kbox_vm_run
 * 在栈上分配的"内层状态块"（{@link VmInnerState}）中，以 m0 指向；内层镜像指针
 * 为 m1、字节数为 m2、机器寄存器块为 m3、keystream 例程为 m4；handler 偏移
 * 表地址由 vm_meta_exec 置于 m5。</p>
 *
 * <p>与 vm_engine.cpp（内层 C++ 引擎）逐条语义对齐——两者必须给出完全相同的结果。</p>
 *
 * <p>Java 侧无原生指针：地址空间取「传给 {@code vmMetaExec} 的 image 数组」，
 * 即地址 = 数组下标（详见 {@link #vmExecInnerNested}）。</p>
 */
public final class MetaInner {

    private MetaInner() {
    }

    // ==================================================================
    // ---- 内层契约常量（同步 vm_isa.h）----
    // ==================================================================

    private static final int IV_MAGIC = 0x4D56424B;   // "KBVM"
    private static final int IV_VERSION = 2;
    private static final int IV_HEADER = 64;
    private static final int IV_SEM_COUNT = 36;       // A
    private static final int IV_REG_COUNT = 27;       // B
    private static final int IV_INSN_A = 5;
    private static final int IV_INSN_B = 8;
    private static final int IV_BCOFF_A = 136;
    private static final int IV_BCOFF_B = 91;
    private static final int IV_SEM_RET = 21;         // A RET
    private static final int IV_REG_RET = 25;         // B RET
    private static final int IV_FRAME_MASK = 127;
    private static final int IV_STACK_WORDS = 32;
    private static final int IV_MAX_STEPS = VmIsa.VM_MAX_STEPS;

    // ---- A 族语义号 ----
    private static final int A_NOP = VmIsa.SEM_NOP;
    private static final int A_PUSH = VmIsa.SEM_PUSH;
    private static final int A_LOAD = VmIsa.SEM_LOAD;
    private static final int A_STORE = VmIsa.SEM_STORE;
    private static final int A_DUP = VmIsa.SEM_DUP;
    private static final int A_SWAP = VmIsa.SEM_SWAP;
    private static final int A_POP = VmIsa.SEM_POP;
    private static final int A_ADD = VmIsa.SEM_ADD;
    private static final int A_SUB = VmIsa.SEM_SUB;
    private static final int A_MUL = VmIsa.SEM_MUL;
    private static final int A_NEG = VmIsa.SEM_NEG;
    private static final int A_AND = VmIsa.SEM_AND;
    private static final int A_OR = VmIsa.SEM_OR;
    private static final int A_XOR = VmIsa.SEM_XOR;
    private static final int A_NOT = VmIsa.SEM_NOT;
    private static final int A_SHL = VmIsa.SEM_SHL;
    private static final int A_SHR = VmIsa.SEM_SHR;
    private static final int A_SAR = VmIsa.SEM_SAR;
    private static final int A_JMP = VmIsa.SEM_JMP;
    private static final int A_JZ = VmIsa.SEM_JZ;
    private static final int A_JNZ = VmIsa.SEM_JNZ;
    private static final int A_RET = VmIsa.SEM_RET;
    private static final int A_MEMRD = VmIsa.SEM_MEMRD;
    private static final int A_MEMWR = VmIsa.SEM_MEMWR;
    private static final int A_ADDREL = VmIsa.SEM_ADDREL;
    private static final int A_NATIVE = VmIsa.SEM_NATIVE;
    private static final int A_EQ = VmIsa.SEM_EQ;
    private static final int A_NE = VmIsa.SEM_NE;
    private static final int A_ULT = VmIsa.SEM_ULT;
    private static final int A_UGE = VmIsa.SEM_UGE;
    private static final int A_ULE = VmIsa.SEM_ULE;
    private static final int A_UGT = VmIsa.SEM_UGT;
    private static final int A_SLT = VmIsa.SEM_SLT;
    private static final int A_SGE = VmIsa.SEM_SGE;
    private static final int A_SLE = VmIsa.SEM_SLE;
    private static final int A_SGT = VmIsa.SEM_SGT;

    // ---- B 族语义号 ----
    private static final int B_NOP = VmIsa.REG_NOP;
    private static final int B_MOVI = VmIsa.REG_MOVI;
    private static final int B_SET64 = VmIsa.REG_SET64;
    private static final int B_MOV = VmIsa.REG_MOV;
    private static final int B_ADD = VmIsa.REG_ADD;
    private static final int B_SUB = VmIsa.REG_SUB;
    private static final int B_MUL = VmIsa.REG_MUL;
    private static final int B_AND = VmIsa.REG_AND;
    private static final int B_OR = VmIsa.REG_OR;
    private static final int B_XOR = VmIsa.REG_XOR;
    private static final int B_SHL = VmIsa.REG_SHL;
    private static final int B_SHR = VmIsa.REG_SHR;
    private static final int B_SAR = VmIsa.REG_SAR;
    private static final int B_NEG = VmIsa.REG_NEG;
    private static final int B_NOT = VmIsa.REG_NOT;
    private static final int B_FLD = VmIsa.REG_FLD;
    private static final int B_FLD64 = VmIsa.REG_FLD64;
    private static final int B_FST = VmIsa.REG_FST;
    private static final int B_FST64 = VmIsa.REG_FST64;
    private static final int B_LD = VmIsa.REG_LD;
    private static final int B_ST = VmIsa.REG_ST;
    private static final int B_LEA = VmIsa.REG_LEA;
    private static final int B_SETCC = VmIsa.REG_SETCC;
    private static final int B_JCC = VmIsa.REG_JCC;
    private static final int B_JMP = VmIsa.REG_JMP;
    private static final int B_RET = VmIsa.REG_RET;
    private static final int B_NATIVE = VmIsa.REG_NATIVE;

    // ---- 内层状态码（与 vm_isa.h VM_ERR_* 对齐）----
    private static final int IERR_FAULT = 1;
    private static final int IERR_OVER = 2;
    private static final int IERR_UNDER = 3;
    private static final int IERR_MAGIC = 4;
    private static final int IERR_BADOP = 5;
    private static final int IERR_DEEP = 7;

    // ---- Meta 程序寄存器约定 ----
    private static final int R_ST = 0;
    private static final int R_IMG = 1;
    private static final int R_ISZ = 2;
    private static final int R_GPR = 3;
    private static final int R_KS = 4;
    private static final int R_HT = 5;

    private static final int T6 = 6;
    private static final int T7 = 7;
    private static final int T8 = 8;
    private static final int T9 = 9;
    private static final int ZR = 10;

    private static final int V0 = 11;
    private static final int V1 = 12;
    private static final int V2 = 13;
    private static final int V3 = 14;
    private static final int V4 = 15;

    // ==================================================================
    // ---- 极简 Meta 汇编器（标签 + 回填）----
    // ==================================================================

    private static final class Asm {

        final List<VmIsaM.MInsn> code = new ArrayList<VmIsaM.MInsn>();
        final List<Integer> lb = new ArrayList<Integer>();
        final List<int[]> fx = new ArrayList<int[]>();

        int nlabel() {
            lb.add(-1);
            return lb.size() - 1;
        }

        void bind(int l) {
            lb.set(l, code.size());
        }

        void e(int op) {
            e(op, 0, 0, 0, 0);
        }

        void e(int op, int d) {
            e(op, d, 0, 0, 0);
        }

        void e(int op, int d, int s) {
            e(op, d, s, 0, 0);
        }

        void e(int op, int d, int s, int a) {
            e(op, d, s, a, 0);
        }

        /** 发射一条指令：字段按 uint8 截断（与 C++ MInsn 一致）。 */
        void e(int op, int d, int s, int a, int im) {
            code.add(new VmIsaM.MInsn(op & 0xFF, d & 0xFF, s & 0xFF, a & 0xFF, im));
        }

        /** 发射一条待回填指令（imm 在 resolve() 时填为标签的绝对字节偏移）。 */
        void ej(int op, int d, int s, int a, int l) {
            fx.add(new int[]{code.size(), l});
            e(op, d, s, a, 0);
        }

        void resolve() {
            for (int[] f : fx) {
                final int i = lb.get(f[1]);
                if (i < 0) {
                    System.err.println("[meta] unbound label " + f[1]);
                    continue;
                }
                code.get(f[0]).imm = i * VmIsaM.M_INSN_SIZE;
            }
        }
    }

    // ==================================================================
    // ---- 内层解释器 Meta 程序生成器（对应 vm_build_inner_meta 本体）----
    // ==================================================================

    private static final class Gen {

        final Asm A = new Asm();

        // ---- 全部标签先声明（供后续任意位置前向引用）----
        final int L_err_over = A.nlabel();
        final int L_err_under = A.nlabel();
        final int L_e_badmagic = A.nlabel();
        final int L_e_fault = A.nlabel();
        final int L_e_badop = A.nlabel();
        final int L_e_deep = A.nlabel();
        final int L_cceval = A.nlabel();
        final int L_ksbyte = A.nlabel();
        final int L_fetch = A.nlabel();
        final int L_reenc = A.nlabel();
        final int L_loop = A.nlabel();
        final int L_ret_ok = A.nlabel();
        final int L_halt_st = A.nlabel();
        final int L_halt_nr = A.nlabel();   // 取指失败（未解密）：直接停机
        final int L_total_ok = A.nlabel();
        final int L_is_b = A.nlabel();
        final int L_fam_done = A.nlabel();
        final int L_disp_go = A.nlabel();
        final int L_ff_fault = A.nlabel();
        final int L_ff_badop = A.nlabel();
        final int L_ffb_loop = A.nlabel();
        final int L_ffb_b = A.nlabel();
        final int L_ffd_done = A.nlabel();
        final int L_re_loop = A.nlabel();
        final int L_ks_hit = A.nlabel();
        final int L_ks_zero = A.nlabel();
        final int L_rev_z = A.nlabel();
        final int L_dmap = A.nlabel();
        final int L_rev_b = A.nlabel();

        int[] LA;
        int[] LB;

        // ---------------- 指令发射宏 ----------------

        private void movi(int d, int v) {
            A.e(VmIsaM.M_MOVI, d, 0, 0, v);
        }

        private void mov(int d, int s) {
            A.e(VmIsaM.M_MOV, d, s);
        }

        private void add(int d, int s, int a) {
            A.e(VmIsaM.M_ADD, d, s, a);
        }

        private void sub_(int d, int s, int a) {
            A.e(VmIsaM.M_SUB, d, s, a);
        }

        private void mul(int d, int s, int a) {
            A.e(VmIsaM.M_MUL, d, s, a);
        }

        private void and_(int d, int s, int a) {
            A.e(VmIsaM.M_AND, d, s, a);
        }

        private void or_(int d, int s, int a) {
            A.e(VmIsaM.M_OR, d, s, a);
        }

        private void xor_(int d, int s, int a) {
            A.e(VmIsaM.M_XOR, d, s, a);
        }

        private void shl(int d, int s, int a) {
            A.e(VmIsaM.M_SHL, d, s, a);
        }

        private void shr(int d, int s, int a) {
            A.e(VmIsaM.M_SHR, d, s, a);
        }

        private void sar(int d, int s, int a) {
            A.e(VmIsaM.M_SAR, d, s, a);
        }

        private void mod_(int d, int s, int a) {
            A.e(VmIsaM.M_MOD, d, s, a);
        }

        private void not_(int d, int s) {
            A.e(VmIsaM.M_NOT, d, s);
        }

        private void lea(int d, int s, int off) {
            A.e(VmIsaM.M_LEA, d, s, 0, off);
        }

        private void ld32(int d, int b, int off) {
            A.e(VmIsaM.M_LD32, d, b, 0, off);
        }

        private void st32(int b, int off, int s) {
            A.e(VmIsaM.M_ST32, b, s, 0, off);
        }

        private void ld8(int d, int b, int off) {
            A.e(VmIsaM.M_LD8, d, b, 0, off);
        }

        private void st8(int b, int off, int s) {
            A.e(VmIsaM.M_ST8, b, s, 0, off);
        }

        private void st64(int b, int off, int s) {
            A.e(VmIsaM.M_ST, b, s, 0, off);
        }

        private void setcc(int d, int s, int a, int cc) {
            A.e(VmIsaM.M_SETCC, d, s, a, cc);
        }

        private void halt(int st, int rv) {
            A.e(VmIsaM.M_HALT, st, rv);
        }

        private void ret() {
            A.e(VmIsaM.M_RET);
        }

        private void host(int prim) {
            A.e(VmIsaM.M_HOST, 0, 0, 0, prim);
        }

        private void jnz(int r, int l) {
            A.ej(VmIsaM.M_JCC, VmIsaM.M_CC_NE, r, ZR, l);
        }

        private void jz(int r, int l) {
            A.ej(VmIsaM.M_JCC, VmIsaM.M_CC_EQ, r, ZR, l);
        }

        private void jmpL(int l) {
            A.ej(VmIsaM.M_JMP, 0, 0, 0, l);
        }

        private void callL(int l) {
            A.ej(VmIsaM.M_CALL, 0, 0, 0, l);
        }

        /** src 字段承载目标寄存器。 */
        private void callr(int s) {
            A.e(VmIsaM.M_CALLR, 0, s);
        }

        // ---------------- 组合片段 ----------------

        /** 内层栈压栈（失败即置状态并返回当前 handler）。 */
        private void push32(int v) {
            ld32(T6, R_ST, VmInnerState.IS_SP);
            ld32(T7, R_ST, VmInnerState.IS_STACKW);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGE);
            jnz(T8, L_err_over);
            movi(T8, 2);
            shl(T7, T6, T8);
            lea(T8, R_ST, VmInnerState.IS_STACK);
            add(T8, T8, T7);
            st32(T8, 0, v);
            movi(T8, 1);
            add(T6, T6, T8);
            st32(R_ST, VmInnerState.IS_SP, T6);
        }

        /** 内层栈弹栈（失败即置状态并返回当前 handler）。 */
        private void pop32(int v) {
            ld32(T6, R_ST, VmInnerState.IS_SP);
            setcc(T7, T6, ZR, VmIsaM.M_CC_EQ);
            jnz(T7, L_err_under);
            movi(T7, 1);
            sub_(T6, T6, T7);
            st32(R_ST, VmInnerState.IS_SP, T6);
            movi(T7, 2);
            shl(T6, T6, T7);
            lea(T7, R_ST, VmInnerState.IS_STACK);
            add(T7, T7, T6);
            ld32(v, T7, 0);
        }

        /** B 族寄存器号 -> frame 槽地址（out 为临时寄存器）；rn 被消耗。 */
        private void slotaddr(int rn, int out) {
            final int l = A.nlabel();
            movi(T6, 16);
            setcc(T8, rn, T6, VmIsaM.M_CC_ULT);
            jnz(T8, l);
            movi(T6, 32);
            add(rn, rn, T6);
            A.bind(l);
            movi(T6, 3);
            shl(rn, rn, T6);                       // 槽号*8 = 字节偏移
            lea(out, R_ST, VmInnerState.IS_FRAME);
            add(out, out, rn);
        }

        /** 读 IS_IMM 并符号扩展到 64 位 -> dst（用 T6）。 */
        private void sx_imm(int dst) {
            ld32(dst, R_ST, VmInnerState.IS_IMM);
            movi(T6, 32);
            shl(dst, dst, T6);
            movi(T6, 32);
            sar(dst, dst, T6);
        }

        // ---------------- 主体 ----------------

        void run() {
            // ================= 入口 / 初始化 =================
            // m1 = image, m2 = image_size
            movi(ZR, 0);
            movi(T6, IV_HEADER);
            setcc(T7, R_ISZ, T6, VmIsaM.M_CC_ULT);
            jnz(T7, L_e_badmagic);

            ld32(T6, R_IMG, VmInnerState.IH_MAGIC);
            movi(T7, IV_MAGIC);
            setcc(T8, T6, T7, VmIsaM.M_CC_NE);
            jnz(T8, L_e_badmagic);

            ld32(T6, R_IMG, VmInnerState.IH_VERSION);
            movi(T7, IV_VERSION);
            setcc(T8, T6, T7, VmIsaM.M_CC_NE);
            jnz(T8, L_e_badmagic);

            ld32(T6, R_IMG, VmInnerState.IH_FLAGS);
            movi(T7, 0xFF);
            and_(T6, T6, T7);                      // family
            movi(T7, 1);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGT);
            jnz(T8, L_e_badmagic);
            st32(R_ST, VmInnerState.IS_FAMILY, T6);

            ld32(T6, R_IMG, VmInnerState.IH_TOTAL_SIZE);
            jz(T6, L_total_ok);
            setcc(T7, T6, R_ISZ, VmIsaM.M_CC_UGT);
            jnz(T7, L_e_fault);
            A.bind(L_total_ok);

            ld32(T6, R_IMG, VmInnerState.IH_DISPATCH);
            movi(T7, 2);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGE);
            jnz(T8, L_e_badop);

            ld32(T6, R_IMG, VmInnerState.IH_STACK_WORDS);
            jz(T6, L_e_fault);
            movi(T7, IV_STACK_WORDS);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGT);
            jnz(T8, L_e_fault);
            st32(R_ST, VmInnerState.IS_STACKW, T6);

            ld32(T6, R_IMG, VmInnerState.IH_BC_SIZE);
            st32(R_ST, VmInnerState.IS_BCSIZE, T6);

            // ilen / boff / nsem / retc 按族选择
            ld32(T6, R_ST, VmInnerState.IS_FAMILY);
            jnz(T6, L_is_b);
            movi(T7, IV_INSN_A);
            st32(R_ST, VmInnerState.IS_ILEN, T7);
            movi(T7, IV_BCOFF_A);
            st32(R_ST, VmInnerState.IS_BCOFF, T7);
            movi(T7, IV_SEM_COUNT);
            st32(R_ST, VmInnerState.IS_NSEM, T7);
            movi(T7, IV_SEM_RET);
            st32(R_ST, VmInnerState.IS_RETC, T7);
            jmpL(L_fam_done);
            A.bind(L_is_b);
            movi(T7, IV_INSN_B);
            st32(R_ST, VmInnerState.IS_ILEN, T7);
            movi(T7, IV_BCOFF_B);
            st32(R_ST, VmInnerState.IS_BCOFF, T7);
            movi(T7, IV_REG_COUNT);
            st32(R_ST, VmInnerState.IS_NSEM, T7);
            movi(T7, IV_REG_RET);
            st32(R_ST, VmInnerState.IS_RETC, T7);
            A.bind(L_fam_done);

            // bc_size % ilen == 0
            ld32(T6, R_ST, VmInnerState.IS_BCSIZE);
            ld32(T7, R_ST, VmInnerState.IS_ILEN);
            mod_(T9, T6, T7);
            jnz(T9, L_e_fault);

            // boff + bc_size <= image_size
            ld32(T6, R_ST, VmInnerState.IS_BCOFF);
            ld32(T7, R_ST, VmInnerState.IS_BCSIZE);
            add(T6, T6, T7);
            setcc(T8, T6, R_ISZ, VmIsaM.M_CC_UGT);
            jnz(T8, L_e_fault);

            // entry*ilen < bc_size
            ld32(T6, R_IMG, VmInnerState.IH_ENTRY);
            ld32(T7, R_ST, VmInnerState.IS_ILEN);
            mul(T6, T6, T7);
            ld32(T7, R_ST, VmInnerState.IS_BCSIZE);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGE);
            jnz(T8, L_e_fault);
            st32(R_ST, VmInnerState.IS_IP, T6);

            // 标量初值
            movi(T6, 0);
            st32(R_ST, VmInnerState.IS_SP, T6);
            st32(R_ST, VmInnerState.IS_RETVAL, T6);
            st32(R_ST, VmInnerState.IS_STATUS, T6);
            st32(R_ST, VmInnerState.IS_STEPS, T6);
            st32(R_ST, VmInnerState.IS_JUMPED, T6);
            st32(R_ST, VmInnerState.IS_SEM, T6);
            movi(T6, 0xFFFFFFFF);
            st32(R_ST, VmInnerState.IS_KSCNT, T6);

            // 派生密钥：header.key[4] || 固定填充
            ld32(T6, R_IMG, VmInnerState.IH_KEY + 0);
            st32(R_ST, VmInnerState.IS_KEY + 0, T6);
            ld32(T6, R_IMG, VmInnerState.IH_KEY + 4);
            st32(R_ST, VmInnerState.IS_KEY + 4, T6);
            ld32(T6, R_IMG, VmInnerState.IH_KEY + 8);
            st32(R_ST, VmInnerState.IS_KEY + 8, T6);
            ld32(T6, R_IMG, VmInnerState.IH_KEY + 12);
            st32(R_ST, VmInnerState.IS_KEY + 12, T6);
            movi(T6, 0x6B626F58);
            st32(R_ST, VmInnerState.IS_KEY + 16, T6);
            movi(T6, 0x6E67696E);
            st32(R_ST, VmInnerState.IS_KEY + 20, T6);
            movi(T6, 0x203A6F44);
            st32(R_ST, VmInnerState.IS_KEY + 24, T6);
            movi(T6, 0x2179654B);
            st32(R_ST, VmInnerState.IS_KEY + 28, T6);
            // 全零 nonce（16B）
            movi(T6, 0);
            st64(R_ST, VmInnerState.IS_NONCE + 0, T6);
            st64(R_ST, VmInnerState.IS_NONCE + 8, T6);

            // rev[0..255] = 0xFF
            movi(T6, 0);
            movi(T7, 0xFF);
            A.bind(L_rev_z);
            lea(T8, R_ST, VmInnerState.IS_REV);
            add(T8, T8, T6);
            st8(T8, 0, T7);
            movi(T8, 1);
            add(T6, T6, T8);
            movi(T9, 256);
            setcc(T8, T6, T9, VmIsaM.M_CC_ULT);
            jnz(T8, L_rev_z);

            // 解密 opcode_map（IS_OPMAP[i] = image[64+i] ^ ks(64+i)），i < nsem
            movi(T6, 0);                           // i
            A.bind(L_dmap);
            // pos = 64 + i
            movi(T7, IV_HEADER);
            add(T8, T7, T6);
            callL(L_ksbyte);                       // T8 = keystream 字节
            // 明文 = image[64+i] ^ ks（不修改镜像，保持幂等）
            movi(T7, IV_HEADER);
            add(T9, T7, T6);
            add(T9, R_IMG, T9);
            ld8(T7, T9, 0);
            xor_(T7, T7, T8);
            // IS_OPMAP[i] = 明文
            lea(T9, R_ST, VmInnerState.IS_OPMAP);
            add(T9, T9, T6);
            st8(T9, 0, T7);
            movi(T9, 1);
            add(T6, T6, T9);
            ld32(T9, R_ST, VmInnerState.IS_NSEM);
            setcc(T8, T6, T9, VmIsaM.M_CC_ULT);
            jnz(T8, L_dmap);

            // 建反向表 rev[opc] = sem（并校验 opcode_map 为 0..nsem-1 的排列）
            movi(T6, 0);                           // s
            A.bind(L_rev_b);
            // T7 = opc = IS_OPMAP[s]
            lea(T9, R_ST, VmInnerState.IS_OPMAP);
            add(T9, T9, T6);
            ld8(T7, T9, 0);
            ld32(T9, R_ST, VmInnerState.IS_NSEM);
            setcc(T8, T7, T9, VmIsaM.M_CC_UGE);
            jnz(T8, L_e_badop);
            // T9 = &rev[opc]
            lea(T9, R_ST, VmInnerState.IS_REV);
            add(T9, T9, T7);
            ld8(T8, T9, 0);                        // rev[opc]（尚未写入 -> 应为 0xFF）
            movi(V1, 0xFF);
            setcc(V2, T8, V1, VmIsaM.M_CC_NE);
            jnz(V2, L_e_badop);                    // 重复 opcode -> 非排列
            st8(T9, 0, T6);                        // rev[opc] = s
            movi(T9, 1);
            add(T6, T6, T9);
            ld32(T9, R_ST, VmInnerState.IS_NSEM);
            setcc(T8, T6, T9, VmIsaM.M_CC_ULT);
            jnz(T8, L_rev_b);

            // ================= 主循环 =================
            A.bind(L_loop);
            // steps++ 且 <= MAX
            ld32(T6, R_ST, VmInnerState.IS_STEPS);
            movi(T7, 1);
            add(T6, T6, T7);
            st32(R_ST, VmInnerState.IS_STEPS, T6);
            movi(T7, IV_MAX_STEPS);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGT);
            jnz(T8, L_e_deep);
            // jumped = 0
            movi(T6, 0);
            st32(R_ST, VmInnerState.IS_JUMPED, T6);
            // 取指
            callL(L_fetch);
            ld32(T6, R_ST, VmInnerState.IS_STATUS);
            jnz(T6, L_halt_nr);                    // 取指失败：未解密/已自行回写，直接停机
            // 分派：idx = family ? sem+36 : sem
            ld32(T6, R_ST, VmInnerState.IS_SEM);
            ld32(T7, R_ST, VmInnerState.IS_FAMILY);
            jz(T7, L_disp_go);
            movi(T7, 36);
            add(T6, T6, T7);
            A.bind(L_disp_go);
            movi(T7, 2);
            shl(T6, T6, T7);                       // idx*4
            add(T6, R_HT, T6);
            ld32(T6, T6, 0);                       // handler 绝对偏移
            callr(T6);
            // 回加密
            callL(L_reenc);
            // 状态？
            ld32(T6, R_ST, VmInnerState.IS_STATUS);
            jnz(T6, L_halt_st);
            // RET？
            ld32(T6, R_ST, VmInnerState.IS_SEM);
            ld32(T7, R_ST, VmInnerState.IS_RETC);
            setcc(T8, T6, T7, VmIsaM.M_CC_EQ);
            jnz(T8, L_ret_ok);
            // jumped？
            ld32(T6, R_ST, VmInnerState.IS_JUMPED);
            jnz(T6, L_loop);
            // ip += ilen
            ld32(T6, R_ST, VmInnerState.IS_IP);
            ld32(T7, R_ST, VmInnerState.IS_ILEN);
            add(T6, T6, T7);
            st32(R_ST, VmInnerState.IS_IP, T6);
            jmpL(L_loop);

            A.bind(L_halt_st);
            A.bind(L_halt_nr);                     // 与 L_halt_st 同体（均以 IS_STATUS 停机）
            ld32(T6, R_ST, VmInnerState.IS_STATUS);
            halt(T6, T6);

            A.bind(L_ret_ok);
            ld32(T6, R_ST, VmInnerState.IS_RETVAL);
            halt(ZR, T6);

            // ================= keystream 单字节子程序 =================
            // 入 m8 = 镜像内绝对偏移；出 m8 = keystream 字节。
            // 保留 m0..m7 与 m10；破坏 m8(出入)/m9/m11..m15。
            A.bind(L_ksbyte);
            movi(T9, 6);
            shr(T9, T8, T9);                       // blk = pos >> 6
            ld32(V0, R_ST, VmInnerState.IS_KSCNT); // V0 = 当前块号
            setcc(V1, T9, V0, VmIsaM.M_CC_EQ);
            jnz(V1, L_ks_hit);
            st32(R_ST, VmInnerState.IS_KSCNT, T9);
            // 零化 64B 块缓冲
            movi(V1, 0);
            A.bind(L_ks_zero);
            lea(V2, R_ST, VmInnerState.IS_KSBLK);
            add(V2, V2, V1);
            st64(V2, 0, ZR);
            movi(V2, 8);
            add(V1, V1, V2);
            movi(V2, 64);
            setcc(V3, V1, V2, VmIsaM.M_CC_ULT);
            jnz(V3, L_ks_zero);
            // 宿主 ChaCha：m12=buf, m13=len, m14=key, m15=nonce, m11=counter
            lea(V1, R_ST, VmInnerState.IS_KSBLK);  // m12 = buf
            movi(V2, 64);                          // m13 = len
            lea(V3, R_ST, VmInnerState.IS_KEY);    // m14 = key
            lea(V4, R_ST, VmInnerState.IS_NONCE);  // m15 = nonce
            mov(V0, T9);                           // m11 = counter = blk
            host(VmIsaM.M_HOST_CHACHA);
            A.bind(L_ks_hit);
            movi(T9, 63);
            and_(T8, T8, T9);
            lea(T9, R_ST, VmInnerState.IS_KSBLK);
            add(T9, T9, T8);
            ld8(T8, T9, 0);
            ret();

            // ================= 取指子程序 =================
            // 就地解密当前指令并解出 opc/imm/rd/ra/rb；失败置 IS_STATUS 并返回。
            A.bind(L_fetch);
            {
                // 边界：ip > bcs || ip+ilen > bcs（失败时未解密，无需回加密）
                ld32(T6, R_ST, VmInnerState.IS_IP);
                ld32(T7, R_ST, VmInnerState.IS_BCSIZE);
                setcc(T8, T6, T7, VmIsaM.M_CC_UGT);
                jnz(T8, L_ff_fault);               // ip > bcs
                ld32(T8, R_ST, VmInnerState.IS_ILEN);
                add(T6, T6, T8);                   // ip + ilen
                setcc(T8, T6, T7, VmIsaM.M_CC_UGT);
                jnz(T8, L_ff_fault);
                // off = BCOFF + IP（边界通过后再记录 IPIMG）
                ld32(T6, R_ST, VmInnerState.IS_BCOFF);
                ld32(T7, R_ST, VmInnerState.IS_IP);
                add(T6, T6, T7);                   // off
                st32(R_ST, VmInnerState.IS_IPIMG, T6);
                // 解密 ilen 字节（T6=off, T7=i）
                movi(T7, 0);
                A.bind(L_ffb_loop);
                mov(T8, T6);
                add(T8, T8, T7);                   // pos
                callL(L_ksbyte);                   // m8 = byte
                mov(T9, R_IMG);
                add(T9, T9, T6);
                add(T9, T9, T7);                   // addr = image + off + i
                ld8(V0, T9, 0);
                xor_(V0, V0, T8);
                st8(T9, 0, V0);                    // 就地解密
                lea(V1, R_ST, VmInnerState.IS_KS5);
                add(V1, V1, T7);
                st8(V1, 0, T8);
                movi(V1, 1);
                add(T7, T7, V1);
                ld32(T9, R_ST, VmInnerState.IS_ILEN);
                setcc(T8, T7, T9, VmIsaM.M_CC_ULT);
                jnz(T8, L_ffb_loop);
                // opc -> sem
                mov(T9, R_IMG);
                add(T9, T9, T6);
                ld8(T8, T9, 0);                    // opc
                lea(T9, R_ST, VmInnerState.IS_REV);
                add(T9, T9, T8);
                ld8(T9, T9, 0);                    // sem
                st32(R_ST, VmInnerState.IS_SEM, T9);
                ld32(V0, R_ST, VmInnerState.IS_NSEM);
                setcc(T8, T9, V0, VmIsaM.M_CC_UGE);
                jnz(T8, L_ff_badop);
                // 解码字段
                ld32(T9, R_ST, VmInnerState.IS_FAMILY);
                jnz(T9, L_ffb_b);
                // A：imm = LE32(image + off + 1)
                mov(T9, R_IMG);
                add(T9, T9, T6);
                ld32(V0, T9, 1);
                st32(R_ST, VmInnerState.IS_IMM, V0);
                movi(V0, 0);
                st32(R_ST, VmInnerState.IS_RD, V0);
                st32(R_ST, VmInnerState.IS_RA, V0);
                st32(R_ST, VmInnerState.IS_RB, V0);
                jmpL(L_ffd_done);
                A.bind(L_ffb_b);
                mov(T9, R_IMG);
                add(T9, T9, T6);
                ld8(V0, T9, 1);
                st32(R_ST, VmInnerState.IS_RD, V0);
                ld8(V0, T9, 2);
                st32(R_ST, VmInnerState.IS_RA, V0);
                ld8(V0, T9, 3);
                st32(R_ST, VmInnerState.IS_RB, V0);
                ld32(V0, T9, 4);
                st32(R_ST, VmInnerState.IS_IMM, V0);
                A.bind(L_ffd_done);
                ret();

                A.bind(L_ff_fault);
                movi(T6, IERR_FAULT);
                st32(R_ST, VmInnerState.IS_STATUS, T6);
                ret();
                A.bind(L_ff_badop);
                callL(L_reenc);                    // 已解密，先回写密文
                movi(T6, IERR_BADOP);
                st32(R_ST, VmInnerState.IS_STATUS, T6);
                ret();
            }

            // ================= 回加密子程序 =================
            A.bind(L_reenc);
            ld32(T6, R_ST, VmInnerState.IS_IPIMG);
            movi(T7, 0);
            A.bind(L_re_loop);
            lea(T8, R_ST, VmInnerState.IS_KS5);
            add(T8, T8, T7);
            ld8(T8, T8, 0);
            mov(T9, R_IMG);
            add(T9, T9, T6);
            add(T9, T9, T7);
            ld8(V0, T9, 0);
            xor_(V0, V0, T8);
            st8(T9, 0, V0);
            movi(V0, 1);
            add(T7, T7, V0);
            ld32(T9, R_ST, VmInnerState.IS_ILEN);
            setcc(T8, T7, T9, VmIsaM.M_CC_ULT);
            jnz(T8, L_re_loop);
            ret();

            // ================= 条件码求值子程序 =================
            // 入 V0=cc, V1=a, V2=b；出 V0 = 0/1；破坏 T6..T9,V3,V4。
            A.bind(L_cceval);
            {
                final int done = A.nlabel();
                final int fb = A.nlabel();
                final int n1 = A.nlabel();
                final int n2 = A.nlabel();
                final int n3 = A.nlabel();
                final int n4 = A.nlabel();
                final int n5 = A.nlabel();
                final int n6 = A.nlabel();
                final int n7 = A.nlabel();
                final int n8 = A.nlabel();
                final int n9 = A.nlabel();
                caseDo(VmIsaM.M_CC_EQ, n1, done);
                A.bind(n1);
                caseDo(VmIsaM.M_CC_NE, n2, done);
                A.bind(n2);
                caseDo(VmIsaM.M_CC_ULT, n3, done);
                A.bind(n3);
                caseDo(VmIsaM.M_CC_UGE, n4, done);
                A.bind(n4);
                caseDo(VmIsaM.M_CC_ULE, n5, done);
                A.bind(n5);
                caseDo(VmIsaM.M_CC_UGT, n6, done);
                A.bind(n6);
                caseDo(VmIsaM.M_CC_SLT, n7, done);
                A.bind(n7);
                caseDo(VmIsaM.M_CC_SGE, n8, done);
                A.bind(n8);
                caseDo(VmIsaM.M_CC_SLE, n9, done);
                A.bind(n9);
                caseDo(VmIsaM.M_CC_SGT, fb, done);
                A.bind(fb);
                movi(V3, 0);                       // 未知条件码 -> 0
                A.bind(done);
                mov(V0, V3);
                ret();
            }

            // ================= A 族 handler =================
            LA = new int[IV_SEM_COUNT];
            for (int i = 0; i < IV_SEM_COUNT; i++) {
                LA[i] = A.nlabel();
            }

            A.bind(LA[A_NOP]);
            ret();

            A.bind(LA[A_PUSH]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            push32(V0);
            ret();

            A.bind(LA[A_LOAD]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V0, V0, T6);
            movi(T6, 2);
            shl(V0, V0, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V0);
            ld32(V0, T7, 0);
            push32(V0);
            ret();

            A.bind(LA[A_STORE]);
            pop32(V0);
            ld32(V1, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V1, V1, T6);
            movi(T6, 2);
            shl(V1, V1, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V1);
            st32(T7, 0, V0);
            ret();

            A.bind(LA[A_DUP]);
            ld32(T6, R_ST, VmInnerState.IS_SP);
            setcc(T7, T6, ZR, VmIsaM.M_CC_EQ);
            jnz(T7, L_err_under);
            ld32(T7, R_ST, VmInnerState.IS_STACKW);
            setcc(T8, T6, T7, VmIsaM.M_CC_UGE);
            jnz(T8, L_err_over);
            movi(T8, 2);
            shl(T7, T6, T8);
            lea(T8, R_ST, VmInnerState.IS_STACK);
            add(T8, T8, T7);
            ld32(V0, T8, -4);                      // stack[sp-1]
            st32(T8, 0, V0);
            movi(T8, 1);
            add(T6, T6, T8);
            st32(R_ST, VmInnerState.IS_SP, T6);
            ret();

            A.bind(LA[A_SWAP]);
            ld32(T6, R_ST, VmInnerState.IS_SP);
            movi(T7, 2);
            setcc(T8, T6, T7, VmIsaM.M_CC_ULT);
            jnz(T8, L_err_under);
            movi(T7, 2);
            shl(T6, T6, T7);
            lea(T7, R_ST, VmInnerState.IS_STACK);
            add(T7, T7, T6);
            ld32(V0, T7, -4);
            ld32(V1, T7, -8);
            st32(T7, -4, V1);
            st32(T7, -8, V0);
            ret();

            A.bind(LA[A_POP]);
            ld32(T6, R_ST, VmInnerState.IS_SP);
            setcc(T7, T6, ZR, VmIsaM.M_CC_EQ);
            jnz(T7, L_err_under);
            movi(T7, 1);
            sub_(T6, T6, T7);
            st32(R_ST, VmInnerState.IS_SP, T6);
            ret();

            binA(A_ADD, VmIsaM.M_ADD);
            binA(A_SUB, VmIsaM.M_SUB);
            binA(A_MUL, VmIsaM.M_MUL);
            binA(A_AND, VmIsaM.M_AND);
            binA(A_OR, VmIsaM.M_OR);
            binA(A_XOR, VmIsaM.M_XOR);
            shiftA(A_SHL, VmIsaM.M_SHL);
            shiftA(A_SHR, VmIsaM.M_SHR);
            shiftA(A_SAR, VmIsaM.M_SAR);

            A.bind(LA[A_NEG]);
            pop32(V0);
            movi(V1, 0);
            sub_(V0, V1, V0);
            push32(V0);
            ret();

            A.bind(LA[A_NOT]);
            pop32(V0);
            not_(V0, V0);
            push32(V0);
            ret();

            A.bind(LA[A_JMP]);
            reljmpA();
            ret();

            A.bind(LA[A_JZ]);
            {
                final int l = A.nlabel();
                pop32(V0);
                jnz(V0, l);
                reljmpA();
                A.bind(l);
                ret();
            }

            A.bind(LA[A_JNZ]);
            {
                final int l = A.nlabel();
                pop32(V0);
                jz(V0, l);
                reljmpA();
                A.bind(l);
                ret();
            }

            A.bind(LA[A_RET]);
            pop32(V0);
            st32(R_ST, VmInnerState.IS_RETVAL, V0);
            ret();

            A.bind(LA[A_MEMRD]);
            pop32(V1);                             // hi
            pop32(V0);                             // lo
            buildBase(V1, V0);
            sx_imm(V1);
            add(V0, V0, V1);
            ld32(V0, V0, 0);
            push32(V0);
            ret();

            A.bind(LA[A_MEMWR]);
            pop32(V2);                             // val
            pop32(V1);                             // hi
            pop32(V0);                             // lo
            buildBase(V1, V0);
            sx_imm(V1);
            add(V0, V0, V1);
            st32(V0, 0, V2);
            ret();

            A.bind(LA[A_ADDREL]);
            pop32(V1);                             // hi
            pop32(V0);                             // lo
            buildBase(V1, V0);
            sx_imm(V1);
            add(V0, V0, V1);
            push32(V0);
            movi(T6, 32);
            shr(V1, V0, T6);
            push32(V1);
            ret();

            A.bind(LA[A_NATIVE]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            mov(V1, V0);                           // m12 = imm
            host(VmIsaM.M_HOST_INNER_NATIVE);      // m12 = status
            {
                final int l = A.nlabel();
                jz(V1, l);
                st32(R_ST, VmInnerState.IS_STATUS, V1);
                A.bind(l);
            }
            ret();

            cmpA(A_EQ, VmIsaM.M_CC_EQ);
            cmpA(A_NE, VmIsaM.M_CC_NE);
            cmpA(A_ULT, VmIsaM.M_CC_ULT);
            cmpA(A_UGE, VmIsaM.M_CC_UGE);
            cmpA(A_ULE, VmIsaM.M_CC_ULE);
            cmpA(A_UGT, VmIsaM.M_CC_UGT);
            cmpA(A_SLT, VmIsaM.M_CC_SLT);
            cmpA(A_SGE, VmIsaM.M_CC_SGE);
            cmpA(A_SLE, VmIsaM.M_CC_SLE);
            cmpA(A_SGT, VmIsaM.M_CC_SGT);

            // ================= B 族 handler =================
            LB = new int[IV_REG_COUNT];
            for (int i = 0; i < IV_REG_COUNT; i++) {
                LB[i] = A.nlabel();
            }

            A.bind(LB[B_NOP]);
            ret();

            A.bind(LB[B_MOVI]);
            rdno(V0);
            slotaddr(V0, T7);
            ld32(V1, R_ST, VmInnerState.IS_IMM);
            stlo_clrhi(T7, V1);
            ret();

            A.bind(LB[B_SET64]);
            rdno(V0);
            slotaddr(V0, T7);
            ld32(V1, R_ST, VmInnerState.IS_IMM);
            st32(T7, 0, V1);
            movi(T6, 31);
            sar(V1, V1, T6);
            st32(T7, 4, V1);
            ret();

            A.bind(LB[B_MOV]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V1, T7, 0);
            rdno(V2);
            slotaddr(V2, T7);
            stlo_clrhi(T7, V1);
            ret();

            binB(B_ADD, VmIsaM.M_ADD);
            binB(B_SUB, VmIsaM.M_SUB);
            binB(B_MUL, VmIsaM.M_MUL);
            binB(B_AND, VmIsaM.M_AND);
            binB(B_OR, VmIsaM.M_OR);
            binB(B_XOR, VmIsaM.M_XOR);

            shiftB(B_SHL, VmIsaM.M_SHL, false);
            shiftB(B_SHR, VmIsaM.M_SHR, false);
            shiftB(B_SAR, VmIsaM.M_SAR, true);

            A.bind(LB[B_NEG]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V2, T7, 0);
            movi(V3, 0);
            sub_(V2, V3, V2);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V2);
            ret();

            A.bind(LB[B_NOT]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V2, T7, 0);
            not_(V2, V2);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V2);
            ret();

            A.bind(LB[B_FLD]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V0, V0, T6);
            movi(T6, 2);
            shl(V0, V0, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V0);
            ld32(V1, T7, 0);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V1);
            ret();

            A.bind(LB[B_FLD64]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V0, V0, T6);
            movi(T6, 2);
            shl(V0, V0, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V0);
            ld32(V1, T7, 0);                       // lo
            ld32(V2, T7, 4);                       // hi（imm+1 与 imm 相邻槽）
            rdno(V0);
            slotaddr(V0, T7);
            st32(T7, 0, V1);
            st32(T7, 4, V2);
            ret();

            A.bind(LB[B_FST]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V1, T7, 0);
            ld32(V2, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V2, V2, T6);
            movi(T6, 2);
            shl(V2, V2, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V2);
            st32(T7, 0, V1);
            ret();

            A.bind(LB[B_FST64]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V1, T7, 0);
            ld32(V2, T7, 4);                       // lo, hi
            ld32(V3, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_FRAME_MASK);
            and_(V3, V3, T6);
            movi(T6, 2);
            shl(V3, V3, T6);
            lea(T7, R_ST, VmInnerState.IS_FRAME);
            add(T7, T7, V3);
            st32(T7, 0, V1);
            st32(T7, 4, V2);
            ret();

            A.bind(LB[B_LD]);
            rano(V0);
            load64(V0);
            sx_imm(V1);
            add(V2, V2, V1);
            ld32(V3, V2, 0);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V3);
            ret();

            A.bind(LB[B_ST]);
            rano(V0);
            load64(V0);
            sx_imm(V1);
            add(V2, V2, V1);
            rbno(V0);
            slotaddr(V0, T7);
            ld32(V3, T7, 0);
            st32(V2, 0, V3);
            ret();

            A.bind(LB[B_LEA]);
            rano(V0);
            load64(V0);
            sx_imm(V1);
            add(V2, V2, V1);
            rdno(V0);
            slotaddr(V0, T7);
            st32(T7, 0, V2);
            movi(T6, 32);
            shr(V3, V2, T6);
            st32(T7, 4, V3);
            ret();

            A.bind(LB[B_SETCC]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V1, T7, 0);
            rbno(V0);
            slotaddr(V0, T7);
            ld32(V2, T7, 0);
            rdno(V0);                              // V0 = cc
            callL(L_cceval);                       // V0 = 0/1
            rdno(V3);
            slotaddr(V3, T7);
            stlo_clrhi(T7, V0);
            ret();

            A.bind(LB[B_JCC]);
            {
                final int l = A.nlabel();
                rano(V0);
                slotaddr(V0, T7);
                ld32(V1, T7, 0);
                rbno(V0);
                slotaddr(V0, T7);
                ld32(V2, T7, 0);
                rdno(V0);                          // V0 = cc
                callL(L_cceval);
                jz(V0, l);
                ld32(V3, R_ST, VmInnerState.IS_IMM);
                st32(R_ST, VmInnerState.IS_IP, V3);
                movi(V3, 1);
                st32(R_ST, VmInnerState.IS_JUMPED, V3);
                A.bind(l);
                ret();
            }

            A.bind(LB[B_JMP]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            st32(R_ST, VmInnerState.IS_IP, V0);
            movi(V0, 1);
            st32(R_ST, VmInnerState.IS_JUMPED, V0);
            ret();

            A.bind(LB[B_RET]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V1, T7, 0);
            st32(R_ST, VmInnerState.IS_RETVAL, V1);
            ret();

            A.bind(LB[B_NATIVE]);
            ld32(V0, R_ST, VmInnerState.IS_IMM);
            mov(V1, V0);
            host(VmIsaM.M_HOST_INNER_NATIVE);
            {
                final int l = A.nlabel();
                jz(V1, l);
                st32(R_ST, VmInnerState.IS_STATUS, V1);
                A.bind(l);
            }
            ret();

            // ================= 全局错误出口 =================
            A.bind(L_err_over);
            movi(T6, IERR_OVER);
            st32(R_ST, VmInnerState.IS_STATUS, T6);
            ret();

            A.bind(L_err_under);
            movi(T6, IERR_UNDER);
            st32(R_ST, VmInnerState.IS_STATUS, T6);
            ret();

            A.bind(L_e_badmagic);
            movi(T6, IERR_MAGIC);
            halt(T6, T6);
            A.bind(L_e_fault);
            movi(T6, IERR_FAULT);
            halt(T6, T6);
            A.bind(L_e_badop);
            movi(T6, IERR_BADOP);
            halt(T6, T6);
            A.bind(L_e_deep);
            movi(T6, IERR_DEEP);
            halt(T6, T6);
        }

        // ---------------- handler 模板 ----------------

        /** 二元算术模板（A 族）。 */
        private void binA(int sem, int op) {
            A.bind(LA[sem]);
            pop32(V1);              // b
            pop32(V0);              // a
            A.e(op, V0, V0, V1);
            push32(V0);
            ret();
        }

        /** 移位模板（A 族，位移量取低 5 位）。 */
        private void shiftA(int sem, int op) {
            A.bind(LA[sem]);
            pop32(V1);
            pop32(V0);
            movi(T6, 31);
            and_(V1, V1, T6);
            A.e(op, V0, V0, V1);
            push32(V0);
            ret();
        }

        /** 比较模板（A 族）。 */
        private void cmpA(int sem, int cc) {
            A.bind(LA[sem]);
            pop32(V1);
            pop32(V0);
            setcc(V2, V0, V1, cc);
            push32(V2);
            ret();
        }

        /** ip += imm*5（A 族相对跳转）。 */
        private void reljmpA() {
            ld32(V1, R_ST, VmInnerState.IS_IMM);
            movi(T6, IV_INSN_A);
            mul(V1, V1, T6);
            ld32(T6, R_ST, VmInnerState.IS_IP);
            add(T6, T6, V1);
            st32(R_ST, VmInnerState.IS_IP, T6);
        }

        /** MEMRD/MEMWR/ADDREL：base = (hi&lt;&lt;32)|lo。 */
        private void buildBase(int hiV, int loV) {
            movi(T6, 32);
            shl(hiV, hiV, T6);
            or_(loV, loV, hiV);
        }

        /** 二元算术模板（B 族）。 */
        private void binB(int sem, int op) {
            A.bind(LB[sem]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V2, T7, 0);                       // a
            rbno(V1);
            slotaddr(V1, T7);
            ld32(V3, T7, 0);                       // b
            A.e(op, V2, V2, V3);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V2);
            ret();
        }

        /** 移位模板（B 族；算术右移先符号扩展到 64 位）。 */
        private void shiftB(int sem, int op, boolean arith) {
            A.bind(LB[sem]);
            rano(V0);
            slotaddr(V0, T7);
            ld32(V2, T7, 0);
            rbno(V1);
            slotaddr(V1, T7);
            ld32(V3, T7, 0);
            if (arith) {                           // 先符号扩展到 64
                movi(T6, 32);
                shl(V2, V2, T6);
                movi(T6, 32);
                sar(V2, V2, T6);
            }
            movi(T6, 31);
            and_(V3, V3, T6);
            A.e(op, V2, V2, V3);
            rdno(V0);
            slotaddr(V0, T7);
            stlo_clrhi(T7, V2);
            ret();
        }

        /** b64 = RB(ra) | (RBH(ra)&lt;&lt;32) -&gt; V2。 */
        private void load64(int regNoV) {
            slotaddr(regNoV, T7);
            ld32(V2, T7, 0);
            ld32(V3, T7, 4);
            movi(T6, 32);
            shl(V3, V3, T6);
            or_(V2, V2, V3);
        }

        // ---------------- B 族字段读取 ----------------

        private void rdno(int v) {
            ld32(v, R_ST, VmInnerState.IS_RD);
        }

        private void rano(int v) {
            ld32(v, R_ST, VmInnerState.IS_RA);
        }

        private void rbno(int v) {
            ld32(v, R_ST, VmInnerState.IS_RB);
        }

        /** 写 32 位并清 hi。 */
        private void stlo_clrhi(int addrT, int valV) {
            st32(addrT, 0, valV);
            st32(addrT, 4, ZR);
        }

        /** 条件码单分支：cc 匹配则求值并跳到 done，否则落到 next。 */
        private void caseDo(int cc, int next, int done) {
            movi(T6, cc);
            setcc(T7, V0, T6, VmIsaM.M_CC_EQ);
            jz(T7, next);
            setcc(V3, V1, V2, cc);
            jmpL(done);
        }

        // ---------------- 构建 ----------------

        VmMeta.MetaBuildResult build(int seed) {
            run();
            A.resolve();

            // ---- handler 偏移表：0..35 = A 族，36..62 = B 族（绝对字节偏移）----
            int[] tab = new int[VmIsaM.M_HANTAB_ENTRIES];
            for (int s = 0; s < IV_SEM_COUNT; s++) {
                tab[s] = A.lb.get(LA[s]) * VmIsaM.M_INSN_SIZE;
            }
            for (int s = 0; s < IV_REG_COUNT; s++) {
                tab[36 + s] = A.lb.get(LB[s]) * VmIsaM.M_INSN_SIZE;
            }

            VmMeta.MetaBuildOpt opt = new VmMeta.MetaBuildOpt();
            opt.seed = seed;
            opt.entry = 0;
            if (System.getenv("KBOX_DUMP_META") != null) {
                for (int i = 0; i < A.code.size(); i++) {
                    VmIsaM.MInsn in = A.code.get(i);
                    System.err.println("  meta[" + i + "] op=" + (in.op & 0xFF)
                            + " dst=" + (in.dst & 0xFF) + " src=" + (in.src & 0xFF)
                            + " aux=" + (in.aux & 0xFF)
                            + " imm=" + Integer.toUnsignedString(in.imm));
                }
            }
            return VmMeta.vmBuildM(A.code, tab, opt);
        }
    }

    // ==================================================================
    // ---- 公开 API ----
    // ==================================================================

    /** 生成"内层解释器"Meta 程序镜像（对应 C++ vm_build_inner_meta）。 */
    public static VmMeta.MetaBuildResult vmBuildInnerMeta(int seed) {
        return new Gen().build(seed);
    }

    // ---------------- 嵌套执行（测试 / 预演） ----------------

    /**
     * 测试用：在宿主内以 Meta 引擎嵌套执行内层镜像（对应 C++ vm_exec_inner_nested）。
     *
     * <p>Java 侧无原生指针，故地址空间取「传给 {@code vmMetaExec} 的 image 数组」，
     * 即地址 = 数组下标：arena = [Meta 镜像][8 对齐][内层状态块 IS_SIZE][内层镜像]，
     * m0 = 状态块下标、m1 = 内层镜像下标、m2 = 内层字节数。内层状态块与内层镜像
     * 的读写因此落在同一扁平地址空间内（与 C++ 的 m0/m1 语义等价）。</p>
     *
     * @param innerImage 内层镜像（明文；执行后就地解密/回加密，净变化为零）
     * @param innerSize  内层镜像字节数
     * @param gprs       16×u64 机器寄存器块（可为 null）；进出经 IS_FRAME 槽
     * @param out        非 null 且执行成功时写回 M_HALT 的 retval
     * @param metaImage  Meta 引擎镜像（{@link #vmBuildInnerMeta} 产出）
     * @return 内层状态码（M_OK / M_ERR_*）
     */
    public static int vmExecInnerNested(byte[] innerImage, int innerSize, long[] gprs,
                                        int[] out, byte[] metaImage) {
        // 内层状态块（宿主栈上）+ 内层镜像 + Meta 镜像同处一个扁平地址空间
        final int stateOff = Bin.alignUp(metaImage.length, 8);
        final int imgOff = stateOff + VmInnerState.IS_SIZE;   // IS_SIZE 为 8 的倍数
        final byte[] arena = new byte[imgOff + innerSize];
        System.arraycopy(metaImage, 0, arena, 0, metaImage.length);
        System.arraycopy(innerImage, 0, arena, imgOff, innerSize);
        // 状态块已为全零（等价 std::memset(state, 0, sizeof(state))）

        // 机器寄存器 -> 内层帧槽（lo = 2g, hi = 2g+1）
        if (gprs != null) {
            for (int g = 0; g < VmIsa.GPR_COUNT; g++) {
                final int lo = (int) gprs[g];
                final int hi = (int) (gprs[g] >>> 32);
                Bin.w32(arena, stateOff + VmInnerState.IS_FRAME + (2 * g) * 4, lo);
                Bin.w32(arena, stateOff + VmInnerState.IS_FRAME + (2 * g + 1) * 4, hi);
            }
        }

        long[] m = new long[VmIsaM.M_REGS];
        m[0] = stateOff;
        m[1] = imgOff;
        m[2] = innerSize;
        m[3] = 0;   // gprs：内层程序不直接引用（寄存器经 IS_FRAME 槽读写）
        m[4] = 0;   // ks_fn：内层 keystream 经 M_HOST_CHACHA 直接由 ChaCha20 完成

        int[] retval = new int[1];
        final int rc = VmMeta.vmMetaExec(arena, arena.length, 0, m, INNER_META_HOST, arena, retval);
        if (rc == VmIsaM.M_OK && out != null) {
            out[0] = retval[0];
        }

        // 写回机器寄存器块，并回写内层镜像（幂等，与 C++ 就地语义一致）
        if (gprs != null) {
            for (int g = 0; g < VmIsa.GPR_COUNT; g++) {
                final int lo = Bin.i32(arena, stateOff + VmInnerState.IS_FRAME + (2 * g) * 4);
                final int hi = Bin.i32(arena, stateOff + VmInnerState.IS_FRAME + (2 * g + 1) * 4);
                gprs[g] = (lo & 0xFFFFFFFFL) | ((hi & 0xFFFFFFFFL) << 32);
            }
        }
        System.arraycopy(arena, imgOff, innerImage, 0, innerSize);
        return rc;
    }

    // ---- 宿主逃逸回调（M_HOST）----

    /**
     * 内层 native_fn 未接入 → 返回 FAULT（与 vm_exec_mach(native_fn=nullptr) 一致）；
     * M_HOST_CHACHA 由 ChaCha20 直接完成。
     */
    private static int innerMetaHost(Object hostArg, int prim, long[] m) {
        switch (prim) {
            case VmIsaM.M_HOST_CHACHA: {
                final byte[] mem = (byte[]) hostArg;
                final int buf = (int) m[12];
                final int len = (int) m[13];
                final int keyOff = (int) m[14];
                final int counter = (int) m[11];
                int[] key = new int[8];
                for (int i = 0; i < 8; i++) {
                    key[i] = Bin.i32(mem, keyOff + 4 * i);
                }
                byte[] ks = new byte[64];
                for (int pos = 0; pos < len; ) {
                    VmKs.vmKsBlock(key, counter + (pos >>> 6), ks, 0);
                    final int off = pos & 63;
                    final int n = ((64 - off) < (len - pos)) ? (64 - off) : (len - pos);
                    for (int i = 0; i < n; i++) {
                        mem[buf + pos + i] ^= ks[off + i];
                    }
                    pos += n;
                }
                return VmIsaM.M_OK;
            }
            case VmIsaM.M_HOST_INNER_NATIVE:
                m[12] = IERR_FAULT;   // 无原生片段执行器
                return VmIsaM.M_OK;
            default:
                return VmIsaM.M_ERR_FAULT;
        }
    }

    private static final VmMeta.MHostFn INNER_META_HOST = new VmMeta.MHostFn() {
        @Override
        public int call(Object hostArg, int prim, long[] m) {
            return innerMetaHost(hostArg, prim, m);
        }
    };
}
