package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * VmTranslate — 目标函数 → VM 语义流翻译器（由 packer/vm/vm_translate.cpp 移植）。
 *
 * <p>覆盖 samples/sample.cpp 中的 mix 函数（纯 32 位无符号计算，无调用/内存访问），
 * 作为构建期自检与测试锚点；通用 x86/x64 基本块翻译见 {@link LiftX64}。</p>
 */
public final class VmTranslate {

    private VmTranslate() {
    }

    /** mix 原生参考实现（构建期自检 / 测试锚点）。 */
    public static int vmNativeMix(int x) {
        x ^= x << 13;
        x ^= x >>> 17;
        x ^= x << 5;
        x = x * 0x9E3779B1 + 0x85EBCA6B;
        return x;
    }

    /** mix 函数的 VM 语义流（与 vmNativeMix 逐操作对应；参数在 frame[0]，结果 RET 弹出）。 */
    public static List<VmIsa.Insn> vmTranslateMix() {
        List<VmIsa.Insn> p = new ArrayList<>();
        // x ^= x << 13
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_PUSH, 13));
        p.add(i(VmIsa.SEM_SHL, 0));
        p.add(i(VmIsa.SEM_XOR, 0));
        p.add(i(VmIsa.SEM_STORE, 0));
        // x ^= x >> 17
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_PUSH, 17));
        p.add(i(VmIsa.SEM_SHR, 0));
        p.add(i(VmIsa.SEM_XOR, 0));
        p.add(i(VmIsa.SEM_STORE, 0));
        // x ^= x << 5
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_PUSH, 5));
        p.add(i(VmIsa.SEM_SHL, 0));
        p.add(i(VmIsa.SEM_XOR, 0));
        p.add(i(VmIsa.SEM_STORE, 0));
        // x = x * 0x9E3779B1 + 0x85EBCA6B
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_PUSH, 0x9E3779B1));
        p.add(i(VmIsa.SEM_MUL, 0));
        p.add(i(VmIsa.SEM_PUSH, 0x85EBCA6B));
        p.add(i(VmIsa.SEM_ADD, 0));
        p.add(i(VmIsa.SEM_STORE, 0));
        p.add(i(VmIsa.SEM_LOAD, 0));
        p.add(i(VmIsa.SEM_RET, 0));
        return p;
    }

    private static VmIsa.Insn i(int sem, int imm) {
        return new VmIsa.Insn(sem, imm);
    }
}
