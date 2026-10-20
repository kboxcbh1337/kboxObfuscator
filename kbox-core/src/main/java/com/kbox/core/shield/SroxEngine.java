package com.kbox.core.shield;

import java.util.ArrayList;
import java.util.List;

/**
 * SROX — 构建期自研究式表示变换引擎。
 *
 * <p>闭环：</p>
 * <ol>
 *   <li><b>语义建模</b>：以提升后的 {@link Ir.IrFunc} 作为程序表示，原表示保持不变。</li>
 *   <li><b>表示探索</b>：按等级从语义保持变换空间生成候选（指令变异、常量分裂、
 *       不可达区域、控制流平坦化、VM 家族/分发方式）。</li>
 *   <li><b>语义验证</b>：候选与原表示做有界差分解释执行；另对无内存访问的函数
 *       做 VM 镜像执行等价检查。</li>
 *   <li><b>可恢复性评估</b>：用结构代理指标淘汰「只变大、不变难」的候选。</li>
 *   <li><b>选择/回滚</b>：选最高分且验证通过的候选；全部失败时回滚到原有
 *       固定变换路径（绝不输出未经验证的破坏性表示）。</li>
 * </ol>
 *
 * <p>本引擎只影响构建产物，不引入运行期自修改，也不依赖任何反调试/反虚拟机
 * 等独立防御机制。</p>
 */
final class SroxEngine {

    private SroxEngine() {
    }

    /** 选中的表示（VM 镜像 + 可读描述）。 */
    static final class Chosen {
        byte[] image;
        String desc = "";
    }

    /**
     * 为一个函数选择最终表示。
     *
     * @param rep 报告收集器（可为 null）
     * @return null 表示连原有路径都无法编译（调用方跳过该函数）
     */
    static Chosen select(Ir.IrFunc fn, ShieldOptions opts, SroxReport rep,
                         int funcRva, StringBuilder log) {
        final long buildSeed = opts == null ? 0L : opts.sroxSeed;
        if (fn == null || fn.insns.isEmpty()) {
            return null;
        }
        if (rep != null) {
            rep.seen(fn.insns.size());
        }
        // 无法解释的函数（IR_NATIVE）不能做差分验证：保留原有固定路径。
        if (SroxSemantics.hasNative(fn)) {
            if (rep != null) rep.skip(funcRva, fn.insns.size(), "native-ir (differential verify unavailable)");
            return legacy(fn, opts, buildSeed);
        }
        if (opts == null || opts.sroxLevel <= 0
                || fn.insns.size() > opts.sroxMaxIrInsns) {
            if (rep != null) rep.skip(funcRva, fn.insns.size(), "disabled or ir too large");
            return legacy(fn, opts, buildSeed);
        }

        final int level = Math.max(1, Math.min(3, opts.sroxLevel));
        final int rounds = Math.max(2, Math.min(16, opts.sroxRounds));
        final int verifyRuns = Math.max(1, Math.min(32, opts.sroxVerifyRuns));
        final int maxSteps = 200000;
        final boolean memFree = !SroxSemantics.hasMemory(fn);
        byte[] identityImage = null;

        long baseSeed = SroxSemantics.mix(buildSeed
                ^ ((long) funcRva * 0x9E3779B97F4A7C15L)
                ^ ((long) fn.insns.size() * 0xD6E8FEB86659FD93L));

        Chosen best = null;
        double bestScore = -1.0;
        String bestDesc = "";
        int bestIr = fn.insns.size();
        int built = 0;
        List<String> lines = new ArrayList<String>();
        boolean verifyFail = false;

        for (int i = 0; i < rounds; ++i) {
            long cseed = SroxSemantics.mix(baseSeed + i * 0xBF58476D1CE4E5B9L);
            int roll = (int) (cseed >>> 32);

            // ---- 候选参数空间（按等级裁剪）----
            int mut;
            boolean flat;
            int cs;
            boolean dead;
            if (i == 0) {
                // 恒等候选：保证「搜索失败也保留既有虚拟机保护」。
                mut = 0;
                flat = false;
                cs = 0;
                dead = false;
            } else {
                mut = level == 1 ? (roll & 1) : ((roll >>> 1) % 3);
                flat = level >= 2 && ((roll & 4) != 0);
                cs = level >= 1 ? ((roll & 8) == 0 ? 2 : ((roll & 16) == 0 ? 1 : 0)) : 0;
                dead = level >= 3 && ((roll & 32) != 0);
            }
            int dispatch = ((roll & 64) != 0) ? VmIsa.DISPATCH_SWITCH : VmIsa.DISPATCH_TABLE;
            boolean wantB = level >= 3 && ((roll & 128) != 0);

            Ir.IrFunc cand = SroxTransforms.copy(fn);
            boolean didCs = cs > 0 && SroxTransforms.splitConstants(cand, cseed, cs);
            if (mut > 0) {
                IrMutate.mutate(cand, (int) (cseed ^ (cseed >>> 32)), mut);
            }
            boolean didDead = dead && SroxTransforms.deadRegions(cand, cseed);
            boolean didFlat = flat && IrFlatten.flatten(cand);

            String desc = (wantB ? "B/reg" : "A/stack")
                    + "/m" + mut
                    + "/" + (didFlat ? "flat" : "linear")
                    + "/" + (dispatch == VmIsa.DISPATCH_SWITCH ? "switch" : "table")
                    + (didCs ? "/+c" : "")
                    + (didDead ? "/+d" : "");
            ++built;

            // ---- 语义差分验证 ----
            StringBuilder why = new StringBuilder();
            if (!SroxSemantics.equivalent(fn, cand, cseed, verifyRuns, maxSteps, why)) {
                verifyFail = true;
                lines.add(desc + "=verify:" + why);
                continue;
            }

            // ---- 编译 + 镜像 ----
            IrCompile.CompileResult cr = IrCompile.irCompile(cand);
            if (!cr.ok) {
                lines.add(desc + "=compile-A");
                continue;
            }
            IrCompile.CompileResultB cb = wantB ? IrCompile.irCompileB(cand) : null;
            final boolean useB = cb != null && cb.ok;
            VmBuilder.VmBuildOpt opt = new VmBuilder.VmBuildOpt();
            int iseed = (int) (cseed ^ (cseed >>> 32));
            opt.seed = iseed | 1;
            opt.dispatch = dispatch;
            opt.variantCap = VmIsa.VM_VARIANTS;
            VmBuilder.VmBuildResult br = useB
                    ? VmBuilder.vmBuildB(cb.program, opt)
                    : VmBuilder.vmBuild(cr.program, opt);
            if (!br.ok || br.image == null || br.image.length == 0) {
                lines.add(desc + "=image");
                continue;
            }
            if (wantB && !useB) {
                desc = desc.replace("B/reg", "A/stack");
            }

            // ---- 镜像执行等价门（仅无内存访问的函数）----
            if (memFree) {
                if (identityImage == null) {
                    identityImage = buildIdentityImage(fn, buildSeed);
                }
                if (identityImage != null) {
                    String gate = imageGate(fn, identityImage, br.image, cseed, verifyRuns);
                    if (gate != null) {
                        lines.add(desc + "=image-gate:" + gate);
                        continue;
                    }
                }
            }

            SroxMetrics m = SroxMetrics.compute(fn, cand);
            double score = m.score;
            // 变异/分裂/死区确实生效时给极小的多样性加成，避免恒等候选
            // 在指标几乎相同时总是胜出（跨构建差异需要结构性变化）。
            if (didCs || didDead || didFlat || mut > 0) {
                score = Math.min(1.0, score + 0.01);
            }
            lines.add(desc + "=" + String.format(java.util.Locale.ROOT,
                    "%.4f (%s)", score, m.summary()));
            if (score > bestScore) {
                bestScore = score;
                best = new Chosen();
                best.image = br.image;
                best.desc = desc;
                bestDesc = desc;
                bestIr = cand.insns.size();
            }
        }

        if (best != null) {
            if (rep != null) {
                if (verifyFail) rep.verifyFailure();
                rep.accept(funcRva, fn.insns.size(), bestIr, bestDesc, bestScore, lines, built);
            }
            return best;
        }

        // 全部候选失败：回滚到原有固定路径（不输出未验证表示）。
        if (rep != null) {
            if (verifyFail) rep.verifyFailure();
            rep.reject(funcRva, fn.insns.size(), built, "no candidate passed verification", lines);
        }
        return legacy(fn, opts, buildSeed);
    }

    /**
     * 原固定路径：变异 → 平坦化 → 双族编译（SROX 关闭/回滚时使用）。
     * 与历史行为一致，保证兼容性。
     */
    static Chosen legacy(Ir.IrFunc fn, ShieldOptions opts, long buildSeed) {
        if (fn == null || fn.insns.isEmpty()) {
            return null;
        }
        Chosen c = new Chosen();
        Ir.IrFunc f = SroxTransforms.copy(fn);
        int seed = (int) (buildSeed ^ (buildSeed >>> 32)) | 1;
        int mut = opts == null ? 1 : opts.irMutation;
        if (mut > 0) {
            IrMutate.mutate(f, seed, mut);
        }
        boolean flat = (opts == null || opts.cfgFlatten) && IrFlatten.flatten(f);
        IrCompile.CompileResult cr = IrCompile.irCompile(f);
        if (!cr.ok) {
            return null;
        }
        IrCompile.CompileResultB cb = IrCompile.irCompileB(f);
        boolean useB = ((seed & 1) != 0) && cb.ok;

        VmBuilder.VmBuildOpt opt = new VmBuilder.VmBuildOpt();
        opt.seed = seed;
        opt.dispatch = ((seed & 2) != 0) ? VmIsa.DISPATCH_SWITCH : VmIsa.DISPATCH_TABLE;
        opt.variantCap = VmIsa.VM_VARIANTS;
        VmBuilder.VmBuildResult br = useB
                ? VmBuilder.vmBuildB(cb.program, opt)
                : VmBuilder.vmBuild(cr.program, opt);
        if (!br.ok) {
            return null;
        }
        c.image = br.image;
        c.desc = "legacy/" + (useB ? "B/reg" : "A/stack")
                + "/m" + mut + (flat ? "/flat" : "/linear")
                + "/" + (opt.dispatch == VmIsa.DISPATCH_SWITCH ? "switch" : "table");
        return c;
    }

    // ---- 镜像等价门 ----

    private static byte[] buildIdentityImage(Ir.IrFunc fn, long seed) {
        IrCompile.CompileResult cr = IrCompile.irCompile(fn);
        if (!cr.ok) {
            return null;
        }
        VmBuilder.VmBuildOpt opt = new VmBuilder.VmBuildOpt();
        opt.seed = (int) (seed ^ (seed >>> 32)) | 1;
        opt.dispatch = VmIsa.DISPATCH_SWITCH;
        opt.variantCap = VmIsa.VM_VARIANTS;
        VmBuilder.VmBuildResult br = VmBuilder.vmBuild(cr.program, opt);
        return br.ok ? br.image : null;
    }

    /**
     * 对无内存访问函数执行「原镜像 vs 候选镜像」等价检查。
     *
     * @return null 表示通过（或不适用），否则返回失败原因
     */
    private static String imageGate(Ir.IrFunc fn, byte[] base, byte[] cand,
                                    long seed, int runs) {
        int gateRuns = Math.max(1, Math.min(2, runs));
        for (int k = 0; k < gateRuns; ++k) {
            long[] in = new long[VmIsa.VM_MACH_GPRS];
            for (int g = 0; g < in.length; ++g) {
                in[g] = SroxSemantics.mix(seed + 0x94D049BB133111EBL * (g + 1 + k * 17));
            }
            long[] a = in.clone();
            long[] b = in.clone();
            int[] oa = new int[1];
            int[] ob = new int[1];
            int ra = VmEngine.vmExecMach(base, base.length, a, oa, null);
            if (ra != VmIsa.VM_OK) {
                return null;      // 原镜像本身不可在 Java 引擎执行：该门不适用
            }
            int rb = VmEngine.vmExecMach(cand, cand.length, b, ob, null);
            if (rb != VmIsa.VM_OK) {
                return "rc=" + rb;
            }
            if (oa[0] != ob[0]) {
                return "ret-diff";
            }
            for (int g = 0; g < a.length; ++g) {
                if (a[g] != b[g]) {
                    return "gpr" + g + "-diff";
                }
            }
        }
        return null;
    }
}
