package com.kbox.core.shield;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * SROX 构建期研究报告。
 *
 * <p>记录每个函数的候选、评分、接受/回滚原因与验证覆盖边界。报告是
 * <b>可审计</b>的：同一 build seed 下候选选择完全确定，可用于复现实验，
 * 也可对比不同构建的结构指纹是否真的产生了差异。</p>
 */
final class SroxReport {

    private final int level;
    private final long buildSeed;
    private final List<String> decisions = new ArrayList<String>();
    private int functionsSeen;
    private int candidatesBuilt;
    private int candidatesRejected;
    private int accepted;
    private int rolledBack;
    private int verifyFailures;
    private long irSeen;
    private long irBase;
    private long irChosen;
    private double scoreSum;

    SroxReport(int level, long buildSeed) {
        this.level = level;
        this.buildSeed = buildSeed;
    }

    void seen(int irInsns) {
        ++functionsSeen;
        irSeen += irInsns;
    }

    void accept(int rva, int baseIr, int chosenIr, String desc, double score,
                List<String> candidates, int candCount) {
        ++accepted;
        irBase += baseIr;
        irChosen += chosenIr;
        scoreSum += score;
        candidatesBuilt += candCount;
        decisions.add(String.format(java.util.Locale.ROOT,
                "ACCEPT func@0x%x ir=%d->%d chosen=%s score=%.4f candidates=%d",
                rva, baseIr, chosenIr, desc, score, candCount));
        for (String c : candidates) {
            decisions.add("        " + c);
        }
    }

    void reject(int rva, int irInsns, int candCount, String reason,
                List<String> candidates) {
        ++rolledBack;
        ++candidatesRejected;
        candidatesBuilt += candCount;
        decisions.add(String.format(java.util.Locale.ROOT,
                "REJECT func@0x%x ir=%d chosen=- candidates=%d reason=%s",
                rva, irInsns, candCount, reason));
        for (String c : candidates) {
            decisions.add("        " + c);
        }
    }

    void skip(int rva, int irInsns, String reason) {
        decisions.add(String.format(java.util.Locale.ROOT,
                "SKIP   func@0x%x ir=%d reason=%s", rva, irInsns, reason));
    }

    void verifyFailure() {
        ++verifyFailures;
    }

    boolean hasDecisions() {
        return !decisions.isEmpty();
    }

    int acceptedCount() {
        return accepted;
    }

    int builtCount() {
        return candidatesBuilt;
    }

    int rolledBackCount() {
        return rolledBack;
    }

    int verifyFailureCount() {
        return verifyFailures;
    }

    private String fingerprint() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (String d : decisions) {
                md.update(d.getBytes(StandardCharsets.UTF_8));
                md.update((byte) '\n');
            }
            byte[] h = md.digest();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < 12; ++i) {
                sb.append(String.format(java.util.Locale.ROOT, "%02x", h[i] & 0xFF));
            }
            return sb.toString();
        } catch (Exception e) {
            return "unavailable";
        }
    }

    String toText() {
        StringBuilder sb = new StringBuilder();
        sb.append("SROX REPORT v1\n");
        sb.append("================\n");
        sb.append("level            : ").append(level).append('\n');
        sb.append("build_seed       : ")
                .append(String.format(java.util.Locale.ROOT, "%016x", buildSeed)).append('\n');
        sb.append("structure_fp     : ").append(fingerprint()).append('\n');
        sb.append("functions_seen   : ").append(functionsSeen).append('\n');
        sb.append("candidates_built : ").append(candidatesBuilt).append('\n');
        sb.append("candidates_rej   : ").append(candidatesRejected).append('\n');
        sb.append("accepted         : ").append(accepted).append('\n');
        sb.append("rolled_back      : ").append(rolledBack).append('\n');
        sb.append("verify_failures  : ").append(verifyFailures).append('\n');
        sb.append("ir_insns_seen    : ").append(irSeen).append('\n');
        sb.append("ir_insns_base    : ").append(irBase).append('\n');
        sb.append("ir_insns_chosen  : ").append(irChosen).append('\n');
        sb.append("expansion_ratio  : ").append(String.format(java.util.Locale.ROOT,
                "%.3f", irBase == 0 ? 0.0 : (double) irChosen / irBase)).append('\n');
        sb.append("avg_score        : ").append(String.format(java.util.Locale.ROOT,
                "%.4f", accepted == 0 ? 0.0 : scoreSum / accepted)).append('\n');
        sb.append("\n[decisions]\n");
        for (String d : decisions) {
            sb.append(d).append('\n');
        }
        sb.append("\n[verification]\n");
        sb.append("- semantic gate : bounded differential IR interpretation\n");
        sb.append("                  (same seeded vreg/frame state, deterministic memory model,\n");
        sb.append("                   N random states, step limit; NATIVE opcodes excluded)\n");
        sb.append("- image gate    : for memory-free functions, VmEngine.vmExecMach(candidate)\n");
        sb.append("                  must equal the identity image result and return VM_OK\n");
        sb.append("- package gate  : ShieldVerify (PE geometry / entry / imports / config)\n");
        sb.append("- NOT covered   : semantic equivalence over arbitrary native inputs,\n");
        sb.append("                  real process memory aliasing, external call side effects.\n");
        sb.append("                  Run differential tests against the original binary.\n");
        sb.append("\n[evaluation protocol]\n");
        sb.append("Structural / semantic / automation / cross-build tests must be run by\n");
        sb.append("independent analysts under a fixed budget; report per-task success rates\n");
        sb.append("with sample size and confidence intervals. These proxy metrics alone are\n");
        sb.append("not evidence of superiority over any commercial protector.\n");
        return sb.toString();
    }

    /** 写出报告；path 为空时写 {@code <base>.srox.txt} 于给定目录。 */
    boolean write(Path reportPath, Path fallbackDir, String baseName) {
        try {
            Path p = reportPath;
            if (p == null || p.toString().isEmpty()) {
                if (fallbackDir == null) {
                    return false;
                }
                p = fallbackDir.resolve(baseName + ".srox.txt");
            }
            Path parent = p.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(p, toText().getBytes(StandardCharsets.UTF_8));
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    static Path pathOrNull(String s) {
        if (s == null || s.trim().isEmpty()) {
            return null;
        }
        return Paths.get(s.trim());
    }
}
