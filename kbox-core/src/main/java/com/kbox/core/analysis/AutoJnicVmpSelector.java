package com.kbox.core.analysis;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.*;

/**
 * Auto-selects methods for JNIC (Java-to-Native) and VMP (Virtual Machine
 * Protection) when they are enabled but no methods have been configured via
 * annotations or config.
 *
 * <h3>Selection strategy</h3>
 * <b>JNIC</b>: targets medium-to-large methods (&ge;10 instructions) from
 * transformable classes. Excludes constructors, static initializers, tiny
 * getters/setters, and mixin-kept methods. Capped at 50 methods to keep
 * compile times reasonable. Selected methods get their Java bodies removed
 * (marked native), so they run as compiled C.
 *
 * <b>VMP</b>: targets small-to-medium methods (5&ndash;50 instructions) that
 * were <em>not</em> selected for JNIC. These methods keep a Java stub that
 * delegates to the VMP interpreter. Capped at 30 methods.
 *
 * <p>Both selectors are skipped if the config already contains explicitly
 * configured methods (from annotations or config file).
 */
public final class AutoJnicVmpSelector {

    private static final String TAG = "auto-jnic-vmp";
    private static final int JNIC_MAX = 50;
    private static final int JNIC_MIN_SIZE = 10;
    private static final int VMP_MAX = 30;
    private static final int VMP_MIN_SIZE = 5;
    private static final int VMP_MAX_SIZE = 50;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public AutoJnicVmpSelector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Run auto-selection for JNIC and VMP. Only acts when the feature is
     * enabled AND the method set is empty (no annotations/config overrides).
     */
    public void select() {
        if (cfg.isEnableJnic() && cfg.getNativeMethods().isEmpty()) {
            autoSelectJnic();
        }
        if (cfg.isEnableVmp() && cfg.getVmpMethods().isEmpty()) {
            autoSelectVmp();
        }
    }

    // ---- JNIC auto-selection ----

    private void autoSelectJnic() {
        // Lower the size floor in full-coverage mode so even tiny helper
        // methods are sunk to native (maximizing the native blob size).
        int minSize = cfg.isJnicFullCoverage() ? 1 : JNIC_MIN_SIZE;
        int maxCount = cfg.isJnicFullCoverage() ? Integer.MAX_VALUE : JNIC_MAX;
        List<MethodEntry> candidates = collectCandidates(minSize, -1);
        if (candidates.isEmpty()) {
            KBoxLog.warn(TAG, "JNIC auto-select: no eligible methods found");
            return;
        }
        // Pick methods largest-first (more value from native compilation);
        // in full-coverage mode the cap is unlimited, so every candidate wins.
        candidates.sort((a, b) -> Integer.compare(b.size, a.size));
        int selected = 0;
        for (int i = 0; i < candidates.size() && selected < maxCount; i++) {
            MethodEntry me = candidates.get(i);
            String key = ProtectionConfig.memberKey(me.owner, me.name, me.desc);
            cfg.getNativeMethods().add(key);
            selected++;
        }
        KBoxLog.info(TAG, "JNIC auto-select: " + selected + " methods "
                + "(from " + candidates.size() + " candidates, "
                + (cfg.isJnicFullCoverage() ? "FULL coverage (no cap)"
                    : "max=" + JNIC_MAX + ")"));
    }

    // ---- VMP auto-selection ----

    private void autoSelectVmp() {
        // Full-coverage mode selects EVERY eligible method (size window 1..∞,
        // no cap) so the entire engine is virtualized. Legacy mode keeps the
        // medium-sized 5..50 window and a 30-method cap for faster startup.
        int minSize = cfg.isVmpFullCoverage() ? 1 : VMP_MIN_SIZE;
        int maxSize = cfg.isVmpFullCoverage() ? -1 : VMP_MAX_SIZE;
        int maxCount = cfg.isVmpFullCoverage() ? Integer.MAX_VALUE : VMP_MAX;
        List<MethodEntry> candidates = collectCandidates(minSize, maxSize);
        if (candidates.isEmpty()) {
            KBoxLog.warn(TAG, "VMP auto-select: no eligible methods found");
            return;
        }
        // Exclude methods already chosen for JNIC
        Set<String> jnicKeys = cfg.getNativeMethods();
        candidates.removeIf(me -> jnicKeys.contains(
                ProtectionConfig.memberKey(me.owner, me.name, me.desc)));

        if (candidates.isEmpty()) {
            KBoxLog.warn(TAG, "VMP auto-select: all candidates already taken by JNIC");
            return;
        }
        // Full coverage: pick all candidates largest-first (most value from VM
        // protection). Legacy: pick medium-sized methods first (medium complexity
        // benefits from VM protection) up to the cap.
        if (cfg.isVmpFullCoverage()) {
            candidates.sort((a, b) -> Integer.compare(b.size, a.size));
        } else {
            candidates.sort((a, b) -> Integer.compare(a.size, b.size));
        }
        int selected = 0;
        for (int i = 0; i < candidates.size() && selected < maxCount; i++) {
            MethodEntry me = candidates.get(i);
            String key = ProtectionConfig.memberKey(me.owner, me.name, me.desc);
            cfg.getVmpMethods().add(key);
            selected++;
        }
        KBoxLog.info(TAG, "VMP auto-select: " + selected + " methods "
                + "(from " + candidates.size() + " candidates, "
                + (cfg.isVmpFullCoverage() ? "FULL coverage (no cap)"
                    : "max=" + VMP_MAX + ")"));
    }

    // ---- Candidate collection ----

    private List<MethodEntry> collectCandidates(int minSize, int maxSize) {
        List<MethodEntry> out = new ArrayList<>();
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldTransformClass(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                if (!isEligible(cn.name, mn)) continue;
                int size = countInstructions(mn);
                if (size < minSize) continue;
                if (maxSize > 0 && size > maxSize) continue;
                out.add(new MethodEntry(cn.name, mn.name, mn.desc, size));
            }
        }
        return out;
    }

    /**
     * Checks whether a method is eligible for JNIC/VMP.
     * Excludes: abstract, native, bridge, init, clinit, kept members,
     * methods with unsupported bytecode patterns.
     */
    @SuppressWarnings("unchecked")
    private boolean isEligible(String owner, MethodNode mn) {
        // Skip abstract/native/bridge — no body to protect
        int acc = mn.access;
        if ((acc & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE | Opcodes.ACC_BRIDGE)) != 0)
            return false;
        // Skip constructors and static init — protecting them rarely adds value
        if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) return false;
        // Skip javac synthetic lambda impl methods (lambda$N). They are the
        // MethodHandles referenced by invokedynamic bootstraps (LambdaMetafactory);
        // marking them native would clear their bodies and make the JVM fail to
        // build a lambda ("MethodHandle is not direct"), and no JNI binding is
        // registered for them. They stay as ordinary Java methods.
        if (mn.name.startsWith("lambda$")) return false;
        // Skip kept members
        String key = ProtectionConfig.memberKey(owner, mn.name, mn.desc);
        if (cfg.getKeepMembers().contains(key)) return false;
        // MULTIANEWARRAY (multi-dimensional array allocation) is not yet safe in
        // the native interpreter when the array is subsequently iterated by an
        // interpreter loop (EXCEPTION_ACCESS_VIOLATION). Single allocation +
        // direct element access works, but to guarantee no crash we keep such
        // methods as ordinary Java (the pre-change, always-correct behaviour).
        // tableswitch/lookupswitch/invokedynamic are fully supported natively.
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn.getOpcode() == Opcodes.MULTIANEWARRAY) return false;
        }
        return true;
    }

    /** Counts the number of non-label, non-line-number instructions in a method. */
    @SuppressWarnings("unchecked")
    private int countInstructions(MethodNode mn) {
        int n = 0;
        for (AbstractInsnNode insn : mn.instructions) {
            int op = insn.getOpcode();
            if (op >= 0) n++; // skip labels (-1) and frames/line-numbers
        }
        return n;
    }

    // ---- Internal data holder ----

    private static final class MethodEntry {
        final String owner;
        final String name;
        final String desc;
        final int size;

        MethodEntry(String owner, String name, String desc, int size) {
            this.owner = owner;
            this.name = name;
            this.desc = desc;
            this.size = size;
        }
    }
}
