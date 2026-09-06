package com.kbox.core.analysis;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
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
 * <h3>JNIC+VMP full-coverage layering</h3>
 * When both {@code nativeCoverage=full} and {@code vmpCoverage=full} are on,
 * the two selectors split the candidate pool on a size boundary so they are
 * complementary and cover every method exactly once:
 * <ul>
 *   <li>JNIC owns the <b>large</b> methods (size &ge; {@link #JNIC_LAYER_MIN}).</li>
 *   <li>VMP owns every <b>small/medium</b> method (size &lt; {@link #JNIC_LAYER_MIN}).</li>
 * </ul>
 * This prevents JNIC's full-coverage (unbounded) sweep from draining the whole
 * pool and leaving VMP with "all candidates already taken by JNIC" (0 injected),
 * while still attaining true all-JNIC on the big, high-value entry points.
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
    // Layering boundary when BOTH coverage modes are full: JNIC takes
    // size >= this, VMP takes size < this (JNIC_LAYER_MIN - 1 = VMP_MAX_SIZE).
    private static final int JNIC_LAYER_MIN = VMP_MAX_SIZE;

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
        // VMP selects FIRST so its method set is known before JNIC runs.
        // JNIC then avoids translating any "bridge" method that calls into a
        // VMP-protected method (see isJnicBridge). A JNIC-native method passing
        // state (e.g. an int[]) to a VMP Java stub crashes in the native
        // interpreter (EXCEPTION_ACCESS_VIOLATION), so bridges must stay
        // ordinary Java; only leaf/self-contained methods are sunk to native.
        if (cfg.isEnableVmp() && cfg.getVmpMethods().isEmpty()) {
            autoSelectVmp();
        }
        if (cfg.isEnableJnic() && (cfg.getNativeMethods().isEmpty() || cfg.isJnicEplDriven())) {
            autoSelectJnic();
        }
    }

    // ---- JNIC auto-selection ----

    private void autoSelectJnic() {
        // Layering with VMP: when BOTH coverage modes are full, we partition the
        // candidate pool on a size boundary so the two protectors are
        // complementary and no method is double-claimed. JNIC owns the LARGE
        // methods (size >= JNIC_LAYER_MIN); VMP owns every smaller one.
        // When VMP is off (or not full), JNIC full-coverage drops the floor to 1
        // so even helper methods are sunk to native (maximizing the blob).
        boolean layered = cfg.isJnicFullCoverage()
                && cfg.isEnableVmp() && cfg.isVmpFullCoverage();
        int minSize = layered
                ? Math.max(JNIC_MIN_SIZE, JNIC_LAYER_MIN)
                : (cfg.isJnicFullCoverage() ? 1 : JNIC_MIN_SIZE);
        int maxCount = cfg.isJnicFullCoverage() ? Integer.MAX_VALUE : JNIC_MAX;
        List<MethodEntry> candidates = collectCandidates(minSize, -1);
        // VMP selects FIRST; a method already virtualized by VMP must never be
        // sunk to native afterwards — otherwise it ends up BOTH marked native AND
        // re-wrapped with a VMP execute stub (a native method carrying a Code
        // attribute, which the JVM rejects at class-load). Drop such methods.
        if (!cfg.getVmpMethods().isEmpty() && !candidates.isEmpty()) {
            candidates.removeIf(me -> cfg.getVmpMethods().contains(
                    ProtectionConfig.memberKey(me.owner, me.name, me.desc)));
        }
        // Bridge exclusion: a JNIC-native method must never call into a VMP
        // Java stub (native -> interpreter handoff of complex state like an
        // int[] crashes the native VM). Drop such methods so they stay Java.
        if (!cfg.getVmpMethods().isEmpty() && !candidates.isEmpty()) {
            int before = candidates.size();
            candidates.removeIf(me -> isJnicBridge(me.owner, me.name, me.desc));
            int dropped = before - candidates.size();
            if (dropped > 0) {
                KBoxLog.info(TAG, "JNIC auto-select: excluded " + dropped
                        + " bridge method(s) that call VMP-protected methods");
            }
        }
        // Entry-point classes stay in Java: a JNIC-native main()/bootstrap runs
        // in the C interpreter where JVM IO (System.out) is unreliable, yielding
        // a silently silent entry point. Only AUTO-selection is filtered —
        // explicit nativeMethod config still sinks whatever the user asks for.
        java.util.List<String> eps = cfg.getEntryPoints();
        if (!eps.isEmpty() && !candidates.isEmpty()) {
            int before = candidates.size();
            candidates.removeIf(me -> eps.contains(me.owner.replace('/', '.')));
            int dropped = before - candidates.size();
            if (dropped > 0) {
                KBoxLog.info(TAG, "JNIC auto-select: excluded " + dropped
                        + " entry-point class method(s) (main/bootstrap stays Java)");
            }
        }
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
                + (cfg.isJnicFullCoverage()
                    ? "FULL coverage (no cap; layering=" + layered + ", floor=" + minSize + ")"
                    : "max=" + JNIC_MAX + ")"));
    }

    // ---- VMP auto-selection ----

    private void autoSelectVmp() {
        // Layering with JNIC (both full): VMP owns every small/medium method
        // (size < JNIC_LAYER_MIN), which form the complement of the large methods
        // JNIC took. Full-coverage (VMP alone) selects EVERY eligible method.
        // Legacy mode keeps the medium-sized 5..50 window and a 30-method cap.
        boolean layered = cfg.isVmpFullCoverage()
                && cfg.isEnableJnic() && cfg.isJnicFullCoverage();
        int minSizePlus0 = cfg.isVmpFullCoverage() ? 1 : VMP_MIN_SIZE;
        int maxSize = layered ? JNIC_LAYER_MIN - 1
                : (cfg.isVmpFullCoverage() ? -1 : VMP_MAX_SIZE);
        int maxCount = cfg.isVmpFullCoverage() ? Integer.MAX_VALUE : VMP_MAX;
        List<MethodEntry> candidates = collectCandidates(minSizePlus0, maxSize);
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
                + (cfg.isVmpFullCoverage()
                    ? "FULL coverage (no cap; layering=" + layered + ", maxSize=" + maxSize + ")"
                    : "max=" + VMP_MAX + ")"));
    }

    // ---- EPL binning manifest (Phase3-L2a) ----

    /**
     * Builds the EPL (Effective Protection Level) binning manifest
     * {@code method_epd.bin} — a compact, deterministic binary record of every
     * method that an auto-selector assigned to JNIC or VMP, so the binning
     * decision is auditable without running the protected app.
     *
     * <p>Format (big-endian):
     * <pre>
     *   "KEPD"                    // 4-byte magic
     *   u32 count                 // number of records
     *   records[]:                // sorted by (kind, owner, name, desc)
     *     u8  kind                // 1 = JNIC, 2 = VMP
     *     u8  epl                 // 3 = large (size>=50), 2 = medium (5..49), 1 = light
     *     u32 nameLen             // length of "owner#name#desc" UTF-8
     *     bytes name              // internal(owner)#name#desc
     *     u32 size                // instruction count at selection time
     * </pre>
     * Only names are embedded — the manifest is a binning audit log, not a
     * protection primitive, so no secrets are added.
     */
    public static byte[] buildEpdManifest(ClassGraph graph, ProtectionConfig cfg) {
        java.util.Set<String> nativeKeys = new LinkedHashSet<>(cfg.getNativeMethods());
        java.util.Set<String> vmpKeys = new LinkedHashSet<>(cfg.getVmpMethods());
        List<EpdRecord> recs = new ArrayList<>();
        for (ClassNode cn : graph.getClasses().values()) {
            for (MethodNode mn : cn.methods) {
                if (mn.instructions == null) continue;
                String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
                int kind;
                if (nativeKeys.contains(key)) kind = 1;
                else if (vmpKeys.contains(key)) kind = 2;
                else continue;
                int size = countInstructions(mn);
                int epl = size >= JNIC_LAYER_MIN ? 3 : (size >= VMP_MIN_SIZE ? 2 : 1);
                recs.add(new EpdRecord(kind, epl, key, size));
            }
        }
        recs.sort(Comparator
                .comparingInt((EpdRecord r) -> r.kind)
                .thenComparing((EpdRecord r) -> r.name)
                .thenComparingInt((EpdRecord r) -> r.size));
        try {
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            java.io.DataOutputStream d = new java.io.DataOutputStream(bo);
            // Masked magic (NOT ASCII "KEPD"): 'K'^0x7A, 'E'^0x3D, 'P'^0x88, 'D'^0xC1
            d.writeByte(0x31); d.writeByte(0x78); d.writeByte(0xD8); d.writeByte(0x85);
            d.writeInt(recs.size());
            for (EpdRecord r : recs) {
                d.writeByte(r.kind);
                d.writeByte(r.epl);
                byte[] nm = r.name.getBytes(StandardCharsets.UTF_8);
                d.writeInt(nm.length);
                d.write(nm);
                d.writeInt(r.size);
            }
            d.flush();
            return bo.toByteArray();
        } catch (java.io.IOException impossible) {
            throw new RuntimeException(impossible);
        }
    }

    private static final class EpdRecord {
        final int kind;
        final int epl;
        final String name;
        final int size;
        EpdRecord(int kind, int epl, String name, int size) {
            this.kind = kind; this.epl = epl; this.name = name; this.size = size;
        }
    }

    // ---- Candidate collection ----

    private List<MethodEntry> collectCandidates(int minSize, int maxSize) {
        List<MethodEntry> out = new ArrayList<>();
        for (ClassNode cn : graph.getClasses().values()) {
            // VMP/JNIC only replace a method's BODY; they never rename the class
            // or method. Entry-point / kept classes (e.g. the launcher-reflected
            // Main) therefore remain eligible for body-sinking — otherwise a
            // single-class app whose only class is the auto-kept Main would get
            // zero VMP/JNIC coverage. Still excluded here: library, out-of-scope
            // and KBox-runtime classes (see shouldProtectClass).
            if (!cfg.shouldProtectClass(cn.name)) continue;
            if (!cfg.isNativeEligible(cn.name)) continue;
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
        // String/IO safety: the JNIC C interpreter's string & console handling is
        // not byte-faithful to the JVM for non-trivial bodies, so methods that
        // reference String constants or write to PrintStream are kept as Java
        // (the documented "JNIC sinks pure logic" boundary). Without this,
        // nativeCoverage=full would sink Greeter-like methods and produce a
        // silently wrong (null/blank) entry point.
        for (AbstractInsnNode insn : mn.instructions) {
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode l = (LdcInsnNode) insn;
                if (l.cst instanceof String) return false;
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode mi = (MethodInsnNode) insn;
                if (mi.owner.equals("java/io/PrintStream")) return false;
            }
        }
        return true;
    }

    /**
     * True when {@code owner.name(desc)} directly calls a VMP-protected method.
     * Such a method is a native->interpreter "bridge"; translating it to native
     * would hand complex state (e.g. an int[]) to a VMP Java stub and crash the
     * native VM, so it must be kept as ordinary Java.
     */
    @SuppressWarnings("unchecked")
    private boolean isJnicBridge(String owner, String name, String desc) {
        ClassNode cn = graph.getClasses().get(owner);
        if (cn == null) return false;
        for (MethodNode mn : cn.methods) {
            if (!mn.name.equals(name) || !mn.desc.equals(desc)) continue;
            for (AbstractInsnNode insn : mn.instructions) {
                if (insn instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) insn;
                    if (cfg.getVmpMethods().contains(
                            ProtectionConfig.memberKey(mi.owner, mi.name, mi.desc))) {
                        return true;
                    }
                }
            }
            return false;
        }
        return false;
    }

    /** Counts the number of non-label, non-line-number instructions in a method. */
    @SuppressWarnings("unchecked")
    private static int countInstructions(MethodNode mn) {
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
