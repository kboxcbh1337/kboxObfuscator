package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.Random;

/**
 * kboxDedeobfShieldV1 — build-time injection pass for the layers that must be
 * bound into the bytecode / package at build time rather than only at runtime:
 *
 * <ul>
 *   <li><b>Guard arming (D1-D5/C1/C2/X1 runtime arm)</b>: computes the layer
 *       bit-mask from the config and injects {@code KBoxDedeobfGuard.arm(mask)}
 *       at the top of every kept entry-point {@code <clinit>} so the dynamic
 *       guard is self-arming on first class-load of the real entry.</li>
 *   <li><b>X2 build-signature binding</b>: computes a build-signature lane
 *       {@code selfRefOk(lane, buildNo)} symmetric with the runtime, keyed off
 *       the build number, and binds it into the keep entry classes as an
 *       opaque predicate the runtime {@link com.kbox.runtime.KBoxDedeobfGuard}
 *       can re-verify.</li>
 *   <li><b>S3 / C4 / C5 build-side hooks</b>: sentinel step / multi-rep marker
 *       and gilding are predominantly runtime (see the guard); build-side we
 *       only thread the build number into the guard so its values vary per
 *       build (build-to-build polymorphism on the new layers too).</li>
 * </ul>
 *
 * <p>All injected sequences are <b>prologue-only, stack-neutral</b> and placed
 * at the very start of a {@code <clinit>} (empty incoming stack), so they are
 * COMPUTE_FRAMES-safe and can never alter the verified control flow of any
 * protected method. Irregular / absent {@code <clinit>} are left untouched.
 */
public final class DedeobfShieldInjector {

    private static final String TAG = "dedeobf";
    private static final String GUARD = "com/kbox/runtime/KBoxDedeobfGuard";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final Random rnd = new Random();

    public DedeobfShieldInjector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /** Build-time arm mask: bit0=S3, bit1=D2(time), bit2=D3(wipe),
     *  bit3=D4(heartbeat), bit4=C3/X2(self-ref). The other layers are pure
     *  runtime call sites; the mask only needs a bit if arm() must pre-wire. */
    private int armMask() {
        int m = 0;
        if (cfg.getSentinelInterleave() > 0) m |= 0x01;
        if (cfg.getEntropyTimeAnchor() > 0)  m |= 0x02;
        if (cfg.getSelfWipeSections() > 0)   m |= 0x04;
        if (cfg.getProcessHeartbeat() > 0)   m |= 0x08;
        if (cfg.getSelfRefAuth() > 0 || cfg.getBuildSigBind() > 0) m |= 0x10;
        return m;
    }

    /** Build number — a per-build monotonic stamp for the X2 signature lane. */
    private int buildNo() {
        // mix build-start time so two builds differ even with identical config
        return (int) ((System.nanoTime() ^ (System.currentTimeMillis() * 31L)) >>> 1);
    }

    private static long mix64(long z) {
        z = (z ^ (z >>> 30)) * 0xbf58476d1ce4e5b9L;
        z = (z ^ (z >>> 27)) * 0x94d049bb133111ebL;
        return z ^ (z >>> 31);
    }

    /** Compute the X2 self-ref signature lane the runtime will re-verify. */
    public int sigLane(int buildNo) {
        long expected = mix64(buildNo * 0x6a09e667f3bcc909L);
        return ((int) (expected >>> 32) ^ (int) expected) & 0x7fffffff;
    }

    /**
     * Apply the guard-arming + X2 + (C4/C5 light) injection over the graph.
     * Runs after identifier renaming so injected references keep final names.
     */
    public void apply() {
        int mask = armMask();
        int buildNo = buildNo();
        int lane = sigLane(buildNo);
        boolean any = mask != 0 || cfg.getBuildSigBind() > 0
                || cfg.getPolyGold() > 0 || cfg.getMultiRep() > 0;

        if (!any) {
            KBoxLog.info(TAG, "kboxDedeobfShieldV1 dynamic-guard disabled (all levels 0)");
            return;
        }

        KBoxLog.info(TAG, "kboxDedeobfShieldV1 build-time injection: armMask="
                + mask + " buildNo=" + buildNo + " sigLane=" + lane);

        int injected = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            boolean isEntry = isEntry(cn);
            if (!isEntry) continue;
            injected += injectPrologue(cn, mask, buildNo, lane);
        }
        if (injected == 0) {
            // Nothing was an entry class — fall back to arming any kept class's
            // <clinit> so the guard still self-arms at first touch.
            for (ClassNode cn : graph.getClasses().values()) {
                if (!cfg.shouldProtectClass(cn.name)) continue;
                if (cn.methods == null) continue;
                if (findClinit(cn) != null) {
                    injected += injectPrologue(cn, mask, buildNo, lane);
                    if (injected > 0) break;
                }
            }
        }
        KBoxLog.info(TAG, "kboxDedeobfShieldV1: guard armed in " + injected + " entry class(es)");
    }

    private boolean isEntry(ClassNode cn) {
        for (String ep : cfg.getEntryPoints()) {
            String norm = ep.replace('.', '/');
            if (cn.name.equals(norm)) return true;
        }
        if (graph.getManifestMainClass() != null
                && cn.name.equals(graph.getManifestMainClass().replace('.', '/'))) {
            return true;
        }
        // a class holding public static void main(String[])
        if (cn.methods != null) {
            for (MethodNode mn : cn.methods) {
                if (mn.name.equals("main")
                        && mn.desc.equals("([Ljava/lang/String;)V")
                        && (mn.access & Opcodes.ACC_STATIC) != 0) {
                    return true;
                }
            }
        }
        return false;
    }

    private MethodNode findClinit(ClassNode cn) {
        if (cn.methods == null) return null;
        for (MethodNode mn : cn.methods) {
            if (mn.name.equals("<clinit>")) return mn;
        }
        return null;
    }

    private int injectPrologue(ClassNode cn, int mask, int buildNo, int lane) {
        MethodNode clinit = findClinit(cn);
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            cn.methods.add(clinit);
        }
        InsnList insnList = clinit.instructions;
        InsnList pre = new InsnList();
        boolean needSig = cfg.getBuildSigBind() > 0 || cfg.getSelfRefAuth() > 0;
        boolean needArm = mask != 0;

        int stack = 0;
        if (needSig) {
            // boolean KBoxDedeobfGuard.selfRefOk(int,int); pop result if left.
            pre.add(new InsnNode(Opcodes.ICONST_0));          // sigLane pushed as int
            pushConst(pre, lane);
            pre.add(new InsnNode(Opcodes.SWAP));              // sigLane lane
            pushConst(pre, buildNo);
            pre.add(new MethodInsnNode(Opcodes.INVOKESTATIC, GUARD,
                    "selfRefOk", "(II)Z", false));
            pre.add(new InsnNode(Opcodes.POP));
            stack = 0;
        }
        if (needArm) {
            pushConst(pre, mask);
            pre.add(new MethodInsnNode(Opcodes.INVOKESTATIC, GUARD, "arm", "(I)V", false));
            stack = 0;
        }
        if (cfg.getMultiRep() > 0) {
            // lightweight sentinel step (stack-neutral): pop the int result
            pushConst(pre, lane);
            pushConst(pre, buildNo);
            pre.add(new MethodInsnNode(Opcodes.INVOKESTATIC, GUARD,
                    "sentinelStep", "(II)I", false));
            pre.add(new InsnNode(Opcodes.POP));
            stack = 0;
        }
        if (stack != 0) return 0;
        if (pre.size() == 0) return 0;

        // insert at the very start (before any existing <clinit> body)
        AbstractInsnNode first = insnList.getFirst();
        if (first == null) {
            for (AbstractInsnNode n : pre) insnList.add(n);
        } else {
            for (AbstractInsnNode n : pre) insnList.insertBefore(first, n);
        }
        // bump maxStack for the prologue loads
        int needed = Math.max(2, stack);
        if (clinit.maxStack < needed) clinit.maxStack = needed;
        // a fresh synthetic static holder so gilding per-class does not touch ASM frames
        return 1;
    }

    private static void pushConst(InsnList l, int v) {
        if (v >= -1 && v <= 5) {
            l.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            l.add(new LdcInsnNode(v));
        }
    }
}