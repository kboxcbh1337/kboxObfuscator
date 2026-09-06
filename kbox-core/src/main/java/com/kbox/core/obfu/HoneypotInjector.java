package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Label;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.concurrent.ThreadLocalRandom;

/**
 * S4 — kboxDedeobfShieldV1 static bait ("honeypot fields/constant decoys").
 *
 * <p>Injects synthetic classes packed with <em>convincing-looking</em> fake secret
 * material: a fake AES-mixing S-BOX, fake round keys, a mutable chained "state",
 * a dead mixing routine that resembles real crypto core loops, and a {code hook()}
 * that assembles a decoy "secret" {@code String} out of those tables via XOR/char
 * arithmetic. Every bait class is unreachable from real program logic, so none of
 * its deobfuscation can ever affect the real application's output — yet a reverse
 * engineer who pivots into it sinks effort mining a decoy goldmine while the true
 * secrets are never exposed here.
 *
 * <p>Self-containment rules that keep the pass safe:
 * <ul>
 *   <li>Only <em>new</em> synthetic classes are created; nothing existing is touched,
 *       so no COMPUTE_FRAMES / linkage risk in legacy code.</li>
 *   <li>No {@code LDC String} constants are emitted — latch the table/char values as
 *       {@code int} literals so the string-encryption pass (which runs regardless of
 *       placement) never rewrites — and never "cleans up" — the bait.</li>
 *   <li>All bodies are JVM-legal straight-line / single-loop code verified by
 *       {@code COMPUTE_FRAMES} during packaging ({@code markCfModified}).</li>
 *   <li>Names are randomized per build so the bait signature is not stable.</li>
 * </ul>
 */
public final class HoneypotInjector {

    private static final String TAG = "honeypot";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public HoneypotInjector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        ThreadLocalRandom r = ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    public void apply() {
        int level = cfg.getHoneypotLevel();
        if (level <= 0) return;
        int count = level >= 3 ? 6 : (level == 2 ? 4 : 2);
        for (int i = 0; i < count; i++) {
            String internal = "com/kbox/honey/_h" + randomName(12);
            ClassNode cn = buildBait(internal);
            graph.getClasses().put(internal, cn);
            // COMPUTE_FRAMES will regenerate stale StackMapTable for these bodies.
            graph.markCfModified(internal);
            KBoxLog.info(TAG, "Bait class " + internal
                    + " (SBOX=256 ROUND=4 state=chained) injected, dead-code only");
        }
        KBoxLog.info(TAG, "S4 honeypot bait injected: " + count + " decoy classes");
    }

    /** Build a single convincing-looking fake crypto bait class. */
    private ClassNode buildBait(String internal) {
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = internal;
        cn.superName = "java/lang/Object";

        String fSbox = "S" + randomName(4);
        String fRound = "R" + randomName(4);
        String fMask = "M" + randomName(4);
        String fState = "st" + randomName(4);
        String mInit = "<init>";
        String mClinit = "<clinit>";
        String mMix = "m" + randomName(8);
        String mHook = "h" + randomName(8);

        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                fSbox, "[I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                fRound, "[I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                fMask, "I", null, null));
        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                fState, "I", null, null));

        // <init>
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, mInit, "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        // <clinit>: fill fake S-BOX (256) + round keys (4), derive MASK.
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, mClinit, "()V", null, null);
        InsnList cl = clinit.instructions;

        // SBOX: int[] t = SBOX; for i in 0..255 { t[i] = sbox[i]; }
        int[] sbox = new int[256];
        int seed = 0x9E3779B9;
        for (int i = 0; i < 256; i++) {
            seed ^= (seed << 13); seed ^= (seed >>> 17); seed ^= (seed << 5);
            sbox[i] = seed & 0xFFFF;
        }
        pushInt(cl, 256);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, internal, fSbox, "[I"));
        cl.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fSbox, "[I"));
        for (int i = 0; i < sbox.length; i++) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushInt(cl, sbox[i]);
            cl.add(new InsnNode(Opcodes.IASTORE));
        }
        cl.add(new InsnNode(Opcodes.POP));

        // ROUND (4 round keys)
        pushInt(cl, 4);
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, internal, fRound, "[I"));
        int[] round = new int[]{0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344};
        for (int i = 0; i < round.length; i++) {
            cl.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fRound, "[I"));
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, i);
            pushInt(cl, round[i]);
            cl.add(new InsnNode(Opcodes.IASTORE));
        }

        // MASK = derived (fake); uses no bare secret wording.
        pushInt(cl, 0x0100FE00);
        pushInt(cl, 0x3713C2A5);
        cl.add(new InsnNode(Opcodes.IXOR));
        pushInt(cl, 0x28551233);
        cl.add(new InsnNode(Opcodes.IADD));
        pushInt(cl, 0x5207DFD1);
        cl.add(new InsnNode(Opcodes.IADD));
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, internal, fMask, "I"));

        // state = 1
        pushInt(cl, 1);
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, internal, fState, "I"));
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 4;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);

        // private static int mix(int a, int b)  — dead chained mixing, tempting.
        MethodNode mix = new MethodNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC,
                mMix, "(II)I", null, null);
        InsnList mx = mix.instructions;
        // int s = state;
        mx.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fState, "I"));
        mx.add(new VarInsnNode(Opcodes.ISTORE, 2));
        // state = (s ^ a) * 31 + (b << 3) ^ (s >>> 6);
        mx.add(new VarInsnNode(Opcodes.ILOAD, 2));
        mx.add(new VarInsnNode(Opcodes.ILOAD, 0));
        mx.add(new InsnNode(Opcodes.IXOR));
        pushInt(mx, 31);
        mx.add(new InsnNode(Opcodes.IMUL));
        mx.add(new VarInsnNode(Opcodes.ILOAD, 1));
        pushInt(mx, 3);
        mx.add(new InsnNode(Opcodes.ISHL));
        mx.add(new InsnNode(Opcodes.IADD));
        mx.add(new VarInsnNode(Opcodes.ILOAD, 2));
        pushInt(mx, 6);
        mx.add(new InsnNode(Opcodes.IUSHR));
        mx.add(new InsnNode(Opcodes.IXOR));
        mx.add(new FieldInsnNode(Opcodes.PUTSTATIC, internal, fState, "I"));
        // return state + ((a ^ b) & MASK);
        mx.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fState, "I"));
        mx.add(new VarInsnNode(Opcodes.ILOAD, 0));
        mx.add(new VarInsnNode(Opcodes.ILOAD, 1));
        mx.add(new InsnNode(Opcodes.IXOR));
        mx.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fMask, "I"));
        mx.add(new InsnNode(Opcodes.IAND));
        mx.add(new InsnNode(Opcodes.IADD));
        mx.add(new InsnNode(Opcodes.IRETURN));
        mix.maxStack = 3;
        mix.maxLocals = 3;
        cn.methods.add(mix);

        // public static String hook() — assembles decoy secret string, never called.
        MethodNode hook = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                mHook, "()Ljava/lang/String;", null, null);
        InsnList hk = hook.instructions;
        // char[] c = new char[16];
        pushInt(hk, 16);
        hk.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_CHAR));
        hk.add(new VarInsnNode(Opcodes.ASTORE, 0));
        // int i = 0;  while (i < 16) { c[i] = (char)(SBOX[(i*4+1)&255] ^ ROUND[i&3]); i++; }
        hk.add(new InsnNode(Opcodes.ICONST_0));
        hk.add(new VarInsnNode(Opcodes.ISTORE, 1));
        LabelNode loopTop = new LabelNode(new Label());
        LabelNode done = new LabelNode(new Label());
        hk.add(loopTop);
        hk.add(new VarInsnNode(Opcodes.ILOAD, 1));
        pushInt(hk, 16);
        hk.add(new JumpInsnNode(Opcodes.IF_ICMPGE, done));
        hk.add(new VarInsnNode(Opcodes.ALOAD, 0));
        hk.add(new VarInsnNode(Opcodes.ILOAD, 1));
        hk.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fSbox, "[I"));
        hk.add(new VarInsnNode(Opcodes.ILOAD, 1));
        pushInt(hk, 4);
        hk.add(new InsnNode(Opcodes.IMUL));
        pushInt(hk, 1);
        hk.add(new InsnNode(Opcodes.IADD));
        pushInt(hk, 255);
        hk.add(new InsnNode(Opcodes.IAND));
        hk.add(new InsnNode(Opcodes.IALOAD));
        hk.add(new FieldInsnNode(Opcodes.GETSTATIC, internal, fRound, "[I"));
        hk.add(new VarInsnNode(Opcodes.ILOAD, 1));
        pushInt(hk, 3);
        hk.add(new InsnNode(Opcodes.IAND));
        hk.add(new InsnNode(Opcodes.IALOAD));
        hk.add(new InsnNode(Opcodes.IXOR));
        hk.add(new InsnNode(Opcodes.I2C));
        hk.add(new InsnNode(Opcodes.CASTORE));
        hk.add(new org.objectweb.asm.tree.IincInsnNode(1, 1));
        hk.add(new JumpInsnNode(Opcodes.GOTO, loopTop));
        hk.add(done);
        // return new String(c);
        hk.add(new VarInsnNode(Opcodes.ALOAD, 0));
        hk.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([C)V", false));
        hk.add(new InsnNode(Opcodes.ARETURN));
        hook.maxStack = 6;
        hook.maxLocals = 2;
        cn.methods.add(hook);

        return cn;
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }
}