package com.kbox.core.controlflow;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Watermark embedding. Encodes a user-supplied watermark string as a sequence
 * of bits and stores them in a static {@code long[]} field on a synthetic
 * class, with the bit pattern derived from a SHA-256 of the watermark. The
 * field is initialized from a {@code <clinit>} whose body embeds the bits as
 * integer constants — these constants also appear in the constant pool, so
 * the watermark is recoverable by extracting the field's initializer.
 *
 * <p>Additionally, a marker attribute {@code KBox-Watermark} (visible) is
 * attached to the synthetic class so an authorized party can locate and
 * verify the watermark. The attribute value is a SHA-256 of the watermark
 * salted with a fixed KBox marker, so the watermark itself is not stored in
 * the clear.
 *
 * <p>The watermark is <b>not</b> removed by renaming or by opaque-predicate
 * passes — it lives in a synthetic class that those passes don't touch.
 */
public final class Watermarker {

    private static final String TAG = "watermark";
    private static final String HOLDER_CLASS = "com/kbox/runtime/_KboxWm";
    private static final String FIELD_NAME = "_wm";
    private static final String FIELD_DESC = "[J";

    /** Randomized per-build holder class so no stable "_KboxWm" grep signature. */
    private String holderClass = HOLDER_CLASS;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public Watermarker(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    private static String randomName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        java.util.concurrent.ThreadLocalRandom r = java.util.concurrent.ThreadLocalRandom.current();
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    public void apply() {
        String wm = cfg.getWatermark();
        if (wm == null || wm.isEmpty()) return;
        try {
            holderClass = "com/kbox/runtime/_" + randomName(14);
            ClassNode holder = ensureHolder();
            byte[] bits = encode(wm);
            installField(holder, bits);
            installClinit(holder, bits);
            installMarkerAttribute(holder, wm);
            KBoxLog.info(TAG, "Embedded watermark (" + bits.length + " bits) into " + holderClass);
        } catch (Throwable t) {
            KBoxLog.warn(TAG, "Watermark embedding failed: " + t.getMessage());
        }
    }

    /** Encode the watermark string as a bit array derived from SHA-256(string). */
    private static byte[] encode(String wm) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(wm.getBytes(StandardCharsets.UTF_8));
            byte[] bits = new byte[hash.length * 8];
            for (int i = 0; i < hash.length; i++) {
                for (int b = 7; b >= 0; b--) {
                    bits[i * 8 + (7 - b)] = (byte) ((hash[i] >> b) & 1);
                }
            }
            return bits;
        } catch (Exception e) {
            return new byte[0];
        }
    }

    @SuppressWarnings("unchecked")
    private ClassNode ensureHolder() {
        ClassNode cn = graph.getClasses().get(holderClass);
        if (cn != null) return cn;
        cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holderClass;
        cn.superName = "java/lang/Object";
        cn.fields.add(new FieldNode(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                FIELD_NAME, FIELD_DESC, null, null));
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);
        graph.getClasses().put(holderClass, cn);
        return cn;
    }

    private void installField(ClassNode cn, byte[] bits) {
        // Field is already added in ensureHolder; nothing else to do here.
    }

    /** Builds a <clinit> that allocates a long[] and stores each bit as a long. */
    private void installClinit(ClassNode cn, byte[] bits) {
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList l = clinit.instructions;
        // new long[bits.length]
        pushInt(l, bits.length);
        l.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        for (int i = 0; i < bits.length; i++) {
            // dup, push index, push bit value (as long), lastore
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            l.add(new LdcInsnNode((long) bits[i]));
            l.add(new InsnNode(Opcodes.LASTORE));
        }
        l.add(new FieldInsnNode(Opcodes.PUTSTATIC, holderClass, FIELD_NAME, FIELD_DESC));
        l.add(new InsnNode(Opcodes.RETURN));
        // Replace any existing <clinit>.
        for (int i = cn.methods.size() - 1; i >= 0; i--) {
            MethodNode m = (MethodNode) cn.methods.get(i);
            if (m.name.equals("<clinit>")) cn.methods.remove(i);
        }
        cn.methods.add(clinit);
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= 0 && v <= 5) {
            l.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v == -1) {
            l.add(new InsnNode(Opcodes.ICONST_M1));
        } else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) {
            l.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, v));
        } else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) {
            l.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, v));
        } else {
            l.add(new LdcInsnNode(v));
        }
    }

    /** Attach a visible annotation carrying a salted hash of the watermark. */
    private void installMarkerAttribute(ClassNode cn, String wm) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update("KBox-WM-v1:".getBytes(StandardCharsets.UTF_8));
            byte[] hash = md.digest(wm.getBytes(StandardCharsets.UTF_8));
            String hex = toHex(hash);
            org.objectweb.asm.tree.AnnotationNode an = new org.objectweb.asm.tree.AnnotationNode(
                    "Lcom/kbox/runtime/KBoxWatermark;");
            an.values = new java.util.ArrayList<>();
            an.values.add("hash"); an.values.add(hex);
            if (cn.visibleAnnotations == null) cn.visibleAnnotations = new java.util.ArrayList<>();
            cn.visibleAnnotations.add(an);
        } catch (Throwable ignored) {}
    }

    private static String toHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16));
            sb.append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }
}
