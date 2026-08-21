package com.kbox.core.stringenc;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
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
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;
import org.objectweb.asm.tree.IincInsnNode;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * String-scattering encryptor: the hardened companion to {@link StringEncryptor}.
 *
 * <p>Instead of a single inline byte[] literal decrypted via a central
 * {@code KBoxRuntime.d()} call, each string literal is:
 * <ol>
 *   <li>Split into N segments (default 3).</li>
 *   <li>Each segment is XOR-encrypted with a per-segment key and stored as a
 *       static {@code byte[]} field in one of K holder classes
 *       ({@code com/kbox/runtime/_KboxS0} .. {@code _KboxS7}).</li>
 *   <li>At the use site, inline bytecode loads each field, inlines an XOR
 *       decryption loop, converts each segment to String, and concatenates
 *       via StringBuilder. <b>No call to KBoxRuntime.d()</b> — the
 *       decryption is fully inlined, defeating pattern-matching hooks.</li>
 * </ol>
 *
 * <p>The inline decryption loop for each segment looks like:
 * <pre>
 *   byte[] seg = Holder.field;     // encrypted segment
 *   for (int i = 0; i &lt; seg.length; i++)
 *       seg[i] ^= (key &gt;&gt; (i % 4 * 8)) &amp; 0xFF;
 *   String s = new String(seg, UTF_8);
 * </pre>
 *
 * <p>Holder classes are synthetic and added to the graph before the rename
 * pass, so they get renamed along with everything else. Each holder has up
 * to 256 static byte[] fields, so the mapping from string to field is
 * non-deterministic across builds.
 */
public final class StringScatterer {

    private static final String TAG = "scatter";
    private static final String HOLDER_PREFIX = "com/kbox/runtime/_KboxS";
    private static final int NUM_HOLDERS = 8;
    private static final int FIELDS_PER_HOLDER = 256;
    private static final int SEGMENTS = 3;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private final HolderManager holders = new HolderManager();
    private int scattered;

    public StringScatterer(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isScatterStrings() || !cfg.isEncryptStrings()) {
            return;
        }
        // Pre-create holder classes.
        for (int i = 0; i < NUM_HOLDERS; i++) {
            ensureHolder(i);
        }
        for (ClassNode cn : graph.getClasses().values()) {
            // Single canonical decision: library classes, KBox runtime, and
            // out-of-scope classes are skipped uniformly. Kept classes are
            // still body-protected (their names are preserved separately).
            if (!cfg.shouldProtectClass(cn.name)) continue;
            try {
                scatterClass(cn);
            } catch (Exception e) {
                KBoxLog.warn(TAG, "Scatter failed for " + cn.name + ": " + e.getMessage());
            }
        }
        // Finalize: write <clinit> for each holder.
        for (Holder h : holders.all()) {
            writeHolderClinit(h);
        }
        KBoxLog.info(TAG, "Scattered " + scattered + " strings across "
                + NUM_HOLDERS + " holders (" + holders.totalFields() + " fields)");
    }

    @SuppressWarnings("unchecked")
    private void scatterClass(ClassNode cn) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                    LdcInsnNode ldc = (LdcInsnNode) ins;
                    if (ldc.cst instanceof String) {
                        String s = (String) ldc.cst;
                        if (s.isEmpty()) { ins = next; continue; }
                        InsnList repl = buildScattered(s, mn);
                        if (repl != null) {
                            mn.instructions.insertBefore(ins, repl);
                            mn.instructions.remove(ins);
                            scattered++;
                        }
                    }
                }
                ins = next;
            }
        }
    }

    /**
     * Builds the inline decryption + concatenation for a single string.
     * Generates:
     * <pre>
     *   StringBuilder sb = new StringBuilder();
     *   // segment 1
     *   byte[] a = HolderX.fY;
     *   for (int i=0;i<a.length;i++) a[i]^=((key>>((i%4)*8))&0xFF);
     *   sb.append(new String(a, UTF_8));
     *   // segment 2, 3 ...
     *   String result = sb.toString().intern();
     * </pre>
     */
    private InsnList buildScattered(String s, MethodNode mn) {
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        int len = utf8.length;
        // Split into SEGMENTS parts.
        int[] bounds = splitBounds(len, SEGMENTS);
        Segment[] segs = new Segment[SEGMENTS];
        for (int i = 0; i < SEGMENTS; i++) {
            int start = bounds[i];
            int end = bounds[i + 1];
            int segLen = end - start;
            if (segLen <= 0) {
                segs[i] = null;
                continue;
            }
            byte[] segBytes = new byte[segLen];
            System.arraycopy(utf8, start, segBytes, 0, segLen);
            int key = rng.nextInt();
            byte[] enc = xorEncrypt(segBytes, key);
            FieldSlot slot = holders.allocField();
            slot.holder.fieldData.add(new EncodedField(slot.fieldName, enc));
            segs[i] = new Segment(slot.holder.name, slot.fieldName, key, segLen);
        }

        // We need a local var for the StringBuilder.
        // Determine next available local var index.
        int sbLocal = mn.maxLocals;
        mn.maxLocals += 1;
        // We also need a temp local for the byte[] and loop counter.
        int arrLocal = mn.maxLocals;
        int idxLocal = mn.maxLocals + 1;
        mn.maxLocals += 2;

        InsnList l = new InsnList();

        // new StringBuilder()
        l.add(new TypeInsnNode(Opcodes.NEW, "java/lang/StringBuilder"));
        l.add(new InsnNode(Opcodes.DUP));
        l.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/StringBuilder", "<init>", "()V", false));
        l.add(new VarInsnNode(Opcodes.ASTORE, sbLocal));

        for (Segment seg : segs) {
            if (seg == null) continue;
            // byte[] a = Holder.field.clone();  // clone to avoid mutating static field
            l.add(new FieldInsnNode(Opcodes.GETSTATIC, seg.holderName, seg.fieldName, "[B"));
            l.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "[B", "clone", "()Ljava/lang/Object;", false));
            l.add(new TypeInsnNode(Opcodes.CHECKCAST, "[B"));
            l.add(new VarInsnNode(Opcodes.ASTORE, arrLocal));

            // Inline XOR loop: for (int i=0; i<a.length; i++)
            //   a[i] ^= (key >> ((i % 4) * 8)) & 0xFF;
            LabelNode loopStart = new LabelNode();
            LabelNode loopEnd = new LabelNode();
            l.add(new InsnNode(Opcodes.ICONST_0));
            l.add(new VarInsnNode(Opcodes.ISTORE, idxLocal));
            l.add(loopStart);
            // condition: if (idx >= a.length) goto end
            l.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
            l.add(new VarInsnNode(Opcodes.ALOAD, arrLocal));
            l.add(new InsnNode(Opcodes.ARRAYLENGTH));
            l.add(new JumpInsnNode(Opcodes.IF_ICMPGE, loopEnd));
            // a[idx] ^= (key >> ((idx % 4) * 8)) & 0xFF
            l.add(new VarInsnNode(Opcodes.ALOAD, arrLocal));
            l.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
            l.add(new VarInsnNode(Opcodes.ALOAD, arrLocal));
            l.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
            l.add(new InsnNode(Opcodes.BALOAD));
            // compute (key >>> ((idx % 4) * 8)) & 0xFF
            // IUSHR pops value1, value2 and yields value1 >>> value2,
            // so push key FIRST, then the shift amount.
            l.add(new LdcInsnNode(seg.key));
            l.add(new VarInsnNode(Opcodes.ILOAD, idxLocal));
            l.add(new LdcInsnNode(4));
            l.add(new InsnNode(Opcodes.IREM));
            l.add(new InsnNode(Opcodes.ICONST_3)); // * 8 = << 3
            l.add(new InsnNode(Opcodes.ISHL));
            l.add(new InsnNode(Opcodes.IUSHR)); // key >>> shift
            l.add(new LdcInsnNode(0xFF));
            l.add(new InsnNode(Opcodes.IAND));
            // XOR
            l.add(new InsnNode(Opcodes.IXOR));
            l.add(new InsnNode(Opcodes.I2B)); // to byte
            l.add(new InsnNode(Opcodes.BASTORE));
            // i++
            l.add(new IincInsnNode(idxLocal, 1));
            l.add(new JumpInsnNode(Opcodes.GOTO, loopStart));
            l.add(loopEnd);

            // sb.append(new String(a, UTF_8))
            l.add(new VarInsnNode(Opcodes.ALOAD, sbLocal));
            l.add(new TypeInsnNode(Opcodes.NEW, "java/lang/String"));
            l.add(new InsnNode(Opcodes.DUP));
            l.add(new VarInsnNode(Opcodes.ALOAD, arrLocal));
            // push UTF_8 charset: java.nio.charset.StandardCharsets.UTF_8
            l.add(new FieldInsnNode(Opcodes.GETSTATIC, "java/nio/charset/StandardCharsets", "UTF_8", "Ljava/nio/charset/Charset;"));
            l.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/String", "<init>", "([BLjava/nio/charset/Charset;)V", false));
            l.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;", false));
            l.add(new InsnNode(Opcodes.POP));
        }

        // result = sb.toString().intern()
        l.add(new VarInsnNode(Opcodes.ALOAD, sbLocal));
        l.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/StringBuilder", "toString", "()Ljava/lang/String;", false));
        l.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "intern", "()Ljava/lang/String;", false));

        return l;
    }

    /** XOR encrypt with a 4-byte rolling key. */
    private byte[] xorEncrypt(byte[] data, int key) {
        byte[] out = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            int shift = (i % 4) * 8;
            out[i] = (byte) (data[i] ^ ((key >>> shift) & 0xFF));
        }
        return out;
    }

    /** Split [0, len) into n roughly-equal parts. Returns n+1 boundaries. */
    private static int[] splitBounds(int len, int n) {
        int[] bounds = new int[n + 1];
        bounds[0] = 0;
        bounds[n] = len;
        int base = len / n;
        int remainder = len % n;
        int pos = 0;
        for (int i = 1; i < n; i++) {
            pos += base + (i <= remainder ? 1 : 0);
            bounds[i] = pos;
        }
        return bounds;
    }

    // ===== Holder management =====

    private Holder ensureHolder(int idx) {
        String name = HOLDER_PREFIX + idx;
        Holder h = holders.get(idx);
        if (h != null) return h;
        ClassNode cn = graph.getClasses().get(name);
        if (cn == null) {
            cn = new ClassNode();
            cn.version = Opcodes.V1_8;
            cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
            cn.name = name;
            cn.superName = "java/lang/Object";
            // Default constructor: must call super() before return or JVM
            // verifier rejects with "Constructor must call super() or this()".
            MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
            ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
            ctor.instructions.add(new MethodInsnNode(
                    Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
            ctor.instructions.add(new InsnNode(Opcodes.RETURN));
            ctor.maxStack = 1;
            ctor.maxLocals = 1;
            cn.methods.add(ctor);
            graph.getClasses().put(name, cn);
        }
        h = new Holder(idx, name, cn);
        holders.put(idx, h);
        return h;
    }

    /**
     * Maximum number of byte-array fields initialized per static method.
     * Each field's init emits ~ (dataLen + 8) instructions; a 64KB method
     * caps out around 200 medium fields. We chunk conservatively so no
     * init method ever exceeds the JVM 64KB per-method bytecode limit.
     * Without chunking, a holder with many fields overflows <clinit> and
     * its serialization fails during packaging — the synthetic class has no
     * original bytes to roll back to, so it is silently dropped, and any
     * class referencing its fields crashes at runtime with
     * NoClassDefFoundError. Splitting into multiple static init methods
     * (called from <clinit>) keeps every method well under the limit.
     */
    private static final int FIELDS_PER_INIT_METHOD = 150;

    @SuppressWarnings("unchecked")
    private void writeHolderClinit(Holder h) {
        if (h.fieldData.isEmpty()) return;
        // Remove any existing init helpers / <clinit>.
        for (int i = h.node.methods.size() - 1; i >= 0; i--) {
            MethodNode m = (MethodNode) h.node.methods.get(i);
            if (m.name.equals("<clinit>") || m.name.startsWith("k$")) {
                h.node.methods.remove(i);
            }
        }
        // Declare fields first.
        for (EncodedField ef : h.fieldData) {
            h.node.fields.add(new FieldNode(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                    ef.name, "[B", null, null));
        }
        // Chunk the fields into multiple static init methods so no single
        // method's bytecode exceeds the JVM 64KB limit.
        List<List<EncodedField>> chunks = chunk(h.fieldData, FIELDS_PER_INIT_METHOD);
        int chunkIdx = 0;
        List<String> helperNames = new ArrayList<>();
        for (List<EncodedField> ch : chunks) {
            String helperName = "k$" + chunkIdx;
            MethodNode helper = new MethodNode(
                    Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC, helperName, "()V", null, null);
            InsnList l = helper.instructions;
            for (EncodedField ef : ch) {
                // new byte[ef.data.length]
                pushInt(l, ef.data.length);
                l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
                for (int i = 0; i < ef.data.length; i++) {
                    l.add(new InsnNode(Opcodes.DUP));
                    pushInt(l, i);
                    pushByte(l, ef.data[i]);
                    l.add(new InsnNode(Opcodes.BASTORE));
                }
                l.add(new FieldInsnNode(Opcodes.PUTSTATIC, h.name, ef.name, "[B"));
            }
            l.add(new InsnNode(Opcodes.RETURN));
            helper.maxStack = 4;
            helper.maxLocals = 0;
            h.node.methods.add(helper);
            helperNames.add(helperName);
            chunkIdx++;
        }
        // <clinit> simply calls each helper in order.
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;
        for (String hn : helperNames) {
            cl.add(new MethodInsnNode(Opcodes.INVOKESTATIC, h.name, hn, "()V", false));
        }
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 0;
        clinit.maxLocals = 0;
        h.node.methods.add(clinit);
    }

    /** Splits a list into fixed-size sublists. */
    private static <T> List<List<T>> chunk(List<T> list, int size) {
        List<List<T>> out = new ArrayList<>();
        for (int i = 0; i < list.size(); i += size) {
            out.add(new ArrayList<>(list.subList(i, Math.min(i + size, list.size()))));
        }
        return out;
    }

    static void pushInt(InsnList l, int v) {
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

    static void pushByte(InsnList l, byte b) {
        int v = b & 0xFF;
        if (v >= 0 && v <= 5) {
            l.add(new InsnNode(Opcodes.ICONST_0 + v));
        } else if (v <= 127) {
            l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        } else {
            l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        }
    }

    // ===== Inner types =====

    private static final class Segment {
        final String holderName;
        final String fieldName;
        final int key;
        final int length;
        Segment(String holderName, String fieldName, int key, int length) {
            this.holderName = holderName; this.fieldName = fieldName;
            this.key = key; this.length = length;
        }
    }

    private static final class EncodedField {
        final String name;
        final byte[] data;
        EncodedField(String name, byte[] data) { this.name = name; this.data = data; }
    }

    private static final class Holder {
        final int idx;
        final String name;
        final ClassNode node;
        final List<EncodedField> fieldData = new ArrayList<>();
        int nextFieldIdx = 0;
        Holder(int idx, String name, ClassNode node) {
            this.idx = idx; this.name = name; this.node = node;
        }
    }

    private static final class FieldSlot {
        final Holder holder;
        final String fieldName;
        FieldSlot(Holder holder, String fieldName) {
            this.holder = holder; this.fieldName = fieldName;
        }
    }

    private static final class HolderManager {
        final Map<Integer, Holder> holders = new HashMap<>();
        Holder get(int idx) { return holders.get(idx); }
        void put(int idx, Holder h) { holders.put(idx, h); }
        Collection<Holder> all() { return holders.values(); }
        int totalFields() {
            int total = 0;
            for (Holder h : holders.values()) total += h.fieldData.size();
            return total;
        }
        FieldSlot allocField() {
            // Pick the holder with the fewest fields.
            Holder best = null;
            for (Holder h : holders.values()) {
                if (best == null || h.nextFieldIdx < best.nextFieldIdx) best = h;
            }
            if (best == null) best = holders.values().iterator().next();
            String fieldName = "f" + best.nextFieldIdx;
            best.nextFieldIdx++;
            return new FieldSlot(best, fieldName);
        }
    }
}
