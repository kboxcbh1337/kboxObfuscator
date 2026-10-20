package com.kbox.core.reflection;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.stringenc.StringEncryptor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 条目 58: class-literal reference hiding.
 *
 * <p>{@code Foo.class} compiles to {@code LDC CONSTANT_Class Foo}, which is a
 * direct, greppable constant-pool reference to {@code Foo}. This pass rewrites
 * every such literal (object and array classes) into
 * {@code KBoxRuntime.c(new byte[]{enc})}: the binary name is XOR-encrypted at
 * build time and resolved through the context class loader at run time.
 * {@code Class.forName} returns the same {@link Class} instance the JVM would
 * have pushed, so identity comparisons and {@code isAssignableFrom} checks are
 * unaffected.
 *
 * <p>Primitive class literals ({@code int.class}) are left alone: there is no
 * name-based resolution for them and they carry no reference to app code.
 */
public final class ClassLiteralHider {

    private static final String TAG = "class-refs";
    private static final String OWNER = "com/kbox/runtime/KBoxRuntime";
    private static final String DESC = "([B)Ljava/lang/Class;";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int hidden;

    public ClassLiteralHider(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        // Only meaningful with reference-hiding strength >= 2 (same knob as the
        // AES string mode); at strength 1 the extra decryptor call would bloat
        // the output for no benefit.
        if (!cfg.isEncryptStrings() || cfg.getStringEncryptionStrength() < 2) return;
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name.equals(OWNER) || cn.name.startsWith("com/kbox/runtime/")) continue;
            if (!cfg.shouldProtectClass(cn.name)) continue;
            try {
                for (MethodNode mn : (List<MethodNode>) cn.methods) {
                    if (mn.instructions == null || mn.instructions.size() == 0) continue;
                    hideInMethod(mn);
                }
            } catch (Exception e) {
                if (cfg.isNeverFail()) {
                    KBoxLog.warn(TAG, "class-literal hiding failed for " + cn.name
                            + ": " + e.getMessage());
                } else {
                    throw new com.kbox.core.KBoxException(
                            "class-literal hiding failed for " + cn.name, e);
                }
            }
        }
        if (hidden > 0) KBoxLog.info(TAG, "Hid " + hidden + " class literal reference(s)");
    }

    private void hideInMethod(MethodNode mn) {
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins.getOpcode() == Opcodes.LDC && ins instanceof LdcInsnNode) {
                Object cst = ((LdcInsnNode) ins).cst;
                if (cst instanceof Type) {
                    Type t = (Type) cst;
                    String binary = binaryName(t);
                    if (binary != null) {
                        mn.instructions.insertBefore(ins, replacement(binary));
                        mn.instructions.remove(ins);
                        hidden++;
                    }
                }
            }
            ins = next;
        }
    }

    /** Binary name usable with {@code Class.forName}, or null when unsupported. */
    private static String binaryName(Type t) {
        if (t.getSort() == Type.OBJECT) return t.getClassName();
        if (t.getSort() == Type.ARRAY) return t.getDescriptor().replace('/', '.');
        return null; // primitives / method types
    }

    /** Emits {@code KBoxRuntime.c(new byte[]{enc})}. */
    private static InsnList replacement(String binaryName) {
        byte[] utf8 = binaryName.getBytes(StandardCharsets.UTF_8);
        int key = ThreadLocalRandom.current().nextInt();
        byte[] enc = new byte[utf8.length + 4];
        enc[0] = (byte) (key >>> 24);
        enc[1] = (byte) (key >>> 16);
        enc[2] = (byte) (key >>> 8);
        enc[3] = (byte) key;
        for (int i = 0; i < utf8.length; i++) {
            int shift = (i * 7) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift));
            enc[i + 4] = (byte) (utf8[i] ^ (k & 0xFF));
        }
        InsnList l = new InsnList();
        StringEncryptor.pushInt(l, enc.length);
        l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        for (int i = 0; i < enc.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            StringEncryptor.pushInt(l, i);
            StringEncryptor.pushByte(l, enc[i]);
            l.add(new InsnNode(Opcodes.BASTORE));
        }
        l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, OWNER, "c", DESC, false));
        return l;
    }
}
