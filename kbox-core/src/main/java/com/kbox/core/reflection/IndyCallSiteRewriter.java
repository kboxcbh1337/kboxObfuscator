package com.kbox.core.reflection;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * 条目 59/61/62: invokedynamic call-site rewriting.
 *
 * <p>Selected call sites are replaced by an {@code INVOKEDYNAMIC} whose
 * bootstrap argument is an encrypted {@code owner\0name\0descriptor} blob:
 * <ul>
 *   <li>{@code INVOKESTATIC owner.m(args)} → indy + {@code KboxIndy.bootStatic}</li>
 *   <li>{@code INVOKEVIRTUAL/INTERFACE o.m(args)} → indy + {@code bootVirtual}</li>
 *   <li>{@code GETSTATIC owner.f} → indy + {@code bootGet}</li>
 *   <li>{@code PUTSTATIC owner.f = v} → indy + {@code bootPut}</li>
 * </ul>
 * The constant pool then contains no {@code Methodref}/{@code Fieldref} to the
 * target — the reference only exists as ciphertext inside BootstrapMethods,
 * which also defeats call-graph recovery (the call graph now passes through a
 * single generic bootstrap). Semantics and access checks are unchanged: the
 * bootstrap receives the caller's trusted {@code Lookup} and links the real
 * {@code MethodHandle} once (ConstantCallSite).
 *
 * <p>Ordering: must run AFTER identifier/package renaming (the encrypted
 * owner/name are final runtime names) and must NOT touch methods selected for
 * VMP/JNIC (their translators do not support invokedynamic and their
 * signatures are consumed by the native layer).
 */
public final class IndyCallSiteRewriter {

    private static final String TAG = "indy-rewrite";
    private static final String INDY = "com/kbox/runtime/KboxIndy";
    private static final String BSM_DESC =
            "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;"
                    + "Ljava/lang/invoke/MethodType;Ljava/lang/String;)"
                    + "Ljava/lang/invoke/CallSite;";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int rewritten;
    private Map<String, ClassNode> byName;

    public IndyCallSiteRewriter(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isEncryptStrings() || cfg.getStringEncryptionStrength() < 2) return;
        byName = new HashMap<>(graph.getClasses());
        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name.equals(INDY) || cn.name.startsWith("com/kbox/runtime/")) continue;
            if (!cfg.shouldProtectClass(cn.name)) continue;
            // invokedynamic requires class file version >= 51 (Java 7).
            if (cn.version < Opcodes.V1_7) continue;
            try {
                for (MethodNode mn : (List<MethodNode>) cn.methods) {
                    if (mn.instructions == null || mn.instructions.size() == 0) continue;
                    if (isVmpOrJnicTarget(cn, mn)) continue;
                    rewriteMethod(cn, mn);
                }
            } catch (Exception e) {
                if (cfg.isNeverFail()) {
                    KBoxLog.warn(TAG, "indy rewrite failed for " + cn.name + ": "
                            + e.getMessage());
                } else {
                    throw new com.kbox.core.KBoxException(
                            "indy rewrite failed for " + cn.name, e);
                }
            }
        }
        if (rewritten > 0) {
            KBoxLog.info(TAG, "Rewrote " + rewritten + " call/field site(s) to invokedynamic");
        }
    }

    private boolean isVmpOrJnicTarget(ClassNode cn, MethodNode mn) {
        String key = ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
        if (cfg.isEnableVmp() && cfg.getVmpMethods().contains(key)) return true;
        if (cfg.isEnableJnic() && cfg.getNativeMethods().contains(key)) return true;
        return false;
    }

    private void rewriteMethod(ClassNode cn, MethodNode mn) {
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins instanceof MethodInsnNode) {
                MethodInsnNode mi = (MethodInsnNode) ins;
                if (mi.name.equals("<init>") || mi.name.equals("<clinit>")) {
                    ins = next; continue;
                }
                int op = mi.getOpcode();
                if (op != Opcodes.INVOKESTATIC && op != Opcodes.INVOKEVIRTUAL
                        && op != Opcodes.INVOKEINTERFACE) {
                    ins = next; continue;
                }
                MethodNode target = findMethod(mi.owner, mi.name, mi.desc);
                if (target == null) { ins = next; continue; }
                boolean targetStatic = (target.access & Opcodes.ACC_STATIC) != 0;
                if ((op == Opcodes.INVOKESTATIC) != targetStatic) { ins = next; continue; }
                if (!accessible(cn, mi.owner, target.access)) { ins = next; continue; }
                String indyDesc = (op == Opcodes.INVOKESTATIC)
                        ? mi.desc
                        : "(L" + mi.owner + ";" + mi.desc.substring(1);
                String bsm = (op == Opcodes.INVOKESTATIC) ? "bootStatic" : "bootVirtual";
                mn.instructions.insertBefore(mi, indy(mi.name, indyDesc, bsm,
                        mi.owner, mi.name, mi.desc));
                mn.instructions.remove(mi);
                rewritten++;
            } else if (ins instanceof FieldInsnNode) {
                FieldInsnNode fi = (FieldInsnNode) ins;
                int op = fi.getOpcode();
                if (op == Opcodes.GETSTATIC || op == Opcodes.PUTSTATIC) {
                    FieldNode fn = findField(fi.owner, fi.name, fi.desc);
                    if (fn != null
                            && (fn.access & Opcodes.ACC_STATIC) != 0
                            && (op != Opcodes.PUTSTATIC || (fn.access & Opcodes.ACC_FINAL) == 0)
                            && accessible(cn, fi.owner, fn.access)) {
                        boolean get = op == Opcodes.GETSTATIC;
                        String indyDesc = get ? "()" + fi.desc : "(" + fi.desc + ")V";
                        mn.instructions.insertBefore(fi, indy(fi.name, indyDesc,
                                get ? "bootGet" : "bootPut",
                                fi.owner, fi.name, fi.desc));
                        mn.instructions.remove(fi);
                        rewritten++;
                    }
                }
            }
            ins = next;
        }
    }

    private InvokeDynamicInsnNode indy(String name, String desc, String bsmName,
                                       String owner, String fieldOrMethod, String type) {
        // The bootstrap resolves the owner with Class.forName, which needs the
        // dotted binary name; the descriptor keeps internal '/' spelling.
        String meta = owner.replace('/', '.') + "\u0000" + fieldOrMethod + "\u0000" + type;
        Handle bsm = new Handle(Opcodes.H_INVOKESTATIC, INDY, bsmName, BSM_DESC, false);
        return new InvokeDynamicInsnNode("k", desc, bsm, encode(meta));
    }

    /** XOR + Base64 of {@code owner\0name\0desc}. */
    private static String encode(String s) {
        byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
        int key = ThreadLocalRandom.current().nextInt();
        byte[] out = new byte[utf8.length + 4];
        out[0] = (byte) (key >>> 24);
        out[1] = (byte) (key >>> 16);
        out[2] = (byte) (key >>> 8);
        out[3] = (byte) key;
        for (int i = 0; i < utf8.length; i++) {
            int shift = (i * 7) % 32;
            int k = (key >>> shift) ^ (key << (32 - shift));
            out[i + 4] = (byte) (utf8[i] ^ (k & 0xFF));
        }
        return Base64.getEncoder().withoutPadding().encodeToString(out);
    }

    private MethodNode findMethod(String owner, String name, String desc) {
        ClassNode cn = byName.get(owner);
        if (cn == null || cn.methods == null) return null;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.name.equals(name) && mn.desc.equals(desc)) return mn;
        }
        return null;
    }

    private FieldNode findField(String owner, String name, String desc) {
        ClassNode cn = byName.get(owner);
        if (cn == null || cn.fields == null) return null;
        for (FieldNode fn : (List<FieldNode>) cn.fields) {
            if (fn.name.equals(name) && fn.desc.equals(desc)) return fn;
        }
        return null;
    }

    /** Conservative access check: public, same class, or same package. */
    private static boolean accessible(ClassNode caller, String owner, int access) {
        if ((access & Opcodes.ACC_PUBLIC) != 0) return true;
        if (caller.name.equals(owner)) return true;
        String cp = pkg(caller.name), op = pkg(owner);
        return cp.equals(op);
    }

    private static String pkg(String internal) {
        int i = internal.lastIndexOf('/');
        return i < 0 ? "" : internal.substring(0, i);
    }
}
