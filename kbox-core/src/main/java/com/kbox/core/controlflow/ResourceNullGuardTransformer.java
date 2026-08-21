package com.kbox.core.controlflow;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.util.List;

/**
 * Injects null-guards after every {@code Class.getResourceAsStream(String)}
 * call. If the call returns {@code null} (because a resource was renamed by
 * {@code obfuscateResources} and the ClassLoader cannot resolve the new path),
 * the guard substitutes an empty {@code ByteArrayInputStream(new byte[0])}.
 *
 * <p>This prevents downstream NPEs from {@code Objects.requireNonNull()},
 * {@code .read()}, or any other dereference on the returned {@code InputStream}.
 *
 * <p>Bytecode transformation (injected after each getResourceAsStream call):
 * <pre>
 *   ; Stack: InputStream (possibly null)
 *   DUP                          ; dup the ref
 *   IFNONNULL notNull            ; if non-null, continue as normal
 *   POP                          ; discard null
 *   NEW ByteArrayInputStream     ; create replacement
 *   DUP
 *   ICONST_0
 *   NEWARRAY T_BYTE              ; new byte[0]
 *   INVOKESPECIAL ByteArrayInputStream.&lt;init&gt;([B)V
 *   notNull:                     ; stack has a non-null InputStream
 *   ; ... original code continues
 * </pre>
 *
 * <p>Each method is scanned only for {@code Class.getResourceAsStream} calls;
 * methods without such calls are left untouched. Processing iterates backwards
 * to keep {@code AbstractInsnNode} indices stable as new instructions are
 * injected.
 */
public final class ResourceNullGuardTransformer {

    private static final String TAG = "null-guard";
    private static final String CLASS_CLASS = "java/lang/Class";
    private static final String GET_RESOURCE_AS_STREAM = "getResourceAsStream";
    private static final String GET_RESOURCE_AS_STREAM_DESC = "(Ljava/lang/String;)Ljava/io/InputStream;";
    private static final String BIS_INTERNAL = "java/io/ByteArrayInputStream";
    private static final String BIS_INIT = "<init>";
    private static final String BIS_INIT_DESC = "([B)V";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public ResourceNullGuardTransformer(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /**
     * Apply null-guard injection to all eligible classes.
     * @return number of getResourceAsStream callsites guarded
     */
    public int apply() {
        if (!cfg.isNullGuard()) {
            return 0;
        }

        int totalGuarded = 0;
        int classCount = 0;

        for (ClassNode cn : graph.getClasses().values()) {
            String internalName = cn.name;
            // Skip KBox runtime classes (they already handle null safely)
            if (internalName.startsWith("com/kbox/runtime/")) {
                continue;
            }
            // Skip library classes (kept classes are still body-protected)
            if (!cfg.shouldProtectClass(internalName)) {
                continue;
            }

            int classGuarded = 0;
            @SuppressWarnings("unchecked")
            List<MethodNode> methods = cn.methods;
            for (MethodNode mn : methods) {
                // Skip abstract/native methods (no code to transform)
                if ((mn.access & Opcodes.ACC_ABSTRACT) != 0
                        || (mn.access & Opcodes.ACC_NATIVE) != 0) {
                    continue;
                }
                classGuarded += guardMethod(mn);
            }

            if (classGuarded > 0) {
                classCount++;
                totalGuarded += classGuarded;
            }
        }

        KBoxLog.info(TAG, "Null-guard injected: " + totalGuarded
                + " getResourceAsStream call(s) across " + classCount + " class(es)");
        return totalGuarded;
    }

    /**
     * Inject null-guards into a single method. Iterates backwards so injected
     * instructions don't shift the indices of earlier instructions.
     *
     * @return number of guarded callsites in this method
     */
    @SuppressWarnings("unchecked")
    private int guardMethod(MethodNode mn) {
        int count = 0;
        InsnList insns = mn.instructions;

        // Walk backwards to keep indices stable during injection
        for (int i = insns.size() - 1; i >= 0; i--) {
            AbstractInsnNode insn = insns.get(i);
            if (!(insn instanceof MethodInsnNode)) continue;

            MethodInsnNode call = (MethodInsnNode) insn;
            if (call.getOpcode() != Opcodes.INVOKEVIRTUAL) continue;
            if (!CLASS_CLASS.equals(call.owner)) continue;
            if (!GET_RESOURCE_AS_STREAM.equals(call.name)) continue;
            if (!GET_RESOURCE_AS_STREAM_DESC.equals(call.desc)) continue;

            // Found a Class.getResourceAsStream(String) call.
            // Inject null-guard right after it.
            injectNullGuard(insns, call);
            count++;
        }

        return count;
    }

    /**
     * Inject the null-guard instruction sequence after the given
     * getResourceAsStream call.
     */
    private void injectNullGuard(InsnList insns, MethodInsnNode call) {
        LabelNode notNullLabel = new LabelNode();

        InsnList guard = new InsnList();
        // dup the InputStream reference
        guard.add(new InsnNode(Opcodes.DUP));
        // if non-null, skip to notNullLabel
        guard.add(new JumpInsnNode(Opcodes.IFNONNULL, notNullLabel));
        // it's null: pop the null ref
        guard.add(new InsnNode(Opcodes.POP));
        // push a replacement: new ByteArrayInputStream(new byte[0])
        guard.add(new TypeInsnNode(Opcodes.NEW, BIS_INTERNAL));
        guard.add(new InsnNode(Opcodes.DUP));
        guard.add(new InsnNode(Opcodes.ICONST_0));
        guard.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
        guard.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, BIS_INTERNAL,
                BIS_INIT, BIS_INIT_DESC, false));
        // notNull: stack now has a guaranteed-non-null InputStream
        guard.add(notNullLabel);

        // Insert after the getResourceAsStream call instruction
        insns.insert(call, guard);
    }
}
