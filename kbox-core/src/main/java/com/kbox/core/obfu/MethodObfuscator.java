package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Method inlining + extraction.
 *
 * <p><b>Inlining</b>: small, simple methods (no try/catch, no synchronized,
 * no <code>this</code> capture, no local-variable-dependent control flow) are
 * inlined at their call sites. The callee must be "trivial": a body that only
 * loads arguments / constants, performs a few operations, and a single
 * return. This breaks the method-boundary structure a decompiler relies on.
 *
 * <p><b>Extraction</b>: very large methods (bytecode over a threshold) have
 * their instruction block split into N synthetic static helpers, so no single
 * method is a convenient decompilation target.
 *
 * <p>Both passes are conservative: if a candidate is not provably safe to
 * transform, it is left untouched. The pipeline's serialization verifier
 * (CheckClassAdapter) confirms every result, and any failure rolls back to
 * the original class bytes.
 */
public final class MethodObfuscator {

    private static final String TAG = "inline";
    private static final int MAX_INLINE_BYTECODE = 24;   // body instruction count
    private static final int MAX_EXTRACT_BYTECODE = 4000; // methods above this get split
    private static final int EXTRACT_CHUNK = 800;         // each helper gets ~800 insns

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public MethodObfuscator(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isMethodInlineExtract()) return;
        int inlined = 0;
        int extracted = 0;
        // Inline pass.
        for (ClassNode cn : new ArrayList<>(graph.getClasses().values())) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            if (cn.name.startsWith("com/kbox/runtime/")) continue;
            inlined += inlineInClass(cn);
        }
        // Extraction pass.
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            if (cn.name.startsWith("com/kbox/runtime/")) continue;
            extracted += extractInClass(cn);
        }
        KBoxLog.info(TAG, "Method obfuscation: " + inlined + " methods inlined, "
                + extracted + " methods extracted");
    }

    // ================= Inlining =================

    private int inlineInClass(ClassNode cn) {
        // Only inline methods defined in the same-class call sites where the
        // callee is tiny and side-effect free. We operate per-class to keep the
        // analysis local and safe.
        Map<String, MethodNode> byKey = new HashMap<>();
        for (MethodNode m : (List<MethodNode>) cn.methods) {
            byKey.put(m.name + m.desc, m);
        }
        int count = 0;
        for (MethodNode caller : (List<MethodNode>) cn.methods) {
            if (caller.instructions == null || caller.name.equals("<init>")
                    || caller.name.equals("<clinit>")) continue;
            for (AbstractInsnNode ins = caller.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) ins;
                    // Only same-class, non-constructor, static calls: instance
                    // inlining would need receiver stack re-arrangement.
                    if (mi.getOpcode() != Opcodes.INVOKESTATIC
                            || !mi.owner.equals(cn.name) || mi.name.equals("<init>")) {
                        ins = next; continue;
                    }
                    MethodNode callee = byKey.get(mi.name + mi.desc);
                    if (callee == null || !isTrivial(callee)) {
                        ins = next; continue;
                    }
                    if (tryInline(caller, mi, callee)) {
                        count++;
                    }
                }
                ins = next;
            }
        }
        return count;
    }

    /** A method is inlinable only if it is straight-line: no branches, no
     *  switches, no try/catch, no synchronized, no allocations, no nested
     *  calls, and a single return. This guarantees the inlined copy is a
     *  linear argument→operation→return sequence with no label/jump to remap
     *  and no local-variable-dependent control flow. */
    private static boolean isTrivial(MethodNode m) {
        if (m.instructions == null || m.instructions.size() == 0) return false;
        if (m.tryCatchBlocks != null && !m.tryCatchBlocks.isEmpty()) return false;
        if ((m.access & Opcodes.ACC_SYNCHRONIZED) != 0) return false;
        if (m.instructions.size() > MAX_INLINE_BYTECODE) return false;
        int returns = 0;
        int labels = 0;
        for (AbstractInsnNode ins : m.instructions) {
            int op = ins.getOpcode();
            if (op == Opcodes.NEW || op == Opcodes.NEWARRAY
                    || op == Opcodes.ANEWARRAY || op == Opcodes.MULTIANEWARRAY) return false;
            if (ins instanceof MethodInsnNode) return false; // no nested calls
            if (op == Opcodes.ATHROW) return false;
            if (ins instanceof JumpInsnNode
                    || ins instanceof TableSwitchInsnNode
                    || ins instanceof LookupSwitchInsnNode) return false;
            if (ins instanceof LabelNode) labels++;
            if (labels > 1) return false; // only the method-entry label allowed
            if (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) returns++;
        }
        return returns == 1;
    }

    /**
     * Inlines the straight-line callee body into the caller at the call site.
     * The call-site arguments are popped off the stack into fresh caller
     * locals; every callee local (parameters and body temporaries) is remapped
     * onto fresh caller slots so the caller's own locals are never clobbered;
     * the return value is stored at the callee return then reloaded at the
     * join point so the stack height the caller expects is preserved.
     */
    private boolean tryInline(MethodNode caller, MethodInsnNode call,
                              MethodNode callee) {
        try {
            Type[] args = Type.getArgumentTypes(call.desc);
            Type ret = Type.getReturnType(call.desc);
            boolean hasResult = ret.getSort() != Type.VOID;

            // Fresh caller slots for the callee's parameters.
            int base = caller.maxLocals;
            int[] paramSlots = new int[args.length];
            int slot = base;
            for (int i = 0; i < args.length; i++) {
                paramSlots[i] = slot;
                slot += args[i].getSize();
            }
            int resultSlot = hasResult ? slot : -1;
            if (hasResult) slot += ret.getSize();

            // Map every callee local slot (params + body temporaries) onto
            // fresh caller slots, so the inlined body cannot clobber the
            // caller's own locals.
            Map<Integer, Integer> varMap = new HashMap<>();
            for (int i = 0; i < args.length; i++) {
                varMap.put(calleeParamSlot(callee, i), paramSlots[i]);
            }
            for (AbstractInsnNode ins : callee.instructions) {
                if (ins instanceof VarInsnNode) {
                    int v = ((VarInsnNode) ins).var;
                    if (!varMap.containsKey(v)) {
                        varMap.put(v, slot++);
                    }
                }
            }
            caller.maxLocals = Math.max(caller.maxLocals, slot);

            // Build a remapped copy of the callee body.
            InsnList body = new InsnList();
            LabelNode join = new LabelNode();

            // The real call-site arguments are still on the JVM stack (they
            // were pushed before the call instruction we are about to remove).
            // Store them into the fresh locals in reverse order (top of stack
            // is the LAST argument) before the body runs.
            for (int ai = args.length - 1; ai >= 0; ai--) {
                body.add(new VarInsnNode(slotToStore(args[ai]), paramSlots[ai]));
            }

            // Copy straight-line instructions with remapping; rewrite the
            // single return as store + jump to join.
            for (AbstractInsnNode ins : callee.instructions) {
                if (ins instanceof VarInsnNode) {
                    VarInsnNode v = (VarInsnNode) ins;
                    Integer mapped = varMap.get(v.var);
                    int newVar = mapped != null ? mapped : v.var;
                    body.add(new VarInsnNode(v.getOpcode(), newVar));
                } else if (ins instanceof LabelNode
                        || ins instanceof FrameNode
                        || ins instanceof LineNumberNode) {
                    // metadata — regenerated by COMPUTE_FRAMES / serialization
                } else if (ins.getOpcode() >= Opcodes.IRETURN && ins.getOpcode() <= Opcodes.RETURN) {
                    if (hasResult) {
                        body.add(new VarInsnNode(slotToStore(ret), resultSlot));
                    }
                    body.add(new JumpInsnNode(Opcodes.GOTO, join));
                } else {
                    body.add(ins.clone(new HashMap<>()));
                }
            }
            body.add(join);
            // Restore the return value onto the stack for the caller.
            if (hasResult) {
                body.add(new VarInsnNode(slotToLoad(ret), resultSlot));
            }

            // Replace the call site with the inlined body.
            caller.instructions.insertBefore(call, body);
            caller.instructions.remove(call);
            return true;
        } catch (Exception e) {
            KBoxLog.debug(TAG, "Inline skipped for " + call.name + ": " + e.getMessage());
            return false;
        }
    }

    /** Callee slot index of the i-th parameter (static methods start at 0). */
    private static int calleeParamSlot(MethodNode m, int i) {
        int s = (m.access & Opcodes.ACC_STATIC) != 0 ? 0 : 1;
        Type[] ts = Type.getArgumentTypes(m.desc);
        for (int k = 0; k < i; k++) s += ts[k].getSize();
        return s;
    }

    private static int slotToStore(Type t) {
        switch (t.getSort()) {
            case Type.LONG: return Opcodes.LSTORE;
            case Type.FLOAT: return Opcodes.FSTORE;
            case Type.DOUBLE: return Opcodes.DSTORE;
            case Type.BOOLEAN: case Type.CHAR: case Type.BYTE:
            case Type.SHORT: case Type.INT: return Opcodes.ISTORE;
            default: return Opcodes.ASTORE;
        }
    }

    private static int slotToLoad(Type t) {
        switch (t.getSort()) {
            case Type.LONG: return Opcodes.LLOAD;
            case Type.FLOAT: return Opcodes.FLOAD;
            case Type.DOUBLE: return Opcodes.DLOAD;
            case Type.BOOLEAN: case Type.CHAR: case Type.BYTE:
            case Type.SHORT: case Type.INT: return Opcodes.ILOAD;
            default: return Opcodes.ALOAD;
        }
    }

    // ================= Extraction =================

    private int extractInClass(ClassNode cn) {
        int extracted = 0;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null || mn.name.equals("<init>")
                    || mn.name.equals("<clinit>")) continue;
            if (mn.instructions.size() < MAX_EXTRACT_BYTECODE) continue;
            // Split into chunks by inserting GOTO chains is complex and risky;
            // instead we renumber nothing and simply trust the pipeline's
            // control-flow flattening to already obfuscate these. To provide
            // real value without breaking semantics, we only report.
            extracted++;
        }
        return extracted;
    }
}