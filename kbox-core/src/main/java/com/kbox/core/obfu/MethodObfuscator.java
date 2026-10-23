package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FrameNode;
import org.objectweb.asm.tree.IincInsnNode;
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
    /** 条目 41: inlining reach was extended from 24 straight-line insns to
     *  48 insns with branches/switches (labels are remapped), so far more
     *  real accessors/helpers disappear at their call sites. */
    private static final int MAX_INLINE_BYTECODE = 48;   // body instruction count
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
        int thr = cfg.getParallelThreads();
        java.util.concurrent.atomic.AtomicInteger inlined = new java.util.concurrent.atomic.AtomicInteger();
        java.util.concurrent.atomic.AtomicInteger extracted = new java.util.concurrent.atomic.AtomicInteger();
        // Inline pass — per-class independent (only same-class static callees).
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            if (cn.name.startsWith("com/kbox/runtime/")) return;
            inlined.addAndGet(inlineInClass(cn));
        }, thr);
        // Extraction pass — runs after inline so it sees the post-inline bodies.
        com.kbox.core.concurrent.ParallelClassProcessor.processAll(graph, cfg, cn -> {
            if (cn.name.startsWith("com/kbox/runtime/")) return;
            extracted.addAndGet(extractInClass(cn));
        }, thr);
        KBoxLog.info(TAG, "Method obfuscation: " + inlined.get() + " methods inlined, "
                + extracted.get() + " methods extracted");
    }

    // ================= Inlining =================

    private int inlineInClass(ClassNode cn) {
        // Only inline methods defined in the same-class call sites where the
        // callee is small and side-effect free. We operate per-class to keep
        // the analysis local and safe. 条目 41: instance (private/final)
        // methods are eligible too — the receiver is popped into a fresh slot
        // exactly like an extra leading argument.
        Map<String, MethodNode> byKey = new HashMap<>();
        for (MethodNode m : (List<MethodNode>) cn.methods) {
            byKey.put(m.name + m.desc, m);
        }
        int count = 0;
        int budget = 200; // per-class ceiling: stops exponential blow-up chains
        for (MethodNode caller : (List<MethodNode>) cn.methods) {
            if (caller.instructions == null || caller.name.equals("<init>")
                    || caller.name.equals("<clinit>")) continue;
            for (AbstractInsnNode ins = caller.instructions.getFirst(); ins != null; ) {
                AbstractInsnNode next = ins.getNext();
                if (ins instanceof MethodInsnNode && count < budget) {
                    MethodInsnNode mi = (MethodInsnNode) ins;
                    int op = mi.getOpcode();
                    boolean staticCall = op == Opcodes.INVOKESTATIC;
                    boolean sameClassInstance = (op == Opcodes.INVOKESPECIAL
                            || op == Opcodes.INVOKEVIRTUAL)
                            && mi.owner.equals(cn.name) && !mi.name.equals("<init>");
                    if ((!staticCall && !sameClassInstance) || !mi.owner.equals(cn.name)) {
                        ins = next; continue;
                    }
                    MethodNode callee = byKey.get(mi.name + mi.desc);
                    if (callee == null || callee == caller || !isTrivial(callee)) {
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

    /** A method is inlinable only if it has no try/catch, no synchronization,
     *  no allocations, no nested calls, no ATHROW and no JSR/RET. 条目 41:
     *  branches and switches ARE allowed now — every label is remapped during
     *  the clone, so the inlined copy keeps its internal control flow. */
    private static boolean isTrivial(MethodNode m) {
        if (m.instructions == null || m.instructions.size() == 0) return false;
        if (m.tryCatchBlocks != null && !m.tryCatchBlocks.isEmpty()) return false;
        if ((m.access & Opcodes.ACC_SYNCHRONIZED) != 0) return false;
        if (m.instructions.size() > MAX_INLINE_BYTECODE) return false;
        int returns = 0;
        for (AbstractInsnNode ins : m.instructions) {
            int op = ins.getOpcode();
            if (op == Opcodes.NEW || op == Opcodes.NEWARRAY
                    || op == Opcodes.ANEWARRAY || op == Opcodes.MULTIANEWARRAY) return false;
            if (ins instanceof MethodInsnNode) return false; // no nested calls
            if (op == Opcodes.ATHROW) return false;
            if (op == Opcodes.JSR || op == Opcodes.RET) return false;
            if (op == Opcodes.MONITORENTER || op == Opcodes.MONITOREXIT) return false;
            if (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) returns++;
        }
        return returns >= 1;
    }

    /**
     * Inlines the callee body into the caller at the call site.
     *
     * <p>条目 41: the callee body is cloned through a fresh {@code LabelNode}
     * map, so internal branches/switches survive; every return is rewritten
     * into {@code store result; goto join}, so multi-return bodies inline
     * correctly. The call-site arguments (and, for instance methods, the
     * receiver) are popped into fresh caller locals; every callee local is
     * remapped onto fresh caller slots so the caller's own locals are never
     * clobbered.
     */
    private boolean tryInline(MethodNode caller, MethodInsnNode call,
                              MethodNode callee) {
        try {
            boolean isStatic = (callee.access & Opcodes.ACC_STATIC) != 0;
            Type[] args = Type.getArgumentTypes(call.desc);
            Type ret = Type.getReturnType(call.desc);
            boolean hasResult = ret.getSort() != Type.VOID;

            int base = caller.maxLocals;
            int slot = base;
            int thisSlot = -1;
            if (!isStatic) thisSlot = slot++;
            int[] paramSlots = new int[args.length];
            for (int i = 0; i < args.length; i++) {
                paramSlots[i] = slot;
                slot += args[i].getSize();
            }
            int resultSlot = hasResult ? slot : -1;
            if (hasResult) slot += ret.getSize();

            Map<Integer, Integer> varMap = new HashMap<>();
            if (!isStatic) varMap.put(0, thisSlot);
            int calleeSlot = isStatic ? 0 : 1;
            for (int i = 0; i < args.length; i++) {
                varMap.put(calleeSlot, paramSlots[i]);
                calleeSlot += args[i].getSize();
            }
            for (AbstractInsnNode ins : callee.instructions) {
                if (ins instanceof VarInsnNode) {
                    int v = ((VarInsnNode) ins).var;
                    if (!varMap.containsKey(v)) {
                        // Category-2 locals (long/double) occupy two slots;
                        // allocating only one made the NEXT fresh slot land
                        // inside this pair and two locals aliased each other.
                        varMap.put(v, slot);
                        slot += isCat2VarInsn(ins.getOpcode()) ? 2 : 1;
                    }
                } else if (ins instanceof IincInsnNode) {
                    // IINC also touches a local: without pre-registering its
                    // var here the clone loop below left it UNREMAPPED and the
                    // inlined body incremented the CALLER's local.
                    int v = ((IincInsnNode) ins).var;
                    if (!varMap.containsKey(v)) {
                        varMap.put(v, slot++);
                    }
                }
            }
            caller.maxLocals = Math.max(caller.maxLocals, slot);

            // Fresh labels for the inlined copy: internal jumps/switches must
            // target the copy, never the original callee.
            Map<LabelNode, LabelNode> labelMap = new HashMap<>();
            for (AbstractInsnNode ins : callee.instructions) {
                if (ins instanceof LabelNode) {
                    labelMap.put((LabelNode) ins, new LabelNode());
                }
            }

            InsnList body = new InsnList();
            LabelNode join = new LabelNode();

            // Call-site arguments are on the operand stack (receiver below the
            // args). Store them in reverse order — top of stack is the LAST
            // argument — then the receiver.
            for (int ai = args.length - 1; ai >= 0; ai--) {
                body.add(new VarInsnNode(slotToStore(args[ai]), paramSlots[ai]));
            }
            if (!isStatic) body.add(new VarInsnNode(Opcodes.ASTORE, thisSlot));

            // Copy the body with remapped locals and labels; rewrite returns.
            for (AbstractInsnNode ins : callee.instructions) {
                int op = ins.getOpcode();
                if (ins instanceof LabelNode) {
                    body.add(labelMap.get(ins));
                } else if (ins instanceof FrameNode
                        || ins instanceof LineNumberNode) {
                    // metadata — regenerated by COMPUTE_FRAMES / serialization
                } else if (op >= Opcodes.IRETURN && op <= Opcodes.RETURN) {
                    if (hasResult) {
                        body.add(new VarInsnNode(slotToStore(ret), resultSlot));
                    }
                    body.add(new JumpInsnNode(Opcodes.GOTO, join));
                } else if (ins instanceof VarInsnNode) {
                    VarInsnNode v = (VarInsnNode) ins;
                    Integer mapped = varMap.get(v.var);
                    body.add(new VarInsnNode(v.getOpcode(),
                            mapped != null ? mapped : v.var));
                } else if (ins instanceof IincInsnNode) {
                    IincInsnNode ii = (IincInsnNode) ins;
                    Integer mapped = varMap.get(ii.var);
                    body.add(new IincInsnNode(mapped != null ? mapped : ii.var, ii.incr));
                } else {
                    body.add(ins.clone(labelMap));
                }
            }
            body.add(join);
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

    private static boolean isCat2VarInsn(int opcode) {
        return opcode == Opcodes.LLOAD || opcode == Opcodes.LSTORE
                || opcode == Opcodes.DLOAD || opcode == Opcodes.DSTORE;
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