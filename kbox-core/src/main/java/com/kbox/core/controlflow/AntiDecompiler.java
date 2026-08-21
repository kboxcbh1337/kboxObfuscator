package com.kbox.core.controlflow;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Attribute;
import org.objectweb.asm.ByteVector;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.JumpInsnNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TryCatchBlockNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Anti-decompiler transforms. These deliberately produce JVM-legal bytecode
 * that crashes or severely hampers Recaf, JD-GUI, Bytecode Viewer, CFR,
 * Procyon, FernFlower and the java-deobfuscator/Deobfuscator tool while
 * leaving {@code java -jar} execution unaffected.
 *
 * <p>The synthetic {@code _KboxAntiDec} class is <b>never loaded by the JVM</b>
 * at runtime — it exists solely inside the jar to crash tools that scan every
 * class. Because it is never loaded, the JVM verifier never inspects it; only
 * decompiler parsers (which eagerly parse every class in the jar) hit the
 * traps.
 *
 * <p>Strength levels (controlled by {@link ProtectionConfig#getAntiDecompilerLevel()}):
 * <ul>
 *   <li><b>1 — light</b>: 5k-label goto-chain (JD-GUI path enumeration stack
 *       overflow), self-referencing InnerClasses.</li>
 *   <li><b>2 — medium</b>: + 500-entry exception bomb, circular EnclosingMethod,
 *       deep inheritance chain (100 levels), bloat fields (1000).</li>
 *   <li><b>3 — aggressive</b>: + 50000-label goto-chain (split across 5 methods),
 *       10000-entry exception bomb, constant-pool bomb (65535 bytes),
 *       5000 bloat fields, 500-level inheritance chain, circular SourceFile,
 *       anti-Deobfuscator patterns (malformed constant pool refs, impossible
 *       control flow), logic bomb (dead-code OOM trigger), non-standard
 *       attribute injection (malformed StackMapTable data that parsers choke on).</li>
 * </ul>
 *
 * <p>All transforms are wrapped in try/catch and never abort the build.
 */
public final class AntiDecompiler {

    private static final String TAG = "anti-dec";
    private static final String SYNTH_CLASS = "com/kbox/runtime/_KboxAntiDec";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public AntiDecompiler(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        int level = cfg.getAntiDecompilerLevel();
        if (level <= 0) return;
        try {
            ClassNode sink = ensureSinkClass();

            // === 1. Goto-chain (反 JD-GUI: 路径枚举栈溢出) ===
            int gotoLabels = level >= 3 ? 50000 : (level >= 2 ? 12000 : 5000);
            injectGotoChains(sink, gotoLabels);

            if (level >= 2) {
                // === 2. Exception bomb (反 JD-GUI: 异常表分析 OOM) ===
                int exEntries = level >= 3 ? 10000 : 500;
                injectExceptionBomb(sink, exEntries);

                // === 3. Circular InnerClasses (反 Recaf: 类图构建死循环) ===
                injectSelfReferencingInnerClasses(sink);

                // === 4. Circular EnclosingMethod (反 Recaf: 外部类查找死循环) ===
                injectCircularEnclosingMethod(sink);

                // === 5. Deep inheritance chain (反 Recaf: 类层次构建 OOM) ===
                int depth = level >= 3 ? 500 : 100;
                injectDeepInheritanceChain(sink, depth);

                // === 6. Bloat fields (反所有工具: 类解析内存耗尽) ===
                int fieldCount = level >= 3 ? 5000 : 1000;
                injectBloatFields(sink, fieldCount);
            }

            if (level >= 3) {
                // === 7. Constant-pool bomb (UI 渲染冻结) ===
                injectConstantPoolBomb(sink);

                // === 8. Anti-Deobfuscator patterns (让 transformer 抛异常) ===
                injectAntiDeobfuscatorPatterns(sink);

                // === 9. Logic bomb: dead-code OOM trigger ===
                injectLogicBomb(sink);

                // === 10. Non-standard attribute injection (畸形 StackMapTable 数据) ===
                injectMalformedAttributes(sink);

                // === 11. Impossible control flow (反数据流分析) ===
                injectImpossibleControlFlow(sink);

                // === 12. Malformed constant pool references ===
                injectMalformedConstantPoolRefs(sink);

                // === 13. CFR-specific: stack underrun in dead-code paths ===
                injectCfrStackUnderrun(sink);

                // === 14. CFR-specific: fake try/catch with impossible handler ===
                injectCfrFakeTryCatch(sink);
            }

            // === 15. Procyon-specific: INVOKEDYNAMIC with nonexistent bootstrap ===
            if (level >= 3) {
                injectProcyonInvokedynamicTrap(sink);
            }

            // === 16. JD-GUI specific: ultra-long method body overflow ===
            if (level >= 3) {
                injectJdGuiOverflowTrap(sink);
            }

            // === 17. Enhanced CONSTANT_MethodHandle pointing to wrong tag ===
            if (level >= 3) {
                injectMalformedMethodHandle(sink);
            }

            KBoxLog.info(TAG, "Applied anti-decompiler level " + level
                    + " (goto=" + gotoLabels + " labels, ex-bomb=" + (level >= 2 ? (level >= 3 ? 10000 : 500) : 0)
                    + " entries, fields=" + (level >= 2 ? (level >= 3 ? 5000 : 1000) : 0)
                    + ", inheritance=" + (level >= 2 ? (level >= 3 ? 500 : 100) : 0)
                    + ", cp-bomb, logic-bomb, malformed-attrs, anti-deobf"
                    + (level >= 3 ? ", procyon-id-trap, jdgui-overflow, bad-mh" : "") + ")");
        } catch (Throwable t) {
            KBoxLog.warn(TAG, "Anti-decompiler pass failed: " + t.getMessage());
        }
    }

    /** Ensures the synthetic sink class exists in the graph. */
    @SuppressWarnings("unchecked")
    private ClassNode ensureSinkClass() {
        ClassNode cn = graph.getClasses().get(SYNTH_CLASS);
        if (cn != null) return cn;
        cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = SYNTH_CLASS;
        cn.superName = "java/lang/Object";
        // Default constructor: must call super() before return or the JVM
        // verifier rejects with "Constructor must call super() or this()".
        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);
        graph.getClasses().put(SYNTH_CLASS, cn);
        return cn;
    }

    // ========================================================================
    // 1. Goto-chain: 50000 labels split across multiple methods.
    //    Each label+goto consumes ~5 bytes, so 10000 labels per method = ~50KB
    //    (safely under the 65535-byte code limit). JD-GUI's path enumeration
    //    blows up (stack overflow or OOM) on deeply linear CFGs.
    // ========================================================================
    private void injectGotoChains(ClassNode cn, int totalLabels) {
        int perMethod = 10000; // ~50KB per method, under 65535 limit
        int methods = (totalLabels + perMethod - 1) / perMethod;
        for (int m = 0; m < methods; m++) {
            int labels = Math.min(perMethod, totalLabels - m * perMethod);
            injectGotoChain(cn, labels, m);
        }
    }

    @SuppressWarnings("unchecked")
    private void injectGotoChain(ClassNode cn, int labelCount, int methodIdx) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_bloat" + methodIdx, "()V", null, null);
        InsnList l = mn.instructions;
        LabelNode[] labels = new LabelNode[labelCount];
        for (int i = 0; i < labelCount; i++) labels[i] = new LabelNode();
        for (int i = 0; i < labelCount; i++) {
            l.add(labels[i]);
            l.add(new InsnNode(Opcodes.NOP));
            if (i + 1 < labelCount) {
                l.add(new JumpInsnNode(Opcodes.GOTO, labels[i + 1]));
            } else {
                l.add(new InsnNode(Opcodes.RETURN));
            }
        }
        cn.methods.add(mn);
    }

    // ========================================================================
    // 2. Exception bomb: many try/catch entries pointing at the same dead
    //    handler. The try block throws a real NPE which the handler catches
    //    and ignores — valid, verifiable bytecode. The 10000 duplicate catch
    //    entries hammer decompiler exception-table analyzers combinatorially.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectExceptionBomb(ClassNode cn, int entryCount) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_exbomb", "()V", null, null);
        InsnList l = mn.instructions;
        LabelNode start = new LabelNode();
        LabelNode end = new LabelNode();
        LabelNode handler = new LabelNode();
        // The try block must contain code that CAN throw so that COMPUTE_FRAMES
        // can compute a valid frame for the handler.
        l.add(start);
        l.add(new InsnNode(Opcodes.ACONST_NULL));
        l.add(new InsnNode(Opcodes.ATHROW));
        l.add(end);
        l.add(handler);
        l.add(new InsnNode(Opcodes.POP));
        l.add(new InsnNode(Opcodes.RETURN));
        // Many catch entries — all pointing to the same handler.
        for (int i = 0; i < entryCount; i++) {
            mn.tryCatchBlocks.add(new TryCatchBlockNode(
                    start, end, handler, "java/lang/Throwable"));
        }
        cn.methods.add(mn);
    }

    // ========================================================================
    // 3. Self-referencing InnerClasses: the sink class lists itself as both
    //    inner and outer. Class-graph builders that don't guard against cycles
    //    will loop forever.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectSelfReferencingInnerClasses(ClassNode cn) {
        if (cn.innerClasses == null) cn.innerClasses = new java.util.ArrayList<>();
        cn.innerClasses.add(new org.objectweb.asm.tree.InnerClassNode(
                SYNTH_CLASS, SYNTH_CLASS, "_KboxAntiDec",
                Opcodes.ACC_STATIC | Opcodes.ACC_PUBLIC));
    }

    // ========================================================================
    // 4. Circular EnclosingMethod: the class declares itself as an anonymous
    //    class of its own method. Tools that resolve EnclosingMethod attributes
    //    (Recaf, Bytecode Viewer) will enter an infinite loop trying to find
    //    the outer class.
    // ========================================================================
    private void injectCircularEnclosingMethod(ClassNode cn) {
        // EnclosingMethod attribute: class is enclosed by its own _bloat0 method.
        // ASM doesn't have a direct API for this, so we use a custom attribute.
        if (cn.attrs == null) cn.attrs = new java.util.ArrayList<>();
        cn.attrs.add(new Attribute("EnclosingMethod") {
            @Override
            protected ByteVector write(org.objectweb.asm.ClassWriter cw,
                                        byte[] code, int codeLength,
                                        int maxStack, int maxLocals) {
                ByteVector bv = new ByteVector();
                // CONSTANT_Class_info index pointing to self
                bv.putShort(cw.newClass(SYNTH_CLASS));
                // CONSTANT_NameAndType_info index pointing to _bloat0()V
                bv.putShort(cw.newNameType("_bloat0", "()V"));
                return bv;
            }
        });
    }

    // ========================================================================
    // 5. Deep inheritance chain: creates a chain of synthetic classes
    //    A1 extends A2 extends A3 ... extends A500. Recaf and similar tools
    //    build a class hierarchy graph; deep chains cause OOM or stack
    //    overflow during graph traversal.
    // ========================================================================
    private void injectDeepInheritanceChain(ClassNode sink, int depth) {
        String parent = sink.name;
        for (int i = 1; i <= depth; i++) {
            String name = SYNTH_CLASS + "_chain" + i;
            ClassNode cn = new ClassNode();
            cn.version = Opcodes.V1_8;
            cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
            cn.name = name;
            cn.superName = parent;
            // Minimal constructor calling super()
            MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
            ctor.instructions.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ALOAD, 0));
            ctor.instructions.add(new org.objectweb.asm.tree.MethodInsnNode(
                    Opcodes.INVOKESPECIAL, parent, "<init>", "()V", false));
            ctor.instructions.add(new InsnNode(Opcodes.RETURN));
            ctor.maxStack = 1;
            ctor.maxLocals = 1;
            cn.methods.add(ctor);
            graph.getClasses().put(name, cn);
            parent = name;
        }
    }

    // ========================================================================
    // 6. Bloat fields: injects thousands of synthetic fields. Decompilers
    //    that build field tables for UI display will freeze or OOM. Each field
    //    is a unique int with a unique name.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectBloatFields(ClassNode cn, int count) {
        for (int i = 0; i < count; i++) {
            cn.fields.add(new org.objectweb.asm.tree.FieldNode(
                    Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_f" + i, "I", null, null));
        }
    }

    // ========================================================================
    // 7. Constant-pool bomb: prepends an LDC of a 65535-byte string. The
    //    constant pool then contains a CONSTANT_Utf8 of maximum legal length;
    //    some tools allocate unbounded buffers or attempt to display it,
    //    causing UI freeze / OOM.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectConstantPoolBomb(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_cpbomb", "()V", null, null);
        InsnList l = mn.instructions;
        char[] chars = new char[65535];
        java.util.Arrays.fill(chars, 'x');
        String huge = new String(chars);
        l.add(new LdcInsnNode(huge));
        l.add(new InsnNode(Opcodes.POP));
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 8. Anti-Deobfuscator patterns: constructs bytecode patterns that cause
    //    the java-deobfuscator/Deobfuscator tool's transformers to throw
    //    exceptions or enter infinite loops:
    //    - A method with a LOOKUPSWITCH containing 10000 cases (causes
    //      transformer string-decryption to OOM when it tries to follow
    //      every branch).
    //    - A method that references 5000 different string constants (causes
    //      the string-analysis transformer to exhaust memory building its
    //      string table).
    //    - A circular method-call graph: _a() calls _b() which calls _a()
    //      (causes call-graph transformers to stack-overflow).
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectAntiDeobfuscatorPatterns(ClassNode cn) {
        // 8a. Large LOOKUPSWITCH: 5000 cases.
        injectLargeLookupSwitch(cn);

        // 8b. String reference flood: 2000 unique LDC strings.
        injectStringReferenceFlood(cn);

        // 8c. Circular call graph: _a -> _b -> _c -> _a.
        injectCircularCallGraph(cn);

        // 8d. Impossible type confusion: a method that does
        //     NEW java/lang/Object; CHECKCAST java/lang/String; INVOKEVIRTUAL
        //     length() — this is structurally legal but type-confusing;
        //     Deobfuscator's type-inference transformer may crash.
        injectTypeConfusion(cn);
    }

    @SuppressWarnings("unchecked")
    private void injectLargeLookupSwitch(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_switchbomb", "(I)V", null, null);
        InsnList l = mn.instructions;
        LabelNode dflt = new LabelNode();
        LabelNode[] labels = new LabelNode[5000];
        int[] keys = new int[5000];
        for (int i = 0; i < 5000; i++) {
            labels[i] = new LabelNode();
            keys[i] = i * 2;
        }
        l.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        l.add(new org.objectweb.asm.tree.LookupSwitchInsnNode(dflt, keys, labels));
        for (int i = 0; i < 5000; i++) {
            l.add(labels[i]);
            l.add(new InsnNode(Opcodes.NOP));
        }
        l.add(dflt);
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    @SuppressWarnings("unchecked")
    private void injectStringReferenceFlood(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_strflood", "()V", null, null);
        InsnList l = mn.instructions;
        for (int i = 0; i < 2000; i++) {
            l.add(new LdcInsnNode("_k" + i));
            l.add(new InsnNode(Opcodes.POP));
        }
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    @SuppressWarnings("unchecked")
    private void injectCircularCallGraph(ClassNode cn) {
        // _a calls _b, _b calls _c, _c calls _a — circular.
        for (int cycle = 0; cycle < 3; cycle++) {
            String[] names = {"_circ" + cycle + "a", "_circ" + cycle + "b", "_circ" + cycle + "c"};
            for (int i = 0; i < 3; i++) {
                String caller = names[i];
                String callee = names[(i + 1) % 3];
                MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                        caller, "()V", null, null);
                InsnList l = mn.instructions;
                l.add(new org.objectweb.asm.tree.MethodInsnNode(
                        Opcodes.INVOKESTATIC, SYNTH_CLASS, callee, "()V", false));
                l.add(new InsnNode(Opcodes.RETURN));
                cn.methods.add(mn);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private void injectTypeConfusion(ClassNode cn) {
        // A method that creates an Object, casts it to String, and calls
        // String.length(). Structurally legal (passes class-file verification
        // because CHECKCAST is a runtime check), but Deobfuscator's static
        // type-inference may crash trying to reconcile Object→String→int.
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_typeconfuse", "()I", null, null);
        InsnList l = mn.instructions;
        l.add(new TypeInsnNode(Opcodes.NEW, "java/lang/Object"));
        l.add(new InsnNode(Opcodes.DUP));
        l.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false));
        l.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/String"));
        l.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        l.add(new InsnNode(Opcodes.IRETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 9. Logic bomb: dead-code that would trigger OOM if executed. The code
    //    is reachable only via a goto that is itself unreachable (the method
    //    returns before reaching the goto). Decompilers that perform abstract
    //    interpretation or resource estimation will try to analyze the dead
    //    path and exhaust memory.
    //
    //    The bomb allocates nested arrays:
    //      new int[Integer.MAX_VALUE][Integer.MAX_VALUE][Integer.MAX_VALUE]
    //    This is legal bytecode; JVM would OOM if executed, but the method
    //    returns before reaching it.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectLogicBomb(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_lbomb", "()V", null, null);
        InsnList l = mn.instructions;
        // Reachable path: just return.
        l.add(new InsnNode(Opcodes.RETURN));
        // Dead path (never reached, but decompilers analyze it):
        LabelNode dead = new LabelNode();
        l.add(dead);
        // new int[Integer.MAX_VALUE][Integer.MAX_VALUE][Integer.MAX_VALUE]
        l.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.BIPUSH, 8)); // T_INT
        l.add(new org.objectweb.asm.tree.IntInsnNode(Opcodes.SIPUSH, 2147483647));
        l.add(new InsnNode(Opcodes.MULTIANEWARRAY));
        // The above instruction doesn't exist in ASM tree API as a simple node,
        // so we use MultiANewArrayInsnNode:
        // (rebuild the instruction list properly)
        l.clear();
        l.add(new InsnNode(Opcodes.RETURN));
        l.add(dead);
        l.add(new org.objectweb.asm.tree.MultiANewArrayInsnNode("[[[I", 3));
        l.add(new InsnNode(Opcodes.POP));
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 10. Malformed attribute injection: adds non-standard attributes with
    //     names that look like standard attributes ("StackMapTable",
    //     "Code", "LineNumberTable") but contain deliberately malformed data.
    //     The JVM ignores unknown attributes at the class level, but
    //     decompilers that eagerly parse all attributes will choke on the
    //     malformed bytes.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectMalformedAttributes(ClassNode cn) {
        if (cn.attrs == null) cn.attrs = new java.util.ArrayList<>();

        // 10a. Fake "StackMapTable" class attribute with malformed frame data.
        //     The real StackMapTable is a method-level attribute; a class-level
        //     attribute with the same name confuses parsers that look for it
        //     at the wrong scope.
        cn.attrs.add(new Attribute("StackMapTable") {
            @Override
            protected ByteVector write(org.objectweb.asm.ClassWriter cw,
                                        byte[] code, int codeLength,
                                        int maxStack, int maxLocals) {
                ByteVector bv = new ByteVector();
                // Malformed: 255 frame entries, each with invalid frame type 0xFF
                bv.putShort(255);
                for (int i = 0; i < 255; i++) {
                    bv.putByte(0xFF); // invalid frame type
                    bv.putShort(0xFFFF); // garbage offset
                }
                return bv;
            }
        });

        // 10b. Fake "BootstrapMethods" attribute with circular references.
        cn.attrs.add(new Attribute("BootstrapMethods") {
            @Override
            protected ByteVector write(org.objectweb.asm.ClassWriter cw,
                                        byte[] code, int codeLength,
                                        int maxStack, int maxLocals) {
                ByteVector bv = new ByteVector();
                // 100 bootstrap methods, each referencing the next (circular)
                bv.putShort(100);
                for (int i = 0; i < 100; i++) {
                    bv.putShort(cw.newHandle(
                            org.objectweb.asm.Opcodes.H_INVOKESTATIC,
                            SYNTH_CLASS, "_bloat" + (i % 5), "()V", false));
                    bv.putShort(0); // no arguments
                }
                return bv;
            }
        });

        // 10c. Fake "InnerClasses" attribute at class level with 10000 entries
        //      all pointing to non-existent classes.
        cn.attrs.add(new Attribute("InnerClasses") {
            @Override
            protected ByteVector write(org.objectweb.asm.ClassWriter cw,
                                        byte[] code, int codeLength,
                                        int maxStack, int maxLocals) {
                ByteVector bv = new ByteVector();
                bv.putShort(1000);
                for (int i = 0; i < 1000; i++) {
                    bv.putShort(cw.newClass(SYNTH_CLASS + "_fake" + i));
                    bv.putShort(cw.newClass(SYNTH_CLASS + "_fake" + ((i + 1) % 1000)));
                    bv.putShort(cw.newUTF8("_inner" + i));
                    bv.putShort(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC);
                }
                return bv;
            }
        });
    }

    // ========================================================================
    // 11. Impossible control flow: a method whose CFG is mathematically
    //     impossible (e.g., a branch that is always taken and never taken
    //     simultaneously via opaque predicates). Data-flow analysis tools
    //     (CFR, FernFlower) may enter fixpoint iteration that never converges.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectImpossibleControlFlow(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_impossible", "(I)V", null, null);
        InsnList l = mn.instructions;
        // if (x == 0) goto L1; if (x != 0) goto L1; goto L2;
        // Both branches lead to L1 — but the opaque predicate makes it look
        // like L2 is reachable. Data-flow fixpoint may not converge.
        LabelNode l1 = new LabelNode();
        LabelNode l2 = new LabelNode();
        LabelNode l3 = new LabelNode();
        l.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        l.add(new JumpInsnNode(Opcodes.IFEQ, l1));
        l.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        l.add(new JumpInsnNode(Opcodes.IFNE, l1));
        l.add(new JumpInsnNode(Opcodes.GOTO, l2));
        l.add(l1);
        // At L1: recursively call _impossible (creates a cycle in the call graph)
        l.add(new org.objectweb.asm.tree.VarInsnNode(Opcodes.ILOAD, 0));
        l.add(new org.objectweb.asm.tree.MethodInsnNode(
                Opcodes.INVOKESTATIC, SYNTH_CLASS, "_impossible", "(I)V", false));
        l.add(new JumpInsnNode(Opcodes.GOTO, l3));
        l.add(l2);
        l.add(new InsnNode(Opcodes.NOP));
        l.add(new JumpInsnNode(Opcodes.GOTO, l1)); // back-edge to L1
        l.add(l3);
        l.add(new InsnNode(Opcodes.RETURN));
        // Add a self-referencing try/catch for extra confusion
        mn.tryCatchBlocks.add(new TryCatchBlockNode(l1, l3, l2, null));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 12. Malformed constant pool references: LDC instructions that load
    //     MethodHandle / MethodType / DynamicConstant references pointing to
    //     nonexistent methods. These are structurally legal (ASM can encode
    //     them) but cause decompiler constant-pool walkers to fail when they
    //     try to resolve the referenced methods.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectMalformedConstantPoolRefs(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_cprefs", "()V", null, null);
        InsnList l = mn.instructions;
        // Load 100 MethodHandles pointing to nonexistent classes/methods.
        // ASM's LdcInsnNode accepts MethodHandle objects.
        for (int i = 0; i < 100; i++) {
            org.objectweb.asm.Handle handle = new org.objectweb.asm.Handle(
                    Opcodes.H_INVOKESTATIC,
                    "com/kbox/runtime/_nonexistent" + i,
                    "_phantom" + i,
                    "()V",
                    false);
            l.add(new LdcInsnNode(handle));
            l.add(new InsnNode(Opcodes.POP));
        }
        // Load 100 MethodType references.
        for (int i = 0; i < 100; i++) {
            l.add(new LdcInsnNode(Type.getMethodType("(I)V")));
            l.add(new InsnNode(Opcodes.POP));
        }
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 13. CFR-specific stack underrun: a method with reachable branches that
    //     lead to dead-code blocks containing SWAP/DUP2/POP2 on an underflowed
    //     stack. CFR's StackSim (StackSim.getEntry at StackSim.java:35) throws
    //     ConfusedCFRException: "Underrun type stack" when it tries to simulate
    //     a SWAP on a stack with < 2 elements. The JVM never executes these
    //     paths (they are dead code), but CFR eagerly analyzes all basic blocks
    //     in the CFG, hitting the underrun.
    //
    //     We create multiple methods: each has a reachable return path AND a
    //     dead-code branch guarded by an always-true opaque predicate. The dead
    //     branch contains stack operations that are inconsistent with the
    //     current stack depth. CFR, performing best-effort stack simulation,
    //     will underrun and throw ConfusedCFRException.
    //
    //     Technique inferred from Paramorphism's anti-decompilation output which
    //     shows exactly this error signature.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectCfrStackUnderrun(ClassNode cn) {
        // Create 10 methods, each with a different underrun pattern.
        // CFR's stack simulation is the weakest link — it uses a fixed-size
        // stack with no underflow protection.

        // Pattern A: SWAP on single-element stack (CFR: StackSim.getEntry(1) fails)
        for (int m = 0; m < 3; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfru" + m + "a", "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode dead = new LabelNode();
            LabelNode end = new LabelNode();
            // Reachable path: just return.
            l.add(new InsnNode(Opcodes.ICONST_0));   // push int
            l.add(new JumpInsnNode(Opcodes.IFEQ, dead)); // always true (0==0) — never taken
            l.add(new InsnNode(Opcodes.RETURN));
            // Dead path: stack has 0 elements. SWAP expects 2 → CFR underrun.
            l.add(dead);
            l.add(new InsnNode(Opcodes.SWAP));       // CFR: StackSim.getEntry(1) → ConfusedCFRException
            l.add(new InsnNode(Opcodes.POP));
            l.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(mn);
        }

        // Pattern B: DUP2_X1 on 1-element stack (CFR analyzes ALL branches)
        for (int m = 0; m < 3; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfru" + m + "b", "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode dead = new LabelNode();
            l.add(new InsnNode(Opcodes.ACONST_NULL));
            l.add(new JumpInsnNode(Opcodes.IFNONNULL, dead)); // null -> never taken
            l.add(new InsnNode(Opcodes.RETURN));
            l.add(dead);
            l.add(new InsnNode(Opcodes.DUP2_X1));  // needs ≥3 stack entries; CFR underruns
            l.add(new InsnNode(Opcodes.POP));
            l.add(new InsnNode(Opcodes.POP));
            l.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(mn);
        }

        // Pattern C: POP2 on 1-element stack
        for (int m = 0; m < 2; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfru" + m + "c", "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode dead = new LabelNode();
            l.add(new InsnNode(Opcodes.ICONST_1));
            l.add(new InsnNode(Opcodes.ICONST_1));
            l.add(new JumpInsnNode(Opcodes.IF_ICMPNE, dead)); // 1==1 → never taken
            l.add(new InsnNode(Opcodes.POP));
            l.add(new InsnNode(Opcodes.POP));
            l.add(new InsnNode(Opcodes.RETURN));
            l.add(dead);
            l.add(new InsnNode(Opcodes.POP2));     // needs ≥2 wide; stack has 0 → underrun
            l.add(new InsnNode(Opcodes.SWAP));     // double underrun for extra confusion
            l.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(mn);
        }

        // Pattern D: DUP2 on 1-element stack (only 1 slot, DUP2 needs 2)
        for (int m = 0; m < 2; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfru" + m + "d", "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode dead = new LabelNode();
            l.add(new InsnNode(Opcodes.ICONST_0));
            l.add(new JumpInsnNode(Opcodes.IFNE, dead)); // 0!=0 → never taken
            l.add(new InsnNode(Opcodes.RETURN));
            l.add(dead);
            l.add(new InsnNode(Opcodes.DUP2));    // stack: empty → CFR underrun
            l.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(mn);
        }
    }

    // ========================================================================
    // 14. CFR-specific fake try/catch: a try block that pushes nothing and
    //     an exception handler that pops. CFR's stack simulation for exception
    //     handlers assumes the stack contains a Throwable reference pushed by
    //     the JVM. By making the handler inconsistent (e.g. POP2 instead of
    //     POP, or DUP instead of POP), CFR's type propagation enters an
    //     inconsistent state.
    //
    //     This is combined with an impossible control flow (the try-block
    //     never throws) so the JVM verifier is happy (dead code is not
    //     verified), but CFR still analyzes all blocks.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectCfrFakeTryCatch(ClassNode cn) {
        for (int m = 0; m < 5; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfrtc" + m, "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode start = new LabelNode();
            LabelNode end = new LabelNode();
            LabelNode handler = new LabelNode();
            LabelNode after = new LabelNode();

            // Never-throws try block: just push int and return.
            l.add(start);
            l.add(new InsnNode(Opcodes.ICONST_0));
            l.add(new JumpInsnNode(Opcodes.IFEQ, after)); // always true, never reaches end
            l.add(end);

            // Dead handler: CFR sees Throwable on stack but we DUP2 which
            // expects 2 wide slots — type mismatch causes CFR stack confusion.
            l.add(handler);
            l.add(new InsnNode(Opcodes.DUP));     // duplicate the Throwable
            l.add(new InsnNode(Opcodes.SWAP));    // swap with itself → CFR underrun if stack < 2
            l.add(new InsnNode(Opcodes.ATHROW));

            l.add(after);
            l.add(new InsnNode(Opcodes.RETURN));

            // Handler catches RuntimeException but the try block never throws.
            mn.tryCatchBlocks.add(new TryCatchBlockNode(
                    start, end, handler, "java/lang/RuntimeException"));
            cn.methods.add(mn);
        }

        // Bonus: handler that does POP2 on a single Throwable
        for (int m = 0; m < 3; m++) {
            MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                    "_cfrtc_n" + m, "()V", null, null);
            InsnList l = mn.instructions;
            LabelNode start = new LabelNode();
            LabelNode end = new LabelNode();
            LabelNode handler = new LabelNode();
            LabelNode after = new LabelNode();

            l.add(start);
            l.add(new InsnNode(Opcodes.ACONST_NULL));
            l.add(new JumpInsnNode(Opcodes.IFNONNULL, after)); // never taken
            l.add(end);

            l.add(handler);
            l.add(new InsnNode(Opcodes.POP2));   // JVM pushes 1 Throwable; CFR stack sim expects 1, we pop 2
            l.add(new InsnNode(Opcodes.RETURN));

            l.add(after);
            l.add(new InsnNode(Opcodes.RETURN));

            mn.tryCatchBlocks.add(new TryCatchBlockNode(
                    start, end, handler, "java/lang/Throwable"));
            cn.methods.add(mn);
        }
    }

    // ========================================================================
    // 15. Procyon-specific: INVOKEDYNAMIC pointing to a nonexistent bootstrap
    //     method. Procyon resolves INVOKEDYNAMIC by looking up the bootstrap
    //     method table (BSM index in the constant pool). If the BSM index
    //     points to a valid-looking but semantically nonexistent method,
    //     Procyon throws NullPointerException during resolution.
    //
    //     We create a method with an INVOKEDYNAMIC instruction whose BSM
    //     index references a bootstrap method that doesn't exist in the
    //     class's BootstrapMethods attribute. The JVM never executes this
    //     code (it's in a dead branch), but Procyon eagerly resolves all
    //     INVOKEDYNAMIC sites.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectProcyonInvokedynamicTrap(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_procyon", "()V", null, null);
        InsnList l = mn.instructions;
        LabelNode dead = new LabelNode();
        // Reachable path: just return
        l.add(new InsnNode(Opcodes.ICONST_0));
        l.add(new JumpInsnNode(Opcodes.IFEQ, dead)); // 0==0 → always taken → skip dead code
        l.add(new InsnNode(Opcodes.RETURN));
        // Dead path: INVOKEDYNAMIC with invalid BSM index
        l.add(dead);
        // INVOKEDYNAMIC with a bootstrap method index that exceeds the
        // BootstrapMethods array length. ASM encodes this as a dynamic
        // constant via LdcInsnNode with a ConstantDynamic.
        try {
            // Use a Handle pointing to a nonexistent method as bootstrap
            org.objectweb.asm.Handle bsm = new org.objectweb.asm.Handle(
                    Opcodes.H_INVOKESTATIC,
                    "com/kbox/runtime/_phantom_bsm",
                    "_bootstrap",
                    "(Ljava/lang/invoke/MethodHandles$Lookup;Ljava/lang/String;Ljava/lang/invoke/MethodType;)Ljava/lang/Object;",
                    false);
            // Create a ConstantDynamic that references this phantom bootstrap
            org.objectweb.asm.ConstantDynamic cd = new org.objectweb.asm.ConstantDynamic(
                    "_phantom", "Ljava/lang/Object;", bsm);
            l.add(new LdcInsnNode(cd));
            l.add(new InsnNode(Opcodes.POP));
        } catch (Throwable ignored) {
            // If ConstantDynamic isn't available (older ASM), fall back to
            // a regular MethodHandle LDC pointing to a nonexistent class
            l.add(new LdcInsnNode(new org.objectweb.asm.Handle(
                    Opcodes.H_INVOKESTATIC,
                    "com/kbox/runtime/_phantom_bsm2",
                    "_bootstrap2", "()V", false)));
            l.add(new InsnNode(Opcodes.POP));
        }
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 16. JD-GUI specific: ultra-long method body. JD-GUI 1.6 has a method
    //     body size limit — methods exceeding ~65535 bytes of code cause
    //     integer overflow in JD-GUI's instruction offset tracking, leading
    //     to ArrayIndexOutOfBoundsException or silent truncation.
    //
    //     We create a method with NOP sled + label flood that pushes the
    //     code length close to the 65535-byte JVM limit. The method is
    //     never called at runtime (it's synthetic).
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectJdGuiOverflowTrap(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_jdgui", "()V", null, null);
        InsnList l = mn.instructions;
        // Each NOP = 1 byte, each label = 0 bytes in code (just metadata).
        // But JD-GUI tracks labels as instruction offsets, so many labels
        // with NOPs between them create a huge instruction list.
        // 60000 NOPs = 60000 bytes of code (safely under 65535).
        int nops = 60000;
        for (int i = 0; i < nops; i++) {
            // Add a label every 100 NOPs to bloat the label table
            if (i % 100 == 0) {
                l.add(new LabelNode());
            }
            l.add(new InsnNode(Opcodes.NOP));
        }
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }

    // ========================================================================
    // 17. Enhanced CONSTANT_MethodHandle pointing to wrong tag. A
    //     CONSTANT_MethodHandle with tag 0 (invalid) or tag 9
    //     (H_INVOKEINTERFACE on a static method) causes
    //     ClassFormatException in strict parsers but is silently ignored
    //     by the JVM if the method is never called.
    // ========================================================================
    @SuppressWarnings("unchecked")
    private void injectMalformedMethodHandle(ClassNode cn) {
        MethodNode mn = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "_badmh", "()V", null, null);
        InsnList l = mn.instructions;
        LabelNode dead = new LabelNode();
        l.add(new InsnNode(Opcodes.ICONST_1));
        l.add(new JumpInsnNode(Opcodes.IFNE, dead)); // 1!=0 → always taken → skip dead code
        l.add(new InsnNode(Opcodes.RETURN));
        l.add(dead);
        // Load 50 MethodHandles with various invalid tag combinations
        for (int i = 0; i < 50; i++) {
            // Use H_NEWINVOKESPECIAL (tag 8) on a static method — semantically
            // invalid (H_NEWINVOKESPECIAL is only for constructors)
            org.objectweb.asm.Handle handle = new org.objectweb.asm.Handle(
                    Opcodes.H_NEWINVOKESPECIAL,
                    "com/kbox/runtime/_wrongtag" + i,
                    "_static" + i,
                    "()V",
                    false);
            l.add(new LdcInsnNode(handle));
            l.add(new InsnNode(Opcodes.POP));
        }
        // Also load some with H_GETFIELD on static fields (wrong ref kind)
        for (int i = 0; i < 50; i++) {
            org.objectweb.asm.Handle handle = new org.objectweb.asm.Handle(
                    Opcodes.H_GETFIELD,
                    "com/kbox/runtime/_wrongref" + i,
                    "_field" + i,
                    "I",
                    false);
            l.add(new LdcInsnNode(handle));
            l.add(new InsnNode(Opcodes.POP));
        }
        l.add(new InsnNode(Opcodes.RETURN));
        cn.methods.add(mn);
    }
}
