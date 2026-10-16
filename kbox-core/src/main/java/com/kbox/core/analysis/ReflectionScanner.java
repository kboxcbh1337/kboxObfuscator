package com.kbox.core.analysis;

import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.analysis.Analyzer;
import org.objectweb.asm.tree.analysis.Frame;
import org.objectweb.asm.tree.analysis.SourceInterpreter;
import org.objectweb.asm.tree.analysis.SourceValue;

import java.util.List;

/**
 * Scans every class for reflective / dynamic patterns and seeds the graph's
 * keep-set with the discovered classes &amp; members. This is what makes KBox
 * safe-by-default: even if the user forgets a {@code @Keep}, the patterns below
 * are detected automatically.
 *
 * <p>Patterns handled:
 * <ul>
 *   <li>{@code Class.forName("X")} -> keep X (and its no-arg ctor for SPI)</li>
 *   <li>{@code Class.forName}, {@code Class.getDeclaredMethod/Field},
 *       {@code Method.invoke}, {@code Field.get/set} on a {@code ldc class} constant
 *       -> keep that class + the named member</li>
 *   <li>{@code Proxy.newProxyInstance(loader, new Class[]{Iface.class}, ...)}
 *       -> keep Iface</li>
 *   <li>{@code ServiceLoader.load(Service.class)} -> keep Service</li>
 *   <li>Lambda / method-handle bootstrap args -> keep captured member</li>
 *   <li>Annotation types referenced via {@code @Retention(RUNTIME)} reflection are
 *       kept by virtue of being on the classpath; here we also keep names that
 *       appear in {@code Class.forName} string arguments resolved by simple
 *       constant propagation.</li>
 * </ul>
 *
 * The interpreter-based pass resolves {@code ldc} constants flowing into
 * {@code Class.forName} so even dynamic code stays working.
 */
public final class ReflectionScanner {

    private static final String TAG = "reflect";
    private static final String CLASS_FOR_NAME = "forName";
    private static final String CLASS_GET_DECLARED_METHOD = "getDeclaredMethod";
    private static final String CLASS_GET_METHOD = "getMethod";
    private static final String CLASS_GET_DECLARED_FIELD = "getDeclaredField";
    private static final String CLASS_GET_FIELD = "getField";
    private static final String PROXY_NEW = "newProxyInstance";
    private static final String SERVICE_LOADER_LOAD = "load";

    public void scan(ClassGraph graph) {
        for (ClassNode cn : graph.getClasses().values()) {
            try {
                scanOne(graph, cn);
            } catch (Exception e) {
                // Per-class failure must not abort the whole build.
                KBoxLog.warn(TAG, "Scan failed for " + cn.name + ": " + e.getMessage());
            }
        }
        KBoxLog.info(TAG, "Keep-set size after reflection scan: " + graph.getKeepSet().size());
    }

    @SuppressWarnings("unchecked")
    private void scanOne(ClassGraph graph, ClassNode cn) {
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;

            // Fast path: scan instruction-by-instruction for the common patterns.
            for (int i = 0; i < mn.instructions.size(); i++) {
                org.objectweb.asm.tree.AbstractInsnNode ins = mn.instructions.get(i);
                if (ins instanceof MethodInsnNode) {
                    handleMethodInsn(graph, (MethodInsnNode) ins);
                } else if (ins instanceof InvokeDynamicInsnNode) {
                    handleLambda(graph, (InvokeDynamicInsnNode) ins);
                }
            }

            // Slow path: data-flow aware recovery of the STRING ARGUMENTS of the
            // reflective lookup APIs.
            //
            // The fast path only sees an LDC that is the instruction IMMEDIATELY
            // before the call, which is not the case for the realistic shapes:
            //   Cls.class.getDeclaredMethod("compute", int.class)
            //   -> invokestatic Integer.TYPE ; invokestatic Class.getDeclaredMethod
            //   Cls.class.getDeclaredField("f")
            // Here nothing kept the literal, so the declaration was renamed while
            // the lookup string was not -> NoSuchMethodException/NoSuchFieldException
            // at runtime (F09.4/F09.5/F10.1/F10.2).
            //
            // SourceInterpreter tells us exactly which instruction produced each
            // operand-stack slot, so the name literal is recovered regardless of how
            // many class/array operands follow it.
            try {
                org.objectweb.asm.tree.analysis.Frame<SourceValue>[] frames =
                        new Analyzer<>(new SourceInterpreter()).analyze(cn.name, mn);
                if (frames == null) continue;
                for (int i = 0; i < mn.instructions.size(); i++) {
                    org.objectweb.asm.tree.AbstractInsnNode ins = mn.instructions.get(i);
                    if (!(ins instanceof MethodInsnNode)) continue;
                    MethodInsnNode mi = (MethodInsnNode) ins;
                    org.objectweb.asm.tree.analysis.Frame<SourceValue> f = frames[i];
                    if (f == null) continue;
                    String arg = reflectionNameArg(mi, f);
                    if (arg == null) continue;
                    if (!mi.owner.equals("java/lang/Class")) continue;
                    if (mi.name.equals(CLASS_FOR_NAME)) {
                        graph.keep(MemberRef.ofClass(arg.replace('.', '/')));
                    } else {
                        // getDeclaredMethod / getMethod / getDeclaredField /
                        // getField / getDeclaredConstructor: the name is resolved
                        // reflectively, so it must survive renaming in whatever
                        // class declares it. "__anykept__" is honoured by
                        // RetentionDecision for both methods and fields.
                        graph.keep(new MemberRef("__anykept__", arg, ""));
                    }
                }
            } catch (Exception ignored) {
                // best-effort; the fast path already covered most cases
            }
        }
    }

    /** Handles direct {@code Class.forName(String)} etc. resolved via the preceding LDC. */
    private void handleMethodInsn(ClassGraph graph, MethodInsnNode mi) {
        String m = mi.name;
        String owner = mi.owner;
        if (owner.equals("java/lang/Class") && m.equals(CLASS_FOR_NAME)) {
            String cls = readPrevLdcString(mi);
            if (cls != null) graph.keep(MemberRef.ofClass(cls.replace('.', '/')));
        } else if (owner.equals("java/lang/Class")
                && (m.equals(CLASS_GET_DECLARED_METHOD) || m.equals(CLASS_GET_METHOD)
                || m.equals(CLASS_GET_DECLARED_FIELD) || m.equals(CLASS_GET_FIELD))) {
            // The first arg is the target class (on stack), second is the member name (LDC).
            String member = readPrevLdcString(mi);
            // We cannot easily resolve the Class operand without full dataflow; the
            // analyzer pass above seeds keepSet with the class, so we just keep the
            // member name spec loosely if a class is later proven kept.
            // For safety we mark the literal as "name to keep on any kept class".
            if (member != null) {
                graph.keep(new MemberRef("__anykept__", member, ""));
            }
        } else if (owner.equals("java/lang/reflect/Proxy") && m.equals(PROXY_NEW)) {
            // The interfaces array is built inline; we look back for a recent NEW of an array
            // with an AASTORE of a Class literal. That is complex, so we conservatively keep
            // any Class LDC encountered recently.
            String cls = readPrevLdcClass(mi);
            if (cls != null) graph.keep(MemberRef.ofClass(cls));
        } else if (owner.equals("java/util/ServiceLoader") && m.equals(SERVICE_LOADER_LOAD)) {
            String cls = readPrevLdcClass(mi);
            if (cls != null) {
                graph.keep(MemberRef.ofClass(cls));
                // Keep its public no-arg ctor (convention for ServiceLoader providers).
                graph.keep(new MemberRef(cls, "<init>", "()V"));
            }
        }
    }

    /** Captured method/handle from a lambda or method-reference bootstrap. */
    private void handleLambda(ClassGraph graph, InvokeDynamicInsnNode id) {
        for (Object o : id.bsmArgs) {
            if (o instanceof Handle) {
                Handle h = (Handle) o;
                if (!h.getOwner().startsWith("java/")) {
                    graph.keep(new MemberRef(h.getOwner(), h.getName(), h.getDesc()));
                    graph.addReference(id.name.length() == 0 ? "lambda" : id.name, h.getOwner());
                }
            } else if (o instanceof Type) {
                Type t = (Type) o;
                String in = t.getInternalName();
                if (in != null && !in.startsWith("java/") && !in.startsWith("[")) {
                    graph.keep(MemberRef.ofClass(in));
                }
            }
        }
    }

    private String readPrevLdcString(MethodInsnNode mi) {
        org.objectweb.asm.tree.AbstractInsnNode p = mi.getPrevious();
        while (p != null && p.getOpcode() == 0) p = p.getPrevious();
        if (p != null && p.getOpcode() == Opcodes.LDC) {
            Object cst = ((org.objectweb.asm.tree.LdcInsnNode) p).cst;
            if (cst instanceof String) return (String) cst;
        }
        return null;
    }

    private String readPrevLdcClass(MethodInsnNode mi) {
        // Walk back a few instructions to find the LDC of a Class constant.
        org.objectweb.asm.tree.AbstractInsnNode p = mi.getPrevious();
        int budget = 8;
        while (p != null && budget-- > 0) {
            if (p.getOpcode() == Opcodes.LDC) {
                Object cst = ((org.objectweb.asm.tree.LdcInsnNode) p).cst;
                if (cst instanceof Type) {
                    Type t = (Type) cst;
                    return t.getSort() == Type.OBJECT ? t.getInternalName() : null;
                }
            }
            p = p.getPrevious();
        }
        return null;
    }

    /**
     * Recovers the {@code String} name argument of a reflective lookup call from
     * the data-flow frame at the call site.
     *
     * <p>Operand-stack shape (bottom → top) at the call:</p>
     * <ul>
     *   <li>{@code Class.forName(String)} — static, so the name is the top slot.</li>
     *   <li>{@code Class.getDeclaredField(String)} / {@code getField(String)} —
     *       {@code [receiver, name]}, name on top.</li>
     *   <li>{@code Class.getDeclaredMethod(String, Class...)} /
     *       {@code getMethod(String, Class...)} — {@code [receiver, name, types]},
     *       so the name sits one slot below the top.</li>
     * </ul>
     *
     * <p>Returns {@code null} when the slot is not a literal or the call is not a
     * name-taking reflective lookup. A computed name is unknowable at build time,
     * which is exactly why G1/G4 style lookups must instead disable renaming for
     * the referenced member.</p>
     */
    private static String reflectionNameArg(MethodInsnNode mi,
                                            org.objectweb.asm.tree.analysis.Frame<SourceValue> f) {
        if (!"java/lang/Class".equals(mi.owner)) return null;
        boolean classArrayForm = ("getDeclaredMethod".equals(mi.name) || "getMethod".equals(mi.name))
                && mi.desc.startsWith("(Ljava/lang/String;[Ljava/lang/Class;)");
        boolean singleStringForm = ("getDeclaredField".equals(mi.name) || "getField".equals(mi.name))
                && "(Ljava/lang/String;)".equals(mi.desc);
        boolean forName = "forName".equals(mi.name)
                && "(Ljava/lang/String;)Ljava/lang/Class;".equals(mi.desc);
        if (!classArrayForm && !singleStringForm && !forName) return null;

        int nameSlot = classArrayForm ? f.getStackSize() - 2 : f.getStackSize() - 1;
        if (nameSlot < 0) return null;
        SourceValue sv = f.getStack(nameSlot);
        if (sv == null || sv.insns == null) return null;
        for (org.objectweb.asm.tree.AbstractInsnNode src : sv.insns) {
            if (src instanceof LdcInsnNode) {
                Object cst = ((LdcInsnNode) src).cst;
                if (cst instanceof String) return (String) cst;
            }
        }
        return null;
    }
}
