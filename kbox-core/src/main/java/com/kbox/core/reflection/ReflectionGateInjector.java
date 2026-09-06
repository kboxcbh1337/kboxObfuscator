package com.kbox.core.reflection;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.analysis.MemberRef;
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

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Phase2-L6b: runtime reflection gate. At build time a synthetic holder class
 * {@code com/kbox/runtime/_RefGate<rand>} is generated carrying a compact,
 * non-leaking allowlist (FNV-1a 32-bit hashes of reflectively loadable class
 * internal names), seeded from the graph's class set + keep-set. Then every
 * single-arg {@code Class.forName(String)} call site inside a protectable class
 * is wrapped:
 * <pre>
 *   ... String literal (on stack) ...
 *   INVOKESTATIC <RefGate>.checkForName(Ljava/lang/String;)Ljava/lang/String;
 *   INVOKESTATIC java/lang/Class.forName(Ljava/lang/String;)Ljava/lang/Class;
 * </pre>
 * The gate returns the same name for allowed targets (JDK/boot prefixes or an
 * allowlist hash match) and throws {@code SecurityException("KBox")} otherwise,
 * so reflection-driven discovery / loading of non-kept classes is intercepted.
 * Only hashes are embedded — no plaintext class name leaks from the gate.
 *
 * <p>Fail-closed by design: to {@code forName} a class legitimately it must be
 * in the graph (it ships it) or in the keep-set (ReflectionScanner seeded it),
 * both of which seed the allowlist; JDK/boot classes always pass. Opt-in via
 * config ({@code reflectionGate = true}).
 */
public final class ReflectionGateInjector {

    private static final String TAG = "reflection-gate";
    private static final String FOR_NAME_1 = "(Ljava/lang/String;)Ljava/lang/Class;";
    private static final int FNV_OFFSET = 0x811c9dc5;
    private static final int FNV_PRIME = 0x01000193;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public ReflectionGateInjector(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    /** FNV-1a 32-bit over an internal (slash) name. MUST match the runtime hash loop. */
    static int fnv(String internalName) {
        int h = FNV_OFFSET;
        int n = internalName.length();
        for (int i = 0; i < n; i++) {
            h ^= internalName.charAt(i);
            h *= FNV_PRIME;
        }
        return h;
    }

    public void apply() {
        if (!cfg.isReflectionGate()) return;

        String holder = "com/kbox/runtime/_RefGate" + randName(8);
        Set<Integer> allow = new LinkedHashSet<>();
        for (String cn : graph.getClasses().keySet()) allow.add(fnv(cn));
        for (MemberRef m : graph.getKeepSet()) {
            if (m.isClassRef()) allow.add(fnv(m.owner));
        }

        buildHolder(holder, allow);
        inject(holder);
        KBoxLog.info(TAG, "Reflection gate active: " + allow.size()
                + " allowed hashes, holder=" + holder);
    }

    // ------------------------------------------------------------------
    //  Synthetic holder:  int[] _allow  +  String checkForName(String)
    // ------------------------------------------------------------------

    private void buildHolder(String holder, Set<Integer> allow) {
        if (graph.getClasses().containsKey(holder)) return;
        ClassNode cn = new ClassNode();
        cn.version = Opcodes.V1_8;
        cn.access = Opcodes.ACC_PUBLIC | Opcodes.ACC_FINAL | Opcodes.ACC_SYNTHETIC;
        cn.name = holder;
        cn.superName = "java/lang/Object";

        MethodNode ctor = new MethodNode(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        ctor.instructions.add(new VarInsnNode(Opcodes.ALOAD, 0));
        ctor.instructions.add(new MethodInsnNode(Opcodes.INVOKESPECIAL,
                "java/lang/Object", "<init>", "()V", false));
        ctor.instructions.add(new InsnNode(Opcodes.RETURN));
        ctor.maxStack = 1;
        ctor.maxLocals = 1;
        cn.methods.add(ctor);

        cn.fields.add(new FieldNode(Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_FINAL,
                "_allow", "[I", null, null));

        // <clinit>: _allow = new int[]{h1, h2, ...}
        MethodNode clinit = new MethodNode(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        InsnList cl = clinit.instructions;
        pushInt(cl, allow.size());
        cl.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_INT));
        int idx = 0;
        for (int h : allow) {
            cl.add(new InsnNode(Opcodes.DUP));
            pushInt(cl, idx++);
            pushInt(cl, h);
            cl.add(new InsnNode(Opcodes.IASTORE));
        }
        cl.add(new FieldInsnNode(Opcodes.PUTSTATIC, holder, "_allow", "[I"));
        cl.add(new InsnNode(Opcodes.RETURN));
        clinit.maxStack = 3;
        clinit.maxLocals = 0;
        cn.methods.add(clinit);

        cn.methods.add(buildCheckForName(holder));
        graph.getClasses().put(holder, cn);
    }

    private MethodNode buildCheckForName(String holder) {
        MethodNode m = new MethodNode(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                "checkForName", "(Ljava/lang/String;)Ljava/lang/String;", null, null);
        InsnList d = m.instructions;
        // locals: 0=s, 1=h, 2=i, 3=len, 4=c, 5=j
        LabelNode loop = new LabelNode();
        LabelNode dotDone = new LabelNode();
        LabelNode done = new LabelNode();
        LabelNode scanLoop = new LabelNode();
        LabelNode found = new LabelNode();
        LabelNode allowReturn = new LabelNode();
        LabelNode deny = new LabelNode();

        // h = FNV_OFFSET
        pushInt(d, FNV_OFFSET);
        d.add(new VarInsnNode(Opcodes.ISTORE, 1));
        // i = 0 ; len = s.length()
        d.add(new InsnNode(Opcodes.ICONST_0));
        d.add(new VarInsnNode(Opcodes.ISTORE, 2));
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));
        d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "length", "()I", false));
        d.add(new VarInsnNode(Opcodes.ISTORE, 3));
        d.add(loop);
        // if (i >= len) goto done
        d.add(new VarInsnNode(Opcodes.ILOAD, 2));
        d.add(new VarInsnNode(Opcodes.ILOAD, 3));
        d.add(new JumpInsnNode(Opcodes.IF_ICMPGE, done));
        // c = s.charAt(i)
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));
        d.add(new VarInsnNode(Opcodes.ILOAD, 2));
        d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "charAt", "(I)C", false));
        d.add(new VarInsnNode(Opcodes.ISTORE, 4));
        // if (c != '.') goto dotDone ; else c = '/'
        d.add(new VarInsnNode(Opcodes.ILOAD, 4));
        d.add(new LdcInsnNode('.'));
        d.add(new JumpInsnNode(Opcodes.IF_ICMPNE, dotDone));
        d.add(new IntInsnNode(Opcodes.BIPUSH, '/'));
        d.add(new VarInsnNode(Opcodes.ISTORE, 4));
        d.add(dotDone);
        // h = (h ^ c) * FNV_PRIME
        d.add(new VarInsnNode(Opcodes.ILOAD, 1));
        d.add(new VarInsnNode(Opcodes.ILOAD, 4));
        d.add(new InsnNode(Opcodes.IXOR));
        pushInt(d, FNV_PRIME);
        d.add(new InsnNode(Opcodes.IMUL));
        d.add(new VarInsnNode(Opcodes.ISTORE, 1));
        // i++
        d.add(new VarInsnNode(Opcodes.ILOAD, 2));
        d.add(new InsnNode(Opcodes.ICONST_1));
        d.add(new InsnNode(Opcodes.IADD));
        d.add(new VarInsnNode(Opcodes.ISTORE, 2));
        d.add(new JumpInsnNode(Opcodes.GOTO, loop));
        d.add(done);

        // Boot/JDK prefix short-circuit (dotted, matches Class.forName input).
        for (String p : new String[]{"java.", "javax.", "sun.", "jdk."}) {
            d.add(new VarInsnNode(Opcodes.ALOAD, 0));
            d.add(new LdcInsnNode(p));
            d.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, "java/lang/String", "startsWith",
                    "(Ljava/lang/String;)Z", false));
            d.add(new JumpInsnNode(Opcodes.IFNE, allowReturn));
        }

        // j = 0 ; if (_allow.length == 0) goto deny
        d.add(new InsnNode(Opcodes.ICONST_0));
        d.add(new VarInsnNode(Opcodes.ISTORE, 5));
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_allow", "[I"));
        d.add(new InsnNode(Opcodes.ARRAYLENGTH));
        d.add(new JumpInsnNode(Opcodes.IFEQ, deny));
        d.add(scanLoop);
        // if (j >= _allow.length) goto deny
        d.add(new VarInsnNode(Opcodes.ILOAD, 5));
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_allow", "[I"));
        d.add(new InsnNode(Opcodes.ARRAYLENGTH));
        d.add(new JumpInsnNode(Opcodes.IF_ICMPGE, deny));
        // if (_allow[j] == h) goto found
        d.add(new FieldInsnNode(Opcodes.GETSTATIC, holder, "_allow", "[I"));
        d.add(new VarInsnNode(Opcodes.ILOAD, 5));
        d.add(new InsnNode(Opcodes.IALOAD));
        d.add(new VarInsnNode(Opcodes.ILOAD, 1));
        d.add(new JumpInsnNode(Opcodes.IF_ICMPEQ, found));
        // j++
        d.add(new VarInsnNode(Opcodes.ILOAD, 5));
        d.add(new InsnNode(Opcodes.ICONST_1));
        d.add(new InsnNode(Opcodes.IADD));
        d.add(new VarInsnNode(Opcodes.ISTORE, 5));
        d.add(new JumpInsnNode(Opcodes.GOTO, scanLoop));

        d.add(allowReturn);
        d.add(new VarInsnNode(Opcodes.ALOAD, 0));
        d.add(new InsnNode(Opcodes.ARETURN));

        d.add(found);
        d.add(new JumpInsnNode(Opcodes.GOTO, allowReturn));

        // deny: throw new SecurityException("KBox")
        d.add(deny);
        d.add(new TypeInsnNode(Opcodes.NEW, "java/lang/SecurityException"));
        d.add(new InsnNode(Opcodes.DUP));
        d.add(new LdcInsnNode("KBox"));
        d.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, "java/lang/SecurityException",
                "<init>", "(Ljava/lang/String;)V", false));
        d.add(new InsnNode(Opcodes.ATHROW));

        m.maxStack = 4;
        m.maxLocals = 6;
        return m;
    }

    // ------------------------------------------------------------------
    //  Wrap  Class.forName(String)  call sites in protectable classes.
    // ------------------------------------------------------------------

    @SuppressWarnings("unchecked")
    private void inject(String holder) {
        int wrapped = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ins = ins.getNext()) {
                    if (!(ins instanceof MethodInsnNode)) continue;
                    MethodInsnNode call = (MethodInsnNode) ins;
                    if (call.getOpcode() != Opcodes.INVOKESTATIC) continue;
                    if (!"java/lang/Class".equals(call.owner)) continue;
                    if (!"forName".equals(call.name)) continue;
                    if (!FOR_NAME_1.equals(call.desc)) continue;  // only 1-arg form
                    InsnList wrap = new InsnList();
                    wrap.add(new MethodInsnNode(Opcodes.INVOKESTATIC, holder, "checkForName",
                            "(Ljava/lang/String;)Ljava/lang/String;", false));
                    mn.instructions.insertBefore(call, wrap);
                    wrapped++;
                }
            }
        }
        if (wrapped > 0) {
            KBoxLog.info(TAG, "Wrapped " + wrapped + " Class.forName call sites");
        }
    }

    private static String randName(int len) {
        final String cs = "abcdefghijklmnopqrstuvwxyz";
        StringBuilder sb = new StringBuilder(len);
        ThreadLocalRandom r = ThreadLocalRandom.current();
        for (int i = 0; i < len; i++) sb.append(cs.charAt(r.nextInt(cs.length())));
        return sb.toString();
    }

    static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) { l.add(new InsnNode(Opcodes.ICONST_0 + v)); }
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) { l.add(new IntInsnNode(Opcodes.BIPUSH, v)); }
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) { l.add(new IntInsnNode(Opcodes.SIPUSH, v)); }
        else { l.add(new LdcInsnNode(v)); }
    }
}