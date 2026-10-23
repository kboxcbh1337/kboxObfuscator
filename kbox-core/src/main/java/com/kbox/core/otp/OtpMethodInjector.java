package com.kbox.core.otp;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.bfvm.BfVmException;
import com.kbox.core.bfvm.compile.BfMethodCompiler;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.runtime.KotpRuntime;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.IntInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TypeInsnNode;
import org.objectweb.asm.tree.VarInsnNode;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * K-OTP 构建期注入器 —— 自写「原生种子一次性程序」。
 *
 * <p>对每个入选方法：先用 {@link BfMethodCompiler} 把当前（已混淆过的）方法体编译成
 * BFVM 指令流 {@code P}，再用 JNIC 原生库里隐藏的构建种子派生 keystream，算出 share
 * {@code A = P XOR ks(seed, site, 0, chain0)}；类文件里只写入 {@code A} 和
 * {@code long[]{epoch,chain}}。运行期 {@link KotpRuntime#invoke} 用原生种子还原 P、
 * 交给 BFVM 解释执行，并在返回前用运行期熵重定密钥、就地重写 A。</p>
 *
 * <p>静态逆向者拿到的 A 与明文在信息上无关（seed 不在 Java 侧）；即使动态 dump，
 * 每次调用后 A 都已重随机，dump 到的只是一个已结束 epoch 的 share。</p>
 */
public final class OtpMethodInjector {

    private static final String TAG = "k-otp";
    private static final String RUNTIME = "com/kbox/runtime/KotpRuntime";
    private static final int CHUNK = 16000;          // chars per LDC string (modified UTF-8 safe)
    private static final int MAX_STREAM = 240_000;   // bytes per method
    private static final int MAX_INSNS = 4000;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final Set<String> claimed;
    /**
     * 引擎自身类的**最终名**（原名以 com/kbox/ 开头的类，例如 renamePackages 之后
     * 变成 d/e/f/* 的 S4 honeypot 诱饵类）。这些类绝不能被 OTP 处理：它们是引擎生成
     * 的合成字节码 / 诱饵，注入 stub 会破坏其自洽性（实测 VerifyError）。
     */
    private final Set<String> engineClasses;

    /** K-OTP 原生种子（来自本次构建的 JnicOrchestrator 实例，0 = 跳过）。 */
    private final long otpNativeSeed;

    /** NAT-18: the seed is passed EXPLICITLY from the pipeline (which holds the
     *  JnicOrchestrator instance) instead of being pulled from process-wide
     *  static state, so concurrent builds cannot clobber each other's K-OTP key. */
    public OtpMethodInjector(ClassGraph graph, ProtectionConfig cfg,
                             Set<String> vmpMethods, Set<String> nativeMethods,
                             Set<String> bfvmMethods, Set<String> engineClasses,
                             long otpNativeSeed) {
        this.graph = graph;
        this.cfg = cfg;
        this.otpNativeSeed = otpNativeSeed;
        this.claimed = new LinkedHashSet<>();
        if (vmpMethods != null) claimed.addAll(vmpMethods);
        if (nativeMethods != null) claimed.addAll(nativeMethods);
        if (bfvmMethods != null) claimed.addAll(bfvmMethods);
        this.engineClasses = engineClasses == null
                ? java.util.Collections.emptySet() : engineClasses;
    }

    /** Injection result (for the build report). */
    public static final class Result {
        public int sites;
        public int classes;
        public long bytes;
        public final List<String> transformed = new ArrayList<>();
        public final List<String> skipped = new ArrayList<>();
    }

    public Result apply() {
        Result r = new Result();
        if (!cfg.isEnableOtp()) {
            KBoxLog.info(TAG, "K-OTP disabled (requires enableOtp + enableJnic)");
            return r;
        }
        long raw = otpNativeSeed;
        if (raw == 0L) {
            KBoxLog.warn(TAG, "K-OTP skipped: native seed unavailable (JNIC native build did not run)");
            return r;
        }
        final long seed = KotpRuntime.expand(raw);
        final SecureRandom rnd = new SecureRandom();
        int[] site = {rnd.nextInt(0x40000000) + 1};

        for (ClassNode cn : graph.getClasses().values()) {
            if (cn.name == null || cn.name.startsWith("com/kbox/")) continue;
            if (engineClasses.contains(cn.name)) continue;
            if (cn.methods == null || cn.methods.isEmpty()) continue;
            if (!cfg.shouldProtectClass(cn.name)) continue;

            List<MethodNode> selected = new ArrayList<>();
            for (MethodNode mn : new ArrayList<>(cn.methods)) {
                if (!eligible(cn, mn)) continue;
                selected.add(mn);
            }
            if (selected.isEmpty()) continue;

            int before = r.sites;
            for (MethodNode mn : selected) {
                try {
                    byte[] prog = BfMethodCompiler.compile(mn, cn.name);
                    if (prog.length > MAX_STREAM) {
                        r.skipped.add(key(cn, mn) + " (stream " + prog.length + "B)");
                        continue;
                    }
                    int id = site[0]++;
                    long chain0 = KotpRuntime.initialState(seed, id, 0,
                            rnd.nextLong() ^ ((long) id << 17)) & 0x7FFFFFFFFFFFFFFFL;
                    byte[] ks = KotpRuntime.keystream(seed, id, 0, chain0, prog.length);
                    byte[] share = new byte[prog.length];
                    for (int i = 0; i < prog.length; i++) share[i] = (byte) (prog[i] ^ ks[i]);

                    addFields(cn, id);
                    replaceBody(cn, mn, id, prog.length);
                    addClinitInit(cn, id, share, chain0);
                    r.sites++;
                    r.bytes += prog.length;
                    r.transformed.add(key(cn, mn) + " -> site#" + id + " (" + prog.length + "B)");
                    java.util.Arrays.fill(prog, (byte) 0);
                } catch (BfVmException | UnsupportedOperationException ex) {
                    r.skipped.add(key(cn, mn) + " (" + ex.getMessage() + ")");
                } catch (Exception ex) {
                    r.skipped.add(key(cn, mn) + " (" + ex + ")");
                }
            }
            if (r.sites > before) {
                graph.markCfModified(cn.name);
                r.classes++;
            }
        }
        KBoxLog.info(TAG, "K-OTP: " + r.sites + " one-time program(s) in " + r.classes
                + " class(es), " + r.bytes + " bytecode stream bytes, native-seeded="
                + Long.toHexString(raw));
        if (!r.skipped.isEmpty()) KBoxLog.debug(TAG, "  skipped: " + r.skipped);
        if (!r.transformed.isEmpty()) KBoxLog.debug(TAG, "  sites: " + r.transformed);
        return r;
    }

    private boolean eligible(ClassNode cn, MethodNode mn) {
        if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) return false;
        if (mn.name.charAt(0) == '<') return false;
        if (mn.name.equals("main") && mn.desc.equals("([Ljava/lang/String;)V")) return false;
        if (mn.instructions == null || mn.instructions.size() < 8) return false;
        if (mn.instructions.size() > MAX_INSNS) return false;
        if (!BfMethodCompiler.isSupported(mn)) return false;
        return !claimed.contains(key(cn, mn));
    }

    private static String key(ClassNode cn, MethodNode mn) {
        return ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
    }

    // ---------------------------------------------------------------- fields

    private void addFields(ClassNode cn, int site) {
        if (cn.fields == null) cn.fields = new ArrayList<>();
        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "otpA$" + site, "[B", null, null));
        cn.fields.add(new FieldNode(
                Opcodes.ACC_PRIVATE | Opcodes.ACC_STATIC | Opcodes.ACC_SYNTHETIC,
                "otpS$" + site, "[J", null, null));
    }

    /** Prepends {@code otpA$n = decode(chunks); otpS$n = new long[]{0, chain0};}. */
    private void addClinitInit(ClassNode cn, int site, byte[] share, long chain0) {
        MethodNode clinit = null;
        for (MethodNode m : cn.methods) {
            if (m.name.equals("<clinit>") && m.desc.equals("()V")) { clinit = m; break; }
        }
        if (clinit == null) {
            clinit = new MethodNode(Opcodes.ASM9, Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
            cn.methods.add(clinit);
        }
        InsnList pre = new InsnList();

        // String[] chunks
        int chunks = Math.max(1, (share.length + CHUNK - 1) / CHUNK);
        pushInt(pre, chunks);
        pre.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/String"));
        for (int c = 0; c < chunks; c++) {
            int from = c * CHUNK;
            int to = Math.min(share.length, from + CHUNK);
            char[] cs = new char[to - from];
            for (int i = from; i < to; i++) cs[i - from] = (char) (share[i] & 0xFF);
            pre.add(new InsnNode(Opcodes.DUP));
            pushInt(pre, c);
            pre.add(new LdcInsnNode(new String(cs)));
            pre.add(new InsnNode(Opcodes.AASTORE));
        }
        pre.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                "decode", "([Ljava/lang/String;)[B", false));
        pre.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.PUTSTATIC,
                cn.name, "otpA$" + site, "[B"));

        // long[]{0, chain0}
        pre.add(new InsnNode(Opcodes.ICONST_2));
        pre.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
        pre.add(new InsnNode(Opcodes.DUP));
        pre.add(new InsnNode(Opcodes.ICONST_0));
        pre.add(new InsnNode(Opcodes.LCONST_0));
        pre.add(new InsnNode(Opcodes.LASTORE));
        pre.add(new InsnNode(Opcodes.DUP));
        pre.add(new InsnNode(Opcodes.ICONST_1));
        pre.add(new LdcInsnNode(chain0));
        pre.add(new InsnNode(Opcodes.LASTORE));
        pre.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.PUTSTATIC,
                cn.name, "otpS$" + site, "[J"));

        AbstractInsnNode first = clinit.instructions.getFirst();
        if (first == null) {
            clinit.instructions.add(pre);
            clinit.instructions.add(new InsnNode(Opcodes.RETURN));
        } else {
            clinit.instructions.insertBefore(first, pre);
        }
        clinit.maxStack = Math.max(clinit.maxStack, 6);
    }

    private static void pushInt(InsnList l, int v) {
        if (v >= -1 && v <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + v));
        else if (v >= Byte.MIN_VALUE && v <= Byte.MAX_VALUE) l.add(new IntInsnNode(Opcodes.BIPUSH, v));
        else if (v >= Short.MIN_VALUE && v <= Short.MAX_VALUE) l.add(new IntInsnNode(Opcodes.SIPUSH, v));
        else l.add(new LdcInsnNode(v));
    }

    // ---------------------------------------------------------------- stub

    private void replaceBody(ClassNode cn, MethodNode mn, int site, int streamLen) {
        boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
        Type[] args = Type.getArgumentTypes(mn.desc);
        Type ret = Type.getReturnType(mn.desc);

        mn.instructions.clear();
        if (mn.tryCatchBlocks != null) mn.tryCatchBlocks.clear();
        mn.localVariables = null;
        mn.visibleLocalVariableAnnotations = null;
        mn.invisibleLocalVariableAnnotations = null;

        InsnList l = mn.instructions;
        pushInt(l, site);
        l.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                cn.name, "otpA$" + site, "[B"));
        l.add(new org.objectweb.asm.tree.FieldInsnNode(Opcodes.GETSTATIC,
                cn.name, "otpS$" + site, "[J"));
        l.add(new LdcInsnNode(Type.getObjectType(cn.name)));
        if (isStatic) l.add(new InsnNode(Opcodes.ACONST_NULL));
        else l.add(new VarInsnNode(Opcodes.ALOAD, 0));
        pushInt(l, args.length);
        l.add(new TypeInsnNode(Opcodes.ANEWARRAY, "java/lang/Object"));
        int slot = isStatic ? 0 : 1;
        for (int i = 0; i < args.length; i++) {
            l.add(new InsnNode(Opcodes.DUP));
            pushInt(l, i);
            l.add(new VarInsnNode(loadOpcode(args[i]), slot));
            box(l, args[i]);
            l.add(new InsnNode(Opcodes.AASTORE));
            slot += args[i].getSize();
        }
        l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME,
                "invoke",
                "(I[B[JLjava/lang/Class;Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
                false));
        switch (ret.getSort()) {
            case Type.VOID:
                l.add(new InsnNode(Opcodes.POP));
                l.add(new InsnNode(Opcodes.RETURN));
                break;
            case Type.INT: case Type.BOOLEAN: case Type.CHAR:
            case Type.BYTE: case Type.SHORT:
                l.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Integer"));
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Integer", "intValue", "()I", false));
                l.add(new InsnNode(Opcodes.IRETURN));
                break;
            case Type.LONG:
                l.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Long"));
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Long", "longValue", "()J", false));
                l.add(new InsnNode(Opcodes.LRETURN));
                break;
            case Type.FLOAT:
                l.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Float"));
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Float", "floatValue", "()F", false));
                l.add(new InsnNode(Opcodes.FRETURN));
                break;
            case Type.DOUBLE:
                l.add(new TypeInsnNode(Opcodes.CHECKCAST, "java/lang/Double"));
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKEVIRTUAL,
                        "java/lang/Double", "doubleValue", "()D", false));
                l.add(new InsnNode(Opcodes.DRETURN));
                break;
            default:
                l.add(new TypeInsnNode(Opcodes.CHECKCAST, ret.getInternalName()));
                l.add(new InsnNode(Opcodes.ARETURN));
        }
        mn.maxStack = Math.max(mn.maxStack, 10 + args.length);
        mn.maxLocals = Math.max(mn.maxLocals, slot + 2);
    }

    private static int loadOpcode(Type t) {
        switch (t.getSort()) {
            case Type.LONG: return Opcodes.LLOAD;
            case Type.FLOAT: return Opcodes.FLOAD;
            case Type.DOUBLE: return Opcodes.DLOAD;
            case Type.OBJECT: case Type.ARRAY: return Opcodes.ALOAD;
            default: return Opcodes.ILOAD;
        }
    }

    private static void box(InsnList l, Type t) {
        switch (t.getSort()) {
            case Type.LONG:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Long", "valueOf", "(J)Ljava/lang/Long;", false));
                break;
            case Type.FLOAT:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Float", "valueOf", "(F)Ljava/lang/Float;", false));
                break;
            case Type.DOUBLE:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Double", "valueOf", "(D)Ljava/lang/Double;", false));
                break;
            case Type.BOOLEAN:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false));
                break;
            case Type.CHAR:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Character", "valueOf", "(C)Ljava/lang/Character;", false));
                break;
            case Type.INT: case Type.SHORT: case Type.BYTE:
                l.add(new org.objectweb.asm.tree.MethodInsnNode(Opcodes.INVOKESTATIC,
                        "java/lang/Integer", "valueOf", "(I)Ljava/lang/Integer;", false));
                break;
            default:
                break;
        }
    }
}
