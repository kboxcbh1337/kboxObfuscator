package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.InsnList;
import org.objectweb.asm.tree.InsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

/**
 * 调用点剥离：{@code -assumenosideeffects}、日志剥离、Kotlin Intrinsics 清理。
 *
 * <p>只删除「返回值必然被丢弃」或语义上可安全替换的调用：</p>
 * <ul>
 *   <li>日志：{@code PrintStream}/{@code Logger} 的 void 方法 —— 弹出 receiver+参数；
 *       {@code android.util.Log} 返回 int —— 弹出参数后压入 0（后续 POP 仍成立）。</li>
 *   <li>Kotlin：{@code Intrinsics.checkNotNull*} —— 保留对象、弹出检查字符串。</li>
 *   <li>用户 {@code stripCalls}：{@code owner#name#desc}（实例）或
 *       {@code static:owner#name#desc}（静态），仅支持 {@code )V}。</li>
 * </ul>
 *
 * <p>所有改写都按描述符精确计算栈槽宽度（long/double 占 2 槽），并标记
 * {@code cfModified} 以便打包期重算 StackMapTable。</p>
 */
public final class CallStripper {

    private static final String TAG = "strip-calls";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public CallStripper(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isStripLogs() && !cfg.isStripKotlinIntrinsics()
                && cfg.getStripCalls().isEmpty()) {
            return;
        }
        int removed = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            boolean any = false;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                any |= stripMethod(mn);
            }
            if (any) {
                graph.markCfModified(cn.name);
                removed++;
            }
        }
        KBoxLog.info(TAG, "Stripped calls in " + removed + " class(es) "
                + "(logs=" + cfg.isStripLogs()
                + ", kotlin=" + cfg.isStripKotlinIntrinsics()
                + ", user=" + cfg.getStripCalls().size() + ")");
    }

    private boolean stripMethod(MethodNode mn) {
        boolean changed = false;
        for (AbstractInsnNode ins = mn.instructions.getFirst(); ins != null; ) {
            AbstractInsnNode next = ins.getNext();
            if (ins.getOpcode() == Opcodes.INVOKEVIRTUAL
                    || ins.getOpcode() == Opcodes.INVOKESTATIC
                    || ins.getOpcode() == Opcodes.INVOKEINTERFACE
                    || ins.getOpcode() == Opcodes.INVOKESPECIAL) {
                MethodInsnNode mi = (MethodInsnNode) ins;
                if (stripOne(mn, mi)) {
                    changed = true;
                }
            }
            ins = next;
        }
        return changed;
    }

    /** @return true when the instruction was rewritten/removed. */
    private boolean stripOne(MethodNode mn, MethodInsnNode mi) {
        final boolean isStatic = mi.getOpcode() == Opcodes.INVOKESTATIC;
        final String owner = mi.owner;
        final String name = mi.name;
        final String desc = mi.desc;

        // ---- Kotlin Intrinsics ----
        if (cfg.isStripKotlinIntrinsics() && "kotlin/jvm/internal/Intrinsics".equals(owner)) {
            if ("checkNotNull".equals(name) || "checkNotNullExpressionValue".equals(name)
                    || "checkExpressionValueIsNotNull".equals(name)) {
                if ("(Ljava/lang/Object;)Ljava/lang/Object;".equals(desc)) {
                    mn.instructions.remove(mi);
                    return true;                        // object stays on stack
                }
                if ("(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;".equals(desc)) {
                    popSlots(mn.instructions, mi, 1);   // pop the message, keep object
                    mn.instructions.remove(mi);
                    return true;
                }
            }
            if ("checkNotNullParameter".equals(name)
                    || "checkParameterIsNotNull".equals(name)
                    || "checkNotNullExpressionValue".equals(name)) {
                if ("(Ljava/lang/Object;Ljava/lang/String;)V".equals(desc)) {
                    popSlots(mn.instructions, mi, 2);   // object + message
                    mn.instructions.remove(mi);
                    return true;
                }
            }
        }

        // ---- built-in logging ----
        if (cfg.isStripLogs()) {
            if ("java/io/PrintStream".equals(owner) && desc.endsWith(")V")
                    && (name.startsWith("print") || "format".equals(name)
                        || "write".equals(name))) {
                popSlots(mn.instructions, mi, 1 + argSlots(desc));   // receiver + args
                mn.instructions.remove(mi);
                return true;
            }
            if (isStatic && "android/util/Log".equals(owner)) {
                popSlots(mn.instructions, mi, argSlots(desc));
                mn.instructions.set(mi, new InsnNode(Opcodes.ICONST_0));
                return true;
            }
            if (!isStatic && desc.endsWith(")V")
                    && (owner.startsWith("java/util/logging/")
                        || owner.startsWith("org/apache/logging/log4j/")
                        || owner.startsWith("org/slf4j/"))
                    && (name.startsWith("log") || name.equals("fine") || name.equals("finer")
                        || name.equals("finest") || name.equals("info") || name.equals("warn")
                        || name.equals("severe") || name.equals("config")
                        || name.equals("debug") || name.equals("error") || name.equals("trace")
                        || name.equals("fatal"))) {
                popSlots(mn.instructions, mi, 1 + argSlots(desc));
                mn.instructions.remove(mi);
                return true;
            }
        }

        // ---- user -assumenosideeffects ----
        for (String pat : cfg.getStripCalls()) {
            boolean staticPat = pat.startsWith("static:");
            String body = staticPat ? pat.substring("static:".length()) : pat;
            if (!matches(body, owner, name, desc)) continue;
            if (staticPat && !isStatic) continue;
            if (!staticPat && isStatic) continue;
            if (!desc.endsWith(")V")) {
                KBoxLog.warn(TAG, "stripCalls skipped non-void " + owner + "." + name + desc);
                continue;
            }
            int slots = argSlots(desc) + (isStatic ? 0 : 1);
            popSlots(mn.instructions, mi, slots);
            mn.instructions.remove(mi);
            return true;
        }
        return false;
    }

    private static boolean matches(String pattern, String owner, String name, String desc) {
        int h1 = pattern.indexOf('#');
        if (h1 < 0) {
            // owner only: every method of that owner
            return pattern.equals(owner);
        }
        String po = pattern.substring(0, h1);
        String rest = pattern.substring(h1 + 1);
        int h2 = rest.indexOf('#');
        String pn = h2 < 0 ? rest : rest.substring(0, h2);
        String pd = h2 < 0 ? null : rest.substring(h2 + 1);
        return po.equals(owner) && pn.equals(name) && (pd == null || pd.equals(desc));
    }

    /** Insert POP/POP2 before {@code at} for the given number of stack slots. */
    private static void popSlots(InsnList list, AbstractInsnNode at, int slots) {
        while (slots > 0) {
            if (slots >= 2) {
                list.insertBefore(at, new InsnNode(Opcodes.POP2));
                slots -= 2;
            } else {
                list.insertBefore(at, new InsnNode(Opcodes.POP));
                slots -= 1;
            }
        }
    }

    private static int argSlots(String desc) {
        int slots = 0;
        int i = 1;
        while (i < desc.length() && desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'J' || c == 'D') {
                slots += 2;
                i++;
            } else if (c == 'L') {
                slots += 1;
                i = desc.indexOf(';', i) + 1;
                if (i <= 0) break;
            } else if (c == '[') {
                slots += 1;
                i++;
                while (i < desc.length() && desc.charAt(i) == '[') i++;
                if (i < desc.length() && desc.charAt(i) == 'L') {
                    i = desc.indexOf(';', i) + 1;
                    if (i <= 0) break;
                } else {
                    i++;
                }
            } else {
                slots += 1;
                i++;
            }
        }
        return slots;
    }
}
