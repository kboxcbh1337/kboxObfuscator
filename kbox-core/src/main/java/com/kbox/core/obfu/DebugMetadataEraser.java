package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LineNumberNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;
import java.util.Set;

/**
 * 调试 / 结构元数据擦除（Debug &amp; structural metadata erasure）。
 *
 * <p>逆向者拿到的第一手线索往往不是字节码本身，而是<b>元数据</b>：</p>
 * <ul>
 *   <li>{@code SourceFile} —— 把改名后的类<b>直接还原回原类名</b>。强度测试报告实测：
 *       129 个改名类 100% 可反查，等于把整套混淆 pass 清单交出去。</li>
 *   <li>{@code LineNumberTable} —— 把方法体对回公开源码的行号。</li>
 *   <li>{@code LocalVariableTable} —— 局部变量名。</li>
 *   <li>{@code Signature} —— 泛型结构（类型重建的关键线索）。</li>
 *   <li>{@code EnclosingMethod} —— 本地/匿名类的归属方法。</li>
 *   <li>{@code MethodParameters} / {@code Exceptions} —— 形参名与 checked 异常声明。</li>
 * </ul>
 *
 * <p>本 pass 在写产物前把这些属性抹掉；{@link ProtectionConfig#getKeepAttributes()}
 * 里显式列出的属性会被保留（ProGuard {@code -keepattributes} 语义）。</p>
 *
 * <p>分级：{@code eraseDebugInfo}（默认开）擦除调试/结构属性（安全）；
 * {@code eraseSignatures}（默认关，{@code allMax} 开）额外擦除 {@code Signature} /
 * {@code EnclosingMethod}，会牺牲泛型反射与部分框架能力。
 * {@code InnerClasses} 始终保留：JVM 会在内外类之间做一致性校验（只让一侧保留条目会抛
 * {@code IncompatibleClassChangeError}），且 {@code getSimpleName()} /
 * {@code getDeclaringClass()} / record 的 {@code toString()} 都依赖它。</p>
 */
public final class DebugMetadataEraser {

    private static final String TAG = "meta";

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public DebugMetadataEraser(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isEraseDebugInfo() && !cfg.isEraseSignatures()) return;

        final Set<String> keep = cfg.getKeepAttributes();
        final boolean dropSource = cfg.isEraseDebugInfo() && !keep.contains("SourceFile");
        final boolean dropLines = cfg.isEraseDebugInfo() && !keep.contains("LineNumberTable");
        final boolean dropLocals = cfg.isEraseDebugInfo() && !keep.contains("LocalVariableTable");
        final boolean dropParams = cfg.isEraseDebugInfo() && !keep.contains("MethodParameters");
        final boolean dropExs = cfg.isEraseDebugInfo() && !keep.contains("Exceptions");
        final boolean dropSig = cfg.isEraseSignatures() && !keep.contains("Signature");
        // InnerClasses is NOT erased: the JVM cross-checks it between a class and
        // its outer class (Class.getDeclaringClass0 throws
        // "IncompatibleClassChangeError: X and X$Y disagree on InnerClasses
        // attribute" when only one side keeps the entry), and Record.toString() /
        // getSimpleName() / getDeclaringClass() resolve through it. The attribute
        // only links already-obfuscated names, so keeping it leaks nothing
        // meaningful while keeping nested types working.
        final boolean dropEncl = cfg.isEraseSignatures() && !keep.contains("EnclosingMethod");

        java.util.concurrent.atomic.AtomicInteger n = new java.util.concurrent.atomic.AtomicInteger();
        // 注意：这里不走 ParallelClassProcessor 的 shouldProtectClass 过滤。
        // 被 keep / 入口点保护而"不重命名"的类同样带着 SourceFile——实测 HelloWorld 主类就是
        // 因为被 keep 而漏擦，`HelloWorld.java` 仍能从产物里读出来，改名因此可被反查。
        // 擦除调试属性与"是否混淆这个类"无关，且对语义无影响，因此对所有类生效。
        for (org.objectweb.asm.tree.ClassNode cn : graph.getClasses().values()) {
            try {
                n.addAndGet(erase(cn, dropSource, dropLines, dropLocals, dropParams, dropExs,
                        dropSig, dropEncl));
            } catch (Throwable t) {
                KBoxLog.warn(TAG, "Metadata erase failed for " + cn.name + ": " + t.getMessage());
            }
        }
        int e = n.get();
        KBoxLog.info(TAG, "Erased " + e + " metadata attribute(s)"
                + " (debugInfo=" + cfg.isEraseDebugInfo() + ", signatures=" + cfg.isEraseSignatures() + ")");
    }

    @SuppressWarnings("unchecked")
    private static int erase(ClassNode cn, boolean dropSource, boolean dropLines, boolean dropLocals,
                             boolean dropParams, boolean dropExs, boolean dropSig,
                             boolean dropEncl) {
        int n = 0;

        if (dropSource) {
            if (cn.sourceFile != null) { cn.sourceFile = null; n++; }
            if (cn.sourceDebug != null) { cn.sourceDebug = null; n++; }
        }

        if (dropSig && cn.signature != null) { cn.signature = null; n++; }

        if (dropEncl && (cn.outerClass != null || cn.outerMethod != null)) {
            cn.outerClass = null;
            cn.outerMethod = null;
            cn.outerMethodDesc = null;
            n++;
        }

        for (FieldNode fn : (List<FieldNode>) cn.fields) {
            if (dropSig && fn.signature != null) { fn.signature = null; n++; }
        }

        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (dropSig && mn.signature != null) { mn.signature = null; n++; }
            if (dropExs && mn.exceptions != null && !mn.exceptions.isEmpty()) { mn.exceptions = null; n++; }
            if (dropParams && mn.parameters != null && !mn.parameters.isEmpty()) { mn.parameters = null; n++; }
            if (dropLocals && mn.localVariables != null && !mn.localVariables.isEmpty()) {
                mn.localVariables = null; n++;
            }
            if (dropLines && mn.instructions != null) {
                AbstractInsnNode ins = mn.instructions.getFirst();
                while (ins != null) {
                    AbstractInsnNode next = ins.getNext();
                    if (ins instanceof LineNumberNode) {
                        mn.instructions.remove(ins);
                        n++;
                    }
                    ins = next;
                }
            }
        }
        return n;
    }
}
