package com.kbox.core.bfvm;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.bfvm.compile.BfMethodCompiler;
import com.kbox.core.bfvm.compile.BfProgramWriter;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Pipeline build-side injector: rewrites the bodies of methods listed in
 * {@code bfvmMethods} into executable Brainfuck programs.
 *
 * <p>Each selected method body is compiled to a BFVM stream, serialized as a Brainfuck
 * program (a pure data initialiser), and replaced with a thin stub that calls
 * {@link com.kbox.runtime.bfvm.BfRuntime#call} with the BF source, the owner class,
 * {@code this} (or null) and the boxed arguments. The runtime decodes the program back
 * into the instruction stream and executes it through {@code VmCore}.
 *
 * <p>Methods already claimed by VMP or JNIC, constructors, native/abstract methods and
 * bodies BFVM cannot translate (exception handlers, invokedynamic, monitors, …) are
 * skipped and keep their current (obfuscated) body.
 */
public final class BfvmMethodInjector {

    private static final String TAG = "bfvm";

    private final Set<String> bfvmMethods;
    private final Set<String> vmpMethods;
    private final Set<String> nativeMethods;

    public BfvmMethodInjector(Set<String> bfvmMethods, Set<String> vmpMethods, Set<String> nativeMethods) {
        this.bfvmMethods = bfvmMethods;
        this.vmpMethods = vmpMethods;
        this.nativeMethods = nativeMethods;
    }

    /**
     * 自动挑选可虚拟化的方法（P1-4）。
     *
     * <p>此前 {@code enableBfvm=true} 但没手写 {@code bfvmMethod} 时<b>什么都不做</b>——
     * 开关形同虚设。现在按规则自动铺开：跳过 ctor/clinit、native/abstract、空体、
     * 已被 VMP/JNIC 认领的方法、以及体量超过 {@code maxInsns} 的方法；其余交给
     * {@link BfMethodCompiler#compile} 在编译期判定（不支持的会带原因跳过并留在原样）。</p>
     *
     * <p>只挑用户代码：库类（java/javax/kotlin/asm/第三方）不参与——BFVM 运行期开销大，
     * 只值得用在高价值业务方法上。</p>
     */
    public static Set<String> autoSelect(ClassGraph graph,
                                         com.kbox.core.config.ProtectionConfig cfg,
                                         Set<String> vmpMethods, Set<String> nativeMethods,
                                         int maxInsns) {
        Set<String> out = new java.util.LinkedHashSet<>();
        int scannedClasses = 0, scannedMethods = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            scannedClasses++;
            // 注意：不能用 shouldProtectClass——被 keep 的入口类（如 HelloWorld）会被判为 false，
            // 而它们的<b>方法体</b>完全可以虚拟化（只是方法名/类名要保留）。
            if (isFrameworkOrOwn(cn.name, cfg)) continue;
            // Mixin classes / mixin targets are excluded from body-level
            // obfuscation (their handlers are matched positionally by Mixin).
            if (cfg.isBodyProtectExcluded(cn.name)) continue;
            for (MethodNode mn : cn.methods) {
                scannedMethods++;
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0) continue;
                if (mn.name.startsWith("<")) continue;
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                if (mn.instructions.size() > maxInsns) {
                    KBoxLog.info(TAG, "autoSelect skip " + cn.name + "." + mn.name
                            + " insns=" + mn.instructions.size() + " > " + maxInsns);
                    continue;
                }
                String key = com.kbox.core.config.ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
                if (vmpMethods != null && vmpMethods.contains(key)) continue;
                if (nativeMethods != null && nativeMethods.contains(key)) continue;
                out.add(key);
            }
        }
        KBoxLog.info(TAG, "autoSelect scanned " + scannedClasses + " classes / "
                + scannedMethods + " methods -> " + out.size() + " candidate(s)");
        return out;
    }

    /** 明显的框架/库/自身类：BFVM 运行期开销大，只值得用在高价值业务方法上。 */
    private static boolean isFrameworkOrOwn(String internalName,
                                            com.kbox.core.config.ProtectionConfig cfg) {
        // 库分类器（含 org/spongepowered/asm/、Forge/Fabric、ASM/Kotlin/第三方前缀）。
        // 关键：Mixin/Forge 引导代码绝不能被 BFVM 改写——MixinService 的静态单例
        // 初始化走 NEW + PUTSTATIC，解释器任何语义偏差都会在 tweaker 装载期直接崩溃。
        if (cfg != null && cfg.getLibraryClassifier() != null
                && cfg.getLibraryClassifier().isLibraryClass(internalName)) {
            return true;
        }
        return internalName.startsWith("java/")
                || internalName.startsWith("javax/")
                || internalName.startsWith("jdk/")
                || internalName.startsWith("sun/")
                || internalName.startsWith("com/sun/")
                || internalName.startsWith("kotlin")
                || internalName.startsWith("org/objectweb/asm")
                || internalName.startsWith("org/jetbrains/")
                || internalName.startsWith("org/intellij/")
                || internalName.startsWith("org/spongepowered/")
                || internalName.startsWith("net/minecraftforge/")
                || internalName.startsWith("net/neoforged/")
                || internalName.startsWith("cpw/mods/")
                || internalName.startsWith("net/fabricmc/")
                || internalName.startsWith("com/kbox/");
    }

    /** Result of the injection pass. */
    public static final class Result {
        public final List<String> transformed = new ArrayList<>();
        public final List<String> skipped = new ArrayList<>();
    }

    /**
     * Applies BFVM virtualization to every matching method across the graph.
     * Mutates the ClassNodes in place; marks CF-modified so the packager recomputes
     * stack map frames for transformed classes.
     */
    public Result apply(ClassGraph graph) {
        Result r = new Result();
        if (bfvmMethods == null || bfvmMethods.isEmpty()) {
            return r;
        }
        for (ClassNode cn : graph.getClasses().values()) {
            boolean any = false;
            List<MethodNode> methods = new ArrayList<>(cn.methods);
            List<MethodNode> out = new ArrayList<>(methods.size());
            for (MethodNode mn : methods) {
                String key = com.kbox.core.config.ProtectionConfig.memberKey(cn.name, mn.name, mn.desc);
                if (!bfvmMethods.contains(key)) {
                    out.add(mn);
                    continue;
                }
                if (vmpMethods != null && vmpMethods.contains(key)
                        || nativeMethods != null && nativeMethods.contains(key)) {
                    r.skipped.add(key + " (claimed by VMP/JNIC)");
                    out.add(mn);
                    continue;
                }
                if ((mn.access & (Opcodes.ACC_ABSTRACT | Opcodes.ACC_NATIVE)) != 0
                        || mn.name.startsWith("<")) {
                    r.skipped.add(key + " (native/abstract/ctor)");
                    out.add(mn);
                    continue;
                }
                if (mn.instructions == null || mn.instructions.size() == 0) {
                    r.skipped.add(key + " (empty body)");
                    out.add(mn);
                    continue;
                }
                try {
                    byte[] stream = BfMethodCompiler.compile(mn, cn.name);
                    String bf = BfProgramWriter.write(stream);
                    if (bf.length() > BfVm.MAX_BF_SOURCE) {
                        r.skipped.add(key + " (BF program too large)");
                        out.add(mn);
                        continue;
                    }
                    MethodNode repl = BfVm.buildBody(cn.name, mn.access, mn.name, mn.desc, bf);
                    // Keep every piece of metadata attached to the original method:
                    // Mixin handlers (@Overwrite/@Inject/@Redirect) are recognised by
                    // their ANNOTATIONS, and dropping them makes the mixin loader
                    // reject the class ("contains non-private static method ...").
                    repl.visibleAnnotations = mn.visibleAnnotations;
                    repl.invisibleAnnotations = mn.invisibleAnnotations;
                    repl.visibleParameterAnnotations = mn.visibleParameterAnnotations;
                    repl.invisibleParameterAnnotations = mn.invisibleParameterAnnotations;
                    repl.annotationDefault = mn.annotationDefault;
                    repl.signature = mn.signature;
                    repl.exceptions = mn.exceptions;
                    out.add(repl);
                    r.transformed.add(key);
                    any = true;
                } catch (UnsupportedOperationException e) {
                    r.skipped.add(key + " (" + e.getMessage() + ")");
                    out.add(mn);
                } catch (Exception e) {
                    r.skipped.add(key + " (" + e.getMessage() + ")");
                    out.add(mn);
                }
            }
            if (any) {
                cn.methods = out;
                graph.markCfModified(cn.name);
                KBoxLog.debug(TAG, "BFVM transformed " + cn.name);
            }
        }
        KBoxLog.info(TAG, "  BFVM: " + r.transformed.size() + " methods virtualized, "
                + r.skipped.size() + " skipped");
        if (!r.skipped.isEmpty()) {
            KBoxLog.debug(TAG, "  BFVM skipped: " + r.skipped);
        }
        return r;
    }
}
