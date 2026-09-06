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
                    out.add(BfVm.buildBody(cn.name, mn.access, mn.name, mn.desc, bf));
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
