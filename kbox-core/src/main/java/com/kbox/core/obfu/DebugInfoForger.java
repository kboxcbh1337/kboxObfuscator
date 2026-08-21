package com.kbox.core.obfu;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.LabelNode;
import org.objectweb.asm.tree.LocalVariableNode;
import org.objectweb.asm.tree.MethodNode;

import java.security.SecureRandom;
import java.util.List;

/**
 * Injects fake debug info (bogus LocalVariableTable, LineNumberTable) into
 * every method to mislead decompilers and increase the mental effort of
 * reverse engineering. The fake entries reference random type names,
 * non-existent source lines, and impossible variable scopes — producing
 * confusing decompiler output like "int a = b; String c = d;" where
 * none of the variables actually exist in the bytecode.
 *
 * <p>The JVM ignores this metadata at runtime, so the application works
 * fine. Decompilers that rely on debug info to reconstruct variable names
 * and source lines will produce garbage output.
 */
public final class DebugInfoForger {

    private static final String TAG = "debugforge";
    private static final SecureRandom RNG = new SecureRandom();

    /** Bogus type names that look plausible but are fake. */
    private static final String[] FAKE_TYPES = {
        "Ljava/lang/String;", "I", "Z", "J", "D", "F",
        "Ljava/lang/Object;", "Ljava/util/List;", "Ljava/util/Map;",
        "Ljava/util/Set;", "Ljava/io/File;", "Ljava/io/InputStream;",
        "[B", "[I", "Ljava/lang/Class;", "Ljava/lang/Throwable;"
    };

    /** Fake variable names that look like decompiler output. */
    private static final String[] FAKE_NAMES = {
        "a", "b", "c", "d", "e", "f", "g", "h", "i", "j",
        "k", "l", "m", "n", "o", "p", "var1", "var2", "var3",
        "tmp", "result", "buf", "str", "val", "obj", "arg"
    };

    private final ClassGraph graph;
    private final ProtectionConfig cfg;

    public DebugInfoForger(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void apply() {
        if (!cfg.isFakeDebugInfo()) return;
        int injected = 0;
        for (ClassNode cn : graph.getClasses().values()) {
            if (!cfg.shouldProtectClass(cn.name)) continue;
            if (cn.name.startsWith("com/kbox/runtime/")) continue;
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null || mn.instructions.size() == 0) continue;
                // Strip any real debug info first.
                mn.localVariables = null;
                mn.visibleLocalVariableAnnotations = null;
                mn.invisibleLocalVariableAnnotations = null;
                // Inject fake info.
                mn.localVariables = forgeVariables(mn);
                injected++;
            }
        }
        KBoxLog.info(TAG, "Forged debug info for " + injected + " methods");
    }

    private List<LocalVariableNode> forgeVariables(MethodNode mn) {
        // Count real local slots from the descriptor.
        int slotCount = countParamSlots(mn.desc);
        if ((mn.access & Opcodes.ACC_STATIC) == 0) slotCount++; // this

        java.util.ArrayList<LocalVariableNode> vars = new java.util.ArrayList<>();
        // Create fake entries for each slot up to maxLocals, and a few extra.
        int fakeSlots = Math.max(slotCount, Math.min(mn.maxLocals, 8));
        for (int slot = 0; slot < fakeSlots; slot++) {
            String name = FAKE_NAMES[RNG.nextInt(FAKE_NAMES.length)];
            String desc = FAKE_TYPES[RNG.nextInt(FAKE_TYPES.length)];
            // Use a start label at the beginning of the method and end at the end.
            LabelNode start = new LabelNode();
            LabelNode end = new LabelNode();
            if (mn.instructions.size() > 0) {
                org.objectweb.asm.tree.AbstractInsnNode first = mn.instructions.getFirst();
                if (first != null && first.getPrevious() != null) {
                    mn.instructions.insertBefore(first, start);
                } else {
                    mn.instructions.insert(start);
                }
                mn.instructions.add(end);
            } else {
                mn.instructions.add(start);
                mn.instructions.add(end);
            }
            vars.add(new LocalVariableNode(name, desc, null, start, end, slot));
        }
        return vars;
    }

    private static int countParamSlots(String desc) {
        int slots = 0;
        int i = 1; // skip '('
        while (desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'J' || c == 'D') {
                slots += 2;
                i++;
            } else if (c == 'L') {
                slots++;
                i = desc.indexOf(';', i) + 1;
            } else if (c == '[') {
                i++;
            } else {
                slots++;
                i++;
            }
        }
        return slots;
    }
}