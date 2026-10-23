package com.kbox.core.sedvx;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * SED-VX part B: Critical Slice selection.
 *
 * <p>Ranks the atlas' methods into a protection order instead of protecting
 * everything uniformly. A slice is a method that either carries semantic
 * evidence itself (depth 0) or sits within {@code depth <= maxDepth} call hops
 * of one — i.e. the decision boundary and its immediate data/control
 * neighbours, which is what an analyst has to associate to rebuild the rule.
 *
 * <p>Framework-constrained methods (reflection, indy, class initialisers,
 * access bridges) are kept in the report but excluded from rewriting: the
 * SED-VX design explicitly prefers "degrade or leave untouched" over risky
 * rewrites near language boundaries.
 */
public final class CriticalSlicer {

    private CriticalSlicer() {}

    public static List<SemanticAtlas.MethodInfo> select(SemanticAtlas atlas, int maxSlices, int maxDepth) {
        List<SemanticAtlas.MethodInfo> all = new ArrayList<>();
        for (SemanticAtlas.MethodInfo mi : atlas.methods().values()) {
            if (mi.depth <= maxDepth) all.add(mi);
        }
        all.sort(Comparator
                // evidence-bearing methods first, then by depth, then by evidence
                .comparingInt((SemanticAtlas.MethodInfo m) -> m.sensitive() ? 0 : 1)
                .thenComparingInt(m -> m.depth)
                .thenComparingInt(m -> -m.evidence.size())
                .thenComparing(m -> m.key()));
        if (all.size() > maxSlices) all = new ArrayList<>(all.subList(0, maxSlices));
        return Collections.unmodifiableList(all);
    }

    /** Slices that may safely be rewritten (no framework constraint). */
    public static List<SemanticAtlas.MethodInfo> rewriteable(List<SemanticAtlas.MethodInfo> slices) {
        List<SemanticAtlas.MethodInfo> out = new ArrayList<>();
        for (SemanticAtlas.MethodInfo mi : slices) {
            if (!mi.constrained && !mi.name.startsWith("<")) out.add(mi);
        }
        return out;
    }
}
