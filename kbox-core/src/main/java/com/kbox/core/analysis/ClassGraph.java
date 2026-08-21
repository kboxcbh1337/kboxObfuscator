package com.kbox.core.analysis;

import org.objectweb.asm.tree.ClassNode;

import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * In-memory representation of every class read from the input jar plus the
 * graph of references between them. Kept as plain data structures so each
 * transformation pass can mutate or query it without re-reading the jar.
 */
public final class ClassGraph {

    /** internal name -> parsed ClassNode (never null once loaded). */
    private final Map<String, ClassNode> classes = new HashMap<>();

    /** internal name -> set of classes it references (inheritance + field/method use). */
    private final Map<String, Set<String>> references = new HashMap<>();

    /** Reverse: internal name -> set of classes that reference it. */
    private final Map<String, Set<String>> referencedBy = new HashMap<>();

    /** Members that must be preserved (entry points, reflection targets, SPI, etc.). */
    private final Set<MemberRef> keepSet = new LinkedHashSet<>();

    /** Original raw bytes per class (used for class encryption / unchanged pass-through). */
    private final Map<String, byte[]> originalBytes = new HashMap<>();

    /** Non-class resources (META-INF/services, spring.factories, etc.) keyed by jar path. */
    private final Map<String, byte[]> resources = new HashMap<>();

    /** Manifest bytes (kept separate for ManifestUpdater). */
    private byte[] manifest;

    /** Original main-class from manifest (Spring Boot executable jars have their own layout). */
    private String manifestMainClass;

    /** True if input was a Spring Boot fat jar (BOOT-INF/classes + BOOT-INF/lib). */
    private boolean springBootFatJar;

    /** Classes whose instruction stream was modified by control-flow transforms
     *  (obfuscation, anti-decompiler, exception-jump, etc.). Their StackMapTable
     *  frames are stale and need COMPUTE_FRAMES recomputation during packaging.
     *  Non-CF classes (only ClassRemapper) keep their existing frames. */
    private final Set<String> cfModifiedClasses = new java.util.HashSet<>();

    public Map<String, ClassNode> getClasses() { return classes; }
    public Map<String, Set<String>> getReferences() { return references; }
    public Map<String, Set<String>> getReferencedBy() { return referencedBy; }
    public Set<MemberRef> getKeepSet() { return keepSet; }
    public Map<String, byte[]> getOriginalBytes() { return originalBytes; }
    public Map<String, byte[]> getResources() { return resources; }
    public byte[] getManifest() { return manifest; }
    public void setManifest(byte[] manifest) { this.manifest = manifest; }
    public String getManifestMainClass() { return manifestMainClass; }
    public void setManifestMainClass(String c) { this.manifestMainClass = c; }
    public boolean isSpringBootFatJar() { return springBootFatJar; }
    public void setSpringBootFatJar(boolean v) { springBootFatJar = v; }

    /** Mark a class as having its instruction stream modified by CF transforms. */
    public void markCfModified(String internalName) { cfModifiedClasses.add(internalName); }

    public boolean isCfModified(String internalName) { return cfModifiedClasses.contains(internalName); }

    public Set<String> getCfModifiedClasses() { return cfModifiedClasses; }

    public void addClass(String internal, ClassNode node, byte[] bytes) {
        classes.put(internal, node);
        originalBytes.put(internal, bytes);
    }

    public void addReference(String from, String to) {
        if (from == null || to == null || from.equals(to)) return;
        references.computeIfAbsent(from, k -> new LinkedHashSet<>()).add(to);
        referencedBy.computeIfAbsent(to, k -> new LinkedHashSet<>()).add(from);
    }

    public void keep(MemberRef ref) { keepSet.add(ref); }

    /** Recursive closure: every class reachable from {@code root} (transitive). */
    public Set<String> reachableFrom(String root) {
        Set<String> seen = new LinkedHashSet<>();
        java.util.ArrayDeque<String> q = new java.util.ArrayDeque<>();
        q.add(root);
        while (!q.isEmpty()) {
            String c = q.poll();
            if (!seen.add(c)) continue;
            Set<String> next = references.get(c);
            if (next != null) q.addAll(next);
        }
        return seen;
    }
}
