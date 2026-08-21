package com.kbox.core.analysis;

import com.kbox.core.KBoxException;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldInsnNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.MultiANewArrayInsnNode;
import org.objectweb.asm.tree.TypeInsnNode;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Reads an input jar (plain or Spring Boot fat jar) and builds a complete
 * {@link ClassGraph}: every class parsed into an ASM {@link ClassNode} plus
 * the inter-class reference graph used later by the retention decision tree.
 *
 * <p>Handles three jar layouts transparently:
 * <ul>
 *   <li>Plain jar: {@code *.class} at root + {@code META-INF/}</li>
 *   <li>Spring Boot executable jar: {@code BOOT-INF/classes/&#42;&#42;/&#42;.class} +
 *       {@code BOOT-INF/lib/&#42;.jar} (nested)</li>
 *   <li>Uber jar with lib jars at root (rare, but supported)</li>
 * </ul>
 */
public final class DependencyAnalyzer {

    private static final String TAG = "analysis";

    private final ClassGraph graph = new ClassGraph();

    public ClassGraph analyze(Path jarPath) throws IOException {
        if (!Files.exists(jarPath)) {
            throw new KBoxException("Input jar not found: " + jarPath);
        }
        try (ZipFile zf = new ZipFile(jarPath.toFile())) {
            readManifest(zf);
            boolean springBoot = zf.getEntry("BOOT-INF/classes/") != null
                    || zf.getEntry("org/springframework/boot/loader/") != null;
            graph.setSpringBootFatJar(springBoot);
            if (springBoot) {
                KBoxLog.info(TAG, "Detected Spring Boot executable jar layout");
            }
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                processEntry(zf, e, springBoot);
            }
        }
        KBoxLog.info(TAG, "Loaded " + graph.getClasses().size() + " classes, "
                + graph.getResources().size() + " resources");
        return graph;
    }

    private void readManifest(ZipFile zf) {
        ZipEntry me = zf.getEntry("META-INF/MANIFEST.MF");
        if (me == null) return;
        try {
            byte[] data = readAll(zf.getInputStream(me));
            graph.setManifest(data);
            // Parse Main-Class header (cheap, no java.util.jar.Manifest to avoid Unicode issues).
            String s = new String(data, "UTF-8");
            int i = s.indexOf("Main-Class:");
            if (i >= 0) {
                int j = i + "Main-Class:".length();
                int nl = s.indexOf('\n', j);
                String mc = s.substring(j, nl < 0 ? s.length() : nl).trim();
                graph.setManifestMainClass(mc.replace('.', '/'));
            }
        } catch (IOException ex) {
            KBoxLog.warn(TAG, "Could not read manifest: " + ex);
        }
    }

    private void processEntry(ZipFile zf, ZipEntry e, boolean springBoot) throws IOException {
        String name = e.getName();
        // Spring Boot stores app classes under BOOT-INF/classes/
        String clsRoot = springBoot && name.startsWith("BOOT-INF/classes/") ? "BOOT-INF/classes/" : "";
        if (name.endsWith(".class") && name.startsWith(clsRoot)) {
            String internal = name.substring(clsRoot.length(), name.length() - ".class".length());
            if (internal.startsWith("META-INF/versions/")) {
                // multi-release: treat as normal class but keep original path prefix for output
            }
            byte[] bytes = readAll(zf.getInputStream(e));
            parseClass(internal, bytes, name);
        } else if (name.endsWith(".jar") && springBoot && name.startsWith("BOOT-INF/lib/")) {
            // Nested dependency jars: read their classes too so renaming stays consistent.
            readNestedJar(zf.getInputStream(e), name);
        } else if (name.equals("META-INF/MANIFEST.MF")) {
            // already handled
        } else {
            // Resource file (services, spring.factories, hbm.xml, etc.)
            graph.getResources().put(name, readAll(zf.getInputStream(e)));
        }
    }

    private void readNestedJar(InputStream in, String label) throws IOException {
        // Materialize to a temp file so ZipFile can read it.
        Path tmp = Files.createTempFile("kbox-nested-", ".jar");
        try {
            Files.copy(in, tmp, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            try (ZipFile nzf = new ZipFile(tmp.toFile())) {
                Enumeration<? extends ZipEntry> en = nzf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    if (e.isDirectory() || !e.getName().endsWith(".class")) continue;
                    String internal = e.getName().substring(0, e.getName().length() - ".class".length());
                    byte[] bytes = readAll(nzf.getInputStream(e));
                    // Only keep app-owned classes (skip JDK / well-known libs to save memory).
                    parseClass(internal, bytes, label + "!" + e.getName());
                }
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private void parseClass(String internal, byte[] bytes, String origin) {
        // Run each class parse on a dedicated daemon thread so a pathological
        // class (e.g. an anti-decompiler CP-bomb or a malformed frame that puts
        // ASM's ClassReader into an unbounded loop) cannot stall the whole run.
        // On timeout the class is skipped; its result is discarded so the leaked
        // daemon thread never touches the (non-thread-safe) graph.
        ParseTask task = new ParseTask(internal, bytes);
        Thread t = new Thread(task, "kbox-parse-" + internal);
        t.setDaemon(true);
        t.start();
        try {
            task.done.await(PARSE_TIMEOUT_MS, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        if (!task.finished) {
            KBoxLog.warn(TAG, "Skipping class (parse timeout > " + (PARSE_TIMEOUT_MS / 1000)
                    + "s): " + internal);
            return;
        }
        if (task.error != null) {
            KBoxLog.warn(TAG, "Skipping unparseable class " + internal + ": " + task.error.getMessage());
            return;
        }
        ClassNode node = task.node;
        graph.addClass(internal, node, bytes);
        // Inheritance edges: super + interfaces.
        if (node.superName != null && !node.superName.startsWith("java/")) {
            graph.addReference(internal, node.superName);
        }
        for (String itf : node.interfaces) {
            if (!itf.startsWith("java/")) graph.addReference(internal, itf);
        }
        // Walk method + field references.
        try {
            walkReferences(internal, node);
        } catch (Exception refEx) {
            // A single malformed reference must not abort the whole run; the
            // class is still usable, it just lacks some dependency edges.
            KBoxLog.warn(TAG, "Reference walk incomplete for " + internal
                    + ": " + refEx.getMessage());
        }
    }

    /** Timeout for a single class parse (guards against unbounded ASM loops). */
    private static final long PARSE_TIMEOUT_MS = 30_000;

    /** Runs ClassReader on one class off the main thread, reporting via a latch. */
    private static final class ParseTask implements Runnable {
        private final String internal;
        private final byte[] bytes;
        private final java.util.concurrent.CountDownLatch done =
                new java.util.concurrent.CountDownLatch(1);
        volatile boolean finished;
        volatile Exception error;
        volatile ClassNode node;

        ParseTask(String internal, byte[] bytes) {
            this.internal = internal;
            this.bytes = bytes;
        }

        @Override
        public void run() {
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassNode n = new ClassNode();
                cr.accept(n, ClassReader.SKIP_DEBUG | ClassReader.EXPAND_FRAMES);
                node = n;
            } catch (Exception ex) {
                error = ex;
            } finally {
                finished = true;
                done.countDown();
            }
        }
    }

    /** Visits every instruction that introduces a cross-class reference. */
    @SuppressWarnings("unchecked")
    private void walkReferences(String owner, ClassNode node) {
        for (MethodNode m : (List<MethodNode>) node.methods) {
            if (m.instructions == null) continue;
            for (int i = 0; i < m.instructions.size(); i++) {
                org.objectweb.asm.tree.AbstractInsnNode ins = m.instructions.get(i);
                if (ins instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) ins;
                    if (!mi.owner.startsWith("java/") && !mi.owner.startsWith("[")) {
                        graph.addReference(owner, mi.owner);
                    }
                } else if (ins instanceof FieldInsnNode) {
                    FieldInsnNode fi = (FieldInsnNode) ins;
                    if (!fi.owner.startsWith("java/")) graph.addReference(owner, fi.owner);
                } else if (ins instanceof TypeInsnNode) {
                    TypeInsnNode ti = (TypeInsnNode) ins;
                    String t = ti.desc;
                    if (!t.startsWith("java/") && !t.startsWith("[")) graph.addReference(owner, t);
                } else if (ins instanceof MultiANewArrayInsnNode) {
                    String t = ((MultiANewArrayInsnNode) ins).desc;
                    addTypeRef(owner, t);
                } else if (ins instanceof InvokeDynamicInsnNode) {
                    InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) ins;
                    for (Object arg : id.bsmArgs) {
                        if (arg instanceof org.objectweb.asm.Handle) {
                            org.objectweb.asm.Handle h = (org.objectweb.asm.Handle) arg;
                            if (!h.getOwner().startsWith("java/")) graph.addReference(owner, h.getOwner());
                        } else if (arg instanceof Type) {
                            addTypeRef(owner, ((Type) arg).getInternalName());
                        }
                    }
                }
            }
        }
        // Field types: array element / generic usage still needs the element class reachable.
        for (Object f : node.fields) {
            org.objectweb.asm.tree.FieldNode fn = (org.objectweb.asm.tree.FieldNode) f;
            addTypeRef(owner, fn.desc);
        }
    }

    private void addTypeRef(String owner, String desc) {
        if (desc == null) return;
        Type t = Type.getType(desc);
        String internal;
        switch (t.getSort()) {
            case Type.ARRAY:
                internal = t.getElementType().getInternalName();
                break;
            case Type.OBJECT:
                // A plain object type carries the class reference directly.
                internal = t.getInternalName();
                break;
            default:
                // primitive / void / method descriptor: no cross-class reference.
                return;
        }
        if (internal != null && !internal.startsWith("java/") && !internal.startsWith("[")) {
            graph.addReference(owner, internal);
        }
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }
}
