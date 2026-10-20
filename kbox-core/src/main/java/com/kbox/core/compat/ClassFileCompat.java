package com.kbox.core.compat;

import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.tree.ClassNode;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Class-file version compatibility for Java 8 through Java 27 (major 52..71),
 * plus forward compatibility with newer class files.
 *
 * <p>The bundled ASM knows class-file versions up to {@link #MAX_MAJOR}
 * (Java 27). Every {@code ClassReader} in the tool goes through this helper so:
 * <ul>
 *   <li>the original major version is <b>restored</b> on the parsed
 *       {@link ClassNode} — transforms never silently downgrade a Java 25 class
 *       to Java 8, which would change the verifier's rules on the output;</li>
 *   <li>a class file newer than ASM's ceiling is still parsed: the header's
 *       major version is temporarily masked to {@link #MAX_MAJOR} for parsing,
 *       then restored on the node so the writer emits the original version.
 *       This works for genuinely additive releases (new attributes are either
 *       known to ASM or structurally skippable); a class that introduces a new
 *       constant-pool tag still fails, and the caller's per-class rollback
 *       keeps the original bytes.</li>
 * </ul>
 */
public final class ClassFileCompat {

    /** Java 1.1. */
    public static final int MIN_MAJOR = 45;
    /** Java 27 — highest class-file major the bundled ASM understands. */
    public static final int MAX_MAJOR = 71;

    private static final AtomicBoolean MASK_WARNED = new AtomicBoolean();

    private ClassFileCompat() {}

    /** Class-file major version, or -1 when {@code b} is not a class file. */
    public static int major(byte[] b) {
        if (b == null || b.length < 8) return -1;
        if ((b[0] & 0xFF) != 0xCA || (b[1] & 0xFF) != 0xFE
                || (b[2] & 0xFF) != 0xBA || (b[3] & 0xFF) != 0xBE) return -1;
        return ((b[6] & 0xFF) << 8) | (b[7] & 0xFF);
    }

    /** Human-readable Java feature release for a class-file major. */
    public static String javaName(int major) {
        return major < MIN_MAJOR ? "pre-Java" : "Java " + (major - 44);
    }

    public static boolean isSupported(int major) {
        return major >= MIN_MAJOR && major <= MAX_MAJOR;
    }

    /**
     * Returns a {@link ClassReader} for {@code bytes}, masking the header when
     * the class file is newer than the bundled ASM can recognise.
     */
    public static ClassReader reader(byte[] bytes) {
        int maj = major(bytes);
        if (maj > MAX_MAJOR) {
            if (MASK_WARNED.compareAndSet(false, true)) {
                KBoxLog.info("classfile", "Parsing " + javaName(maj) + " class (major " + maj
                        + ") with a forward-compatible header mask (ASM ceiling: "
                        + javaName(MAX_MAJOR) + "). Output keeps the original version.");
            }
            byte[] masked = bytes.clone();
            masked[6] = (byte) (MAX_MAJOR >>> 8);
            masked[7] = (byte) MAX_MAJOR;
            return new ClassReader(masked);
        }
        return new ClassReader(bytes);
    }

    /** Parses {@code bytes} into {@code cn}, preserving the original major version. */
    public static void accept(byte[] bytes, ClassNode cn, int flags) {
        int maj = major(bytes);
        reader(bytes).accept(cn, flags);
        if (maj > 0) cn.version = maj;
    }

    /** Parses {@code bytes} into a fresh {@link ClassNode} (frames expanded). */
    public static ClassNode read(byte[] bytes) {
        return read(bytes, ClassReader.EXPAND_FRAMES);
    }

    /** Parses {@code bytes} into a fresh {@link ClassNode} with the given flags. */
    public static ClassNode read(byte[] bytes, int flags) {
        ClassNode cn = new ClassNode();
        accept(bytes, cn, flags);
        return cn;
    }
}
