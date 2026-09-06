package com.kbox.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.zip.Inflater;

/**
 * Runtime loader for the compressed+encrypted native library. The JNIC pipeline
 * writes the packed blob to {@code META-INF/kbox/native.bin} (see
 * {@link com.kbox.core.jnic.NativePacker}); this class reads it, derives the
 * ChaCha20 key at runtime (never embedded in plaintext), decompresses with
 * {@link Inflater}, writes the resulting shared library to a temp file and calls
 * {@link System#load(String)}, then immediately purges the temp file from disk.
 *
 * <p>This replaces {@link System#loadLibrary(String)} for JNIC-protected jars so
 * the native library is never stored in plaintext inside the jar. The decrypted
 * PE is only ever written to disk long enough to be mapped by the OS loader, and
 * is deleted from the directory immediately afterwards (Windows image mappings
 * remain valid after the directory entry is removed).
 */
public final class NativeLoader {

    private static final String _BP1 = "META-INF/kbox/native.bin";
    private static final String _BP2 = "META-INF/kbox/jnic.bin";
    private static final String _BP3 = "META-INF/kbox/vmp.bin";

    private NativeLoader() {}

    private static volatile boolean _L1 = false;
    private static volatile boolean _L2 = false;
    private static volatile boolean _L3 = false;
    private static volatile boolean _L4 = false;

    /**
     * Loads the JNIC native library from {@code META-INF/kbox/jnic.bin} (a path
     * distinct from the resident {@code native.bin}, which in Brainfuck mode
     * holds the {BF-safe} decoder). Returns true if a blob was present and
     * loaded. Safe to call multiple times.
     */
    public static synchronized boolean loadJnic() {
        if (_L2) return true;
        ClassLoader cl = NativeLoader.class.getClassLoader();
        byte[] blob;
        try (InputStream in = cl.getResourceAsStream(_BP2)) {
            if (in == null) return false; // JNIC not enabled in this jar.
            blob = readAll(in);
        } catch (IOException e) {
            throw new UnsatisfiedLinkError("KBox JNIC blob read failed: " + e);
        }
        byte[] lib = unpack(blob);
        // In-memory mapping on Windows never writes the decrypted PE to disk;
        // fall back to writeToTemp+System.load+purge when unavailable.
        if (!mapInMemory(lib, "Java_com_kbox_runtime_NativeLoader_registerNatives0")) {
            Path tmp = writeToTemp(lib);
            try {
                System.load(tmp.toAbsolutePath().toString());
            } finally {
                purgeTemp(tmp);
            }
        }
        _L2 = true;
        return true;
    }

    /**
     * Loads the optional native VMP interpreter library from
     * {@code META-INF/kbox/vmp.bin} (shipped only when the pipeline compiles the
     * {@code kbox_vmp_core.c} interpreter). The JNI symbol {@code executeNative} on
     * {@link com.kbox.runtime.VmpInterpreterNative} resolves lazily on first call, so
     * this needs only {@link System#load}. Returns true if a blob was present and
     * loaded. Safe to call multiple times.
     */
    public static synchronized boolean loadVmp() {
        if (_L3) return true;
        ClassLoader cl = NativeLoader.class.getClassLoader();
        byte[] blob;
        try (InputStream in = cl.getResourceAsStream(_BP3)) {
            if (in == null) {
                return false;       // VM原生化 not compiled for this jar.
            }
            blob = readAll(in);
        } catch (IOException e) {
            throw new UnsatisfiedLinkError("KBox VMP blob read failed: " + e);
        }
        byte[] lib = unpack(blob);
        // In-memory mapping on Windows never writes the decrypted PE to disk;
        // fall back to writeToTemp+System.load+purge when unavailable.
        if (!mapInMemory(lib, "Java_com_kbox_runtime_NativeLoader_registerVmpNatives0")) {
            Path tmp = writeToTemp(lib);
            try {
                System.load(tmp.toAbsolutePath().toString());
            } finally {
                purgeTemp(tmp);
            }
        }
        _L3 = true;
        return true;
    }

    /** Loads the native library exactly once. Safe to call from multiple <clinit>. */
    public static synchronized void load() {
        if (_L1) return;
        if (_L4) return; // Already in the process of loading (re-entrant call from bcInit via JNI_OnLoad)
        _L4 = true;
        ClassLoader cl = NativeLoader.class.getClassLoader();
        byte[] blob;
        try (InputStream in = cl.getResourceAsStream(_BP1)) {
            if (in == null) {
                System.err.println("[KBOX-NATIVE] Blob not found in JAR: " + _BP1);
                throw new UnsatisfiedLinkError("KBox native blob not found: " + _BP1);
            }
            blob = readAll(in);
        } catch (IOException e) {
            System.err.println("[KBOX-NATIVE] Load failed: " + e.getMessage());
            e.printStackTrace();
            throw new UnsatisfiedLinkError("KBox native blob read failed: " + e);
        }
        byte[] lib = unpack(blob);
        Path tmp = writeToTemp(lib);
        try {
            System.load(tmp.toAbsolutePath().toString());
            // The resident decoder is the in-memory mapper, so it cannot map
            // itself from memory; the OS loader keeps the image mapped. Windows
            // refuses to delete a mapped image, so purgeSelf renames the module
            // to a random hidden name (removing the predictable temp entry) and
            // returns the renamed path for Java to purge once the module is
            // unloaded at exit.
            // BfSecureLoader exists only in Brainfuck-mode products; non-BF
            // products (e.g. JNIC-only) must not hard-depend on it.
            try {
                Class<?> bf = Class.forName("com.kbox.runtime.BfSecureLoader");
                java.lang.reflect.Method m = bf.getMethod("purgeSelf", String.class);
                String stillThere = (String) m.invoke(null, tmp.toAbsolutePath().toString());
                if (stillThere != null) {
                    nukeTemp(Paths.get(stillThere));   // zero-fill the renamed hidden PE best-effort
                    schedulePurge(Paths.get(stillThere));
                }
            } catch (Throwable noBf) {
                // Brainfuck loader not present in this product — nothing to purge.
            }
        } finally {
            purgeTemp(tmp);
        }
        _L1 = true;
        _L4 = false;
    }

    /** Registers native methods for the given JNIC class, bypassing JNI_OnLoad's
     * FindClass which may fail with custom ClassLoaders. Called from
     * ResourceGuardClassLoader.loadNativeLibOnce() after the DLL is loaded and
     * the JNIC class has been loaded by the parent ClassLoader.
     */
    public static native void registerNatives0(Class<?> targetClass);

    /** Registers {@code VmpInterpreterNative.execute} (exported by the VMP DLL,
     * {@code kbox_vmp_core.c}) onto the given class object. The VMP interpreter
     * is defined inside the {@code BfSecureLoader} blob (a child ClassLoader), so
     * automatic symbol resolution cannot find the DLL it loads via
     * {@link #loadVmp()}; RegisterNatives with the concrete Class binds it anyway.
     * Called by {@code VmpInterpreterNative.tryExecute} after a successful load.
     */
    public static native void registerVmpNatives0(Class<?> targetClass);

    /** Decrypts (ChaCha20) + decompresses (Inflater) the packed blob.
     *  The ChaCha20 key is NOT stored in the blob — it is derived at runtime
     *  from a per-blob salt + the per-build random domain tag read from the
     *  header + the hardware factor ({@link KbnlKey}), so a static scan cannot
     *  pull a clean 32-byte key out of the jar, and one interpreter's key does
     *  not decrypt the others (A1: domain is per-build random, not enumerable). */
    private static byte[] unpack(byte[] blob) {
        if (blob.length < 68 || !KbnlKey.isKbnl(blob, 0)) {
            throw new UnsatisfiedLinkError("KBox native blob: bad magic");
        }
        // Layout: magic[4] | blobSalt[32] | nonce[12] | counter[8] | compLen[4] |
        //   rawLen[4] | domainTag[4] | cipher
        byte[] blobSalt = new byte[32];
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 4, blobSalt, 0, 32);
        System.arraycopy(blob, 36, nonce, 0, 12);
        int compLen = readIntLE(blob, 56);
        int rawLen = readIntLE(blob, 60);
        int domainTag = readIntLE(blob, 64);
        byte[] cipher = new byte[compLen];
        System.arraycopy(blob, 68, cipher, 0, compLen);
        byte[] key = KbnlKey.derive(domainTag, blobSalt);
        byte[] compressed = ChaCha20.process(key, nonce, 0L, cipher);
        if (compressed.length != compLen) {
            KbnlKey.noteBadDecrypt();   // A2: enumeration/wrong-tag burst fuse
            throw new UnsatisfiedLinkError("KBox native: length mismatch after decrypt");
        }
        try {
            byte[] lib = inflate(compressed, rawLen);
            KbnlKey.noteBlobOpened(domainTag);   // A3: bind this blob to the session
            return lib;
        } catch (Exception e) {
            KbnlKey.noteBadDecrypt();   // A2: wrong key → garbage → inflate failure
            throw new UnsatisfiedLinkError("KBox native inflate failed: " + e);
        }
    }

    private static byte[] inflate(byte[] data, int rawLen) throws Exception {
        Inflater inf = new Inflater(true);
        inf.setInput(data);
        byte[] out = new byte[rawLen > 0 ? rawLen : data.length * 4];
        int off = 0;
        while (off < out.length) {
            int n = inf.inflate(out, off, out.length - off);
            if (n == 0) {
                if (inf.finished() || inf.needsDictionary()) break;
                if (inf.needsInput()) {
                    // grow
                    byte[] grown = new byte[out.length * 2];
                    System.arraycopy(out, 0, grown, 0, off);
                    out = grown;
                    continue;
                }
                break;
            }
            off += n;
        }
        inf.end();
        if (off == out.length) return out;
        byte[] trimmed = new byte[off];
        System.arraycopy(out, 0, trimmed, 0, off);
        return trimmed;
    }

    /**
     * Maps a decrypted PE entirely in-memory on Windows via
     * {@link BfSecureLoader#mapModule}, binding its exported registrar onto
     * this class — the plaintext module never touches disk. Returns true only
     * when the module was mapped and its registrar bound; any failure (non-Windows,
     * no resident loader, mapping error) returns false so the caller falls back
     * to the writeToTemp + purge path.
     */
    private static boolean mapInMemory(byte[] lib, String binderName) {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) return false;
        try {
            return BfSecureLoader.mapModule(lib, binderName);
        } catch (Throwable t) {
            return false;   // any failure -> fall back to temp-file path
        }
    }

    /** Immediately removes the temp DLL from the directory after it was mapped.
     *  On Windows the image section keeps the mapped pages valid even once the
     *  directory entry is gone, so callers cannot capture the PE from disk while
     *  the module runs. Non-Windows keeps the delete-on-exit fallback. */
    private static void purgeTemp(Path tmp) {
        nukeTemp(tmp);            // best-effort zero-fill before removal
        try { Files.deleteIfExists(tmp); return; } catch (Exception ignored) {}
    }

    /** Disk-capture closure: overwrites the plaintext PE on disk with zeros
     *  (defeating uncrypted forensic capture/recovery of the laid-on disk
     *  artifact) before the directory entry is deleted or renamed away. This is
     *  best-effort: on Windows a live-mapped image section may refuse write
     *  access (sharing violation) — in that case the caller still removes the
     *  predictable entry via {@code purgeSelf} rename + scheduled delete, so the
     *  plaintext never lingers under a discoverable name. */
    private static void nukeTemp(Path tmp) {
        try {
            long size = Files.size(tmp);
            if (size <= 0) return;
            byte[] zeros = new byte[(int) Math.min(size, 1 << 20)];
            try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(tmp.toFile(), "rw")) {
                long done = 0;
                while (done < size) {
                    int n = (int) Math.min(zeros.length, size - done);
                    raf.write(zeros, 0, n);
                    done += n;
                }
                raf.setLength(0);                 // truncate to 0 bytes after filling
                raf.getFD().sync();               // flush to media, not just page cache
            }
        } catch (Exception ignored) {
            // mapped image (Windows) or transient lock: fall back to delete/rename
        }
    }

    /** Registers delete-on-exit + a background retry thread + a detached helper
     *  process for a path that could only be renamed (not deleted) while its
     *  image stayed mapped. On Windows the OS holds a lock on the loaded DLL
     *  until the process fully exits; neither delete-on-exit nor the in-process
     *  retry thread can remove the file while the JVM holds the DLL. The detached
     *  helper process (ping-delayed delete on Windows; sleep-delayed on POSIX)
     *  survives after the JVM exits, and by the time it runs the OS has released
     *  the file lock. This is the final backstop against PE temp-file residue. */
    private static void schedulePurge(Path p) {
        try { p.toFile().deleteOnExit(); } catch (Exception ignored) {}
        // In-process retry (works on POSIX where mmap doesn't lock the file).
        Thread cleanup = new Thread(() -> {
            for (int i = 0; i < 20; i++) {
                try { Thread.sleep(500); } catch (InterruptedException e) { break; }
                nukeTemp(p);
                try { Files.deleteIfExists(p); return; } catch (Exception ignored) {}
            }
        });
        cleanup.setDaemon(true);
        cleanup.start();
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            nukeTemp(p);
            try { Files.deleteIfExists(p); } catch (Exception ignored) {}
        }));
        // Detached helper: survives JVM exit, deletes after the DLL lock releases.
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            String path = p.toAbsolutePath().toString();
            if (os.contains("win")) {
                // ping -n 4 = ~3s delay, then del. Quoted path for spaces.
                new ProcessBuilder("cmd", "/c",
                        "ping -n 4 127.0.0.1 >nul & del /f /q \"" + path + "\"")
                        .redirectErrorStream(true).start();
            } else {
                // POSIX: sleep 3 then rm.
                new ProcessBuilder("sh", "-c",
                        "sleep 3; rm -f \"" + path + "\"")
                        .redirectErrorStream(true).start();
            }
        } catch (Exception ignored) {}
    }

    private static Path writeToTemp(byte[] lib) {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            String ext = os.contains("win") ? ".dll"
                    : (os.contains("mac") || os.contains("darwin")) ? ".dylib" : ".so";
            // Random non-fingerprintable temp name (no "kbox" prefix).
            String rnd = Long.toHexString(new java.security.SecureRandom().nextLong());
            Path tmp = Files.createTempFile(rnd, ext);
            Files.write(tmp, lib, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING);
            // Mark for delete-on-exit + try immediate delete (Windows: sets
            // DELETE_ON_CLOSE so the file vanishes from directory listings
            // even while loaded).
            tmp.toFile().deleteOnExit();
            // Register a shutdown hook as a best-effort fallback.
            final Path finalTmp = tmp;
            Runtime.getRuntime().addShutdownHook(new Thread(() -> {
                try { Files.deleteIfExists(finalTmp); } catch (Exception ignored) {}
            }));
            return tmp;
        } catch (IOException e) {
            throw new UnsatisfiedLinkError("KBox native temp write failed: " + e);
        }
    }

    private static int readIntLE(byte[] b, int off) {
        return (b[off] & 0xFF) | ((b[off + 1] & 0xFF) << 8)
                | ((b[off + 2] & 0xFF) << 16) | ((b[off + 3] & 0xFF) << 24);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }
}
