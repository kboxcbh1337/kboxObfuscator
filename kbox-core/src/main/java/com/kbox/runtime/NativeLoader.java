package com.kbox.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.zip.Inflater;

/**
 * Runtime loader for the compressed+encrypted native library. The JNIC pipeline
 * writes the packed blob to {@code META-INF/kbox/native.bin} (see
 * {@link com.kbox.core.jnic.NativePacker}); this class reads it, decrypts with
 * ChaCha20, decompresses with {@link Inflater}, writes the resulting shared
 * library to a temp file and calls {@link System#load(String)}.
 *
 * <p>This replaces {@link System#loadLibrary(String)} for JNIC-protected jars so
 * the native library is never stored in plaintext inside the jar (the
 * {@code .dll}/{@code .so}/{@code .dylib} is recovered at runtime only).
 *
 * <p>The temp file is marked delete-on-exit; on Windows the loaded DLL cannot be
 * deleted while the JVM holds it, so we leave it in the temp dir (it is
 * unreadable binary once the JVM exits and the OS reaps the handle).
 */
public final class NativeLoader {

    private static final String BLOB_PATH = "META-INF/kbox/native.bin";
    private static final byte[] MAGIC = {'K', 'B', 'N', 'L'};

    private NativeLoader() {}

    private static volatile boolean loaded = false;
    /**
     * Guard against re-entrant {@link #load()} calls triggered through
     * {@code JNI_OnLoad → FindClass → <clinit> → NativeLoader.load()}.
     */
    private static volatile boolean initializing = false;

    /** Loads the native library exactly once. Safe to call from multiple <clinit>. */
    public static synchronized void load() {
        if (loaded) return;
        if (initializing) return; // Already in the process of loading (re-entrant call from bcInit via JNI_OnLoad)
        initializing = true;
        ClassLoader cl = NativeLoader.class.getClassLoader();
        byte[] blob;
        try (InputStream in = cl.getResourceAsStream(BLOB_PATH)) {
            if (in == null) {
                System.err.println("[KBOX-NATIVE] Blob not found in JAR: " + BLOB_PATH);
                throw new UnsatisfiedLinkError("KBox native blob not found: " + BLOB_PATH);
            }
            blob = readAll(in);
        } catch (IOException e) {
            System.err.println("[KBOX-NATIVE] Load failed: " + e.getMessage());
            e.printStackTrace();
            throw new UnsatisfiedLinkError("KBox native blob read failed: " + e);
        }
        byte[] lib = unpack(blob);
        Path tmp = writeToTemp(lib);
        if (System.getProperty("kbox.vmp.dbg") != null)
            System.err.println("[KBOX-NATIVE] Loading DLL: " + tmp.toAbsolutePath()
                    + " (" + lib.length + " bytes)");
        System.load(tmp.toAbsolutePath().toString());
        if (System.getProperty("kbox.vmp.dbg") != null)
            System.err.println("[KBOX-NATIVE] DLL loaded OK");
        loaded = true;
        initializing = false;
    }

    /**
     * Registers native methods for the given JNIC class, bypassing JNI_OnLoad's
     * FindClass which may fail with custom ClassLoaders. Called from
     * ResourceGuardClassLoader.loadNativeLibOnce() after the DLL is loaded and
     * the JNIC class has been loaded by the parent ClassLoader.
     */
    public static native void registerNatives0(Class<?> targetClass);

    /** Decrypts (ChaCha20) + decompresses (Inflater) the packed blob. */
    private static byte[] unpack(byte[] blob) {
        if (blob.length < 64
                || blob[0] != MAGIC[0] || blob[1] != MAGIC[1]
                || blob[2] != MAGIC[2] || blob[3] != MAGIC[3]) {
            throw new UnsatisfiedLinkError("KBox native blob: bad magic");
        }
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
        System.arraycopy(blob, 4, key, 0, 32);
        System.arraycopy(blob, 36, nonce, 0, 12);
        // counter (8 bytes) at offset 48 — always 0 for the first block.
        int compLen = readIntLE(blob, 56);
        int rawLen = readIntLE(blob, 60);
        byte[] cipher = new byte[compLen];
        System.arraycopy(blob, 64, cipher, 0, compLen);
        byte[] compressed = ChaCha20.process(key, nonce, 0L, cipher);
        if (compressed.length != compLen) {
            throw new UnsatisfiedLinkError("KBox native: length mismatch after decrypt");
        }
        try {
            return inflate(compressed, rawLen);
        } catch (Exception e) {
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

    private static Path writeToTemp(byte[] lib) {
        try {
            String os = System.getProperty("os.name", "").toLowerCase();
            String ext = os.contains("win") ? ".dll"
                    : (os.contains("mac") || os.contains("darwin")) ? ".dylib" : ".so";
            Path tmp = Files.createTempFile("kbox-native-", ext);
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
