package com.kbox.runtime;

import java.io.InputStream;
import java.lang.reflect.Method;

/**
 * Boot-time launcher that takes the place of the application {@code Main-Class}
 * in the protected jar's manifest.
 *
 * <p>At startup it:
 * <ol>
 *   <li>Reads {@code META-INF/kbox/resources.map} (encrypted) and
 *       {@code META-INF/kbox/resource-guard.bin} (the AES-256 seed) from the
 *       classpath.</li>
 *   <li>Constructs a {@link ResourceGuardClassLoader}, loads the mapping
 *       (decrypted with the seed) and installs it on the current thread's
 *       context class loader so frameworks that use
 *       {@code Thread.currentThread().getContextClassLoader().getResource(...)}
 *       (Spring, Jackson, etc.) pick it up transparently.</li>
 *   <li>Reflectively invokes the original {@code main(String[])} of the
 *       application's real Main-Class, whose name is stored in the
 *       {@code Original-Main-Class} manifest attribute.</li>
 * </ol>
 *
 * <p>This is intentionally minimal: it does <strong>not</strong> replace the
 * system class loader. When class-body encryption (Anti-Dump) is enabled,
 * the guard class loader overrides {@code loadClass} for encrypted classes
 * only; non-encrypted classes delegate to the parent as usual. Resource
 * lookup is always transparently remapped when resource obfuscation is on.
 */
public final class ResourceGuardLauncher {

    private static final String MAP_PATH = "META-INF/kbox/resources.map";
    private static final String SEED_PATH = "META-INF/kbox/resource-guard.bin";
    private static final String CLASS_SEED_PATH = "META-INF/kbox/class-seed.bin";
    private static final String ENCRYPTED_CLASSES_PATH = "META-INF/kbox/encrypted-classes.list";
    private static final String JNIC_CLASSES_PATH = "META-INF/kbox/jnic-classes.list";
    private static final String PARENT_DELEGATE_PATH = "META-INF/kbox/parent-delegate.list";
    /** Manifest attribute that carries the real main class (dotted FQN). */
    public static final String ORIGINAL_MAIN_CLASS_ATTR = "Original-Main-Class";

    public static void main(String[] args) throws Exception {
        ClassLoader sys = ResourceGuardLauncher.class.getClassLoader();

        // 0. Anti-debug canary (silent — corrupts results on detection).
        AntiDebug.check();
        // 0b. Integrity check (silent — corrupts results on tamper).
        IntegrityChecker.check();

        // 1. Read resource seed (may be null when resource obfuscation is off).
        byte[] seed = readResource(sys, SEED_PATH);

        // 1b. Read class encryption seed and encrypted-class list (Anti-Dump).
        byte[] classSeed = readResource(sys, CLASS_SEED_PATH);
        java.util.Set<String> encryptedClassNames = readEncryptedClassList(sys);

        // 1c. License gate: if the jar carries a (masked) license public key, verify
        //     the license NOW so appSecretValid is set before any class is decrypted.
        //     A missing/invalid license yields a random appKey -> class decrypt = noise
        //     (no clean boot, no single flag to patch). Silent; never throws.
        try {
            java.io.InputStream licPub = sys.getResourceAsStream("META-INF/kbox/lic.pub");
            if (licPub != null) {
                licPub.close();
                com.kbox.runtime.LicVerifier.verify();
            }
        } catch (Throwable ignored) {
        }

        if (seed == null && classSeed == null) {
            // Neither resource nor class encryption; fall through to plain launch.
            launchOriginal(sys, args, null);
            return;
        }

        // 1a. Pre-load the native DLL BEFORE the guard loader is created.
        // This ensures the DLL is loaded by the system classloader, making
        // JNI-named exports globally visible even to classes defined by
        // the ResourceGuardClassLoader. Uses reflection so it is a no-op when
        // JNIC is disabled (NativeLoader only injected into JNIC-protected jars).
        preloadNativeLib(sys);

        // 1b. Pre-load JNIC classes via the system classloader BEFORE the
        // guard loader intercepts. This avoids the jvm.dll crash that occurs
        // when the guard loader tries to resolve native methods via parent.
        java.util.Set<String> jnicClassNames = readJnicClassList(sys);
        if (jnicClassNames != null) {
            for (String cn : jnicClassNames) {
                String dotted = cn.replace('/', '.');
                try {
                    Class.forName(dotted, true, sys);
                } catch (Throwable t) {
                    System.err.println("[KBOX-NATIVE] Pre-load JNIC class failed: " + dotted + " - " + t);
                }
            }
        }
        byte[] loaderSeed = seed != null ? seed : new byte[32];
        ResourceGuardClassLoader guard = new ResourceGuardClassLoader(sys, loaderSeed);

        // 3. Decrypt the resource mapping and load it.
        if (seed != null) {
            byte[] map = readResource(sys, MAP_PATH);
            if (map != null) {
                map = decryptMap(map, seed);
                if (map != null) guard.loadMapping(map);
            }
        }

        // 3b. Configure class decryption if class encryption is enabled.
        if (classSeed != null && encryptedClassNames != null) {
            guard.setClassDecryption(classSeed, encryptedClassNames);
        }

        // 3c. Configure JNIC class list from build-time metadata (already read above).
        if (jnicClassNames != null) {
            guard.setJnicClasses(jnicClassNames);
        }

        // 3d. Configure parent-delegated library classes (single-loader ASM/lib).
        java.util.Set<String> parentDelegate = readNameList(sys, PARENT_DELEGATE_PATH);
        if (parentDelegate != null) {
            guard.setParentDelegate(parentDelegate);
        }

        // 4. Make this the context class loader so frameworks pick it up.
        Thread.currentThread().setContextClassLoader(guard);

        // 5. Invoke the real main method.
        launchOriginal(guard, args, guard);
    }

    /** Reads the encrypted-classes list from the classpath. Returns null if absent. */
    private static java.util.Set<String> readEncryptedClassList(ClassLoader loader) {
        try (InputStream in = loader.getResourceAsStream(ENCRYPTED_CLASSES_PATH)) {
            if (in == null) return null;
            byte[] data = readAll(in);
            String text = new String(data, java.nio.charset.StandardCharsets.UTF_8);
            java.util.Set<String> set = new java.util.HashSet<>();
            for (String line : text.split("\n")) {
                line = line.trim();
                if (!line.isEmpty()) set.add(line);
            }
            return set;
        } catch (Exception e) {
            return null;
        }
    }

    /** Reads the JNIC-classes list from the classpath. Returns null if absent. */
    private static java.util.Set<String> readJnicClassList(ClassLoader loader) {
        return readNameList(loader, JNIC_CLASSES_PATH);
    }

    /** Reads a newline-separated internal-name list resource. Returns null if absent. */
    private static java.util.Set<String> readNameList(ClassLoader loader, String path) {
        try (InputStream in = loader.getResourceAsStream(path)) {
            if (in == null) return null;
            byte[] data = readAll(in);
            String text = new String(data, java.nio.charset.StandardCharsets.UTF_8);
            java.util.Set<String> set = new java.util.HashSet<>();
            for (String line : text.split("\n")) {
                line = line.trim();
                if (!line.isEmpty()) set.add(line);
            }
            return set;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Tries to load the packed native blob early so JNI_OnLoad can
     * successfully FindClass+RegisterNatives through the parent loader.
     * If the blob is absent (JNIC disabled) this is a no-op.
     */
    private static void preloadNativeLib(ClassLoader sys) {
        // Only pre-load when the jar actually ships a native blob. Products
        // whose JNIC auto-selection found no eligible methods have no
        // META-INF/kbox/native.bin; NativeLoader.load() would otherwise fail
        // loudly (stderr noise) for no benefit.
        try (InputStream in = sys.getResourceAsStream("META-INF/kbox/native.bin")) {
            if (in == null) return;
        } catch (Exception e) {
            return;
        }
        try {
            // NativeLoader.load() is idempotent (synchronized+loaded flag).
            // We call it here, before any encrypted / guard-loaded classes
            // exist, so JNI_OnLoad's FindClass runs against the system
            // classloader.
            Class<?> nl = Class.forName("com.kbox.runtime.NativeLoader", true, sys);
            java.lang.reflect.Method load = nl.getDeclaredMethod("load");
            load.invoke(null);
        } catch (ClassNotFoundException ignored) {
            // JNIC not enabled — nothing to do.
        } catch (Exception e) {
            System.err.println("[KBOX-NATIVE] Early load failed: " + e.getMessage());
        }
    }

    private static void launchOriginal(ClassLoader loader, String[] args, ResourceGuardClassLoader guard) throws Exception {
        String mainClass = readOriginalMainClass(loader);
        if (mainClass == null) {
            System.err.println("[KBox] No Original-Main-Class in manifest; cannot launch.");
            System.exit(2);
            return;
        }
        Class<?> cls = Class.forName(mainClass, false, loader);
        Method m = cls.getMethod("main", String[].class);
        m.setAccessible(true);
        m.invoke(null, (Object) args);
    }

    /** Reads {@code Original-Main-Class} from META-INF/MANIFEST.MF via the loader.
     *  When the packager obfuscated the entry point ({@code Entry-Guard-Seed} present),
     *  the value is an XOR-masked base64 token which is un-masked here. Any failure
     *  falls back to treating the value as plaintext so a mismatched key can never
     *  hard-block launch. */
    private static String readOriginalMainClass(ClassLoader loader) {
        try (InputStream in = loader.getResourceAsStream("META-INF/MANIFEST.MF")) {
            if (in == null) return null;
            byte[] data = readAll(in);
            String text = new String(data, java.nio.charset.StandardCharsets.UTF_8);
            String value = null;
            String seedB64 = null;
            // Manifest attributes are ASCII keys; find ours.
            for (String line : text.split("\r?\n")) {
                int idx = line.indexOf(":");
                if (idx < 0) continue;
                String key = line.substring(0, idx).trim();
                String val = line.substring(idx + 1).trim();
                if (ORIGINAL_MAIN_CLASS_ATTR.equals(key)) value = val;
                else if ("Entry-Guard-Seed".equals(key)) seedB64 = val;
            }
            if (value == null || value.isEmpty()) return null;
            if (seedB64 != null && value.startsWith("KBOX:")) value = value.substring(5);
            if (seedB64 != null) {
                try {
                    byte[] seed = java.util.Base64.getDecoder().decode(seedB64);
                    byte[] masked = java.util.Base64.getDecoder().decode(value.trim());
                    return new String(entryNameCodec(masked, seed),
                            java.nio.charset.StandardCharsets.UTF_8);
                } catch (Throwable t) {
                    // Corrupt/mismatched mask -> fall back to the raw value.
                    return value;
                }
            }
            return value;
        } catch (Exception ignore) {}
        return null;
    }

    /** Mirrors {@code Packager.entryNameCodec}: symmetric XOR keystream (see its javadoc). */
    private static byte[] entryNameCodec(byte[] in, byte[] seed) {
        byte[] out = new byte[in.length];
        long s = 0x6A09E667F3BCC909L;
        for (byte b : seed) s = ((s ^ (b & 0xFF)) * 0x100000001B3L);
        for (int i = 0; i < in.length; i++) {
            s ^= s >>> 12; s ^= s << 25; s ^= s >>> 27;
            s *= 0x2545F4914F6CDD1DL;
            out[i] = (byte) (in[i] ^ (byte) (s >>> 32));
        }
        return out;
    }

    /**
     * The map file is itself encrypted with the same AES-GCM scheme used for
     * resource bodies (magic 'K' + IV + ciphertext+tag), to prevent trivial
     * enumeration of which names map to which.
     */
    private static byte[] decryptMap(byte[] blob, byte[] seed) {
        try {
            if (blob == null || blob.length < 14) return blob;
            if (blob[0] != (byte) 0x4B) return blob;
            byte[] iv = new byte[12];
            System.arraycopy(blob, 1, iv, 0, 12);
            byte[] ct = new byte[blob.length - 13];
            System.arraycopy(blob, 13, ct, 0, ct.length);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] key = md.digest(seed);
            javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            c.init(javax.crypto.Cipher.DECRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            return c.doFinal(ct);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readResource(ClassLoader loader, String path) {
        try (InputStream in = loader.getResourceAsStream(path)) {
            if (in == null) return null;
            return readAll(in);
        } catch (Exception e) {
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }
}
