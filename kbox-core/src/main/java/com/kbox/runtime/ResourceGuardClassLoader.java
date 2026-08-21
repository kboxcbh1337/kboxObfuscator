package com.kbox.runtime;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Drop-in resource + class resolver installed by {@link ResourceGuardLauncher}.
 *
 * <p>The launcher reads the encrypted {@code META-INF/kbox/resources.map} +
 * {@code resource-guard.bin} at boot time, decrypts them with the AES seed, and
 * hands the resulting {@link ResourceMapping} (originalPath -> {newPath,
 * encrypted}) to this loader. Whenever application code calls
 * {@code ClassLoader.getResource("config/db.properties")} the JVM ultimately
 * dispatches to {@link #findResource(String)} / {@link #getResourceAsStream(String)};
 * we look the original name up in the mapping, fetch the renamed file from the
 * underlying system loader, decrypt it if needed, and return the bytes.
 *
 * <p>When class-body encryption (Anti-Dump) is enabled, this loader also
 * overrides {@link #loadClass(String, boolean)}: for classes listed in the
 * encrypted-classes set, it reads the raw (encrypted) bytes from the jar,
 * decrypts them with the class seed, and calls {@code defineClass} itself
 * rather than delegating to the parent. Non-encrypted classes (including all
 * KBox runtime classes) delegate to the parent as usual.
 */
public final class ResourceGuardClassLoader extends ClassLoader {

    private final ClassLoader delegate;
    private final Map<String, Entry> map = new HashMap<>();
    private final byte[] seed;
    private final Map<String, byte[]> cache = new HashMap<>();

    // Anti-Dump state
    private byte[] classSeed;
    private final Set<String> encryptedClasses = new HashSet<>();

    /** License gate material (SHA-256 of LicVerifier.appKey()) when the jar is licensed; else null. */
    private static final byte[] LIC_MATERIAL = computeLicMaterial();
    private static byte[] computeLicMaterial() {
        try {
            java.io.InputStream in = ResourceGuardClassLoader.class
                    .getResourceAsStream("/META-INF/kbox/lic.pub");
            if (in == null) return null;
            in.close();
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            md.update(LicVerifier.appKey());
            return md.digest();
        } catch (Throwable t) {
            return null;
        }
    }

    // JNIC native class list (populated from META-INF/kbox/jnic-classes.list)
    private final Set<String> jnicClasses = new HashSet<>();

    public static final class Entry {
        public final String newPath;
        public final boolean encrypted;
        public Entry(String newPath, boolean encrypted) {
            this.newPath = newPath;
            this.encrypted = encrypted;
        }
    }

    public ResourceGuardClassLoader(ClassLoader parent, byte[] seed) {
        super(parent);
        this.delegate = parent;
        this.seed = seed;
    }

    /** Populate the in-memory mapping from the decrypted {@code resources.map}. */
    public void loadMapping(byte[] decryptedMap) {
        String s = new String(decryptedMap, StandardCharsets.UTF_8);
        for (String line : s.split("\n")) {
            if (line.isEmpty()) continue;
            String[] parts = line.split("\t", 3);
            if (parts.length == 3) {
                map.put(parts[0], new Entry(parts[1], "1".equals(parts[2])));
            }
        }
    }

    /**
     * Configure Anti-Dump class decryption. The seed is the 32-byte value from
     * {@code META-INF/kbox/class-seed.bin}; {@code classNames} is the set of
     * internal names (slash-separated) that were encrypted at build time.
     */
    private volatile boolean nativeLibLoaded;

    public void setClassDecryption(byte[] seed, Set<String> classNames) {
        this.classSeed = seed;
        this.encryptedClasses.clear();
        if (classNames != null) this.encryptedClasses.addAll(classNames);
    }

    /** Populate JNIC class list from build-time metadata (avoids fragile bytecode parsing). */
    public void setJnicClasses(Set<String> classNames) {
        this.jnicClasses.clear();
        if (classNames != null) this.jnicClasses.addAll(classNames);
    }

    /**
     * Load the packed native DLL once, before any JNIC class is loaded.
     * This ensures JVM can link native methods (by JNI naming convention)
     * during class loading, rather than failing because the DLL is loaded
     * later by the class's own &lt;clinit&gt;.
     */
    private void loadNativeLibOnce() {
        if (nativeLibLoaded) return;
        nativeLibLoaded = true;
        try {
            Class<?> nl = Class.forName("com.kbox.runtime.NativeLoader", true, this);
            java.lang.reflect.Method load = nl.getDeclaredMethod("load");
            load.invoke(null);
        } catch (Throwable e) {
            System.err.println("[KBOX-NATIVE] Pre-load failed: " + e);
        }
    }

    /** Explicitly register native methods on a just-loaded JNIC class. */
    private void registerJnicNatives(Class<?> jnicClass) {
        if (jnicClass == null) return;
        try {
            Class<?> nl = Class.forName("com.kbox.runtime.NativeLoader", true, this);
            java.lang.reflect.Method reg = nl.getDeclaredMethod("registerNatives0", Class.class);
            reg.invoke(null, jnicClass);
        } catch (Throwable e) {
            System.err.println("[KBOX-NATIVE] registerNatives0 failed: " + e);
        }
    }

    /**
     * Intercepts class loading for encrypted classes. For non-encrypted
     * classes, delegates to the parent (system) loader as usual.
     */
    @Override
    protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
        synchronized (getClassLoadingLock(name)) {
            Class<?> c = findLoadedClass(name);
            if (c != null) {
                if (resolve) resolveClass(c);
                return c;
            }
            String internal = name.replace('.', '/');
            // JDK / platform classes must always be loaded from the
            // parent — do not try to define them locally.
            if (internal.startsWith("java/") || internal.startsWith("javax/")
                    || internal.startsWith("jdk/") || internal.startsWith("sun/")
                    || internal.startsWith("com/sun/") || internal.startsWith("org/ietf/")
                    || internal.startsWith("org/omg/") || internal.startsWith("org/w3c/")
                    || internal.startsWith("org/xml/") || internal.startsWith("com/kbox/runtime/")) {
                return super.loadClass(name, resolve);
            }
            // Kotlin / standard-library classes are provided by the runtime
            // classpath (kotlin-stdlib is NOT bundled into the protected jar).
            // Always delegate them to the parent: defining a duplicate copy in
            // this loader breaks Kotlin reflection ("Built-in class kotlin.Any
            // is not found") because it sees two distinct kotlin.Any classes.
            if (internal.startsWith("kotlin/")) {
                return super.loadClass(name, resolve);
            }
            // JNIC / native-method classes must be loaded by the
            // parent AppClassLoader so that JNI_OnLoad's FindClass
            // can locate them through the standard loader chain.
            // Check BEFORE encrypted-class check: JNIC classes are
            // explicitly excluded from encryption by Packager, but
            // the encryptedClasses set may still contain them.
            // Load the native DLL BEFORE the class so JVM can link
            // native methods during class loading.
            if (isJnicClass(name)) {
                // Load the native DLL BEFORE the class so JVM can link native
                // methods during class loading.
                loadNativeLibOnce();
                Class<?> jc = null;
                // If the class was pre-loaded by the parent (e.g. via ResourceGuardLauncher),
                // reuse it — but still register natives. JNI_OnLoad's FindClass runs at
                // DLL-load time, when the class is usually not loaded yet, so it cannot
                // register the methods; we must RegisterNatives explicitly here.
                try {
                    jc = super.loadClass(name, false);
                } catch (ClassNotFoundException ignored) { }
                if (jc == null) {
                    byte[] raw = loadPlainClass(internal);
                    if (raw != null) {
                        jc = defineClass(name, raw, 0, raw.length);
                    }
                }
                if (jc != null) {
                    registerJnicNatives(jc);
                    if (resolve) resolveClass(jc);
                    return jc;
                }
                throw new ClassNotFoundException("JNIC class bytes not found: " + name);
            }
            boolean isEncrypted = classSeed != null && encryptedClasses.contains(internal);
            if (isEncrypted) {
                // Load encrypted class bytes and decrypt.
                try {
                    byte[] bytes = loadAndDecryptClass(internal);
                    if (bytes != null) {
                        c = defineClass(name, bytes, 0, bytes.length);
                        if (resolve) resolveClass(c);
                        return c;
                    }
                } catch (Exception e) {
                    throw new ClassNotFoundException("KBox class decryption failed for " + name, e);
                }
                // The class is listed as encrypted but the .class resource
                // could not be found. Throw CNFE immediately — do NOT fall
                // through to parent delegation, because the parent would
                // receive encrypted bytes (KBCE magic) and the JVM would
                // throw an unhelpful ClassFormatError.
                throw new ClassNotFoundException(
                        "KBox encrypted class not found in jar: " + name);
            }
            try {
                byte[] raw = loadPlainClass(internal);
                if (raw != null) {
                    try {
                        c = defineClass(name, raw, 0, raw.length);
                        if (resolve) resolveClass(c);
                        return c;
                    } catch (LinkageError le) {
                        // Already defined by parent.
                    }
                }
            } catch (Exception ex) {
                throw new ClassNotFoundException(
                        "Guard defineClass failed for " + name, ex);
            }
            // Not in the jar (JDK / platform class) or already loaded by
            // the parent. Delegating to parent is safe here.
            return super.loadClass(name, resolve);
        }
    }

    /** Reads the raw (plain, non-encrypted) .class bytes from the delegate. */
    private byte[] loadPlainClass(String internal) {
        String path = internal + ".class";
        try {
            InputStream in = delegate.getResourceAsStream(path);
            if (in == null) return null;
            byte[] raw = readAll(in);
            in.close();
            // Safety check: bytes must start with CAFEBABE.
            if (raw.length < 4) return null;
            if (raw[0] != (byte) 0xCA || raw[1] != (byte) 0xFE
                    || raw[2] != (byte) 0xBA || raw[3] != (byte) 0xBE) {
                return null;
            }
            return raw;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Quick check: does the .class file contain any native-method
     * flags (ACC_NATIVE = 0x0100)?  JNIC-converted classes have native
     * methods and must be loaded via the parent loader so that
     * JNI_OnLoad's FindClass can locate them.
     */
    private boolean classHasNativeMethod(String internal) {
        byte[] raw = loadPlainClass(internal);
        if (raw == null || raw.length < 10) return false;
        try {
            int cpCount = ((raw[8] & 0xFF) << 8) | (raw[9] & 0xFF) - 1;
            int pos = 10;
            for (int i = 0; i < cpCount && pos < raw.length; i++) {
                int tag = raw[pos++] & 0xFF;
                if (tag == 7 || tag == 8 || tag == 16 || tag == 19 || tag == 20) pos += 2;
                else if (tag == 15) pos += 3;
                else if (tag == 3 || tag == 4 || tag == 9 || tag == 10
                        || tag == 11 || tag == 12 || tag == 17 || tag == 18) pos += 4;
                else if (tag == 5 || tag == 6) { pos += 8; i++; }
                else if (tag == 1) {
                    if (pos + 2 > raw.length) return false;
                    int len = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
                    pos += 2 + len;
                }
            }
            if (pos + 6 > raw.length) return false;
            pos += 6;
            int ifcCount = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
            pos += 2 + ifcCount * 2;
            if (pos + 2 > raw.length) return false;
            int fieldCount = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
            pos += 2;
            for (int i = 0; i < fieldCount && pos + 8 <= raw.length; i++) {
                pos += 6;
                int attrCount = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
                pos += 2;
                for (int j = 0; j < attrCount && pos + 6 <= raw.length; j++) {
                    int aLen = ((raw[pos + 2] & 0xFF) << 24) | ((raw[pos + 3] & 0xFF) << 16)
                            | ((raw[pos + 4] & 0xFF) << 8) | (raw[pos + 5] & 0xFF);
                    pos += 6 + aLen;
                }
            }
            if (pos + 2 > raw.length) return false;
            int methodCount = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
            pos += 2;
            for (int i = 0; i < methodCount && pos + 8 <= raw.length; i++) {
                int access = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
                if ((access & 0x0100) != 0) return true; // ACC_NATIVE
                pos += 4;
                int attrCount = ((raw[pos] & 0xFF) << 8) | (raw[pos + 1] & 0xFF);
                pos += 2;
                for (int j = 0; j < attrCount && pos + 6 <= raw.length; j++) {
                    int aLen = ((raw[pos + 2] & 0xFF) << 24) | ((raw[pos + 3] & 0xFF) << 16)
                            | ((raw[pos + 4] & 0xFF) << 8) | (raw[pos + 5] & 0xFF);
                    pos += 6 + aLen;
                }
            }
        } catch (Exception ignored) { }
        return false;
    }

    private boolean isJnicClass(String name) {
        if (jnicClasses == null || jnicClasses.isEmpty()) return false;
        String internal = name.replace('.', '/');
        return jnicClasses.contains(internal);
    }

    /** Reads the encrypted .class resource and decrypts it. */
    private byte[] loadAndDecryptClass(String internal) throws Exception {
        String path = internal + ".class";
        // For Spring Boot fat jars, classes live under BOOT-INF/classes/.
        // Try both the plain path and the Spring Boot path.
        InputStream in = delegate.getResourceAsStream(path);
        if (in == null) {
            in = delegate.getResourceAsStream("BOOT-INF/classes/" + path);
        }
        if (in == null) return null;
        byte[] raw = readAll(in);
        in.close();
        return decryptClass(raw);
    }

    /** Decrypts a class body encrypted with the "KBCE" magic scheme. */
    private byte[] decryptClass(byte[] blob) throws Exception {
        if (blob == null || blob.length < 16) return blob;
        // Check magic "KBCE"
        if (blob[0] != (byte) 0x4B || blob[1] != (byte) 0x42
                || blob[2] != (byte) 0x43 || blob[3] != (byte) 0x45) {
            return blob; // not encrypted, return as-is
        }
        byte[] iv = new byte[12];
        System.arraycopy(blob, 4, iv, 0, 12);
        byte[] ct = new byte[blob.length - 16];
        System.arraycopy(blob, 16, ct, 0, ct.length);
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        md.update("KBox-ClassGuard-v1:".getBytes(StandardCharsets.UTF_8));
        md.update(classSeed);
        md.update(HardwareKeyRing.fingerprint()); // S3: bind to run machine (true HW ring, matches encrypt side)
        if (LIC_MATERIAL != null) md.update(LIC_MATERIAL); // license gate (matches build)
        byte[] key = md.digest();
        javax.crypto.Cipher c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
        c.init(javax.crypto.Cipher.DECRYPT_MODE,
                new javax.crypto.spec.SecretKeySpec(key, 0, 32, "AES"),
                new javax.crypto.spec.GCMParameterSpec(128, iv));
        return c.doFinal(ct);
    }

    @Override
    public URL getResource(String name) {
        byte[] data = resolve(name);
        if (data == null) return super.getResource(name);
        try {
            return new URL("data:," + java.util.Base64.getEncoder().encodeToString(data));
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public InputStream getResourceAsStream(String name) {
        byte[] data = resolve(name);
        if (data != null) return new ByteArrayInputStream(data);
        return super.getResourceAsStream(name);
    }

    @Override
    public Enumeration<URL> getResources(String name) throws java.io.IOException {
        final java.util.List<URL> urls = new java.util.ArrayList<>();
        byte[] data = resolve(name);
        if (data != null) {
            try {
                urls.add(new URL("data:," + java.util.Base64.getEncoder().encodeToString(data)));
            } catch (Exception ignore) {}
        }
        Enumeration<URL> parent = super.getResources(name);
        while (parent.hasMoreElements()) urls.add(parent.nextElement());
        final java.util.Iterator<URL> it = urls.iterator();
        return new Enumeration<URL>() {
            @Override public boolean hasMoreElements() { return it.hasNext(); }
            @Override public URL nextElement() { return it.next(); }
        };
    }

    /** Returns the decrypted bytes for {@code name} or null when unmapped. */
    private byte[] resolve(String name) {
        if (name == null) return null;
        if (cache.containsKey(name)) {
            return cache.get(name);  // may be null if previously missing
        }
        Entry e = map.get(name);
        if (e == null) {
            cache.put(name, null);
            return null;
        }
        try {
            InputStream in = delegate.getResourceAsStream(e.newPath);
            if (in == null) {
                cache.put(name, null);
                return null;
            }
            byte[] raw = readAll(in);
            in.close();
            if (e.encrypted) raw = decryptResource(raw);
            cache.put(name, raw);
            return raw;
        } catch (Exception ex) {
            return null;
        }
    }

    private byte[] decryptResource(byte[] blob) throws Exception {
        if (blob == null || blob.length < 14) return blob;
        if (blob[0] != (byte) 0x4B) return blob;  // magic 'K'
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
    }

    private static byte[] readAll(InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }
}
