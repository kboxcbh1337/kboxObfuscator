package com.kbox.runtime;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.InputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.util.*;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

/**
 * LaunchWrapper tweaker that runs BEFORE {@code MixinTweaker} to decrypt
 * AES-GCM-encrypted class bodies on-the-fly. Without this, the
 * {@code MixinTweaker} would attempt to analyze encrypted bytecode and fail
 * with {@code VerifyError} / {@code ClassFormatError}.
 *
 * <p>This class is compiled WITHOUT direct LaunchWrapper imports to avoid
 * a compile-time dependency. During packaging, the KBox Packager uses ASM
 * to add {@code net.minecraft.launchwrapper.ITweaker} and
 * {@code net.minecraft.launchwrapper.IClassTransformer} to the class's
 * interface list, and rewrites the {@code injectIntoClassLoader} parameter
 * type from {@code Object} to {@code LaunchClassLoader}.
 *
 * <p><b>Decryption key:</b> The 32-byte seed is stored in
 * {@code META-INF/kbox/class-seed.bin}. The AES-256-GCM key is derived as
 * {@code SHA-256("KBox-ClassGuard-v1:" + seed)[0:32]}. Encrypted classes
 * begin with the 4-byte magic {@code KBCE}, followed by a 12-byte IV and
 * the GCM-authenticated ciphertext.
 */
public class KBoxClassDecryptTweaker {

    private static final String SEED_PATH = "META-INF/kbox/class-seed.bin";
    private static final byte[] MAGIC = { 0x4B, 0x42, 0x43, 0x45 }; // "KBCE"

    // ----- ITweaker -----

    /** acceptOptions(Ljava/util/List;Ljava/io/File;Ljava/io/File;Ljava/lang/String;)V */
    public void acceptOptions(List<String> args, File gameDir, File assetsDir, String profile) {
        loadKeys();
    }

    /**
     * injectIntoClassLoader(Lnet/minecraft/launchwrapper/LaunchClassLoader;)V
     * Parameter is typed Object at compile time; Packager rewrites the
     * method descriptor to use LaunchClassLoader via ASM.
     */
    public void injectIntoClassLoader(Object classLoaderObj) {
        try {
            // classLoader.registerTransformer(this.getClass().getName())
            Class<?> lcl = classLoaderObj.getClass();
            java.lang.reflect.Method registerTransformer = lcl.getMethod(
                    "registerTransformer", String.class);
            registerTransformer.invoke(classLoaderObj, getClass().getName());
        } catch (Exception e) {
            System.err.println("[KBox] Failed to register transformer: " + e.getMessage());
        }
    }

    public String getLaunchTarget() {
        return "net.minecraft.client.main.Main";
    }

    public String[] getLaunchArguments() {
        return new String[0];
    }

    // ----- IClassTransformer -----

    public byte[] transform(String name, String transformedName, byte[] basicClass) {
        if (basicClass == null || basicClass.length < 4) return basicClass;
        if (decryptKey == null) return basicClass;

        // Fast magic check: encrypted classes start with "KBCE".
        if (basicClass[0] != MAGIC[0] || basicClass[1] != MAGIC[1]
                || basicClass[2] != MAGIC[2] || basicClass[3] != MAGIC[3]) {
            return basicClass;
        }

        try {
            return decryptClass(basicClass);
        } catch (Exception e) {
            System.err.println("[KBox] Failed to decrypt class: " + transformedName
                    + " (" + name + "): " + e.getMessage());
            return basicClass;
        }
    }

    // ----- Decryption engine -----

    private static byte[] decryptKey;
    private static javax.crypto.Cipher decryptCipher;

    private static void loadKeys() {
        try {
            byte[] seed = readJarResource(SEED_PATH);
            if (seed == null) {
                System.err.println("[KBox] No class-seed.bin found; class encryption not configured.");
                return;
            }
            // Key derivation must match encryptClassBody:
            // SHA-256("KBox-ClassGuard-v1:" + raw seed bytes), truncated to 32 bytes.
            java.security.MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(KEY_DOMAIN);
            md.update(seed);
            md.update(HardwareKeyRing.fingerprint()); // S3: bind to run machine (true HW ring, matches encrypt side)
            byte[] lm = licMaterial();
            if (lm != null) md.update(lm);           // license gate (matches build)
            byte[] fullKey = md.digest();
            decryptKey = new byte[32];
            System.arraycopy(fullKey, 0, decryptKey, 0, 32);
            decryptCipher = Cipher.getInstance("AES/GCM/NoPadding");
        } catch (Exception e) {
            System.err.println("[KBox] Failed to load decryption keys: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static final byte[] KEY_DOMAIN =
            "KBox-ClassGuard-v1:".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    /** License gate material (SHA-256 of LicVerifier.appKey()) when the jar is licensed; else null. */
    private static byte[] licMaterial() {
        try {
            java.io.InputStream in = KBoxClassDecryptTweaker.class
                    .getResourceAsStream("/META-INF/kbox/lic.pub");
            if (in == null) return null;
            in.close();
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(LicVerifier.appKey());
            return md.digest();
        } catch (Throwable t) {
            return null;
        }
    }

    private static byte[] decryptClass(byte[] blob) throws Exception {
        if (blob.length < 4 + 12 + 16) return blob;
        byte[] iv = new byte[12];
        System.arraycopy(blob, 4, iv, 0, 12);
        byte[] ct = new byte[blob.length - 4 - 12];
        System.arraycopy(blob, 4 + 12, ct, 0, ct.length);

        synchronized (KBoxClassDecryptTweaker.class) {
            decryptCipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(decryptKey, "AES"),
                    new GCMParameterSpec(128, iv));
            return decryptCipher.doFinal(ct);
        }
    }

    private static byte[] readJarResource(String path) {
        try {
            URL url = KBoxClassDecryptTweaker.class.getProtectionDomain()
                    .getCodeSource().getLocation();
            if (url == null) return null;
            try (JarFile jar = new JarFile(new File(url.toURI()))) {
                ZipEntry entry = jar.getEntry(path);
                if (entry == null) return null;
                return readAll(jar.getInputStream(entry));
            }
        } catch (Exception e) {
            try (InputStream in = KBoxClassDecryptTweaker.class.getClassLoader()
                    .getResourceAsStream(path)) {
                if (in == null) return null;
                return readAll(in);
            } catch (Exception ignored) {}
            return null;
        }
    }

    private static byte[] readAll(InputStream in) throws java.io.IOException {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) out.write(buf, 0, n);
        return out.toByteArray();
    }
}
