package com.kbox.core.resource;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;

/**
 * Encrypts the content of resources flagged as {@code encrypted=true} by
 * {@link ResourceNameObfuscator} using AES-256-GCM. The encrypted blob layout is:
 *
 * <pre>
 *   [1-byte magic 0xKB][12-byte IV][ciphertext + 16-byte GCM tag]
 * </pre>
 *
 * <p>The AES key is derived once per jar via SHA-256 of a random 32-byte seed
 * that is stored (in the clear, but only useful together with the AES algorithm)
 * inside the runtime {@code resources.map} entry header. The actual seed bytes
 * are written into the {@code resource-guard.bin} file at packaging time and
 * read at boot by {@code ResourceGuardLauncher}; without that file the encrypted
 * resources cannot be decrypted, providing a basic license-bound hook.
 *
 * <p>Non-encrypted resources are left untouched (only their name was randomized).
 *
 * <p>The transformed bytes are written back into {@code graph.resources} under
 * the new path so that {@code Packager} simply copies them.
 */
public final class ResourceEncryptor {

    private static final String TAG = "resource-enc";
    private static final byte MAGIC = (byte) 0x93;   // 'K'^0xD8, masked (NOT ASCII 'K')
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private final SecureRandom rng = new SecureRandom();
    private final byte[] seed;

    public ResourceEncryptor(ClassGraph graph, ProtectionConfig cfg, byte[] seed) {
        this.graph = graph;
        this.cfg = cfg;
        this.seed = seed;
    }

    /** Derive a fresh AES-256 key seed (32 bytes). */
    public static byte[] newSeed() {
        byte[] s = new byte[32];
        new SecureRandom().nextBytes(s);
        return s;
    }

    public void apply(ResourceMapping mapping) {
        if (!cfg.isObfuscateResources()) return;
        Map<String, byte[]> resources = graph.getResources();
        int encrypted = 0;
        // Rebuild resources map: remove old-path entries, insert new-path entries
        // (with possibly encrypted content).
        java.util.Map<String, byte[]> updated = new java.util.LinkedHashMap<>();
        for (Map.Entry<String, ResourceMapping.Entry> e : mapping.entries().entrySet()) {
            String oldPath = e.getKey();
            ResourceMapping.Entry ent = e.getValue();
            byte[] data = resources.remove(oldPath);
            if (data == null) continue;
            if (ent.encrypted) {
                try {
                    data = encrypt(data);
                    encrypted++;
                } catch (Exception ex) {
                    KBoxLog.warn(TAG, "Encrypt failed for " + oldPath + ": " + ex.getMessage()
                            + " (storing plaintext under new name)");
                }
            }
            updated.put(ent.newPath, data);
        }
        // Merge: keep remaining entries (untouched ones) + updated entries.
        updated.forEach(resources::putIfAbsent);
        if (!updated.isEmpty()) resources.putAll(updated);
        KBoxLog.info(TAG, "Encrypted " + encrypted + " resource bodies");
    }

    private byte[] encrypt(byte[] data) throws Exception {
        byte[] iv = new byte[IV_LEN];
        rng.nextBytes(iv);
        SecretKeySpec key = deriveKey();
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        byte[] ct = c.doFinal(data);
        ByteBuffer out = ByteBuffer.allocate(1 + IV_LEN + ct.length);
        out.put(MAGIC);
        out.put(iv);
        out.put(ct);
        return out.array();
    }

    /** Runtime-side decryption (mirrors {@link #encrypt}). */
    public static byte[] decrypt(byte[] blob, byte[] seed) throws Exception {
        if (blob == null || blob.length < 1 + IV_LEN + 1) return blob;
        ByteBuffer bb = ByteBuffer.wrap(blob);
        if (bb.get() != MAGIC) return blob;   // not actually encrypted
        byte[] iv = new byte[IV_LEN];
        bb.get(iv);
        byte[] ct = new byte[bb.remaining()];
        bb.get(ct);
        SecretKeySpec key = deriveKey(seed);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
        return c.doFinal(ct);
    }

    private SecretKeySpec deriveKey() throws Exception {
        return deriveKey(seed);
    }

    private static SecretKeySpec deriveKey(byte[] seed) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(seed);
        return new SecretKeySpec(hash, 0, 32, "AES");
    }
}
