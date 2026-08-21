package com.kbox.cli;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

/**
 * Batch license publisher — companion to {@link LicGen} for issuing many
 * licenses at once. Runs on the PUBLISHER machine only (never in the jar).
 *
 * <p>Because class/VM decryption is gated on a single app secret baked into the
 * build config ({@code licAppSecret}), <b>every</b> license for a given jar
 * must embed that same secret. These commands therefore require it explicitly —
 * they never generate a fresh random one silently.
 *
 * <pre>
 *   java -cp kbox-protector.jar com.kbox.cli.BatchLicGen batch \
 *        &lt;priv.der&gt; &lt;devices.csv&gt; &lt;subject&gt; &lt;days&gt; &lt;features&gt; &lt;appSecretHex&gt; &lt;outDir&gt;
 *        devices.csv : one "alias,deviceFpHex" per line (# = comment).
 *        -> outDir/&lt;alias&gt;.lic for each machine, plus outDir/report.csv
 *
 *   java -cp kbox-protector.jar com.kbox.cli.BatchLicGen generic \
 *        &lt;priv.der&gt; &lt;prefix&gt; &lt;subject&gt; &lt;days&gt; &lt;features&gt; &lt;appSecretHex&gt; &lt;count&gt; &lt;outDir&gt;
 *        -> outDir/&lt;prefix&gt;_0001.lic .. &lt;prefix&gt;_NNNN.lic (device-unbound)
 * </pre>
 *
 * <p>All output uses the same encrypted, Ed25519-signed {@code .lic} v0x02
 * format written by {@link LicGen#buildBlob}.
 */
public final class BatchLicGen {

    private BatchLicGen() {}

    public static void main(String[] a) throws Exception {
        if (a.length < 1) { usage(); return; }
        switch (a[0]) {
            case "batch":
                batch(a);
                break;
            case "generic":
                generic(a);
                break;
            default:
                usage();
        }
    }

    /** per-line: alias,deviceFpHex */
    private static void batch(String[] a) throws Exception {
        if (a.length < 8) { usage(); return; }
        String privPath = a[1];
        String csv      = a[2];
        String subject  = a[3];
        long days       = Long.parseLong(a[4]);
        int  features   = Integer.parseInt(a[5]);
        byte[] appBytes = LicGen.hexToBytes(a[6]);
        requireSecret(a[6]);
        Path outDir     = Files.createDirectories(Paths.get(a[7]));

        PrivateKey pk = loadPriv(privPath);
        byte[] spki = LicGen.tryReadPub(privPath);

        List<String[]> rows = readCsv(csv);
        StringBuilder report = new StringBuilder("alias,file,expiryMs,bound\n");
        int ok = 0, skip = 0;
        long now = System.currentTimeMillis();
        for (String[] r : rows) {
            String alias = r[0].trim();
            String fp = r[1].trim();
            if (alias.isEmpty() || fp.isEmpty()) { skip++; continue; }
            String fileName = sanitize(alias) + ".lic";
            long notAfter = now + days * 86_400_000L;
            long nonce = System.nanoTime() ^ ((long) features << 32);
            byte[] payload = LicGen.buildPayload(subject, now, notAfter, features, fp, nonce, appBytes);
            byte[] blob = LicGen.buildBlob(pk, payload, spki);
            Files.write(outDir.resolve(fileName), blob);
            report.append(alias).append(',').append(fileName)
                    .append(',').append(notAfter).append(",1\n");
            ok++;
            System.out.println("  wrote " + fileName + " (" + blob.length + "B) bound=" + fp.substring(0, Math.min(8, fp.length())) + "...");
        }
        Files.write(outDir.resolve("report.csv"), report.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Batch: " + ok + " issued, " + skip + " skipped -> " + outDir.toAbsolutePath());
        System.out.println("Report: " + outDir.resolve("report.csv"));
    }

    private static void generic(String[] a) throws Exception {
        if (a.length < 9) { usage(); return; }
        String privPath = a[1];
        String prefix   = a[2];
        String subject  = a[3];
        long days       = Long.parseLong(a[4]);
        int  features   = Integer.parseInt(a[5]);
        requireSecret(a[6]);
        byte[] appBytes = LicGen.hexToBytes(a[6]);
        int count       = Integer.parseInt(a[7]);
        Path outDir     = Files.createDirectories(Paths.get(a[8]));

        PrivateKey pk = loadPriv(privPath);
        byte[] spki = LicGen.tryReadPub(privPath);

        StringBuilder report = new StringBuilder("alias,file,expiryMs,bound\n");
        long now = System.currentTimeMillis();
        for (int i = 1; i <= count; i++) {
            String fileName = prefix + "_" + String.format("%04d", i) + ".lic";
            long notAfter = now + days * 86_400_000L;
            long nonce = System.nanoTime() ^ ((long) features << 32) ^ (long) i;
            byte[] payload = LicGen.buildPayload(subject, now, notAfter, features, null, nonce, appBytes);
            byte[] blob = LicGen.buildBlob(pk, payload, spki);
            Files.write(outDir.resolve(fileName), blob);
            report.append(fileName).append(',').append(fileName)
                    .append(',').append(notAfter).append(",0\n");
            if (count <= 200 || i == count) System.out.println("  wrote " + fileName + " (" + blob.length + "B)");
        }
        Files.write(outDir.resolve("report.csv"), report.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("Generic: issued " + count + " device-unbound licenses -> " + outDir.toAbsolutePath());
    }

    private static void requireSecret(String hex) {
        if (hex == null || hex.length() != 64) {
            System.err.println("appSecretHex must be 64 hex chars (the licAppSecret baked into the build config).");
            System.exit(1);
        }
    }

    private static PrivateKey loadPriv(String path) throws Exception {
        byte[] priv = Files.readAllBytes(Paths.get(path));
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        return kf.generatePrivate(new PKCS8EncodedKeySpec(priv));
    }

    private static List<String[]> readCsv(String path) throws Exception {
        List<String[]> rows = new ArrayList<>();
        for (String line : Files.readAllLines(Paths.get(path), StandardCharsets.UTF_8)) {
            String t = line.trim();
            if (t.isEmpty() || t.startsWith("#")) continue;
            String[] parts = t.split(",");
            if (parts.length < 2) continue;
            rows.add(new String[]{parts[0], parts[1]});
        }
        return rows;
    }

    private static String sanitize(String s) {
        return s.replaceAll("[^A-Za-z0-9._-]", "_");
    }

    private static void usage() {
        System.out.println("BatchLicGen (publisher-only)");
        System.out.println("  batch   <priv.der> <devices.csv> <subject> <days> <features> <appSecretHex> <outDir>");
        System.out.println("  generic <priv.der> <prefix> <subject> <days> <features> <appSecretHex> <count> <outDir>");
    }
}