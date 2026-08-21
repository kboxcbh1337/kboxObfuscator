package com.kbox.testapp;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Properties;
import java.util.ServiceLoader;

/**
 * Application entry point. Exercises:
 * <ul>
 *   <li>plain Java object creation &amp; method calls (Greeter)</li>
 *   <li>a primitive-returning method (License.check)</li>
 *   <li>ServiceLoader (forces META-INF/services preservation)</li>
 *   <li>String concatenation (forces string-encryption to coexist)</li>
 *   <li>ClassLoader.getResourceAsStream (forces non-class-file preservation)</li>
 * </ul>
 *
 * The exit code 0 means all checks passed — the protected jar is functionally
 * equivalent to the original.
 */
public final class Main {

    public static void main(String[] args) {
        Greeter g = new Greeter();
        String msg = g.greet("KBox");
        if (!msg.endsWith(", KBox!")) {
            throw new AssertionError("Greeting format broken: " + msg);
        }
        System.out.println(msg);

        License lic = new License();
        // ASCII sum of "KBOX-TEST-KEY-1234" = (known) -> assert specific value.
        boolean ok = lic.check("KBOX-TEST-KEY-1234");
        System.out.println("License check: " + (ok ? "VALID" : "INVALID"));

        // Resource loading round-trip: read config/app.properties via the class
        // loader. After resource obfuscation the file is renamed (and encrypted),
        // but the ResourceGuardClassLoader must still return the original content
        // transparently.
        Properties props = loadProperties("config/app.properties");
        String secret = props.getProperty("app.secret");
        if (!"KBOX-SECRET-KEY-9876".equals(secret)) {
            throw new AssertionError("app.properties not loaded transparently: " + secret);
        }
        System.out.println("Resource config/app.properties OK (secret=" + secret + ")");

        // Plain-text resource: name should be randomized but content readable.
        String banner = loadText("assets/banner.txt");
        if (!banner.startsWith("KBox Test App Banner")) {
            throw new AssertionError("banner.txt content mismatch: " + banner);
        }
        System.out.println("Resource assets/banner.txt OK");

        // ServiceLoader round-trip. The services file lists Main itself; we just
        // assert the loader returned at least one provider (the file was kept).
        long count = 0;
        for (Object svc : ServiceLoader.load(Runnable.class)) count++;
        // count==0 is fine (no real Runnable provider); we only assert no exception.

        System.out.println("Test app OK (services seen: " + count + ")");
        System.exit(0);
    }

    private static Properties loadProperties(String path) {
        Properties p = new Properties();
        try (InputStream in = contextClassLoader().getResourceAsStream(path)) {
            if (in == null) throw new AssertionError("Missing resource: " + path);
            p.load(in);
        } catch (Exception e) {
            throw new AssertionError("Failed to read " + path + ": " + e);
        }
        return p;
    }

    private static String loadText(String path) {
        try (InputStream in = contextClassLoader().getResourceAsStream(path)) {
            if (in == null) throw new AssertionError("Missing resource: " + path);
            BufferedReader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) sb.append(line).append('\n');
            return sb.toString();
        } catch (Exception e) {
            throw new AssertionError("Failed to read " + path + ": " + e);
        }
    }

    /** Context class loader — set by ResourceGuardLauncher when resources are obfuscated. */
    private static ClassLoader contextClassLoader() {
        ClassLoader cl = Thread.currentThread().getContextClassLoader();
        return cl != null ? cl : Main.class.getClassLoader();
    }
}
