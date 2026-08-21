package com.kbox.core.config;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Classifies internal class names as <em>library</em> (must not be transformed)
 * or <em>user</em> (eligible for obfuscation). Library classes are read-only:
 * they can be referenced, but KBox never renames their members, injects code
 * into their methods, encrypts their strings, or rewrites their control flow.
 *
 * <p>By default the classifier treats any class whose package is on the
 * well-known library list (JDK + common third-party libs like commons-lang3,
 * Guava, Kotlin stdlib, Spring, Jackson, etc.) as library code. Users can
 * extend or override this via {@link #addLibraryPrefix(String)} and
 * {@link #addUserPrefix(String)}.
 *
 * <p>This is the KBox equivalent of ProGuard's {@code -libraryjars} +
 * {@code -dontskipnonpubliclibraryclasses} behaviour, but automatic — no
 * manual configuration required for the common case. The goal is
 * <strong>obfuscation must never break a working jar</strong>: when in doubt,
 * a class is treated as library code and left untouched.
 *
 * <p>Decision precedence (highest priority first):
 * <ol>
 *   <li>{@link #addUserPrefix(String) user prefixes} — always user code,
 *       even if it would otherwise match a library prefix.</li>
 *   <li>{@link ProtectionConfig#getKeepPrefixes() keep prefixes} — kept, so
 *       also not transformed (handled by {@link ProtectionConfig#isKept}).
 *       The classifier itself does not consult keepPrefixes; the caller is
 *       expected to do so separately.</li>
 *   <li>{@link #addLibraryPrefix(String) library prefixes} — library code.</li>
 *   <li>Default bundled library prefix list.</li>
 *   <li>If nothing matches: treat as <em>user</em> code (obfuscate).</li>
 * </ol>
 */
public final class LibraryClassifier {

    /**
     * Bundled prefixes for well-known library packages (internal names,
     * slash-separated). Anything starting with one of these is treated as
     * library code by default. The list covers the JDK and the libraries
     * most commonly shaded into fat jars (Spring Boot, Minecraft mods,
     * Maven-shaded uber jars, etc.).
     *
     * <p>Users can override any entry via {@link #addUserPrefix(String)}.
     */
    static final String[] DEFAULT_LIBRARY_PREFIXES = {
        // ---- JDK & platform ----
        "java/", "javax/", "jakarta/", "sun/", "com/sun/", "jdk/",
        "org/ietf/", "org/omg/", "org/w3c/", "org/xml/", "org/jcp/",
        "apple/", "com/apple/",
        // ---- Kotlin / Scala ----
        "kotlin/", "kotlinx/", "org/jetbrains/annotations/",
        "scala/", "scala/util/", "scalafix/",
        // ---- Apache ecosystem ----
        "org/apache/commons/", "org/apache/log4j/", "org/apache/logging/",
        "org/apache/http/", "org/apache/maven/", "org/apache/ant/",
        "org/apache/tools/", "org/apache/batik/", "org/apache/poi/",
        "org/apache/catalina/", "org/apache/tomcat/", "org/apache/jasper/",
        "org/apache/jsp/", "org/apache/ibatis/", "org/apache/struts/",
        "org/apache/wicket/", "org/apache/thrift/", "org/apache/avro/",
        "org/apache/zookeeper/", "org/apache/curator/", "org/apache/kafka/",
        "org/apache/storm/", "org/apache/lucene/", "org/apache/derby/",
        "org/apache/xerces/", "org/apache/xalan/", "org/apache/cxf/",
        "org/apache/camel/", "org/apache/logging/log4j/",
        // ---- Google ----
        "com/google/", "org/checkerframework/",
        // ---- Spring / Spring Boot ----
        "org/springframework/",
        // ---- JBoss / WildFly / Hibernate ----
        "org/jboss/", "org/hibernate/", "org/aspectj/",
        // ---- Eclipse / OSGi ----
        "org/eclipse/jdt/", "org/eclipse/core/", "org/eclipse/osgi/",
        "org/eclipse/jetty/",
        // ---- Joda / other time ----
        "org/joda/",
        // ---- Testing frameworks ----
        "org/junit/", "org/mockito/", "org/hamcrest/", "org/testng/",
        "org/assertj/", "org/spockframework/", "org/jacoco/",
        // ---- Logging ----
        "org/slf4j/", "ch/qos/logback/",
        // ---- Reactive / async ----
        "reactor/core/", "reactor/util/", "io/reactivex/",
        "org/reactivestreams/", "io/projectreactor/",
        // ---- Jackson / JSON ----
        "com/fasterxml/jackson/", "com/fasterxml/uuid/",
        // ---- Netty / gRPC ----
        "io/netty/", "io/grpc/",
        // ---- JAX-RS / Jersey / REST ----
        "javax/ws/", "jakarta/ws/", "org/glassfish/jersey/",
        // ---- Other common libs ----
        "org/yaml/snakeyaml/", "org/codehaus/", "org/aopalliance/",
        "org/xmlpull/", "org/jsoup/", "com/zaxxer/",
        "mysql/", "org/postgresql/", "com/microsoft/sqlserver/",
        "oracle/jdbc/", "com/mysql/", "org/hsqldb/", "org/h2/",
        "org/mariadb/",
        // ---- ASM / bytecode libs ----
        "org/objectweb/asm/", "org/ow2/asm/",
        // ---- JNA / JNI helpers ----
        "com/sun/jna/", "jnr/ffi/",
        // ---- Lombok / annotations ----
        "lombok/",
        // ---- Minecraft / mod loaders (covered by presets, but safe default) ----
        "net/minecraft/", "cpw/mods/", "net/neoforg/",
        "net/minecraftforge/", "net/fabricmc/",
        "org/spongepowered/asm/", "org/bukkit/", "org/spigotmc/",
        "com/mojang/",
        // ---- Glassfish / other Jakarta ----
        "org/glassfish/",
        // ---- AI / ML libs ----
        "ai/djl/", "org/tensorflow/", "org/pytorch/", "ai/onnxruntime/",
        // ---- Clojure / Groovy ----
        "clojure/", "groovy/", "org/codehaus/groovy/",
        // ---- Cglib / ByteBuddy / dynamic proxies ----
        "net/sf/cglib/", "cglib/", "net/bytebuddy/",
        "org/objenesis/",
    };

    /** User-extensible library prefixes (always includes the default list). */
    private final Set<String> libraryPrefixes = new HashSet<>();

    /** User prefixes always take precedence — they are treated as user code. */
    private final Set<String> userPrefixes = new HashSet<>();

    /**
     * When {@code true} (default), the bundled default library prefixes are
     * applied. Set to {@code false} to disable the built-in list entirely
     * (advanced users who want to manage their own prefix list).
     */
    private boolean useDefaultPrefixes = true;

    public LibraryClassifier() {
        for (String p : DEFAULT_LIBRARY_PREFIXES) libraryPrefixes.add(p);
    }

    /** Adds a library-class prefix. Both dotted and slashed forms are accepted. */
    public void addLibraryPrefix(String prefix) {
        if (prefix != null && !prefix.isEmpty()) libraryPrefixes.add(normalize(prefix));
    }

    /** Adds a user-class prefix that overrides any library prefix match. */
    public void addUserPrefix(String prefix) {
        if (prefix != null && !prefix.isEmpty()) userPrefixes.add(normalize(prefix));
    }

    public boolean isUseDefaultPrefixes() { return useDefaultPrefixes; }
    public void setUseDefaultPrefixes(boolean v) { this.useDefaultPrefixes = v; }

    /**
     * True if the class with this internal name is library code (must not be
     * transformed). Returns {@code false} for user code.
     *
     * <p>User prefixes always take precedence: if a class matches a user
     * prefix, it is treated as user code even if it also matches a library
     * prefix.
     */
    public boolean isLibraryClass(String internalName) {
        if (internalName == null) return false;
        // User prefixes always win — even over the default library list.
        for (String p : userPrefixes) {
            if (internalName.startsWith(p)) return false;
        }
        // Then check the user-extensible library prefix set (which by default
        // contains the bundled list unless useDefaultPrefixes is false).
        for (String p : libraryPrefixes) {
            if (internalName.startsWith(p)) return true;
        }
        return false;
    }

    /** True if the class is user code (eligible for transformation). */
    public boolean isUserClass(String internalName) {
        return !isLibraryClass(internalName);
    }

    /**
     * Combined decision: should this class be transformed?
     *
     * <p>Returns {@code true} only if:
     * <ol>
     *   <li>The class is user code (not a library class), AND</li>
     *   <li>The class is not in {@link ProtectionConfig#isKept(String) keep prefixes}, AND</li>
     *   <li>The class is selected by {@link FileSelector#shouldObfuscateClass(String, ProtectionConfig) FileSelector}.</li>
     * </ol>
     *
     * This is the single canonical entry point that every transformation
     * stage should consult before touching a class. Centralizing the
     * decision keeps the "never break a working jar" invariant consistent
     * across all passes.
     */
    public boolean shouldTransform(String internalName, ProtectionConfig cfg) {
        if (internalName == null) return false;
        // Library classes are never transformed.
        if (isLibraryClass(internalName)) return false;
        // Kept classes (explicit keep-prefix / entry-point) are not transformed.
        if (cfg != null && cfg.isKept(internalName)) return false;
        // KBox runtime classes are never transformed by the obfuscator itself.
        if (internalName.startsWith("com/kbox/runtime/")) return false;
        // Fine-grained scope / pattern filter.
        if (cfg != null && !FileSelector.shouldObfuscateClass(internalName, cfg)) return false;
        return true;
    }

    /**
     * Body-protection decision used by string-encryption and control-flow
     * passes. Unlike {@link #shouldTransform}, this returns {@code true} for
     * kept classes (explicit keep-prefix / entry-point) so their method bodies
     * are still encrypted and flattened — only their names are preserved.
     *
     * <p>This mirrors how commercial obfuscators (ZKM, Allatori, etc.) treat
     * entry points: the class/method name is kept so the JVM can launch and
     * reflection still resolves, but the body is still protected. The only
     * things that must never be touched are library classes, KBox runtime
     * classes, and out-of-scope classes.
     */
    public boolean shouldProtect(String internalName, ProtectionConfig cfg) {
        if (internalName == null) return false;
        // Library classes are never transformed.
        if (isLibraryClass(internalName)) return false;
        // KBox runtime classes are never transformed by the obfuscator itself.
        if (internalName.startsWith("com/kbox/runtime/")) return false;
        // Fine-grained scope / pattern filter.
        if (cfg != null && !FileSelector.shouldObfuscateClass(internalName, cfg)) return false;
        return true;
    }

    /** Returns an unmodifiable view of the configured library prefixes. */
    public Set<String> getLibraryPrefixes() {
        return Collections.unmodifiableSet(libraryPrefixes);
    }

    /** Returns an unmodifiable view of the user overrides. */
    public Set<String> getUserPrefixes() {
        return Collections.unmodifiableSet(userPrefixes);
    }

    /** Removes the default library prefixes (advanced users only). */
    public void clearDefaults() {
        for (String p : DEFAULT_LIBRARY_PREFIXES) libraryPrefixes.remove(p);
        useDefaultPrefixes = false;
    }

    private static String normalize(String prefix) {
        // Accept either dotted or slashed form; always store slashed.
        return prefix.replace('.', '/');
    }
}
