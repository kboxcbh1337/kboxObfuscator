package com.kbox.core.jnic;

import com.kbox.core.log.KBoxLog;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Compiles a generated C source file into a shared library for the current
 * platform. Detects the C compiler in this order:
 * <ol>
 *   <li>User-configured {@code cc} (explicit)</li>
 *   <li>{@code CC} environment variable</li>
 *   <li>Auto-discovery: cl.exe (MSVC) on Windows, gcc/clang elsewhere</li>
 * </ol>
 *
 * Output file naming:
 * <ul>
 *   <li>Windows: {@code kbox_native.dll}</li>
 *   <li>Linux: {@code libkbox_native.so}</li>
 *   <li>macOS: {@code libkbox_native.dylib}</li>
 * </ul>
 *
 * JNI header include path is resolved from {@code JAVA_HOME}/include + the
 * platform subdirectory ({@code win32}, {@code linux}, {@code darwin}).
 */
public final class NativeCompiler {

    private static final String TAG = "native";

    /** Result of a compile attempt. {@code success=false} means the caller falls back. */
    public static final class Result {
        public final boolean success;
        public final Path library;
        public final String log;
        public Result(boolean success, Path library, String log) {
            this.success = success; this.library = library; this.log = log;
        }
    }

    private final String userCc;
    private final Path javaHome;

    public NativeCompiler(String userCc) {
        this.userCc = userCc;
        this.javaHome = Paths.get(System.getProperty("java.home")).getParent();
    }

    public Result compile(Path cSource, Path outputDir, String libName) {
        List<String> cmd = new ArrayList<>();
        String cc = pickCompiler();
        if (cc == null) {
            return new Result(false, null, "No C compiler found (set cc= in config or install gcc/clang/MSVC).");
        }
        Path libOut = outputDir.resolve(libFileName(libName));
        cmd.add(cc);
        cmd.add("-shared");
        cmd.add("-fPIC");              // ignored by MSVC; harmless on gcc/clang
        cmd.add("-fvisibility=hidden"); // hide non-JNIEXPORT symbols (only JNI_OnLoad exported)
        cmd.add("-s");                 // strip .symtab: no static identifier names (leaks KBOX_* table names)
        cmd.add("-O2");
        cmd.add("-I"); cmd.add(normalizeJdkInclude());
        String plat = platformInclude();
        if (plat != null) {
            Path p = Paths.get(normalizeJdkInclude()).resolve(plat);
            cmd.add("-I"); cmd.add(p.toString());
        }
        // MSVC uses different syntax; detect and switch.
        if (cc.toLowerCase(Locale.ROOT).endsWith("cl.exe") || cc.toLowerCase(Locale.ROOT).endsWith("cl")) {
            cmd.clear();
            cmd.add(cc);
            cmd.add("/LD");                 // build DLL
            cmd.add("/O2");
            cmd.add("/I"); cmd.add(normalizeJdkInclude());
            if (plat != null) cmd.add("/I:" + normalizeJdkInclude() + "/" + plat);
            cmd.add(cSource.toString());
            cmd.add("/Fe:" + libOut.toString());
        } else {
            cmd.add("-o"); cmd.add(libOut.toString());
            cmd.add(cSource.toString());
        }
        KBoxLog.info(TAG, "Compiling native lib: " + String.join(" ", cmd));
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            enrichPath(pb, cc);
            Process p = pb.start();
            // Consume output in background thread to avoid pipe deadlock.
            java.io.ByteArrayOutputStream outBuf = new java.io.ByteArrayOutputStream();
            Thread drainer = new Thread(() -> {
                try {
                    p.getInputStream().transferTo(outBuf);
                } catch (IOException ignored) {}
            });
            drainer.start();
            int code = p.waitFor();
            drainer.join(5000);
            String out = outBuf.toString(StandardCharsets.UTF_8);
            if (code == 0 && Files.exists(libOut)) {
                KBoxLog.info(TAG, "Native lib built: " + libOut);
                return new Result(true, libOut, out);
            }
            return new Result(false, null, out);
        } catch (IOException | InterruptedException e) {
            return new Result(false, null, "Compile failed: " + e);
        }
    }

    /** Selects a compiler: user config > env > auto-discover. */
    private String pickCompiler() {
        if (userCc != null && !userCc.isEmpty()) return userCc;
        String envCc = System.getenv("CC");
        if (envCc != null && !envCc.isEmpty()) return envCc;
        // Auto-discover.
        if (isWindows()) {
            String[] cands = {"cl.exe", "C:\\msys64\\mingw64\\bin\\gcc.exe",
                    "C:\\msys64\\mingw32\\bin\\gcc.exe", "gcc.exe", "clang.exe"};
            for (String c : cands) {
                if (findOnPath(c) != null) return c;
            }
        } else {
            for (String c : new String[]{"gcc", "clang", "cc"}) {
                if (findOnPath(c) != null) return c;
            }
        }
        return null;
    }

    private String findOnPath(String exe) {
        String path = System.getenv("PATH");
        if (path == null) return null;
        for (String dir : path.split(isWindows() ? ";" : ":")) {
            if (dir.isEmpty()) continue;
            try {
                Path p = Paths.get(dir).resolve(exe);
                if (Files.exists(p)) return p.toString();
            } catch (Exception ignored) {}
        }
        return null;
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }

    private static String normalizeJdkInclude() {
        // Prefer JAVA_HOME (a full JDK ships jni.h; some JREs do not), then the
        // running JVM's java.home, then java.home's parent. Verify the platform
        // subdir (win32/darwin/linux) exists so the returned path always works.
        String[] candidates = {
                System.getenv("JAVA_HOME"),
                System.getProperty("java.home"),
        };
        String plat = platformInclude();
        for (String h : candidates) {
            if (h == null || h.isEmpty()) continue;
            java.nio.file.Path inc = java.nio.file.Paths.get(h).resolve("include");
            if (java.nio.file.Files.isDirectory(inc)) return inc.toString();
            // JRE layout: java.home/lib vs JDK layout: $JAVA_HOME.
            if (java.nio.file.Files.isDirectory(inc.resolve(plat))) return inc.toString();
        }
        java.nio.file.Path jh = java.nio.file.Paths.get(System.getProperty("java.home"));
        java.nio.file.Path inc = jh.resolve("include");
        if (java.nio.file.Files.isDirectory(inc)) return inc.toString();
        java.nio.file.Path parent = jh.getParent();
        if (parent != null) {
            inc = parent.resolve("include");
            if (java.nio.file.Files.isDirectory(inc)) return inc.toString();
        }
        return jh.resolve("include").toString();
    }

    private static String platformInclude() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return "win32";
        if (os.contains("mac") || os.contains("darwin")) return "darwin";
        if (os.contains("nux") || os.contains("nix")) return "linux";
        return null;
    }

    private static String libFileName(String base) {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.contains("win")) return base + ".dll";
        if (os.contains("mac") || os.contains("darwin")) return "lib" + base + ".dylib";
        return "lib" + base + ".so";
    }

    /** Escapes backslash and double-quote for embedding in a C string literal. */
    private static String escapeC(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 4);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') sb.append("\\\\");
            else if (c == '"') sb.append("\\\"");
            else sb.append(c);
        }
        return sb.toString();
    }

    /**
     * Assembles C source for interpreter-based stubs (no JNI_OnLoad needed —
     * the interpreter is linked directly). Each stub is a self-contained C
     * function with its bytecode and CP arrays baked in.
     *
     * @param classMethodCounts owner class (internal, '/'-separated) -> method
     *        name -> number of methods with that name in the class. The JVM
     *        resolves a native method's JNI symbol by the SHORT name when the
     *        method name is unique in its class, and by the LONG name
     *        ({@code __} + JNI-mangled argument list) when the class overloads
     *        it. The count must therefore cover every method of the class
     *        (translated or not) so the emitted export symbol always matches
     *        what the VM looks up.
     */
    public static String assembleInterpSource(List<JniBytecodeInterp.InterpFn> fns,
                                              java.util.Map<String, java.util.Map<String, Integer>> classMethodCounts) {
        StringBuilder sb = new StringBuilder();
        sb.append("/* KBox-JNIC interpreter-based stubs. Do not edit. */\n");
        sb.append("#include <jni.h>\n");
        sb.append("#include <stdint.h>\n");
        sb.append("#include <stdlib.h>\n");
        sb.append("#include <string.h>\n");
        sb.append("#include <stdio.h>\n");
        // <math.h> supplies the NAN / INFINITY macros used by generated hex-float
        // and special-value constant arrays (NaN, +-Infinity LDC constants).
        sb.append("#include <math.h>\n\n");
        // Forward-declare the v3 interpreter (encrypted bytecode + execution erasure).
        sb.append("typedef union { jint i; jlong l; jfloat f; jdouble d; } kbox_value_t;\n");
        sb.append("kbox_value_t kbox_jvm_interp_v3(JNIEnv*, jobject, const unsigned char*, int, void**, int, int, uint8_t*);\n\n");
        for (JniBytecodeInterp.InterpFn fn : fns) {
            sb.append(fn.cBody).append("\n");
        }

        // Group by javaClass.
        java.util.Map<String, java.util.List<JniBytecodeInterp.InterpFn>> byClass = new java.util.LinkedHashMap<>();
        for (JniBytecodeInterp.InterpFn f : fns) {
            byClass.computeIfAbsent(f.javaClass, k -> new java.util.ArrayList<>()).add(f);
        }

        // === JNI_OnLoad: minimal. ===
        sb.append("\n/* === JNI_OnLoad: minimal. === */\n");
        sb.append("JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {\n");
        sb.append("  (void)reserved;\n");
        sb.append("  return JNI_VERSION_1_8;\n");
        sb.append("}\n\n");

        // === Java-side RegisterNatives entry point. ===
        // Called from ResourceGuardClassLoader after the JNIC class is loaded.
        sb.append("/* === registerNatives0 (called from Java). === */\n");
        sb.append("JNIEXPORT void JNICALL Java_com_kbox_runtime_NativeLoader_registerNatives0\n");
        sb.append("    (JNIEnv* env, jclass loaderClass, jclass targetClass) {\n");
        sb.append("  (void)loaderClass;\n");
        sb.append("  char _targetName[512] = {0};\n");
        sb.append("  {\n");
        sb.append("    jclass _clsCls = (*env)->GetObjectClass(env, targetClass);\n");
        sb.append("    jmethodID _nm = _clsCls ? (*env)->GetMethodID(env, _clsCls, \"getName\", \"()Ljava/lang/String;\") : NULL;\n");
        sb.append("    jstring _ns = _nm ? (jstring)(*env)->CallObjectMethod(env, targetClass, _nm) : NULL;\n");
        sb.append("    const char* _c = _ns ? (*env)->GetStringUTFChars(env, _ns, NULL) : NULL;\n");
        sb.append("    if (_c) { strncpy(_targetName, _c, sizeof(_targetName)-1); (*env)->ReleaseStringUTFChars(env, _ns, _c); }\n");
        sb.append("    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);\n");
        sb.append("  }\n");
        int regIdx = 0;
        for (java.util.Map.Entry<String, java.util.List<JniBytecodeInterp.InterpFn>> e : byClass.entrySet()) {
            java.util.List<JniBytecodeInterp.InterpFn> group = e.getValue();
            String dotted = e.getKey().replace('/', '.');
            sb.append("  static JNINativeMethod _methods").append(regIdx).append("[] = {\n");
            for (JniBytecodeInterp.InterpFn f : group) {
                sb.append("    { \"").append(escapeC(f.javaName)).append("\", \"")
                        .append(escapeC(f.javaDesc)).append("\", (void*)").append(f.symbol).append(" },\n");
            }
            sb.append("  };\n");
            sb.append("  if (strcmp(_targetName, \"").append(escapeC(dotted)).append("\") == 0) {\n");
            sb.append("    if ((*env)->RegisterNatives(env, targetClass, _methods").append(regIdx)
                    .append(", ").append(group.size()).append(") != 0) {\n");
            sb.append("      if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);\n");
            sb.append("    }\n");
            sb.append("  }\n");
            regIdx++;
        }
        sb.append("}\n\n");

        // === JNI-named exports with correct parameter types. ===
        // The JVM validates declared JNI parameter types against the Java signature.
        // Using 'jobject' for arrays causes "Non-array passed to JNI array operations"
        // crashes; we must emit 'jobjectArray' for any array descriptor.
        sb.append("/* === JNI-named exports (correct param types). === */\n");
        for (JniBytecodeInterp.InterpFn fn : fns) {
            // JNI-named export. The JVM resolves a native method by the SHORT
            // name `Java_pkg_Cls_meth` when the class has no other method with
            // the same name, and by the LONG name (`__` + JNI-mangled argument
            // list) when the name is overloaded. Emit the exact symbol the VM
            // looks up for this method. (RegisterNatives0, the primary path for
            // guard-loader products, is unaffected — it binds the opaque
            // interpreter stub symbols directly.) Overloaded methods (same
            // name, different desc) would collide on the bare symbol and fail
            // gcc with "redefinition/conflicting types", which is why the
            // long name is mandatory for them.
            boolean overloaded = false;
            java.util.Map<String, Integer> nameCounts = classMethodCounts.get(fn.javaClass);
            if (nameCounts != null && nameCounts.getOrDefault(fn.javaName, 0) > 1) {
                overloaded = true;
            }
            String shortSym = "Java_" + mangleJni(fn.javaClass) + "_" + mangleJni(fn.javaName);
            String longSym = shortSym + jniSigSuffix(fn.javaDesc);
            String bodySym = overloaded ? longSym : shortSym;
            StringBuilder cParams = new StringBuilder("JNIEnv* env, jclass cls");
            StringBuilder callArgs = new StringBuilder("env, NULL");
            int argIdx = 0;
            if (fn.javaDesc != null && fn.javaDesc.startsWith("(")) {
                int endIdx = fn.javaDesc.indexOf(')');
                for (int i = 1; i < endIdx; ) {
                    char ch = fn.javaDesc.charAt(i);
                    if (ch == '[') {
                        // Array type — emit jobjectArray regardless of nesting/element.
                        cParams.append(", jobjectArray a").append(argIdx);
                        // Skip all '[' and the element type.
                        while (i < endIdx && fn.javaDesc.charAt(i) == '[') i++;
                        if (i < endIdx && fn.javaDesc.charAt(i) == 'L') {
                            while (i < endIdx && fn.javaDesc.charAt(i) != ';') i++;
                        }
                        i++; // skip element type char or ';'
                    } else if (ch == 'L') {
                        // Object type.
                        cParams.append(", jobject a").append(argIdx);
                        while (i < endIdx && fn.javaDesc.charAt(i) != ';') i++;
                        i++; // skip ';'
                    } else {
                        // Primitive.
                        if (ch == 'Z') cParams.append(", jboolean a").append(argIdx);
                        else if (ch == 'B') cParams.append(", jbyte a").append(argIdx);
                        else if (ch == 'C') cParams.append(", jchar a").append(argIdx);
                        else if (ch == 'S') cParams.append(", jshort a").append(argIdx);
                        else if (ch == 'I') cParams.append(", jint a").append(argIdx);
                        else if (ch == 'J') cParams.append(", jlong a").append(argIdx);
                        else if (ch == 'F') cParams.append(", jfloat a").append(argIdx);
                        else if (ch == 'D') cParams.append(", jdouble a").append(argIdx);
                        else cParams.append(", jobject a").append(argIdx);
                        i++;
                    }
                    // The interpreter stub (`<symbol>`) declares each parameter with its
                    // JVM-matching C type (jobject for object/array, jint/jlong/... for
                    // primitives). Cast each argument to THAT type so primitives are not
                    // widened to a pointer (which would corrupt the primitive value and
                    // fail to compile with -Wint-conversion).
                    callArgs.append(", (").append(cArgType(fn.javaDesc, argIdx)).append(")a").append(argIdx);
                    argIdx++;
                }
            }
            String returnPart = fn.javaDesc.substring(fn.javaDesc.indexOf(')') + 1);
            // The interpreter stub stores all 32-bit primitives in a jint slot and
            // declares its C return type accordingly (jint for I/Z/B/C/S). Keep the
            // export's declared return type identical to the stub so the direct
            // `return fn.symbol(...)` compiles without -Wint-conversion (the JNI
            // descriptor string determines the true JVM signature at registration).
            String retC;
            if ("V".equals(returnPart)) retC = "void";
            else if ("I".equals(returnPart) || "Z".equals(returnPart)
                    || "B".equals(returnPart) || "C".equals(returnPart)
                    || "S".equals(returnPart)) retC = "jint";
            else if ("J".equals(returnPart)) retC = "jlong";
            else if ("F".equals(returnPart)) retC = "jfloat";
            else if ("D".equals(returnPart)) retC = "jdouble";
            else retC = "jobject";
            emitJniExport(sb, retC, bodySym, cParams.toString(), callArgs.toString(), returnPart, fn.symbol);
            // Extra symbols so either lookup style resolves:
            //   - non-overloaded: the VM uses the short name, but a long-name
            //     wrapper keeps overload-style lookups working too.
            //   - overloaded no-arg: the long name is the bare symbol; some VMs
            //     append `__` with an empty argument list, so cover that too.
            if (!overloaded) {
                if (!longSym.equals(shortSym)) {
                    emitJniWrapper(sb, retC, longSym, cParams.toString(), callArgs.toString(), shortSym, returnPart);
                }
            } else if (jniSigSuffix(fn.javaDesc).isEmpty()) {
                emitJniWrapper(sb, retC, shortSym + "__", cParams.toString(), callArgs.toString(), shortSym, returnPart);
            }
        }
        sb.append("\n");
        return sb.toString();
    }

    /** Emits a JNI-exported function body that forwards to the interpreter stub. */
    private static void emitJniExport(StringBuilder sb, String retC, String sym,
                                      String cParams, String callArgs, String returnPart, String stubSym) {
        sb.append("JNIEXPORT ").append(retC).append(" JNICALL ").append(sym)
                .append("(").append(cParams).append(") {\n");
        sb.append("  (void)cls;\n");
        if ("V".equals(returnPart)) {
            sb.append("  ").append(stubSym).append("(").append(callArgs).append(");\n");
            sb.append("  return;\n");
        } else {
            sb.append("  return ").append(stubSym).append("(").append(callArgs).append(");\n");
        }
        sb.append("}\n");
    }

    /** Emits a JNI-exported wrapper that forwards to another export symbol. */
    private static void emitJniWrapper(StringBuilder sb, String retC, String sym,
                                       String cParams, String callArgs, String target, String returnPart) {
        sb.append("JNIEXPORT ").append(retC).append(" JNICALL ").append(sym)
                .append("(").append(cParams).append(") {\n");
        sb.append("  (void)cls;\n");
        if ("V".equals(returnPart)) {
            sb.append("  ").append(target).append("(").append(callArgs).append(");\n");
            sb.append("  return;\n");
        } else {
            sb.append("  return ").append(target).append("(").append(callArgs).append(");\n");
        }
        sb.append("}\n");
    }

    /**
     * Returns the C type used by the interpreter stub ({@code <symbol>}) for the
     * given argument index, matching {@link JniCTranslator#cType}. The JNI-named
     * export declares the precise JVM type (jboolean/jbyte/jchar/jshort/jint) but
     * the interpreter stub collapses all of these to {@code jint}, so the call
     * argument must be cast to that collapsed type to keep primitives as values
     * rather than widening them to pointers.
     */
    private static String cArgType(String desc, int argIdx) {
        int endIdx = desc.indexOf(')');
        for (int idx = 0, p = 1; p < endIdx; ) {
            char ch = desc.charAt(p);
            if (ch == '[') {
                while (p < endIdx && desc.charAt(p) == '[') p++;
                if (p < endIdx && desc.charAt(p) == 'L') {
                    while (p < endIdx && desc.charAt(p) != ';') p++;
                }
                p++;
                if (idx == argIdx) return "jobject";
                idx++;
            } else if (ch == 'L') {
                while (p < endIdx && desc.charAt(p) != ';') p++;
                p++;
                if (idx == argIdx) return "jobject";
                idx++;
            } else {
                if (idx == argIdx) {
                    switch (ch) {
                        case 'J': return "jlong";
                        case 'F': return "jfloat";
                        case 'D': return "jdouble";
                        case 'Z': case 'B': case 'C': case 'S': case 'I':
                        default:  return "jint";
                    }
                }
                idx++;
                p++;
            }
        }
        return "jobject";
    }

    /**
     * JNI signature suffix used in the LONG export symbol for overloaded
     * methods: {@code __} + the JNI-mangled parameter list (primitive letters
     * kept, reference types as the mangled class name without the leading 'L'
     * and with the trailing ';' encoded as '_2', arrays as '_3' + element).
     * Returns "" for a descriptor with no parameters — the long name of a
     * no-arg method is the bare symbol.
     */
    private static String jniSigSuffix(String desc) {
        if (desc == null || !desc.startsWith("(")) return "";
        int endIdx = desc.indexOf(')');
        if (endIdx <= 1) return ""; // no parameters -> bare symbol
        StringBuilder sb = new StringBuilder("__");
        for (int p = 1; p < endIdx; ) {
            char ch = desc.charAt(p);
            if (ch == '[') {
                sb.append("_3");
                p++;
            } else if (ch == 'L') {
                p++; // consume 'L' (omitted from the mangled form)
                int start = p;
                while (p < endIdx && desc.charAt(p) != ';') p++;
                sb.append(mangleJni(desc.substring(start, p)));
                if (p < endIdx) {
                    sb.append("_2"); // trailing ';' of the reference type
                    p++;
                }
            } else {
                sb.append(ch); // Z B C S I J F D
                p++;
            }
        }
        return sb.toString();
    }

    /**
     * JNI symbol mangling per the JNI naming rules: '/'→'_', '_'→"_1",
     * ';'→"_2", '['→"_3", '$'→"_00024" and any other non-alphanumeric
     * character→"_0xxxx" (4 lowercase hex digits). Applied to the class name
     * and method name parts of both the short and long JNI export symbols.
     */
    private static String mangleJni(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '/') sb.append('_');
            else if (c == '_') sb.append("_1");
            else if (c == ';') sb.append("_2");
            else if (c == '[') sb.append("_3");
            else if (c == '$') sb.append("_00024");
            else if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')) sb.append(c);
            else sb.append(String.format("_0%04x", (int) c));
        }
        return sb.toString();
    }

    /** Helper invoked by the packager to write the C source to disk. */
    public static Path writeSource(Path dir, String libName, String src) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve(libName + ".c");
        Files.write(p, src.getBytes(StandardCharsets.UTF_8));
        return p;
    }

    /**
     * Writes the KBox JNIC bytecode interpreter (v3 enhanced) alongside generated stubs.
     * Returns the path to the written file, or null if the resource is not found.
     *
     * <p>v3 ({@code kbox_jnic_interp_v3.c}) is the only interpreter and is always
     * bundled in the same jar as this class, so there is deliberately no legacy
     * fallback: the legacy {@code kbox_jvm_interp.c} used a different (sequential)
     * CP/bytecode layout and exported a different symbol, so falling back to it
     * would guarantee a link failure against the generated {@code kbox_jvm_interp_v3}
     * stubs. If v3 is ever absent we fail cleanly rather than emit a broken build.
     */
    public static Path writeInterpreterSource(Path dir) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve("kbox_jnic_interp.c");
        java.io.InputStream is = NativeCompiler.class.getClassLoader()
                .getResourceAsStream("kbox_jnic_interp_v3.c");
        if (is == null) {
            KBoxLog.warn(TAG, "No interpreter source found in resources");
            return null;
        }
        byte[] data = is.readAllBytes();
        is.close();
        String src = com.kbox.core.nativeshell.NativeShellGuard.guardSource(
                new String(data, StandardCharsets.UTF_8));
        Files.write(p, src.getBytes(StandardCharsets.UTF_8));
        KBoxLog.info(TAG, "Wrote interpreter: " + p);
        return p;
    }

    /**
     * Writes the KBox VMP native interpreter source ({@code kbox_vmp_core.c})
     * from the engine resources to disk. Returns the path, or null if the
     * resource is not present in this engine build.
     */
    public static Path writeVmpSource(Path dir) throws IOException {
        Files.createDirectories(dir);
        Path p = dir.resolve("kbox_vmp_core.c");
        java.io.InputStream is = NativeCompiler.class.getClassLoader()
                .getResourceAsStream("kbox_vmp_core.c");
        if (is == null) {
            KBoxLog.warn(TAG, "kbox_vmp_core.c not found in resources (VM原生化 unavailable)");
            return null;
        }
        byte[] data = is.readAllBytes();
        is.close();
        String src = com.kbox.core.nativeshell.NativeShellGuard.guardSource(
                new String(data, StandardCharsets.UTF_8));
        Files.write(p, src.getBytes(StandardCharsets.UTF_8));
        KBoxLog.info(TAG, "Wrote VMP interpreter source: " + p);
        return p;
    }

    /**
     * Compiles the VMP native interpreter ({@code kbox_vmp_core.c}) into a
     * shared library and packs it into the runtime blob shipped as
     * {@code META-INF/kbox/vmp.bin}. VM原生化 is a strictly optional hardening
     * layer: on any compile failure this returns null and the protected app
     * falls back to the byte-identical Java {@code VmpInterpreter}, so a broken
     * toolchain never breaks the output.
     *
     * @return the packed native blob, or null when the source is absent or the
     *         compile failed.
     */
    public static byte[] compileVmp(Path workDir, String userCc) throws IOException {
        Path vmpDir = workDir.resolve("kbox-vmp-native");
        Path src = writeVmpSource(vmpDir);
        if (src == null) return null;
        NativeCompiler compiler = new NativeCompiler(userCc);
        NativeCompiler.Result cres = compiler.compileMulti(
                java.util.Collections.singletonList(src), vmpDir, "kbox_vmp");
        if (!cres.success) {
            KBoxLog.warn(TAG, "VMP native compile failed (falling back to Java interpreter): "
                    + cres.log);
            try {
                java.nio.file.Files.write(
                        java.nio.file.Paths.get(System.getProperty("user.dir"), "vmp-gcc.log"),
                        cres.log.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            } catch (Exception ignored) {}
            return null;
        }
        byte[] blob = com.kbox.core.jnic.NativePacker.pack(cres.library).blob;
        KBoxLog.info(TAG, "VMP native lib packed: " + blob.length + " bytes (vmp.bin)");
        return blob;
    }

    /**
     * Compiles multiple C source files into a single shared library.
     */
    public Result compileMulti(List<Path> sources, Path outputDir, String libName) {
        List<String> cmd = new ArrayList<>();
        String cc = pickCompiler();
        if (cc == null) {
            return new Result(false, null, "No C compiler found.");
        }
        Path libOut = outputDir.resolve(libFileName(libName));
        cmd.add(cc);
        cmd.add("-shared");
        cmd.add("-fPIC");
        cmd.add("-fvisibility=hidden"); // hide non-JNIEXPORT symbols
        cmd.add("-s");                 // strip .symtab: no static identifier names
        cmd.add("-O2");
        cmd.add("-I"); cmd.add(normalizeJdkInclude());
        String plat = platformInclude();
        if (plat != null) {
            Path p = Paths.get(normalizeJdkInclude()).resolve(plat);
            cmd.add("-I"); cmd.add(p.toString());
        }
        // MSVC path
        if (cc.toLowerCase(Locale.ROOT).endsWith("cl.exe") || cc.toLowerCase(Locale.ROOT).endsWith("cl")) {
            cmd.clear();
            cmd.add(cc);
            cmd.add("/LD"); cmd.add("/O2");
            cmd.add("/I"); cmd.add(normalizeJdkInclude());
            if (plat != null) { String p = normalizeJdkInclude() + "\\" + plat; cmd.add("/I"); cmd.add(p); }
            for (Path s : sources) cmd.add(s.toString());
            cmd.add("/Fe:" + libOut.toString());
            // Strip symbols: /LINK /RELEASE removes debug info, /OPT:REF eliminates
            // unreferenced functions, /OPT:ICF folds identical functions.
            cmd.add("/link");
            cmd.add("/RELEASE");
            cmd.add("/OPT:REF");
            cmd.add("/OPT:ICF");
        } else {
            cmd.add("-o"); cmd.add(libOut.toString());
            for (Path s : sources) cmd.add(s.toString());
        }
        KBoxLog.info(TAG, "Compiling native lib (multi-file): " + String.join(" ", cmd));
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            enrichPath(pb, cc);
            Process p = pb.start();
            // Consume output in background thread to avoid pipe deadlock.
            java.io.ByteArrayOutputStream outBuf = new java.io.ByteArrayOutputStream();
            Thread drainer = new Thread(() -> {
                try {
                    p.getInputStream().transferTo(outBuf);
                } catch (IOException ignored) {}
            });
            drainer.start();
            int code = p.waitFor();
            drainer.join(5000);
            String out = outBuf.toString(StandardCharsets.UTF_8);
            if (code == 0 && Files.exists(libOut)) {
                KBoxLog.info(TAG, "Native lib built: " + libOut);
                return new Result(true, libOut, out);
            }
            return new Result(false, null, out);
        } catch (IOException | InterruptedException e) {
            return new Result(false, null, "Multi-compile failed: " + e);
        }
    }

    /**
     * Adds the compiler's bin directory to PATH so it can find its runtime DLLs
     * (e.g. libgcc_s_seh-1.dll, libwinpthread-1.dll for MinGW GCC).
     * For MSVC, also sets up INCLUDE and LIB from the VC Tools and Windows SDK
     * installations detected relative to the cl.exe path.
     */
    private static void enrichPath(ProcessBuilder pb, String cc) {
        try {
            Path ccParent = Paths.get(cc).getParent();
            if (ccParent != null) {
                String currentPath = pb.environment().getOrDefault("PATH", "");
                String binDir = ccParent.toAbsolutePath().toString();
                pb.environment().put("PATH", binDir + File.pathSeparator + currentPath);

                // MSVC-specific: detect VC Tools root and Windows SDK from the cl.exe path.
                String ccLower = cc.toLowerCase(Locale.ROOT);
                if (ccLower.endsWith("cl.exe") || ccLower.endsWith("cl")) {
                    setupMsvcEnvironment(pb, Paths.get(cc));
                }
            }
        } catch (Exception e) {
            KBoxLog.warn(TAG, "enrichPath failed: " + e.getMessage());
        }
    }

    /**
     * Configures INCLUDE and LIB for MSVC by walking up from cl.exe's bin
     * directory to find the VC Tools root and Windows Kits SDK.
     *
     * <p>Expected MSVC layout relative to cl.exe:
     * <pre>
     *   VC/Tools/MSVC/14.xx/bin/Hostx64/x64/cl.exe    &lt;-- cc path
     *   VC/Tools/MSVC/14.xx/include/                   &lt;-- VC includes
     *   VC/Tools/MSVC/14.xx/lib/x64/                   &lt;-- VC libs
     *   Windows Kits/10/Include/10.0.x/ucrt/           &lt;-- UCRT includes
     *   Windows Kits/10/Include/10.0.x/um/             &lt;-- Win SDK includes
     *   Windows Kits/10/Lib/10.0.x/um/x64/             &lt;-- Win SDK libs
     *   Windows Kits/10/Lib/10.0.x/ucrt/x64/           &lt;-- UCRT libs
     * </pre>
     */
    private static void setupMsvcEnvironment(ProcessBuilder pb, Path clExe) {
        try {
            // Walk up from bin/HostArch/TargetArch/cl.exe → bin → VC version → MSVC → Tools → VC
            // MSVC layout: .../MSVC/{ver}/bin/Hostx64/x64/cl.exe
            Path hostArch = clExe.getParent();           // bin/Hostx64/x64 (contains cl.exe)
            if (hostArch == null) return;
            Path binDir = hostArch.getParent().getParent(); // bin (skip Hostx64/)
            if (binDir == null) return;
            Path vcVersionDir = binDir.getParent();      // 14.xx.xxxxx
            if (vcVersionDir == null) return;
            Path msvcDir = vcVersionDir.getParent();     // MSVC
            if (msvcDir == null) return;
            Path toolsDir = msvcDir.getParent();         // Tools
            if (toolsDir == null) return;
            Path vcDir = toolsDir.getParent();           // VC

            String vcVersion = vcVersionDir.getFileName().toString();
            String vcInclude = vcVersionDir.resolve("include").toString();
            String vcLib = vcVersionDir.resolve("lib").resolve("x64").toString();

            // Find Windows Kits — look at the same level as VC
            Path windowsKits = vcDir.resolveSibling("Windows Kits").resolve("10");
            if (!Files.isDirectory(windowsKits)) {
                // Try drive-root fallback (D:\Windows Kits\10)
                Path driveRoot = vcDir.getRoot().resolve("Windows Kits").resolve("10");
                if (Files.isDirectory(driveRoot)) windowsKits = driveRoot;
                else {
                    KBoxLog.warn(TAG, "MSVC SDK not found: tried "
                            + vcDir.resolveSibling("Windows Kits").resolve("10")
                            + " and " + driveRoot);
                    return;
                }
            }

            // Find SDK version (e.g. 10.0.28000.0)
            Path sdkIncludeDir = windowsKits.resolve("Include");
            Path sdkLibDir = windowsKits.resolve("Lib");
            if (!Files.isDirectory(sdkIncludeDir) || !Files.isDirectory(sdkLibDir)) return;

            String sdkVersion = null;
            try (java.util.stream.Stream<Path> stream = Files.list(sdkIncludeDir)) {
                sdkVersion = stream
                        .filter(Files::isDirectory)
                        .map(p -> p.getFileName().toString())
                        .filter(n -> n.startsWith("10."))
                        .sorted((a, b) -> b.compareTo(a)) // latest first
                        .findFirst().orElse(null);
            }
            if (sdkVersion == null) return;

            String ucrtInclude = sdkIncludeDir.resolve(sdkVersion).resolve("ucrt").toString();
            String umInclude = sdkIncludeDir.resolve(sdkVersion).resolve("um").toString();
            String sharedInclude = sdkIncludeDir.resolve(sdkVersion).resolve("shared").toString();
            String winrtInclude = sdkIncludeDir.resolve(sdkVersion).resolve("winrt").toString();
            String cppwinrtInclude = sdkIncludeDir.resolve(sdkVersion).resolve("cppwinrt").toString();

            String ucrtLib = sdkLibDir.resolve(sdkVersion).resolve("ucrt").resolve("x64").toString();
            String umLib = sdkLibDir.resolve(sdkVersion).resolve("um").resolve("x64").toString();

            // Set INCLUDE
            String include = vcInclude + ";" + ucrtInclude + ";" + umInclude
                    + ";" + sharedInclude + ";" + winrtInclude + ";" + cppwinrtInclude;
            pb.environment().put("INCLUDE", include);

            // Set LIB
            String lib = vcLib + ";" + ucrtLib + ";" + umLib;
            pb.environment().put("LIB", lib);

            KBoxLog.info(TAG, "MSVC auto-detected: VC=" + vcVersion + " SDK=" + sdkVersion);
        } catch (Exception e) {
            KBoxLog.warn(TAG, "MSVC env detection failed: " + e.getMessage());
        }
    }
}
