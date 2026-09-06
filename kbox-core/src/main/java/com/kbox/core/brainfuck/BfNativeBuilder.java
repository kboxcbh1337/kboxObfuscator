package com.kbox.core.brainfuck;

import com.kbox.core.jnic.NativeCompiler;
import com.kbox.core.jnic.NativeImageHash;
import com.kbox.core.jnic.NativePacker;
import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 * Build-time builder for the <b>Brainfuck chaos</b> native decoder.
 *
 * <p>Pipeline:</p>
 * <ol>
 *   <li>Extract the hand-written C decoder {@code kbox_bf_loader.c} (a classpath
 *       resource) into the work directory.</li>
 *   <li>Compile it into a shared library for the current platform with
 *       {@link NativeCompiler}.</li>
 *   <li>Compress + encrypt it with {@link NativePacker} so the protected jar
 *       contains no plaintext native code (same {@code KBNL} blob format that
 *       {@code META-INF/kbox/native.bin} expects).</li>
 * </ol>
 *
 * <p>The resulting blob is embedded in the Brainfuck-protected jar and unpacked
 * at runtime by {@link com.kbox.runtime.NativeLoader} (which is also reused for
 * the JNIC pipeline — the two never coexist because Brainfuck mode disables
 * JNIC).</p>
 */
public final class BfNativeBuilder {

    private static final String TAG = "bf-native";
    /** Classpath resource name of the native C decoder. */
    private static final String C_SOURCE = "kbox_bf_loader.c";
    private static final String LIB_NAME = "kbox_bf_loader";

    /** 0..F lookup for {@link #hexArray}. */
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /* ------------------------------------------------------------------ */
    /* Plaintext source lists for the per-build encrypted tables. These    */
    /* MUST stay in sync with the plaintext fallbacks in kbox_bf_loader.c */
    /* (the #else branches under #ifdef KBOX_BF_ENCRYPTED).                */
    /* ------------------------------------------------------------------ */
    private static final String[] WINDOWS_MODULES = {
        "instrument.dll",   /* -javaagent / Attach-API instrumentation */
        "attach.dll",       /* Attach API bridge (Windows) */
        "jdk.attach.dll",   /* Attach API native (some JDK builds) */
        "jdwp.dll",         /* -Xrunjdwp debugger */
        "dt_socket.dll",    /* JDWP socket transport */
        "dt_shmem.dll",     /* JDWP shared-memory transport */
        "hprof.dll"         /* -Xrunhprof profiler */
    };

    private static final String[] MAC_MARKERS = {
        "libinstrument", "libattach", "jdk.attach",
        "libdt_socket",  "libjdwp",   "libhprof"
    };

    private static final String[] LINUX_MARKERS = {
        "libinstrument.so", "libinstrument.dylib",
        "libattach.so",     "libattach.dylib",
        "jdk.attach",       "/jdk.attach",
        "libdt_socket.so",  "libjdwp.so",   "libjdwp.dylib",
        "libhprof.so"
    };

    private static final String[] ARG_NEEDLES = {
        "-agentlib:", "-javaagent", "-agentpath",
        "-xrunjdwp",  "jdwp=",      "transport=dt_socket"
    };

    /* Critical API exports watched for user-land interception ("module!export").
     * These are the exact primitives a memory dumper / API hooker must touch;
     * a trampoline or IAT rewrite on any of them is a strong signal. MUST stay
     * in sync with the plaintext fallback table in kbox_bf_loader.c. */
    private static final String[] HOOK_NEEDLES = {
        "kernel32.dll!VirtualProtect",
        "kernel32.dll!VirtualAlloc",
        "kernel32.dll!ReadProcessMemory",
        "kernel32.dll!WriteProcessMemory",
        "kernel32.dll!GetProcAddress",
        "kernel32.dll!LoadLibraryA",
        "kernel32.dll!GetModuleHandleA",
        "kernel32.dll!IsDebuggerPresent",
        "kernel32.dll!GetThreadContext",
        "kernel32.dll!QueryPerformanceCounter",
        "ntdll.dll!NtQueryInformationProcess",
        "ntdll.dll!NtQuerySystemInformation",
        "ntdll.dll!NtReadVirtualMemory",
        "ntdll.dll!NtWriteVirtualMemory",
        "ntdll.dll!NtProtectVirtualMemory",
        "ntdll.dll!NtAllocateVirtualMemory"
    };

    /** Result of the build attempt. */
    public static final class Result {
        public final boolean success;
        /** Packed (compressed + encrypted) native blob, or null on failure. */
        public final byte[] packedBlob;
        /** Raw shared library path (for diagnostics), or null on failure. */
        public final Path library;
        public final String log;

        Result(boolean success, byte[] packedBlob, Path library, String log) {
            this.success = success;
            this.packedBlob = packedBlob;
            this.library = library;
            this.log = log;
        }
    }

    private BfNativeBuilder() {}

    /**
     * Builds the Brainfuck decoder native library and returns the packed blob.
     *
     * <p>The {@code sym} symbol set is baked into the compiled decoder as the
     * {@code KBOX_BF_PLUS/MINUS/DOT} macros, so the native side decodes with the
     * exact same per-build symbols that {@link BrainfuckPacker} used to encode
     * the payload. Two builds therefore never share a byte-identical decoder /
     * program pair (build-to-build polymorphism on the native side).</p>
     *
     * @param workDir directory to write the C source and compiled lib into.
     * @param cc      explicit C compiler (from config), may be null/empty.
     * @param sym     the per-build Brainfuck symbol set (must match the one used
     *                by {@link BrainfuckPacker#pack} for this build).
     */
    public static Result build(Path workDir, String cc, BfSymbolSet sym) throws IOException {
        Files.createDirectories(workDir);
        // Per-build salt for the native integrity self-hash. The SAME value is
        // compiled into the decoder (KBOX_TEXT_SALT, injected below) and used to
        // compute the expected image hash over the compiled library.
        long salt = new SecureRandom().nextInt() & 0xFFFFFFFFL;
        Path src = writeSource(workDir, sym, salt);

        NativeCompiler compiler = new NativeCompiler(cc);
        NativeCompiler.Result cres = compiler.compile(src, workDir, LIB_NAME);
        if (!cres.success) {
            KBoxLog.error(TAG, "Native compile failed: " + cres.log);
            return new Result(false, null, null, cres.log);
        }

        // Strip PE/ELF debug metadata (PDB paths, .debug* / .symtab / .strtab /
        // .comment toolchain strings, DEBUG data-directory) before hashing, so
        // the shipped decoder carries no debugger-walkable debug info nor a
        // toolchain fingerprint. MUST precede computeAndPatch: the expected hash
        // must cover exactly the shipped (stripped) image, and the runtime hash
        // skips the now-discardable sections identically.
        String stripLog = NativeImageHash.strip(cres.library);
        KBoxLog.info(TAG, "strip: " + stripLog);

        // Compute the expected integrity hash over the compiled image and patch
        // it into the .kboxexp section (build-time baseline; see kbox_selfCheck
        // in kbox_bf_loader.c). On failure the decoder falls back to a runtime
        // baseline, so this is hardening, not a hard dependency.
        NativeImageHash.Expected exp = NativeImageHash.computeAndPatch(cres.library, salt);
        KBoxLog.info(TAG, "self-hash: " + exp.log);

        try {
            NativePacker.Packed packed = NativePacker.pack(cres.library);
            KBoxLog.info(TAG, "BF decoder built + packed: raw=" + cres.library
                    + " blob=" + packed.blob.length + " bytes"
                    + " sym=(" + (int) sym.plus + "," + (int) sym.minus + ","
                    + (int) sym.right + "," + (int) sym.left + ","
                    + (int) sym.open + "," + (int) sym.close + ","
                    + (int) sym.dot + "," + (int) sym.comma + ")");
            return new Result(true, packed.blob, cres.library, cres.log);
        } catch (Exception e) {
            KBoxLog.warn(TAG, "Native packing failed: " + e.getMessage());
            return new Result(false, null, cres.library, "pack failed: " + e);
        }
    }

    /**
     * Copies {@code kbox_bf_loader.c} from the classpath into {@code workDir},
     * then injects the per-build {@code KBOX_BF_*} symbol macros at the top of
     * the source so the compiled decoder understands this build's Brainfuck
     * alphabet.
     */
    private static Path writeSource(Path workDir, BfSymbolSet sym, long salt) throws IOException {
        Path out = workDir.resolve(C_SOURCE);
        String source;
        try (InputStream in = BfNativeBuilder.class.getClassLoader()
                .getResourceAsStream(C_SOURCE)) {
            if (in == null) {
                throw new IOException("Missing classpath resource: " + C_SOURCE);
            }
            source = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        // Symbols are printable ASCII minus digits; emit as decimal byte values
        // so no escaping is ever needed in the C char context.
        StringBuilder defines = new StringBuilder(
                "/* KBox-BF per-build obfuscation material (injected by "
                + "BfNativeBuilder). */\n"
                + "#define KBOX_BF_PLUS " + (int) sym.plus + "\n"
                + "#define KBOX_BF_MINUS " + (int) sym.minus + "\n"
                + "#define KBOX_BF_RIGHT " + (int) sym.right + "\n"
                + "#define KBOX_BF_LEFT " + (int) sym.left + "\n"
                + "#define KBOX_BF_OPEN " + (int) sym.open + "\n"
                + "#define KBOX_BF_CLOSE " + (int) sym.close + "\n"
                + "#define KBOX_BF_DOT " + (int) sym.dot + "\n"
                + "#define KBOX_BF_COMMA " + (int) sym.comma + "\n"
                + "#define KBOX_BF_SEED " + sym.seed + "\n"
                // Per-build salt for the native integrity self-hash; MUST equal
                // the salt NativeImageHash uses to compute the expected hash.
                + "#define KBOX_TEXT_SALT 0x"
                + String.format("%08x", salt) + "u\n");
        // Per-build semantic dispatch permutation (0..7): canonical op i is
        // executed by handler slot dispatch[i], so the native interpreter's
        // opcode->semantic mapping is re-dealt every build.
        for (int i = 0; i < 8; i++) {
            defines.append("#define KBOX_BF_DISP_").append(i).append(' ')
                   .append(sym.dispatch[i]).append('\n');
        }
        // Inverse of the dispatch: KBOX_BF_DINV_k = the semantic executed by
        // handler slot k. The interpreter's switch case k runs opcode DINV_k, so
        // slot DISP[op] always falls on the opcode of `op` — correct for any
        // permutation, while every build assigns each case a different opcode.
        int[] dinv = new int[8];
        for (int i = 0; i < 8; i++) dinv[sym.dispatch[i]] = i;
        for (int i = 0; i < 8; i++) {
            defines.append("#define KBOX_BF_DINV_").append(i).append(' ')
                   .append(dinv[i]).append('\n');
        }
        defines.append('\n');
        String sourceWith = defines + source;

        // Splicing the XOR-encrypted material (detection signatures, JVM arg
        // needles, BF operator alphabet) between the markers the C decoder
        // declares for this purpose. When the markers are absent (e.g. the
        // resource drifted), keep the plaintext fallbacks inside the C source
        // so the build still works — encrypted material is a hardening layer,
        // not a compile-time dependency.
        String beginMarker = "/* KBOX_BF_ENCRYPTED_BEGIN */";
        String endMarker = "/* KBOX_BF_ENCRYPTED_END */";
        int bi = sourceWith.indexOf(beginMarker);
        int ei = sourceWith.indexOf(endMarker);
        if (bi >= 0 && ei > bi) {
            String injected = encryptedBlock(sym);
            sourceWith = sourceWith.substring(0, bi)
                       + beginMarker + "\n" + injected + endMarker
                       + sourceWith.substring(ei + endMarker.length());
        } else {
            KBoxLog.warn(TAG, "KBOX_BF_ENCRYPTED markers missing in " + C_SOURCE
                    + "; shipping plaintext fallback tables");
        }

        Files.write(out, sourceWith.getBytes(StandardCharsets.UTF_8));
        // Native shell hardening: apply the enhanced-shield passes (M1 string
        // erasure, M2 control-flow mutation + vendor scatter) to the BF decoder
        // source — the kboxShield carrier — before the toolchain compiles it.
        // Re-expresss the final text through guardSource so the decoder's
        // function-body literals become per-build XOR tables and its guard
        // functions get opaque-predicate preambles. No-op when nativeShell=0.
        String guarded = com.kbox.core.nativeshell.NativeShellGuard.guardSource(sourceWith);
        Files.write(out, guarded.getBytes(StandardCharsets.UTF_8));
        // The decoder #includes "kbox_reflect_loader.c" (in-memory PE32+ loader
        // for vmp.bin / jnic.bin) — extract it next to the decoder so gcc's
        // quote-include resolves it from the same work dir.
        try (InputStream rin = BfNativeBuilder.class.getClassLoader()
                .getResourceAsStream("kbox_reflect_loader.c")) {
            if (rin != null) {
                Files.write(workDir.resolve("kbox_reflect_loader.c"),
                        rin.readAllBytes());
            } else {
                KBoxLog.warn(TAG, "Missing classpath resource: kbox_reflect_loader.c"
                        + " (in-memory module mapping unavailable)");
            }
        }
        return out;
    }

    /**
     * Builds the C block injected between the KBOX_BF_ENCRYPTED_BEGIN/END
     * markers: a random 16-byte key and the XOR ciphertext for the canonical
     * BF alphabet plus every detection table. One random key per table; each
     * string is decrypted into a stack buffer for the duration of its own probe
     * and wiped immediately on the native side. Only the current platform's
     * module table is emitted, so the shipped binary carries no foreign
     * plaintext seed and no unused-table warnings.
     */
    private static String encryptedBlock(BfSymbolSet sym) {
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder(2048);
        sb.append("#define KBOX_BF_ENCRYPTED 1\n");
        sb.append("typedef struct { const unsigned char* enc; int len; } "
                + "kbox_enc_entry;\n");

        // Canonical operator alphabet (0=plus..7=comma), one symbol byte per
        // canonical semantic, XOR-encrypted so the BF symbol set never appears
        // in plaintext in the shipped binary. decrypts via canonAt().
        char[] canon = { sym.plus, sym.minus, sym.right, sym.left,
                         sym.open,  sym.close, sym.dot,   sym.comma };
        byte[] canonKey = new byte[16];
        rnd.nextBytes(canonKey);
        byte[] canonEnc = new byte[8];
        for (int i = 0; i < 8; i++) canonEnc[i] = (byte) (canon[i] ^ canonKey[i & 15]);
        sb.append("static const unsigned char KBOX_CANON_KEY[16] = {")
          .append(hexArray(canonKey)).append("};\n");
        sb.append("static const unsigned char KBOX_CANON_ENC[8] = {")
          .append(hexArray(canonEnc)).append("};\n");

        emitEncGroup(sb, rnd, "KBOX_ARGS", ARG_NEEDLES); // platform-independent
        sb.append("#if defined(_WIN32)\n");
        emitEncGroup(sb, rnd, "KBOX_WMODS", WINDOWS_MODULES);
        emitEncGroup(sb, rnd, "KBOX_HOOKS", HOOK_NEEDLES);
        sb.append("#endif\n");
        sb.append("#if defined(__APPLE__)\n");
        emitEncGroup(sb, rnd, "KBOX_MAC", MAC_MARKERS);
        sb.append("#endif\n");
        sb.append("#if !defined(_WIN32) && !defined(__APPLE__)\n");
        emitEncGroup(sb, rnd, "KBOX_LIN", LINUX_MARKERS);
        sb.append("#endif\n");
        return sb.toString();
    }

    /**
     * Emits one encrypted table: {@code <T>_KEY[16]} plus one static ciphertext
     * array per entry and the {@code kbox_enc_entry} list, all under a single
     * per-build random key. The native side decrypts entry by entry on a stack
     * buffer with {@code kbox_xdec(..., <T>_KEY)}.
     */
    private static void emitEncGroup(StringBuilder sb, SecureRandom rnd,
                                     String tableName, String[] strs) {
        byte[] key = new byte[16];
        rnd.nextBytes(key);
        String lower = tableName.toLowerCase();
        sb.append("static const unsigned char ").append(tableName).append("_KEY[16] = {")
          .append(hexArray(key)).append("};\n");
        for (int i = 0; i < strs.length; i++) {
            byte[] plain = strs[i].getBytes(StandardCharsets.US_ASCII);
            byte[] enc = new byte[plain.length];
            for (int j = 0; j < enc.length; j++) enc[j] = (byte) (plain[j] ^ key[j & 15]);
            sb.append("static const unsigned char ").append(lower).append('_').append(i)
              .append('[').append(enc.length).append("] = {").append(hexArray(enc))
              .append("};\n");
        }
        sb.append("static const kbox_enc_entry ").append(tableName).append("[] = {\n");
        for (int i = 0; i < strs.length; i++) {
            sb.append("    { ").append(lower).append('_').append(i)
              .append(", ").append(strs[i].length()).append(" },\n");
        }
        sb.append("};\n");
    }

    /** {@code 0xAA,0xBB,...} from a byte array (no trailing space). */
    private static String hexArray(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 5);
        for (int i = 0; i < a.length; i++) {
            if (i > 0) sb.append(',');
            int v = a[i] & 0xFF;
            sb.append("0x").append(HEX[v >>> 4]).append(HEX[v & 0xF]);
        }
        return sb.toString();
    }
}
