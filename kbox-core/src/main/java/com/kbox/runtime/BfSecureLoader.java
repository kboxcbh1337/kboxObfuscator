package com.kbox.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;
import java.nio.charset.StandardCharsets;

/**
 * Runtime class loader + entry point for the <b>Brainfuck chaos</b> scheme.
 *
 * <p>When a jar is protected with {@code brainfuckLoader=true}, its entire
 * content (obfuscated classes + resources) is packed into one payload
 * ({@code META-INF/kbox/classes.bf.rle}) and the manifest {@code Main-Class}
 * becomes this class. On startup:</p>
 *
 * <ol>
 *   <li>{@link NativeLoader#load()} unpacks and loads the native decoder
 *       (compressed + ChaCha20-encrypted {@code META-INF/kbox/native.bin}) —
 *       its {@code JNI_OnLoad} installs the 6&nbsp;TiB virtual-address dump trap.</li>
 *   <li>The RLE noise is handed to {@code init(byte[])}; the native decoder then
 *       performs RLE&rarr;Brainfuck&rarr;DEFLATE&rarr;raw-jar inflation entirely in
 *       <b>native heap</b>. The plaintext jar blob never exists as a Java
 *       {@code byte[]}, so a heap dump shows only RLE noise. The name&rarr;(offset,len)
 *       index is embedded as a signed header at the head of that same blob and is
 *       parsed <b>only inside native memory</b> — this class never holds an offset.</li>
 *   <li>{@link #findClass} resolves the class <b>by name</b> in native memory and
 *       defines it via JNI {@code DefineClass} (native pointer, no intermediate
 *       Java array). No (offset,len) reader exists anywhere in the public API, so
 *       there is no primitive left to enumerate or slice the blob out.</li>
 *   <li>{@link #main} reads the renamed entry point from
 *       {@code Original-Main-Class} and invokes its {@code main}.</li>
 * </ol>
 *
 * <p>This class (plus {@code NativeLoader} / {@code ChaCha20}) is injected as a
 * <b>plain</b> jar entry; everything else lives inside the Brainfuck payload.</p>
 */
public final class BfSecureLoader extends ClassLoader {

    private static final String _RP = "META-INF/kbox/classes.bf.rle";
    private static final String _MP = "META-INF/MANIFEST.MF";

    /** Caller-frame walk used to verify the <b>direct caller</b> of
     *  reflective-vulnerable entry points (constructor +
     *  {@link #defineClassFromBF}).
     *
     *  <p>Window of attack: an attacker who runs the protected jar on its own
     *  classpath (not via {@code -jar}) could {@code setAccessible(true)} a
     *  private convenience wrapper and reach the native define. The legit
     *  loading path always goes through this loader's own methods
     *  ({@link #findClass} / the constructor / {@link #attach}), so the gate
     *  checks the <b>immediate caller</b> is inside {@code com.kbox.runtime.} —
     *  NOT the thread root: a worker thread's root frame is always
     *  {@code java.lang.Thread.run}, and refusing it would break every
     *  application thread that loads classes through this loader (the
     *  pre-fix "KBox-BF: external define refused" in thread pools).</p>
     *
     *  <p>Fail-closed on any frame-walk anomaly.</p>
     */
    /** Frame kinds {@link java.lang.StackWalker#getCallerClass()} filters out
     *  (reflection, MethodHandle internals, hidden frames) regardless of the
     *  configured options. {@code Throwable.getStackTrace()} already omits
     *  hidden frames on Java 9+, so only the named packages need skipping. */
    private static boolean isFilteredFrame(String className) {
        return className.startsWith("java.lang.reflect.")
                || className.startsWith("jdk.internal.reflect.")
                || className.startsWith("sun.reflect.")
                || className.startsWith("java.lang.invoke.");
    }

    /** Returns true iff the immediate caller of this method is this loader
     *  itself (or another {@code com.kbox.runtime.} helper). A genuine
     *  {@code -jar} launch defines classes through {@link #findClass}; a
     *  reflective attacker calling {@code defineClassFromBF} directly roots
     *  the immediate caller in its own (external) class and is refused.
     *
     *  <p>Java-8-safe equivalent of {@code StackWalker#getCallerClass()}: walk
     *  the frames and return the first one above this method that is not a
     *  reflection / MethodHandle / hidden frame — the same resolver rule the
     *  original walker used (a reflective {@code Method.invoke} of
     *  {@code defineClassFromBF} therefore resolves to the attacker's class,
     *  not to the reflect machinery).</p> */
    private static boolean callerIsKbox() {
        try {
            StackTraceElement[] st = new Throwable().getStackTrace();
            // st[0] is this method's own frame; start at the caller.
            for (int i = 1; i < st.length; i++) {
                String n = st[i].getClassName();
                if (isFilteredFrame(n)) continue;
                return n.startsWith("com.kbox.runtime.");
            }
            return false;
        } catch (Throwable t) {
            return false; // fail-closed on any frame-walk anomaly
        }
    }

    static {
        // Load the Brainfuck decoder DLL/SO (unpacked from the packed blob).
        NativeLoader.load();
        // Static-init agent gate: catches an agent already mapped BEFORE the
        // bootstrap class is even initialized (covers reflection-style entry:
        // Class.forName triggers <clinit>, and we refuse to proceed if an agent
        // is present, so neither the constructor nor findClass can be reached).
        failIfAgentPresent();
        // Pull the native-loader's per-run epoch root and attach it to the Java
        // session layer (KbnlKey.attachEpochRoot). This routes the native load-time
        // time base into the ephemeral key feed; it never touches any domain seed
        // (see the blob-contract note in KbnlKey.sessionEpoch). Best-effort: if the
        // native side is unavailable the pure-Java session epoch still stands.
        try {
            byte[] nativeEpoch = epoch();
            if (nativeEpoch != null && nativeEpoch.length > 0) {
                KbnlKey.attachEpochRoot(nativeEpoch);
            }
        } catch (Throwable ignored) { }
    }

    /** Registers the RLE payload with the native decoder. Returns byte count. */
    private static native int init(byte[] rle);

    /** Registers the RLE payload directly from an OFF-HEAP direct buffer so the
     *  whole blob never rests in the Java heap. Native copies the noise into
     *  page-secure memory and wipes the out buffer. Returns byte count. */
    private static native int initDirect(ByteBuffer buf, int len);

    /** Defines one class by resolving its name inside the native jar blob.
     *  <p>Java-side wrapper that enforces a caller-class gate BEFORE the
     *  native define is reached: an attacker who {@code setAccessible(true)}
     *  on this private method cannot dump arbitrary class bytes from the
     *  native blob, because the immediate caller must itself live in the
     *  {@code com.kbox.} runtime package (i.e. {@link #findClass}). The
     *  actual JNI define happens in {@link #defineClassFromBFImpl}. */
    private Class<?> defineClassFromBF(String name) {
        if (!callerIsKbox()) {
            throw new SecurityException("KBox-BF: external define refused");
        }
        // The native blob decoder keeps mutable scratch state (decode buffers,
        // KBF2 index cursors). Application/analysis threads define classes
        // concurrently through this loader, so serialize the native define to
        // avoid a data race in kbox_bf_loader.c (seen as 0xC0000005 during
        // multi-threaded class analysis).
        synchronized (this) {
            return defineClassFromBFImpl(name);
        }
    }

    /** Native define: name resolved through the embedded KBF2 index, decoded
     *  transiently in native secure memory, defined via JNI DefineClass, and
     *  wipe+unmapped before returning. Do NOT call directly — go through
     *  {@link #defineClassFromBF} which checks the caller. */
    private native Class<?> defineClassFromBFImpl(String name);

    /** Copies a resource out of the native blob by exact name into an OFF-HEAP
     *  direct {@link java.nio.ByteBuffer} (never a Java heap {@code byte[]}), so
     *  the plaintext does not rest in the heap where a heap dump / memory
     *  scanner could find it. Class bytecode is deliberately NOT served here
     *  (fail-closed: reading {@code "<cls>.class"} as a resource would expose
     *  its plaintext; integrity checks must use {@link #probeClassFromBF}). The
     *  returned buffer must be released with {@link #wipeResource} once
     *  consumed. */
    private native java.nio.ByteBuffer getResourceBytes(String name);

    /** Wipes + unmaps an off-heap direct buffer returned by
     *  {@link #getResourceBytes}. Called by {@link BfBlobInputStream} as soon
     *  as the buffer is exhausted or closed, whichever comes first. */
    static native void wipeResource(java.nio.ByteBuffer buf);

    /**
     * Existence + integrity probe for a class WITHOUT materialising its plaintext
     * into the Java heap. The class is decoded transiently in native secure memory,
     * validated, and wipe+unmapped before returning — no plaintext byte ever
     * crosses into the heap. Accepts either the internal name ("a/b/C") or the
     * resource-style name ("a/b/C.class"). Returns true when present and intact.
     * Only meaningful in Brainfuck mode (the native decoder is present); callers
     * outside BF mode must fall back to a resource read.
     */
    static native boolean probeClassFromBF(String name);

    /** Best-effort zeroing + release of the native decode state. */
    private static native void wipe();

    /**
     * Opaque single-call boot gate, evaluated ENTIRELY in native (per-build
     * polymorphic native.bin): probes for agent / debugger shared libraries
     * mapped into this process (Windows GetModuleHandle / POSIX /proc/self/maps)
     * and scans the JVM input arguments for agent/debugger markers. All detection
     * patterns live in native code, so the readable plaintext bootstrap class
     * contains none of them — a static reader cannot see what is checked, and a
     * bootstrap that had this call stripped is still re-gated natively at every
     * class definition. Returns true when an agent/debugger is present.
     */
    private static native boolean safeBoot(String[] jvmArgs);

    /**
     * Maps a decrypted PE module (vmp.bin / jnic.bin) entirely in-memory — never
     * writing it to disk — and binds its exported registrar
     * ({@code registerNatives0} / {@code registerVmpNatives0}) onto
     * {@link NativeLoader}. Windows-only: on non-Windows or any mapping failure
     * returns {@code false} so {@link NativeLoader} falls back to the
     * temp-file + purge path. Registered by the resident native decoder's
     * {@code JNI_OnLoad}.
     */
    static native boolean mapModule(byte[] pe, String binderName);

    /**
     * Purges the temporary bootstrap PE ({@code native.bin}) from disk
     * immediately after {@code System.load} mapped it. On Windows the image
     * section keeps the mapped pages valid but refuses deletion while it is
     * mapped (delete-pending / {@code DeleteFileW} both return
     * {@code ACCESS_DENIED}), so the resident decoder renames the module to a
     * random hidden name — the one operation the OS permits on a mapped image —
     * commits a POSIX delete-pending (frees the content when the section closes)
     * and schedules a delete-at-reboot. The still-on-disk path (the renamed
     * name) is returned so the caller can purge it at exit; {@code null} means
     * the file was fully removed. On POSIX plain unlink works because a loaded
     * {@code .so} keeps its inode until unmapped. Registered by the resident
     * native decoder's {@code JNI_OnLoad}.
     */
    static native String purgeSelf(String path);

    /** Per-run native session epoch (32 bytes), mixed from the loader's load-time
     *  time base. Volatile across processes by design; consumed by the session layer
     *  (KbnlKey.sessionEpoch). NEVER folded into a blob/domain seed (see the
     *  blob-contract note in KbnlKey.sessionEpoch). */
    static native byte[] epoch();

    /** D7 cold-section self-wipe. {@code mask & 0xFF == 0xFF} additionally purges
     *  the live encoded archive (safe only at JVM shutdown); any other mask is a
     *  light scrub (icache flush + scratch wipe). Best-effort; fail-open. */
    static native int nativeSelfWipe(int mask);

    /** Environment re-probe by the resident native decoder. Returns a bitmask:
     *  <pre>
     *    bit0 = agent / injection module mapped (Frida / .NET-CLR mscoree /
     *           coreclr / debugger helper — see the decoder's module table)
     *    bit1 = registry tamper vector armed (AppInit_DLLs / AppCertDlls / IFEO)
     *    bit2 = Frida in-memory feature found (private-memory scan)
     *    bit3 = strong debugger signal (PEB / debug port / hardware BP)
     *    bit4 = JVMTI hook capability present (ClassFileLoadHook / retransform)
     *    bit5 = any loaded module exports a JVMTI agent entry point
     *           (Agent_OnLoad / Agent_OnAttach / Agent_OnUnload) — a renamed /
     *           arbitrary -agentpath or attach DLL the module-name table cannot
     *           match, detected name-independently by export signature.
     *  </pre>
     *  0 means a clean environment. Only meaningful in Brainfuck mode (the
     *  resident decoder is present); callers outside BF must treat it as 0.
     *  Registered by the decoder's {@code JNI_OnLoad}. */
    static native int probeEnv();

    /** Native hard-kill. Wipes every live plaintext window (the same
     *  fail-closed path the native W1/W2 watchdogs use) then terminates the
     *  process with {@code code}. Never returns on success. */
    static native void terminate(int code);

    /** Periodic environment re-check ("runtime watchdog"): every
     *  {@code intervalMs} (clamped to &ge; 500) asks the resident native decoder
     *  for a fresh injection / tamper probe and hard-kills the process on any
     *  signal (bit0..3 non-zero). Complements the native W1/W2 mutual-sentinel
     *  threads with an application-visible heartbeat. Idempotent: only the
     *  first call starts the single shared daemon thread. No-op when the native
     *  decoder is absent (non-BF jar / already shutting down). */
    static void startRuntimeWatchdogs(long intervalMs) {
        if (intervalMs < 500) intervalMs = 500;
        final long iv = intervalMs;
        synchronized (BfSecureLoader.class) {
            if (_runtimeWd != null) return;
            _runtimeWd = new Thread(() -> {
                for (;;) {
                    try {
                        Thread.sleep(iv);
                    } catch (InterruptedException e) {
                        return;
                    }
                    int m;
                    try {
                        m = probeEnv();
                    } catch (Throwable ignored) {
                        return;   // decoder unloaded / shutdown — stop probing
                    }
                    if (m != 0) {
                        try {
                            terminate(0x6B);   // 0x6B = runtime-watchdog kill
                        } catch (Throwable ignored) {
                            // native side never returns; ignore if already gone
                        }
                        return;
                    }
                }
            }, "kbox-watchdog-java");
            _runtimeWd.setDaemon(true);
            _runtimeWd.start();
        }
    }

    private static volatile Thread _runtimeWd;

    /** Whether a JNIC native lib was loaded (enables per-class native registration). */
    private final boolean _jl;

    private BfSecureLoader() {
        // Parent is the system class loader, which already holds the injected
        // plain runtime classes (this loader, NativeLoader, ChaCha20, ...).
        super(BfSecureLoader.class.getClassLoader());
        // Caller-class gate: refuse reflective construction from outside the
        // kbox runtime package. Without this, an attacker who
        // setAccessible(true)s the private constructor can instantiate the
        // loader directly (skipping main()'s safeBoot agent gate) and then
        // call defineClassFromBF to extract arbitrary class bytes from the
        // BF blob. main() is itself in BfSecureLoader.class so legitimate
        // construction (the only intended caller) is unaffected.
        if (!callerIsKbox()) {
            throw new SecurityException("KBox-BF: external construction refused");
        }
        // Per-instance agent gate: catches an agent loaded AFTER <clinit> but
        // BEFORE the constructor runs (defense-in-depth — together with the
        // caller gate this closes both reflection-without-agent and
        // reflection-with-agent entry paths).
        failIfAgentPresent();
        ByteBuffer rle = readBlobDirect(_RP);
        if (rle == null) {
            throw new IllegalStateException("KBox-BF: missing " + _RP);
        }
        int n = initDirect(rle, rle.limit());
        // Drop the Java reference to the RLE noise; native copied + wiped the
        // out buffer, so nothing meaningful stays behind. It was never a heap
        // byte[], only an off-heap direct buffer.
        rle = null;
        if (n < 0) {
            throw new IllegalStateException("KBox-BF: native init failed");
        }
        // JNIC co-existence: if the jar carries a JNIC lib (META-INF/kbox/jnic.bin),
        // load it now so native methods on blob classes can be registered later.
        _jl = NativeLoader.loadJnic();
        Runtime.getRuntime().addShutdownHook(new Thread(BfSecureLoader::wipe));
    }

    // ------------------------------------------------------------------
    // MC-mod hybrid attach point
    // ------------------------------------------------------------------

    /** Singleton holder for BF-MC hybrid mode (no Main-Class execution: the mod
     *  loader instantiates the entry classes directly, so an entry class' <clinit>
     *  calls {@link #attach()} to decode the blob once). */
    private static volatile BfSecureLoader _hybrid;

    /**
     * Attaches the BF loader from a plaintext MC entry class. Idempotent.
     * In hybrid mode the loader-critical surface (metadata / entry classes /
     * mixin package) is plaintext, so the default parent-first {@code loadClass}
     * resolves those from the mod loader and {@code findClass} only serves the
     * blob — exactly the mixed jar layout the packer produces.
     */
    public static void attach() {
        if (_hybrid != null) return;
        synchronized (BfSecureLoader.class) {
            if (_hybrid != null) return;
            _hybrid = new BfSecureLoader();
        }
    }

    /** Loads a class through the hybrid loader (parent first, blob fallback). */
    public static Class<?> loadHybrid(String name) throws ClassNotFoundException {
        BfSecureLoader l = _hybrid;
        if (l == null) {
            attach();
            l = _hybrid;
        }
        return l.loadClass(name);
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    public static void main(String[] args) throws Throwable {
        failIfAgentPresent();
        BfSecureLoader loader = new BfSecureLoader();
        String main = loader.readOriginalMainClass();
        if (main == null) {
            throw new IllegalStateException(
                    "KBox-BF: no Original-Main-Class attribute in manifest");
        }
        Thread.currentThread().setContextClassLoader(loader);
        Class<?> mainCls = loader.loadClass(main);
        java.lang.reflect.Method m = mainCls.getMethod("main", String[].class);
        m.invoke(null, (Object) args);
    }

    /** Fail-closed early agent gate. Runs BEFORE any protected class is defined.
     *  The detection itself is delegated entirely to native ({@link #safeBoot}):
     *  the plaintext bootstrap only forwards the raw JVM argument list and reads
     *  back one boolean, so the readable class contains no detection pattern. An
     *  agent that has already hooked {@code ClassLoader.defineClass} would
     *  otherwise capture every class this loader defines, so we define none. */
    private static void failIfAgentPresent() {
        java.util.List<String> args = null;
        try {
            java.lang.management.RuntimeMXBean rt =
                    java.lang.management.ManagementFactory.getRuntimeMXBean();
            args = rt.getInputArguments();
        } catch (Throwable ignored) {
        }
        if (safeBoot(args == null ? null : args.toArray(new String[0]))) {
            throw new IllegalStateException("KBox-BF: startup refused");
        }
    }

    /** Reads the renamed application entry point from the manifest. */
    private String readOriginalMainClass() {
        byte[] mf = readBlob(_MP);
        if (mf == null) return null;
        String s = new String(mf, StandardCharsets.UTF_8);
        for (String line : s.split("\r?\n")) {
            if (line.startsWith("Original-Main-Class:")) {
                return line.substring(line.indexOf(':') + 1).trim();
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Class loading
    // ------------------------------------------------------------------

    @Override
    protected Class<?> findClass(String name) throws ClassNotFoundException {
        // Per-class agent gate: catches an agent attached AFTER construction
        // but BEFORE any protected class is defined (defense-in-depth — every
        // defineClass call is independently gated, so an agent that hooks
        // ClassLoader.defineClass after the loader is built still cannot
        // harvest plaintext class bytes through this loader).
        failIfAgentPresent();
        Class<?> c;
        try {
            c = defineClassFromBF(name.replace('.', '/'));
        } catch (Throwable t) {
            throw new ClassNotFoundException(name, t);
        }
        // JNIC co-existence: bind any native methods this class carries to the
        // already-loaded JNIC lib. registerNatives0 no-ops for non-JNIC classes.
        if (_jl) {
            try {
                NativeLoader.registerNatives0(c);
            } catch (Throwable t) {
                // Fail loud rather than silently shipping a method that will throw
                // UnsatisfiedLinkError at first call.
                throw new ClassNotFoundException(
                        "KBox-BF: native registration failed for " + name, t);
            }
        }
        return c;
    }

    // ------------------------------------------------------------------
    // Resource loading (served from the native blob)
    // ------------------------------------------------------------------

    /**
     * Serves resources from the native jar blob. Falls back to the parent
     * loader for anything not hidden in the blob.
     *
     * <p>Note: this class intentionally defines no {@code findResource}
     * (URL-based) override — implementing one would need a custom
     * {@link java.net.URLStreamHandler}, which is an anonymous/nested class
     * that would have to be injected into the jar as a second class file.
     * Stream access via {@link #getResourceAsStream} (the canonical API used
     * by {@code Class.getResourceAsStream}, config loaders, etc.) is fully
     * supported; {@code Class.getResource(...)} returns {@code null} for blob
     * resources. The loader itself is injected as a plain jar entry and must
     * reference no class that is not also injected.</p>
     */
    @Override
    public InputStream getResourceAsStream(String name) {
        java.nio.ByteBuffer bb = getResourceBytes(name);
        if (bb != null) {
            // Streams straight out of the off-heap buffer; wiped on EOF/close.
            return new BfBlobInputStream(bb);
        }
        return super.getResourceAsStream(name);
    }

    // ------------------------------------------------------------------
    // Payload plumbing
    // ------------------------------------------------------------------

    /** Reads a plain jar resource via the parent (system) class loader. */
    private static byte[] readBlob(String path) {
        try (InputStream in = BfSecureLoader.class.getClassLoader()
                .getResourceAsStream(path)) {
            if (in == null) return null;
            java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
            return bo.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    /** Streams a resource into an OFF-HEAP direct buffer, so a large payload
     *  (the {@code classes.bf.rle} blob) never materialises as a Java heap
     *  {@code byte[]}. Returns a buffer with {@code position=0, limit=len}
     *  pointing at the exact bytes, or {@code null} if the resource is absent.
     *  On failure the transient direct buffers are released via reflection-free
     *  means — a failed direct buffer is simply dropped for GC. */
    private static ByteBuffer readBlobDirect(String path) {
        try (InputStream in = BfSecureLoader.class.getClassLoader()
                .getResourceAsStream(path)) {
            if (in == null) return null;
            ReadableByteChannel ch = Channels.newChannel(in);
            ByteBuffer buf = ByteBuffer.allocateDirect(1 << 16);
            int total = 0;
            while (true) {
                if (!buf.hasRemaining()) {
                    int ncap = buf.capacity() << 1;
                    ByteBuffer nb = ByteBuffer.allocateDirect(ncap);
                    buf.flip();
                    nb.put(buf);
                    buf = nb;
                }
                int n = ch.read(buf);
                if (n < 0) break;
                total += n;
            }
            buf.limit(total);
            buf.position(0);
            return buf;
        } catch (IOException e) {
            return null;
        }
    }
}
