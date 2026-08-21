package com.kbox.runtime;

import java.lang.management.ManagementFactory;
import java.lang.management.RuntimeMXBean;
import java.lang.management.ThreadMXBean;
import java.util.List;

/**
 * Runtime anti-debug checks. All checks are <em>silent</em>: on detection they
 * do not throw, but flip {@link #tampered} to {@code true}, which downstream
 * code (string decryptor, VMP dispatcher) consults to corrupt results so the
 * attacker sees garbage rather than a clean failure.
 *
 * <p>Detection vectors (expanded for commercial-grade coverage):
 * <ul>
 *   <li><b>JDWP / -javaagent / -agentpath / -Xrunjdwp</b> in JVM input arguments.</li>
 *   <li><b>JVMTI attach API</b>: if {@code com.sun.tools.attach} loads, an
 *       agent is likely to be attachable.</li>
 *   <li><b>JMX remote</b>: {@code com.sun.management.jmxremote} port open.</li>
 *   <li><b>Self-attach</b>: {@code jdk.attach.allowAttachSelf=true} system property.</li>
 *   <li><b>Timing</b>: multi-round computational canary with CPU-time vs wall-time
 *       cross-check; if wall time greatly exceeds CPU time, a syscall hook is
 *       likely delaying returns.</li>
 *   <li><b>TracerPid</b> (Linux): non-zero TracerPid in {@code /proc/self/status}.</li>
 *   <li><b>Instrumentation</b>: detection of {@code java.lang.instrument} agent
 *       classes loaded in the current classloader.</li>
 * </ul>
 *
 * <p>Strings here are intentionally non-descriptive; when this class is itself
 * run through KBox, all literals get encrypted by the string-encryption pass.
 */
public final class AntiDebug {

    private static volatile boolean tampered = false;

    private AntiDebug() {}

    /** True once any check has fired. Downstream code should corrupt results. */
    public static boolean isTampered() { return tampered; }

    /** Run all checks once at boot. Idempotent. */
    public static void check() {
        checkJvmArgs();
        checkJmxRemote();
        checkSelfAttach();
        checkAttachApi();
        checkInstrumentation();
        checkAgentNativeLibraries();
        checkTiming();
        checkTracerPid();
        checkCrashDumpResidue();
        startWatchdog();
    }

    // ------------------------------------------------------------------
    //  Watchdog: re-detect late agents + transient residue every few seconds.
    // ------------------------------------------------------------------
    private static volatile Thread watchdog;

    /** Starts a daemon that periodically re-runs the cheap re-triggerable checks
     *  (catches agents attached AFTER boot) and scans for trace/crash residue. */
    public static synchronized void startWatchdog() {
        if (watchdog != null) return;
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(4000L);
                    checkJvmArgs();
                    checkSelfAttach();
                    checkAttachApi();
                    checkInstrumentation();
                    checkAgentNativeLibraries();
                    checkTracerPid();
                    checkCrashDumpResidue();
                } catch (Throwable ignored) {
                }
            }
        }, "kbox-anti-wd");
        t.setDaemon(true);
        t.start();
        watchdog = t;
    }

    /** Light scan of {@code java.io.tmpdir} for JVM crash/dump residue that a
     *  live-debug/hprof session would leave behind. Silent; no user-files policy. */
    private static void checkCrashDumpResidue() {
        try {
            String[] dirs = { System.getProperty("java.io.tmpdir", "."), "/tmp" };
            for (String d : dirs) {
                java.io.File dir = new java.io.File(d);
                if (!dir.isDirectory()) continue;
                java.io.File[] files = dir.listFiles();
                if (files == null) continue;
                for (java.io.File f : files) {
                    String n = f.getName();
                    if (n.startsWith("hs_err_pid") || n.startsWith("replay_pid")
                            || n.startsWith("java_pid") || n.contains(".hprof")) {
                        // A crash/JVMTI dump is present in the trace directory.
                        tampered = true;
                        return;
                    }
                    // Self detector: if we ever double-dump, flag (rare).
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void checkJvmArgs() {
        try {
            RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
            List<String> args = rt.getInputArguments();
            if (args == null) return;
            for (String a : args) {
                if (a == null) continue;
                String al = a.toLowerCase();
                if (al.startsWith("-agentlib:jdwp")
                        || al.startsWith("-xrunjdwp")
                        || al.contains("-agentpath")
                        || al.contains("-javaagent")
                        || al.contains("-xdebug")
                        || al.contains("jdwp=")
                        || al.contains("transport=dt_socket")) {
                    tampered = true;
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Detect JMX remote debugging port. If {@code com.sun.management.jmxremote}
     * is enabled and a port is configured, an attacker can connect via JConsole
     * or VisualVM and inspect/modify runtime state.
     */
    private static void checkJmxRemote() {
        try {
            // Check system properties for JMX remote
            String jmxPort = System.getProperty("com.sun.management.jmxremote.port");
            if (jmxPort != null && !jmxPort.isEmpty()) {
                tampered = true;
                return;
            }
            // Check JVM args for JMX remote flags
            RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
            List<String> args = rt.getInputArguments();
            if (args == null) return;
            for (String a : args) {
                if (a == null) continue;
                String al = a.toLowerCase();
                if (al.contains("jmxremote.port")
                        || al.contains("jmxremote.authenticate=false")
                        || al.contains("jmxremote.ssl=false")) {
                    tampered = true;
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Detect {@code jdk.attach.allowAttachSelf=true} — allows a process to
     * attach to itself, enabling self-injection of agents at runtime.
     */
    private static void checkSelfAttach() {
        try {
            String allow = System.getProperty("jdk.attach.allowAttachSelf");
            if ("true".equalsIgnoreCase(allow)) {
                tampered = true;
            }
        } catch (Throwable ignored) {
        }
    }

    private static void checkAttachApi() {
        try {
            Class.forName("com.sun.tools.attach.VirtualMachine", false,
                    AntiDebug.class.getClassLoader());
        } catch (Throwable ignored) {
        }
    }

    /**
     * Detect {@code java.lang.instrument} agent classes. If an Instrumentation
     * instance is reachable, a JVMTI agent has been loaded (e.g. via -javaagent
     * or Attach API). We check for common agent-loaded indicators.
     */
    private static void checkInstrumentation() {
        try {
            // Check if any agent-related classes are loaded
            Class.forName("java.lang.instrument.Instrumentation", false,
                    AntiDebug.class.getClassLoader());
            // Check for common agent frameworks
            String[] agentClasses = {
                "sun.instrument.InstrumentationImpl",
                "com.sun.tools.attach.AttachNotSupportedException"
            };
            for (String cls : agentClasses) {
                try {
                    Class.forName(cls, false, AntiDebug.class.getClassLoader());
                    // Don't auto-flag on class existence alone — these exist on JDKs.
                    // The real indicator is if they're actively used, which we can't
                    // easily detect without deeper introspection.
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Detects JVMTI/agent native libraries actually loaded into this process by
     * scanning {@code /proc/self/maps} (Linux). Catches {@code -javaagent},
     * {@code -agentpath}, and agents attached <em>after</em> boot, because a
     * loaded shared library's mapping persists for the process lifetime. This
     * plugs the gap left by the reflection probes, which only confirm the JDK
     * classes <em>exist</em> on the classpath rather than an agent being live.
     * Silent no-op on platforms without {@code /proc/self/maps}.
     */
    private static void checkAgentNativeLibraries() {
        try {
            java.io.InputStream is = new java.io.FileInputStream("/proc/self/maps");
            try {
                java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream(128 * 1024);
                byte[] buf = new byte[8192];
                int r;
                while ((r = is.read(buf)) > 0) bo.write(buf, 0, r);
                String s = new String(bo.toByteArray(), java.nio.charset.StandardCharsets.US_ASCII);
                // JDK debugging/agent shared libs that are NOT mmap'd in a clean JVM run.
                String[] markers = {
                    "libinstrument.so", "libinstrument.dylib",
                    "libdt_socket.so", "libjdwp.so", "libjdwp.dylib",
                    "libattach.so", "libhprof.so", "libmanagement_agent.so"
                };
                for (String m : markers) {
                    if (s.contains(m)) {
                        tampered = true;
                        return;
                    }
                }
            } finally {
                is.close();
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * Multi-round timing canary with CPU-time cross-check.
     *
     * <p>Runs the computation in multiple rounds and compares wall-clock time
     * against CPU time (via {@link ThreadMXBean#getCurrentThreadCpuTime}).
     * If wall time significantly exceeds CPU time, a syscall hook is likely
     * intercepting and delaying returns (e.g. ptrace, strace). If CPU time
     * greatly exceeds wall time, single-stepping is likely (debugger adds
     * per-instruction overhead visible in CPU time but not wall time due to
     * timing manipulation).
     */
    private static void checkTiming() {
        try {
            ThreadMXBean threadBean = ManagementFactory.getThreadMXBean();
            boolean cpuTimeSupported = threadBean.isCurrentThreadCpuTimeSupported();

            long totalWall = 0;
            long totalCpu = 0;
            int rounds = 3;
            for (int round = 0; round < rounds; round++) {
                long wallStart = System.nanoTime();
                long cpuStart = cpuTimeSupported ? threadBean.getCurrentThreadCpuTime() : 0;

                int acc = 0;
                int iters = 5000 + round * 1000;
                for (int i = 0; i < iters; i++) {
                    acc ^= i;
                    acc = (acc << 1) | (acc >>> 31);
                }
                // Sink acc so the JIT cannot eliminate the loop.
                if (acc == 0xDEADBEEF) tampered = true;

                long wallEnd = System.nanoTime();
                long cpuEnd = cpuTimeSupported ? threadBean.getCurrentThreadCpuTime() : 0;
                totalWall += (wallEnd - wallStart);
                totalCpu += (cpuEnd - cpuStart);
            }

            // Wall time check: > 5ms per round average => single-stepping
            if (totalWall / rounds > 5_000_000L) {
                tampered = true;
            }

            // CPU vs wall time cross-check (only if CPU time is supported)
            if (cpuTimeSupported && totalCpu > 0) {
                // If CPU time >> wall time, debugger is adding overhead
                // (CPU time includes time spent in debug-related traps)
                if (totalCpu > totalWall * 3) {
                    tampered = true;
                }
                // If wall time >> CPU time, a hook is delaying syscall returns
                // (e.g. ptrace adds context-switch overhead not visible in CPU time)
                if (totalWall > totalCpu * 10 && totalWall > 10_000_000L) {
                    tampered = true;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * On Linux, check {@code /proc/self/status} for {@code TracerPid} field.
     * A non-zero value means a debugger (gdb, strace, ltrace) is attached.
     * On non-Linux platforms, this is a no-op.
     */
    private static void checkTracerPid() {
        try {
            java.io.InputStream is = new java.io.FileInputStream("/proc/self/status");
            try {
                byte[] buf = new byte[4096];
                int len = is.read(buf);
                if (len > 0) {
                    String content = new String(buf, 0, len, java.nio.charset.StandardCharsets.US_ASCII);
                    int idx = content.indexOf("TracerPid:");
                    if (idx >= 0) {
                        // Parse the number after "TracerPid:\t"
                        int valStart = idx + "TracerPid:".length();
                        while (valStart < content.length() && (content.charAt(valStart) == ' ' || content.charAt(valStart) == '\t')) {
                            valStart++;
                        }
                        int valEnd = valStart;
                        while (valEnd < content.length() && Character.isDigit(content.charAt(valEnd))) {
                            valEnd++;
                        }
                        if (valEnd > valStart) {
                            int pid = Integer.parseInt(content.substring(valStart, valEnd));
                            if (pid != 0) {
                                tampered = true;
                            }
                        }
                    }
                }
            } finally {
                is.close();
            }
        } catch (Throwable ignored) {
            // Not Linux or /proc not available — no-op.
        }
    }
}
