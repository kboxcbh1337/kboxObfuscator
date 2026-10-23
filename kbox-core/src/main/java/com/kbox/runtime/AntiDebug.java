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
 *   <li><b>JMX remote</b>: {@code com.sun.management.jmxremote} port open
 *       (KBX-NAT-05: now a documented no-op — legitimate ops tooling).</li>
 *   <li><b>Timing</b>: multi-round computational canary with CPU-time vs wall-time
 *       cross-check; if wall time greatly exceeds CPU time, a syscall hook is
 *       likely delaying returns.</li>
 *   <li><b>TracerPid</b> (Linux): non-zero TracerPid in {@code /proc/self/status}.</li>
 *   <li><b>Loaded agent libraries</b> (Linux): JVMTI/agent shared-object
 *       markers in {@code /proc/self/maps} — the live-agent indicator
 *       (KBX-NAT-18: the earlier reflection probes for the attach API /
 *       instrumentation classes were dead checks and have been removed).</li>
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
        // KBX-NAT-18: the reflection probes (self-attach property, attach-API
        // presence, instrumentation classes) were removed — their results never
        // influenced any decision, so they were dead checks. Real agent detection
        // happens in checkAgentNativeLibraries (/proc/self/maps markers).
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

    /** Light scan of {@code java.io.tmpdir} for JVM crash/dump residue belonging to
     *  <em>this</em> process. Silent; no user-files policy.
     *
     *  <p>Only dumps whose PID matches the current JVM are considered. A stale
     *  {@code hs_err_pid*.log} left in the temp directory by any other JVM (every
     *  developer machine accumulates them after a crash) must never trip the
     *  canary: a false positive flips {@link #tampered} and makes every protected
     *  string decrypt to noise for the whole run, which looks like a broken
     *  obfuscation build. */
    private static void checkCrashDumpResidue() {
        try {
            long pid = currentPid();
            if (pid <= 0L) return;
            String[] dirs = { System.getProperty("java.io.tmpdir", "."), "/tmp" };
            for (String d : dirs) {
                java.io.File dir = new java.io.File(d);
                if (!dir.isDirectory()) continue;
                java.io.File[] files = dir.listFiles();
                if (files == null) continue;
                for (java.io.File f : files) {
                    String n = f.getName();
                    // KBX-NAT-05: java_pid<pid> is the attach-listener socket the
                    // JVM creates on demand for jstack/jcmd/jmap — plain ops
                    // tooling, NOT a crash dump. Flagging it corrupted strings
                    // after every routine jstack. Only real crash artifacts
                    // (hs_err/replay) count as residue.
                    if (n.startsWith("hs_err_pid" + pid) || n.startsWith("replay_pid" + pid)) {
                        tampered = true;
                        return;
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /** Current process id, derived from the JVM's {@code pid@host} runtime name
     *  (Java 6+; avoids {@code ProcessHandle} so the runtime stays Java 8 clean). */
    private static long currentPid() {
        try {
            String n = ManagementFactory.getRuntimeMXBean().getName();
            int at = n.indexOf('@');
            return Long.parseLong(at > 0 ? n.substring(0, at) : n);
        } catch (Throwable t) {
            return -1L;
        }
    }

    // KBX-NAT-05: production JVMs legitimately run APM/profiling agents
    // (-javaagent / -agentpath). Flagging every agent permanently corrupted all
    // protected strings on monitored deployments. Agents whose path matches one
    // of these keywords are whitelisted; anything else still trips the canary.
    private static final String[] AGENT_WHITELIST = {
        "skywalking", "pinpoint", "elastic-apm", "apm-elastic", "newrelic",
        "appdynamics", "datadog", "opentelemetry", "otel", "jacoco",
        "jrebel", "prometheus", "jmx_prometheus", "async-profiler",
        "brightwing", "oneapm", "tingyun", "听云", "egls", "bugsnag"
    };

    private static boolean whitelistedAgent(String arg) {
        String al = arg.toLowerCase(java.util.Locale.ROOT);
        for (String w : AGENT_WHITELIST) {
            if (al.contains(w)) return true;
        }
        return false;
    }

    private static void checkJvmArgs() {
        try {
            RuntimeMXBean rt = ManagementFactory.getRuntimeMXBean();
            List<String> args = rt.getInputArguments();
            if (args == null) return;
            for (String a : args) {
                if (a == null) continue;
                String al = a.toLowerCase();
                // Debugger-specific flags are always fatal indicators.
                if (al.startsWith("-agentlib:jdwp")
                        || al.startsWith("-xrunjdwp")
                        || al.contains("jdwp=")
                        || al.contains("-xdebug")
                        || al.contains("transport=dt_socket")) {
                    tampered = true;
                    return;
                }
                // Generic agents only trip the canary when NOT whitelisted
                // (APM/coverage agents are legitimate production tooling).
                if ((al.contains("-agentpath") || al.contains("-javaagent")
                        || al.startsWith("-agentlib:"))
                        && !whitelistedAgent(a)) {
                    tampered = true;
                    return;
                }
            }
        } catch (Throwable ignored) {
        }
    }

    /**
     * KBX-NAT-05: JMX remote monitoring is standard operations tooling
     * (jconsole/VisualVM/jmx-prometheus exporters). It exposes read/manage
     * hooks, not execution control, and flagging it corrupted every protected
     * string on managed production hosts. This check is intentionally a no-op
     * now; kept for API compatibility and to document the decision.
     */
    @SuppressWarnings("unused")
    private static void checkJmxRemote() {
        // Deliberately no tampered flag — see javadoc above.
    }

    /**
     * Detects JVMTI/agent native libraries actually loaded into this process by
     * scanning {@code /proc/self/maps} (Linux). Catches {@code -javaagent},
     * {@code -agentpath}, and agents attached <em>after</em> boot, because a
     * loaded shared library's mapping persists for the process lifetime. This is
     * the authoritative live-agent signal; class-presence reflection probes were
     * removed as dead checks (KBX-NAT-18) since these JDK classes always exist.
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
            long[] wallPerRound = new long[rounds];
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
                wallPerRound[round] = wallEnd - wallStart;
                totalWall += (wallEnd - wallStart);
                totalCpu += (cpuEnd - cpuStart);
            }

            // KBX-NAT-05: use the MEDIAN of per-round wall times instead of the
            // mean — a single GC pause or scheduler burst inflates the mean and
            // permanently corrupted every protected string. The median is robust
            // to one outlier round (median of 3 = middle value).
            java.util.Arrays.sort(wallPerRound);
            long medianWall = wallPerRound[rounds / 2];
            // The canary loop is a few thousand trivial integer ops; even under
            // single-stepping the median round stays far above 50ms, while GC /
            // descheduling hits at most one of three rounds.
            if (medianWall > 50_000_000L) {
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
                // (e.g. ptrace adds context-switch overhead not visible in CPU time).
                // Require a large absolute gap so a descheduled thread on a busy
                // host is not mistaken for a tracer.
                if (totalWall > totalCpu * 20 && totalWall > 250_000_000L) {
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
