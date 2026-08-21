package com.kbox.core.log;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Lightweight logger used across all KBox modules. Avoids pulling in a logging
 * framework so the obfuscator can run in minimal environments (e.g. a plain
 * java -jar invocation without extra dependencies on the classpath).
 *
 * <p>Supports an optional {@link ProgressListener} that receives stage-change
 * and percentage callbacks. The CLI uses it to print a progress bar; the GUI
 * uses it to update a {@code JProgressBar}.
 *
 * <p><b>Encoding.</b> Log lines are always encoded to <em>UTF-8</em> on disk.
 * The console stream ({@code System.out}) inherits the JVM's console encoding,
 * which on Windows is often the local code page (e.g. GBK) and renders UTF-8
 * multibyte sequences as mojibake. To never lose Chinese/multibyte log output,
 * call {@link #setFile(Path)} to also write every line to a UTF-8 log file:
 * the file's bytes are always correct regardless of the terminal's code page.
 */
public final class KBoxLog {

    public static final int LEVEL_DEBUG = 0;
    public static final int LEVEL_INFO = 1;
    public static final int LEVEL_WARN = 2;
    public static final int LEVEL_ERROR = 3;

    private static final SimpleDateFormat TS = new SimpleDateFormat("HH:mm:ss.SSS");
    private static volatile PrintStream out = System.out;
    private static volatile int level = LEVEL_INFO;
    private static volatile ProgressListener listener;
    /** Optional UTF-8 file tap: every log line is also written here. */
    private static volatile PrintStream fileOut;

    private KBoxLog() {}

    public static void setLevel(int l) { level = l; }
    public static void setOut(PrintStream s) { out = s; }

    /**
     * Taps every log line into a UTF-8 file in addition to the console. This
     * decouples the log's correctness from the console's code page (fixing the
     * mojibake seen when Windows PowerShell renders UTF-8 as GBK). The file is
     * opened in append mode. Passing {@code null} disables the tap.
     *
     * @return the {@link PrintStream} bound to the file, or {@code null} if the
     *         tap is off / the file could not be opened.
     */
    public static synchronized PrintStream setFile(Path file) {
        if (fileOut != null) { try { fileOut.close(); } catch (Throwable ignore) {} fileOut = null; }
        if (file == null) return null;
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            OutputStream fos = Files.newOutputStream(file, java.nio.file.StandardOpenOption.CREATE,
                    java.nio.file.StandardOpenOption.APPEND, java.nio.file.StandardOpenOption.WRITE);
            fileOut = new PrintStream(fos, true, StandardCharsets.UTF_8);
            return fileOut;
        } catch (IOException e) {
            System.err.println("[KBoxLog] cannot open UTF-8 log file " + file + ": " + e.getMessage());
            return null;
        }
    }

    public static void setListener(ProgressListener l) { listener = l; }

    /** Interface for receiving progress updates from the pipeline. */
    public interface ProgressListener {
        /** Called when a new stage begins. {@code stage} is 1-indexed, {@code total} is the number of stages. */
        void onStage(int stage, int total, String name);
        /** Called with a progress percentage (0-100) within the current stage. */
        void onProgress(int percent, String detail);
        /** Called when the entire pipeline finishes. */
        void onComplete(String summary);
    }

    /** Notifies the listener that a new stage has begun. */
    public static void stage(int stage, int total, String name) {
        info("pipeline", ">>> Stage " + stage + "/" + total + ": " + name);
        if (listener != null) listener.onStage(stage, total, name);
    }

    /** Notifies the listener of progress within the current stage. */
    public static void progress(int percent, String detail) {
        debug("pipeline", "    [" + percent + "%] " + detail);
        if (listener != null) listener.onProgress(percent, detail);
    }

    /** Notifies the listener that the pipeline has completed. */
    public static void complete(String summary) {
        info("pipeline", ">>> " + summary);
        if (listener != null) listener.onComplete(summary);
    }

    private static void log(String tag, String lvl, String msg) {
        String line = "[" + TS.format(new Date()) + "] [" + lvl + "] " + tag + " - " + msg;
        if (out != null) {
            out.println(line);
            out.flush();  // Ensure output is visible immediately (not buffered).
        }
        if (fileOut != null) {
            fileOut.println(line);
            fileOut.flush();
        }
    }

    public static void debug(String tag, String msg) {
        if (level <= LEVEL_DEBUG) log(tag, "DEBUG", msg);
    }
    public static void info(String tag, String msg) {
        if (level <= LEVEL_INFO) log(tag, "INFO ", msg);
    }
    public static void warn(String tag, String msg) {
        if (level <= LEVEL_WARN) log(tag, "WARN ", msg);
    }
    public static void error(String tag, String msg) {
        if (level <= LEVEL_ERROR) log(tag, "ERROR", msg);
    }
    public static void error(String tag, String msg, Throwable t) {
        error(tag, msg + ": " + t.toString());
        // Print full stack trace at DEBUG level for detailed diagnostics.
        if (level <= LEVEL_DEBUG && t != null) {
            java.io.StringWriter sw = new java.io.StringWriter();
            t.printStackTrace(new java.io.PrintWriter(sw));
            for (String line : sw.toString().split("\n")) {
                if (!line.isEmpty()) log(tag, "ERROR", "    " + line);
            }
        }
    }
}
