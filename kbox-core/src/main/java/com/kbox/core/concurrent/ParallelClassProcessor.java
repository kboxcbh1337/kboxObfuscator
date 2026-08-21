package com.kbox.core.concurrent;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.tree.ClassNode;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Drives embarrassingly-parallel per-class transforms (control-flow
 * obfuscation, string encryption, annotation erasure, debug forging, etc.)
 * across a thread pool sized to the CPU count. Each class is independent,
 * so we can process them concurrently with no shared mutable state.
 *
 * <p>The caller supplies a {@link ClassOp} that mutates a single
 * {@link ClassNode} in place. This executor distributes the class list over
 * worker threads, reports progress, and returns how many classes were
 * processed. Failures on any single class are caught and logged, leaving the
 * class untouched (the pipeline's rollback verifier still guards the output).
 *
 * <p>This is the primary speedup for large jars: the control-flow pass that
 * previously dominated wall-clock time now runs across all cores.
 */
public final class ParallelClassProcessor {

    private static final String TAG = "parallel";

    /** A per-class transform. Implementations must be safe to call concurrently. */
    public interface ClassOp {
        /** Mutate a single class in place. Thrown exceptions are caught &amp; logged. */
        void process(ClassNode cn) throws Exception;
    }

    /**
     * Applies {@code op} to every class in {@code graph} that
     * {@link ProtectionConfig#shouldProtectClass(String)} permits, in parallel.
     *
     * @param threads 0 = auto (CPU cores), else a fixed pool size.
     * @return number of classes processed.
     */
    public static int processAll(ClassGraph graph, ProtectionConfig cfg,
                                 ClassOp op, int threads) {
        int cores = Runtime.getRuntime().availableProcessors();
        int poolSize = threads > 0 ? threads : Math.max(1, cores);
        if (poolSize <= 1) {
            // Single-threaded fallback (deterministic, bit-for-bit same output).
            int n = 0;
            for (ClassNode cn : graph.getClasses().values()) {
                if (!cfg.shouldProtectClass(cn.name)) continue;
                try { op.process(cn); n++; }
                catch (Exception e) {
                    KBoxLog.warn(TAG, "Class op failed for " + cn.name + ": " + e.getMessage());
                }
            }
            return n;
        }

        List<ClassNode> targets = new ArrayList<>();
        for (ClassNode cn : graph.getClasses().values()) {
            if (cfg.shouldProtectClass(cn.name)) targets.add(cn);
        }
        ExecutorService pool = Executors.newFixedThreadPool(poolSize);
        AtomicInteger done = new AtomicInteger();
        AtomicInteger failed = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (final ClassNode cn : targets) {
            futures.add(pool.submit(() -> {
                try {
                    op.process(cn);
                } catch (Throwable t) {
                    failed.incrementAndGet();
                    KBoxLog.warn(TAG, "Class op failed for " + cn.name + ": " + t.getMessage());
                } finally {
                    done.incrementAndGet();
                }
            }));
        }
        pool.shutdown();
        try {
            pool.awaitTermination(Long.MAX_VALUE, TimeUnit.NANOSECONDS);
        } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
        }
        KBoxLog.info(TAG, "Processed " + done.get() + " classes in parallel"
                + (failed.get() > 0 ? " (" + failed.get() + " failed)" : "")
                + " — pool=" + poolSize);
        return done.get();
    }
}