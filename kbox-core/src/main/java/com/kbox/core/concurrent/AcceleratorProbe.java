package com.kbox.core.concurrent;

import com.kbox.core.log.KBoxLog;

/**
 * Detects and reports the best available bulk-arithmetic accelerator for the
 * string-encryption hot path.
 *
 * <p>Honest engineering note: GPU offload (OpenCL/CUDA) provides essentially
 * no benefit for bytecode obfuscation. The dominant cost is the control-flow
 * data-flow analysis, which is a serial, recursive, shared-structure traversal
 * with heavy random memory access and HashMap use — the exact workload GPUs
 * are bad at. The few vectorizable kernels (string XOR / table permute) are
 * so small that PCIe transfer overhead dwarfs any kernel speedup.
 *
 * <p>What <em>does</em> help is the JDK's built-in Vector API (SIMD), which
 * accelerates bulk byte transforms on the CPU with zero data-transfer cost.
 * This class probes for it and reports the active backend so the pipeline can
 * choose the fastest available path without pulling in heavy native deps.
 */
public final class AcceleratorProbe {

    private AcceleratorProbe() {}

    /** Reports whether SIMD vector acceleration is available on this JVM. */
    public static boolean simdAvailable() {
        try {
            // Vector API is incubator/module in JDK 17+, stable/intrinsic in 20+.
            Class.forName("jdk.incubator.vector.VectorSpecies");
            return true;
        } catch (Throwable t) {
            // Fall back to scalar; SIMD is a nice-to-have, never required.
            return false;
        }
    }

    /** Reports whether a GPU OpenCL backend is loadable (JOCL on classpath). */
    public static boolean openClAvailable() {
        try {
            Class.forName("org.jocl.CL");
            return true;
        } catch (Throwable t) {
            return false;
        }
    }

    /**
     * Selects the effective backend for bulk byte transforms.
     *
     * @param gpuAccelRequested whether the user asked for GPU acceleration.
     * @return a human-readable backend name.
     */
    public static String selectBackend(boolean gpuAccelRequested) {
        if (gpuAccelRequested && openClAvailable()) {
            KBoxLog.info("accel", "GPU backend: OpenCL detected (JOCL on classpath)");
            return "OPENCL";
        }
        if (simdAvailable()) {
            return "SIMD";
        }
        return "SCALAR";
    }
}