package com.kbox.core.bfvm;

/**
 * Runtime exception thrown by the BFVM pipeline (compile, decode, execute).
 * Lives in the build-side package; the shipped runtime carries its own copy
 * under {@code com.kbox.runtime.bfvm} so protected apps stay self-contained.
 */
public class BfVmException extends RuntimeException {
    public BfVmException(String message) {
        super(message);
    }

    public BfVmException(String message, Throwable cause) {
        super(message, cause);
    }
}
