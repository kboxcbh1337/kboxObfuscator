package com.kbox.runtime.bfvm;

/**
 * Runtime exception thrown by the BFVM runtime (decode, execute). Self-contained copy so
 * protected jars that ship only {@code com.kbox.runtime.bfvm.*} never need build-side classes.
 */
public class BfVmException extends RuntimeException {
    public BfVmException(String message) {
        super(message);
    }

    public BfVmException(String message, Throwable cause) {
        super(message, cause);
    }
}
