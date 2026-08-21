package com.kbox.core;

/**
 * Root runtime exception for all KBox protection failures. Subclasses are used
 * to distinguish recoverable per-method failures (which should fall back to
 * obfuscation) from fatal configuration errors.
 */
public class KBoxException extends RuntimeException {
    private static final long serialVersionUID = 1L;
    public KBoxException(String msg) { super(msg); }
    public KBoxException(String msg, Throwable cause) { super(msg, cause); }
}
