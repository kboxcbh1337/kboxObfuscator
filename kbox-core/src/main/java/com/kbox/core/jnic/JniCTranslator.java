package com.kbox.core.jnic;

import org.objectweb.asm.Type;

/**
 * Shared C/JNI type-mapping helper for the JNIC pipeline.
 *
 * <p>Historically this class was the "one C statement per JVM opcode"
 * translator, but that per-instruction path is obsolete — the current JNIC
 * route serialises raw bytecode and runs it through the native
 * {@code kbox_jvm_interp_v3} interpreter (see {@link JniBytecodeInterp}). Only
 * {@link #cType} is still referenced ({@link JniBytecodeInterp} maps JVM types
 * to C types via it); the old translation body and its dead helpers
 * ({@code cTypeSuffix}, {@code escapeC} — the latter duplicated by the private
 * {@code NativeCompiler.escapeC}) have been removed.
 */
public final class JniCTranslator {

    private JniCTranslator() {}

    /** Maps a JVM type to the C type used in generated JNI stubs. */
    public static String cType(Type t) {
        switch (t.getSort()) {
            case Type.VOID: return "void";
            case Type.BOOLEAN: case Type.BYTE: case Type.CHAR: case Type.SHORT:
            case Type.INT: return "jint";
            case Type.LONG: return "jlong";
            case Type.FLOAT: return "jfloat";
            case Type.DOUBLE: return "jdouble";
            default: return "jobject";
        }
    }

}
