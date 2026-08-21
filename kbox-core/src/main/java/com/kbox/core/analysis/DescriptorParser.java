package com.kbox.core.analysis;

import org.objectweb.asm.Type;

import java.util.ArrayList;
import java.util.List;

/**
 * ZKM-style descriptor and internal-name parser. Provides utilities for
 * parsing JVM method descriptors ({@code (Ljava/lang/String;I)V}) and
 * internal names ({@code com/example/MyClass}) into their component parts,
 * enabling precise member matching for annotation-based targeting.
 *
 * <p>This is the "地基" (foundation) layer of ZKM compatibility — every
 * advanced feature (native translation, VMP, name retention) depends on
 * the ability to understand and decompose JVM type system elements.
 */
public final class DescriptorParser {

    private DescriptorParser() {}

    /** A parsed method descriptor with typed argument and return components. */
    public static final class MethodSignature {
        public final Type[] argTypes;
        public final Type returnType;
        public final String rawDescriptor;

        MethodSignature(String desc) {
            this.rawDescriptor = desc;
            this.argTypes = Type.getArgumentTypes(desc);
            this.returnType = Type.getReturnType(desc);
        }

        /** Human-readable form: {@code (String, int) -> void}. */
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("(");
            for (int i = 0; i < argTypes.length; i++) {
                if (i > 0) sb.append(", ");
                sb.append(simpleName(argTypes[i]));
            }
            sb.append(") -> ").append(simpleName(returnType));
            return sb.toString();
        }
    }

    /** A parsed internal name (e.g. {@code com/example/Outer$Inner}). */
    public static final class ClassName {
        public final String internal;   // com/example/Outer$Inner
        public final String binary;     // com.example.Outer$Inner
        public final String simple;     // Outer$Inner
        public final String package_;   // com/example (internal form, or "")

        ClassName(String internal) {
            this.internal = internal;
            this.binary = internal.replace('/', '.');
            int lastSlash = internal.lastIndexOf('/');
            this.simple = lastSlash >= 0 ? internal.substring(lastSlash + 1) : internal;
            this.package_ = lastSlash >= 0 ? internal.substring(0, lastSlash) : "";
        }

        /** The outermost class name (before first '$'). */
        public String outerSimple() {
            int d = simple.indexOf('$');
            return d >= 0 ? simple.substring(0, d) : simple;
        }

        @Override
        public String toString() { return binary; }
    }

    /** A parsed field descriptor with the field name and its JVM type. */
    public static final class FieldSignature {
        public final String name;
        public final Type type;
        public final String rawDescriptor;

        FieldSignature(String name, String desc) {
            this.name = name;
            this.rawDescriptor = desc;
            this.type = Type.getType(desc);
        }

        @Override
        public String toString() { return simpleName(type) + " " + name; }
    }

    /**
     * Parses a JVM method descriptor (e.g. {@code (Ljava/lang/String;I)V})
     * into its component type objects.
     */
    public static MethodSignature parseMethod(String descriptor) {
        return new MethodSignature(descriptor);
    }

    /**
     * Parses an internal class name (e.g. {@code com/example/Outer$Inner})
     * into its component parts.
     */
    public static ClassName parseClass(String internalName) {
        return new ClassName(internalName);
    }

    /**
     * Parses a field name and its type descriptor into a typed signature.
     */
    public static FieldSignature parseField(String name, String descriptor) {
        return new FieldSignature(name, descriptor);
    }

    /**
     * Returns the argument count for a method descriptor, excluding
     * implicit receiver.
     */
    public static int argCount(String methodDescriptor) {
        return Type.getArgumentTypes(methodDescriptor).length;
    }

    /**
     * Returns whether two descriptors are structurally identical
     * (same argument types and return type).
     */
    public static boolean descriptorsEqual(String desc1, String desc2) {
        return desc1.equals(desc2);
    }

    /**
     * Returns whether the given type is a primitive ({@code I, J, F, D,
     * B, C, S, Z, V}).
     */
    public static boolean isPrimitive(char descriptorChar) {
        switch (descriptorChar) {
            case 'I': case 'J': case 'F': case 'D':
            case 'B': case 'C': case 'S': case 'Z': case 'V':
                return true;
            default: return false;
        }
    }

    /**
     * Returns whether the descriptor represents an array type (starts with '[').
     */
    public static boolean isArray(String descriptor) {
        return descriptor.charAt(0) == '[';
    }

    /**
     * Extracts the element type from an array descriptor. For {@code [Ljava/lang/String;}
     * returns {@code java/lang/String}; for {@code [[I} returns {@code [I}.
     */
    public static String arrayElementType(String arrayDescriptor) {
        if (arrayDescriptor.charAt(0) != '[') {
            throw new IllegalArgumentException("Not an array descriptor: " + arrayDescriptor);
        }
        return arrayDescriptor.substring(1);
    }

    /**
     * Returns a human-readable simple type name for display purposes.
     */
    public static String simpleName(Type t) {
        switch (t.getSort()) {
            case Type.VOID: return "void";
            case Type.BOOLEAN: return "boolean";
            case Type.BYTE: return "byte";
            case Type.CHAR: return "char";
            case Type.SHORT: return "short";
            case Type.INT: return "int";
            case Type.LONG: return "long";
            case Type.FLOAT: return "float";
            case Type.DOUBLE: return "double";
            case Type.ARRAY: return simpleName(t.getElementType()) + "[]";
            case Type.OBJECT:
                String internal = t.getInternalName();
                int lastSlash = internal.lastIndexOf('/');
                return lastSlash >= 0 ? internal.substring(lastSlash + 1) : internal;
            default: return t.getClassName();
        }
    }

    /**
     * Builds a ProGuard-style member specification:
     * {@code owner.name(desc)} for methods, {@code owner.name: type} for fields.
     */
    public static String toProGuardSpec(String owner, String name, String desc) {
        if (desc.startsWith("(")) {
            return owner.replace('/', '.') + "." + name + desc;
        } else {
            return owner.replace('/', '.') + "." + name + ": " + desc;
        }
    }

    /**
     * Returns all classes referenced in a method descriptor (parameter types
     * and return type that are object/array types).
     */
    public static List<String> referencedClasses(String methodDescriptor) {
        List<String> refs = new ArrayList<>();
        Type methodType = Type.getMethodType(methodDescriptor);
        for (Type arg : methodType.getArgumentTypes()) {
            collectClassRefs(arg, refs);
        }
        collectClassRefs(methodType.getReturnType(), refs);
        return refs;
    }

    private static void collectClassRefs(Type t, List<String> out) {
        switch (t.getSort()) {
            case Type.OBJECT:
                out.add(t.getInternalName());
                break;
            case Type.ARRAY:
                collectClassRefs(t.getElementType(), out);
                break;
            default:
                break;
        }
    }
}
