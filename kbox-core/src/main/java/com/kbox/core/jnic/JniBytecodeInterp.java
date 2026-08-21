package com.kbox.core.jnic;

import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.*;

import java.security.SecureRandom;
import java.util.*;

/**
 * Packages a Java method's bytecode and constant-pool references into a
 * data block and generates a thin C stub that invokes the native JVM
 * bytecode interpreter ({@code kbox_jvm_interp}).
 *
 * <p>Unlike {@link JniCTranslator} which emits one C statement per JVM
 * opcode (and frequently fails GCC compilation for non-trivial methods),
 * this translator serialises the raw bytecode with <b>sequential CP
 * indices</b> and pre-resolved CP arrays so the native interpreter can
 * execute them directly.
 */
public final class JniBytecodeInterp {

    /** Resolved constant-pool entries for one method. All use sequential 0-based keys. */
    public static final class ResolvedCP {
        /** Class refs, keyed by sequential index. */
        public final Map<Integer, String> classes = new LinkedHashMap<>();
        /** Field refs: {owner, name, desc} per sequential index. */
        public final Map<Integer, String[]> fields = new LinkedHashMap<>();
        /** Method refs: {owner, name, desc, isStatic} per sequential index. */
        public final Map<Integer, String[]> methods = new LinkedHashMap<>();
        /** String constants per sequential index. */
        public final Map<Integer, String> strings = new LinkedHashMap<>();
        /** Integer constants per sequential index. */
        public final Map<Integer, Integer> integers = new LinkedHashMap<>();
        /** Invokedynamic site metadata per sequential index (see extractCP). */
        public final Map<Integer, Object[]> indies = new LinkedHashMap<>();

        public boolean isEmpty() {
            return classes.isEmpty() && fields.isEmpty()
                    && methods.isEmpty() && strings.isEmpty() && integers.isEmpty()
                    && indies.isEmpty();
        }
    }

    /**
     * Maps a CP-entry signature to its sequential index in ResolvedCP.
     * Used during bytecode serialisation to emit the correct 2-byte operand.
     */
    public static final class CPIdxMap {
        public final Map<String, Integer> clsIdx = new LinkedHashMap<>();
        public final Map<String, Integer> fldIdx = new LinkedHashMap<>();
        public final Map<String, Integer> midIdx = new LinkedHashMap<>();
        public final Map<String, Integer> strIdx = new LinkedHashMap<>();
        public final Map<Integer, Integer> intIdx = new LinkedHashMap<>();
        public final Map<InvokeDynamicInsnNode, Integer> indyIdx = new LinkedHashMap<>();
    }

    public static final class InterpFn {
        public final String symbol;
        public final String javaClass;
        public final String javaName;
        public final String javaDesc;
        public final String cBody;    // stub + bytecode + CP-arrays
        public final String[] argTypes;
        public final int bcLen;       // bytecode length (for the stub call)

        public InterpFn(String symbol, String javaClass, String javaName,
                        String javaDesc, String cBody, String[] argTypes, int bcLen) {
            this.symbol = symbol; this.javaClass = javaClass; this.javaName = javaName;
            this.javaDesc = javaDesc; this.cBody = cBody; this.argTypes = argTypes;
            this.bcLen = bcLen;
        }
    }

    // ---- public entry point ----

    private static final SecureRandom RNG = new SecureRandom();

    /* Field separators for the packed invokedynamic metadata string consumed by
     * com.kbox.runtime.JnicIndy at runtime. Must match that class's constants. */
    private static final char IMP_SEP   = 0x1f; // top-level field separator
    private static final char IMP_PARTS = 0x1e; // static-argument payload separator

    /**
     * Builds the packed metadata row for one invokedynamic site:
     * {@code { meta, argCodes, ret }}.
     * {@code meta} is a single string field-joined by {@code \u001f}; the static
     * bootstrap argument payloads are joined by {@code \u001e}. The C interpreter
     * passes this meta string verbatim to {@link com.kbox.runtime.JnicIndy}.
     */
    private static Object[] indyMeta(String callerClass, InvokeDynamicInsnNode id) {
        org.objectweb.asm.Handle b = id.bsm;
        StringBuilder tags = new StringBuilder();
        java.util.List<String> parts = new java.util.ArrayList<>();
        for (Object a : id.bsmArgs) tags.append(encArg(a, parts));
        // meta fields [0..8] as before, plus [9] = caller class (internal name).
        // The caller's own lookup is needed so lambdas can "crack" private impls.
        String meta = b.getOwner() + IMP_SEP + b.getName() + IMP_SEP + b.getDesc()
                + IMP_SEP + b.getTag() + IMP_SEP + (b.isInterface() ? "1" : "0")
                + IMP_SEP + id.name + IMP_SEP + id.desc + IMP_SEP + tags
                + IMP_SEP + String.join(String.valueOf(IMP_PARTS), parts)
                + IMP_SEP + callerClass;
        String[] codes = sideCodes(id.desc);
        return new Object[]{meta, codes[0], codes[1]};
    }

    /** Encodes one static bootstrap argument into a tag char; appends its payload. */
    private static char encArg(Object a, java.util.List<String> parts) {
        if (a instanceof String) { parts.add((String) a); return 's'; }
        if (a instanceof Integer) { parts.add(Integer.toString((Integer) a)); return 'i'; }
        if (a instanceof Long) { parts.add(Long.toString((Long) a)); return 'l'; }
        if (a instanceof Float) { parts.add(Float.toString((Float) a)); return 'f'; }
        if (a instanceof Double) { parts.add(Double.toString((Double) a)); return 'd'; }
        if (a instanceof org.objectweb.asm.Handle) {
            org.objectweb.asm.Handle h = (org.objectweb.asm.Handle) a;
            parts.add(h.getOwner() + "|" + h.getName() + "|" + h.getDesc()
                    + "|" + h.getTag() + "|" + (h.isInterface() ? "1" : "0"));
            return 'h';
        }
        if (a instanceof org.objectweb.asm.Type) {
            org.objectweb.asm.Type t = (org.objectweb.asm.Type) a;
            if (t.getSort() == org.objectweb.asm.Type.METHOD) {
                parts.add(t.getDescriptor()); return 'm';
            }
            parts.add(t.getInternalName()); return 'c';
        }
        parts.add(""); return 'n';
    }

    /**
     * Call-site descriptor → {@code { argSlotCodes, returnCode }}.
     * Slot codes mirror how the interpreter stores values on its operand stack:
     * I (int boolean byte char short), J, F, D, or L for any object/reference.
     */
    private static String[] sideCodes(String desc) {
        StringBuilder args = new StringBuilder();
        int i = desc.indexOf('(');
        int j = desc.indexOf(')');
        for (int k = i + 1; k < j; k++) {
            char c = desc.charAt(k);
            if (c == 'L') { while (desc.charAt(k) != ';') k++; args.append('L'); }
            else if (c == '[') { while (desc.charAt(k) == '[') k++; if (desc.charAt(k) == 'L') while (desc.charAt(k) != ';') k++; args.append('L'); }
            else if (c == 'I' || c == 'Z' || c == 'B' || c == 'C' || c == 'S') args.append('I');
            else if (c == 'J') args.append('J');
            else if (c == 'F') args.append('F');
            else if (c == 'D') args.append('D');
        }
        char ret = 'L';
        if (j + 1 < desc.length()) {
            char r = desc.charAt(j + 1);
            if (r == 'V') ret = 'V';
            else if (r == 'I' || r == 'Z' || r == 'B' || r == 'C' || r == 'S') ret = 'I';
            else if (r == 'J') ret = 'J';
            else if (r == 'F') ret = 'F';
            else if (r == 'D') ret = 'D';
        }
        return new String[]{args.toString(), String.valueOf(ret)};
    }

    /**
     * Replicates the C-side {@code kbox_key_byte} non-linear mixer for
     * bytecode XOR encryption at build time.
     */
    static int keyByteC(long seed, int pc) {
        int k = (int)(seed ^ (pc * 0x9E3779B9L));
        k = (k ^ (k >>> 16)) * 0x85EBCA6B;
        k = (k ^ (k >>> 13)) * 0xC2B2AE35;
        return (k ^ (k >>> 16)) & 0xFF;
    }

    public static InterpFn translate(String className, MethodNode mn, int index) {
        // Random symbol prefix to prevent IDA symbol-table enumeration.
        String symPrefix = Long.toHexString(RNG.nextLong() & 0x7FFFFFFFFFFFFFFFL);
        String symbol = "_jf" + symPrefix + "_" + index;
        Type[] argTypes = Type.getArgumentTypes(mn.desc);
        Type retType = Type.getReturnType(mn.desc);
        String cRet = JniCTranslator.cType(retType);
        String[] cArgs = new String[argTypes.length + 2];
        cArgs[0] = "JNIEnv* env";
        cArgs[1] = mn.name.equals("<init>") ? "jclass _cls" : "jobject _recv";
        for (int i = 0; i < argTypes.length; i++)
            cArgs[i + 2] = JniCTranslator.cType(argTypes[i]) + " _a" + i;

        // 1. Extract CP refs with sequential indices.
        CPIdxMap idxMap = new CPIdxMap();
        ResolvedCP rcp = extractCP(className, mn, idxMap);

        // 2. Serialise bytecode using sequential indices.
        byte[] raw = serializeBytecode(mn, idxMap);
        if (Boolean.getBoolean("kbox.jnic.dumpserial")) {
            StringBuilder hx = new StringBuilder("SERIAL " + className + " " + mn.name + mn.desc + ": ");
            for (byte b : raw) hx.append(String.format("%02x ", b & 0xff));
            System.err.println(hx);
        }

        // 2b. Generate key seed and XOR-encrypt the bytecode.
        // key_seed is a 32-bit non-zero value; 0 means plain mode.
        int keySeed = 0;
        while (keySeed == 0) {
            keySeed = RNG.nextInt() & 0x7FFFFFFF; // ensure non-zero positive
        }
        byte[] encryptedBC = new byte[raw.length];
        for (int i = 0; i < raw.length; i++) {
            encryptedBC[i] = (byte)((raw[i] & 0xFF) ^ keyByteC(keySeed, i));
        }
        String bcArray = byteArrayLiteral(symbol + "_bc", encryptedBC);
        // Emit key seed as a static variable.
        String keySeedVar = "static const uint32_t " + symbol + "_key = " + keySeed + "U;\n";

        // 3. Build CP arrays (already sequen tial from extractCP).
        StringBuilder cpDecls = new StringBuilder();
        List<Integer> clsKeys = seqList(rcp.classes.size());
        List<Integer> fldKeys = seqList(rcp.fields.size());
        List<Integer> midKeys = seqList(rcp.methods.size());
        List<Integer> strKeys = seqList(rcp.strings.size());
        List<Integer> intKeys = seqList(rcp.integers.size());

        // Class names.
        if (!clsKeys.isEmpty()) {
            cpDecls.append("static const char* ").append(symbol).append("_cpcls[] = { ");
            for (int i : clsKeys)
                cpDecls.append("\"").append(escC(rcp.classes.get(i))).append("\", ");
            cpDecls.append("};\n");
        }
        // Field refs.
        if (!fldKeys.isEmpty()) {
            cpDecls.append("static const char* ").append(symbol).append("_cpfld[] = { ");
            for (int i : fldKeys) {
                String[] f = rcp.fields.get(i);
                cpDecls.append("\"").append(escC(f[0])).append("\", \"")
                        .append(escC(f[1])).append("\", \"").append(escC(f[2])).append("\", ");
            }
            cpDecls.append("};\n");
            // Field type codes (for correct Get/Set*Field JNI dispatch by the interpreter).
            cpDecls.append("static const char ").append(symbol).append("_cpfld_rt[] = { ");
            for (int i : fldKeys) {
                String[] f = rcp.fields.get(i);
                cpDecls.append("'").append(fieldTypeCode(f[2])).append("', ");
            }
            cpDecls.append("};\n");
        }
        List<Integer> midArgCounts = new ArrayList<>();
        List<Character> midRetTypes = new ArrayList<>();
        if (!midKeys.isEmpty()) {
            cpDecls.append("static const char* ").append(symbol).append("_cpmid[] = { ");
            for (int i : midKeys) {
                String[] m = rcp.methods.get(i);
                cpDecls.append("\"").append(escC(m[0])).append("\", \"")
                        .append(escC(m[1])).append("\", \"").append(escC(m[2]))
                        .append("\", \"").append(m[3]).append("\", ");
                // Compute arg count and return type from descriptor.
                int ac = countArgs(m[2]);
                char rt = returnTypeCode(m[2]);
                midArgCounts.add(ac);
                midRetTypes.add(rt);
            }
            cpDecls.append("};\n");
        }
        // Arg count arrays for methods.
        if (!midArgCounts.isEmpty()) {
            cpDecls.append("static const int ").append(symbol).append("_cpmid_ac[] = { ");
            for (int ac : midArgCounts) cpDecls.append(ac).append(", ");
            cpDecls.append("};\n");
        }
        // Return type arrays for methods.
        if (!midRetTypes.isEmpty()) {
            cpDecls.append("static const char ").append(symbol).append("_cpmid_rt[] = { ");
            for (char rt : midRetTypes) cpDecls.append("'").append(rt).append("', ");
            cpDecls.append("};\n");
        }
        // String constants.
        if (!strKeys.isEmpty()) {
            cpDecls.append("static const char* ").append(symbol).append("_cpstr[] = { ");
            for (int i : strKeys)
                cpDecls.append("\"").append(escC(rcp.strings.get(i))).append("\", ");
            cpDecls.append("};\n");
        }
        // Int constants.
        if (!intKeys.isEmpty()) {
            cpDecls.append("static const jint ").append(symbol).append("_cpint[] = { ");
            for (int i : intKeys)
                cpDecls.append(rcp.integers.get(i)).append(", ");
            cpDecls.append("};\n");
        }
        // Invokedynamic sites: per-site packed metadata, arg slot codes and return
        // code. The C interpreter forwards these to the injected JnicIndy resolver.
        List<Integer> indyKeys = seqList(rcp.indies.size());
        if (!indyKeys.isEmpty()) {
            cpDecls.append("static const char* ").append(symbol).append("_indy_meta[] = { ");
            for (int i : indyKeys) cpDecls.append("\"").append(escC((String) rcp.indies.get(i)[0])).append("\", ");
            cpDecls.append("};\n");
            cpDecls.append("static const char* ").append(symbol).append("_indy_argc[] = { ");
            for (int i : indyKeys) cpDecls.append("\"").append(escC((String) rcp.indies.get(i)[1])).append("\", ");
            cpDecls.append("};\n");
            cpDecls.append("static const char ").append(symbol).append("_indy_ret[] = { ");
            for (int i : indyKeys) cpDecls.append("'").append(((String) rcp.indies.get(i)[2]).charAt(0)).append("', ");
            cpDecls.append("};\n");
        }

        // 4. Build the C stub (v3: encrypted bytecode + execution erasure).
        StringBuilder body = new StringBuilder();
        body.append("JNIEXPORT ").append(cRet).append(" JNICALL ").append(symbol)
                .append("(").append(String.join(", ", cArgs)).append(") {\n");

        int nc = clsKeys.size(), nf = fldKeys.size(), nm = midKeys.size();
        int ns = strKeys.size(), ni = intKeys.size();

        if (nc > 0) body.append("  static jclass _cpclsR[").append(nc).append("];\n");
        if (nf > 0) body.append("  static jfieldID _cpfldR[").append(nf).append("];\n");
        if (nf > 0) body.append("  static jclass _cpfldClsR[").append(nf).append("];\n");
        if (nm > 0) body.append("  static jmethodID _cpmidR[").append(nm).append("];\n");
        if (nm > 0) body.append("  static jclass _cpmidCls[").append(nm).append("];\n");

        // Allocate mutable copy of encrypted bytecode for in-place erasure.
        body.append("  uint8_t* _mutBC=(").append(symbol).append("_key")
                .append(") ? (uint8_t*)malloc(").append(raw.length).append(") : NULL;\n");
        body.append("  if (_mutBC) memcpy(_mutBC,").append(symbol)
                .append("_bc,").append(raw.length).append(");\n");

        body.append("  static int _init=0;\n");
        // NOTE: cached jclass/jfieldID/jmethodID are created on the FIRST call and
        // reused by every subsequent call. FindClass returns a LOCAL reference that
        // is invalidated when the native method returns, so we must promote every
        // cached class to a GLOBAL reference (NewGlobalRef) or later calls will
        // crash (EXCEPTION_ACCESS_VIOLATION) when the interpreter dereferences a
        // stale jclass. jfieldID/jmethodID are non-reference values and stay valid.
        body.append("  if (!_init) {\n");
        // Pre-resolve classes (promoted to global refs).
        for (int i : clsKeys) {
            body.append("    { jclass _l=(*env)->FindClass(env,\"")
                    .append(rcp.classes.get(i)).append("\"); _cpclsR[").append(i)
                    .append("]=(jclass)(*env)->NewGlobalRef(env,_l); }\n");
        }
        // Pre-resolve field IDs. Track each field's OWNER class (global ref) and
        // whether it is static: static fields MUST be resolved with
        // GetStaticFieldID and read/written against their own owner class, not the
        // method's class (cp_cls[0]). Mixing these up made System.out & co fail
        // (NoSuchFieldError on new JVMs / EXCEPTION_ACCESS_VIOLATION on older ones).
        for (int i : fldKeys) {
            String[] f = rcp.fields.get(i);
            boolean st = "1".equals(f[3]);
            body.append("    { jclass c=(*env)->NewGlobalRef(env,(*env)->FindClass(env,\"").append(f[0])
                    .append("\")); _cpfldClsR[").append(i).append("]=c; ")
                    .append(st ? "_cpfldR[" + i + "]=(*env)->GetStaticFieldID(env,c,\"" + f[1] + "\",\"" + f[2] + "\");"
                                : "_cpfldR[" + i + "]=(*env)->GetFieldID(env,c,\"" + f[1] + "\",\"" + f[2] + "\");")
                    .append(" if (!_cpfldR[").append(i).append("]) { fprintf(stderr,\"[JNIC] FIELDFAIL ")
                    .append((st ? "STATIC " : "INST  ")).append(f[0]).append("\\t").append(f[1]).append("\\t").append(f[2]).append("\\n\"); ")
                    .append("if ((*env)->ExceptionCheck(env)) (*env)->ExceptionDescribe(env), (*env)->ExceptionClear(env); }\n");
            body.append("    }\n");
        }
        // Pre-resolve method IDs.
        for (int i : midKeys) {
            String[] m = rcp.methods.get(i);
            body.append("    { jclass c=(*env)->NewGlobalRef(env,(*env)->FindClass(env,\"").append(m[0])
                    .append("\")); _cpmidCls[").append(i).append("]=c; ");
            if ("1".equals(m[3]))
                body.append("_cpmidR[").append(i).append("]=(*env)->GetStaticMethodID(env,c,\"")
                        .append(m[1]).append("\",\"").append(m[2]).append("\"); }\n");
            else
                body.append("_cpmidR[").append(i).append("]=(*env)->GetMethodID(env,c,\"")
                        .append(m[1]).append("\",\"").append(m[2]).append("\"); }\n");
        }
        body.append("    _init=1;\n  }\n");

        // Build _args[] with CP arrays + sizes.
        body.append("  void* _a[]={ ");
        appendPtrArg(body, "_cpclsR", nc);
        appendPtrArg(body, "_cpfldR", nf);
        appendPtrArg(body, "_cpmidR", nm);
        appendPtrArg(body, symbol + "_cpstr", ns);
        appendPtrArg(body, symbol + "_cpint", ni);
        // Method arg-count + return-type arrays (for correct INVOKE handling)
        appendPtrArg(body, symbol + "_cpmid_ac", nm);
        appendPtrArg(body, symbol + "_cpmid_rt", nm);
        // jclass per method (for INVOKESTATIC when no NEW-based cp_cls exists)
        appendPtrArg(body, "_cpmidCls", nm);
        // args[16..17] = field type codes (for Get/Set*Field dispatch)
        appendPtrArg(body, symbol + "_cpfld_rt", nf);
        // args[18..19] = per-field OWNER jclass (static fields read/write the
        //   field against its declaring class, not the method's own class)
        appendPtrArg(body, "_cpfldClsR", nf);
        // args[20..21] = per-class internal NAME strings (MULTIANEWARRAY needs the
        //   array descriptor at runtime to build nested arrays of the right type).
        appendPtrArg(body, symbol + "_cpcls", nc);
        // args[22..27] = invokedynamic site metadata: meta strings, arg slot codes,
        //   return code chars (forwarded to the JnicIndy bootstrap resolver).
        appendPtrArg(body, symbol + "_indy_meta", rcp.indies.size());
        appendPtrArg(body, symbol + "_indy_argc", rcp.indies.size());
        appendPtrArg(body, symbol + "_indy_ret", rcp.indies.size());
        // args[28] = pointer to key_seed (for v3 entry)
        body.append("(void*)&").append(symbol).append("_key, ");
        for (int i = 2; i < cArgs.length; i++)
            body.append("(void*)(intptr_t)").append("_a" + (i - 2)).append(", ");
        body.append("NULL };\n");

        // The interpreter occupies local[0] for the receiver ONLY when it's non-NULL.
        // For static methods and constructors, we pass NULL so locals start at slot 0.
        boolean isStatic = (mn.access & Opcodes.ACC_STATIC) != 0;
        String recvExpr = (mn.name.equals("<init>") || isStatic) ? "NULL" : "_recv";
        int localsCount = mn.maxLocals;  // no override needed when receiver=NULL for static
        // Clamp the frame the interpreter allocates into its fixed-size
        // locals[]/stack[] arrays (KBOX_MAX_SLOTS=256); selection already rejects
        // oversized frames, this is defense-in-depth against any straggler.
        if (localsCount > 256) localsCount = 256;

        // Use v3 entry: encrypted bytecode + per-instruction decrypt + execution erasure.
        body.append("  kbox_value_t _r=kbox_jvm_interp_v3(env,")
                .append(recvExpr)
                .append(",").append(symbol).append("_bc,").append(raw.length)
                .append(",_a,").append(localsCount).append(",").append(mn.maxStack)
                .append(",_mutBC);\n");
        body.append("  if (_mutBC) free(_mutBC);\n");

        int s = retType.getSort();
        if (s == Type.VOID) body.append("  return;\n");
        else if (s <= Type.INT) body.append("  return _r.i;\n");
        else if (s == Type.LONG) body.append("  return _r.l;\n");
        else if (s == Type.FLOAT) body.append("  return _r.f;\n");
        else if (s == Type.DOUBLE) body.append("  return _r.d;\n");
        else body.append("  return (jobject)(intptr_t)_r.l;\n");
        body.append("}\n");

        String fullBody = bcArray + "\n" + keySeedVar + "\n" + cpDecls + "\n" + body;
        return new InterpFn(symbol, className, mn.name, mn.desc, fullBody, cArgs, raw.length);
    }

    private static void appendPtrArg(StringBuilder sb, String arrName, int count) {
        if (count > 0) {
            sb.append("(void*)").append(arrName).append(", ");
            sb.append("(void*)(intptr_t)").append(count).append(", ");
        } else {
            sb.append("NULL, NULL, ");
        }
    }

    private static List<Integer> seqList(int n) {
        List<Integer> out = new ArrayList<>(n);
        for (int i = 0; i < n; i++) out.add(i);
        return out;
    }

    // ---- CP extraction with sequential indices ----

    @SuppressWarnings("unchecked")
    private static ResolvedCP extractCP(String className, MethodNode mn, CPIdxMap idxMap) {
        ResolvedCP rcp = new ResolvedCP();
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            int op = insn.getOpcode();
            if (insn instanceof LdcInsnNode) {
                LdcInsnNode ldc = (LdcInsnNode) insn;
                if (ldc.cst instanceof String) {
                    String v = (String) ldc.cst;
                    if (!idxMap.strIdx.containsKey(v)) {
                        int seq = idxMap.strIdx.size();
                        idxMap.strIdx.put(v, seq);
                        rcp.strings.put(seq, v);
                    }
                } else if (ldc.cst instanceof Integer) {
                    int v = (Integer) ldc.cst;
                    if (!idxMap.intIdx.containsKey(v)) {
                        int seq = idxMap.intIdx.size();
                        idxMap.intIdx.put(v, seq);
                        rcp.integers.put(seq, v);
                    }
                }
            } else if (insn instanceof TypeInsnNode
                    && (op == Opcodes.NEW || op == Opcodes.ANEWARRAY
                        || op == Opcodes.CHECKCAST || op == Opcodes.INSTANCEOF)) {
                String name = ((TypeInsnNode) insn).desc;
                if (!idxMap.clsIdx.containsKey(name)) {
                    int seq = idxMap.clsIdx.size();
                    idxMap.clsIdx.put(name, seq);
                    rcp.classes.put(seq, name);
                }
            } else if (insn instanceof MultiANewArrayInsnNode) {
                // MULTIANEWARRAY references an ARRAY type (e.g. "[[I"), used by the
                // native interpreter to build nested arrays of the correct runtime type.
                String name = ((MultiANewArrayInsnNode) insn).desc;
                if (!idxMap.clsIdx.containsKey(name)) {
                    int seq = idxMap.clsIdx.size();
                    idxMap.clsIdx.put(name, seq);
                    rcp.classes.put(seq, name);
                }
            } else if (insn instanceof FieldInsnNode) {
                FieldInsnNode f = (FieldInsnNode) insn;
                // Track staticness so the native stub resolves static fields via
                // GetStaticFieldID (System.out & co) and instance fields via
                // GetFieldID — using the wrong accessor makes the lookup return
                // NULL + NoSuchFieldError (new JVM) or crash (old JVM).
                boolean st = f.getOpcode() == Opcodes.GETSTATIC || f.getOpcode() == Opcodes.PUTSTATIC;
                String sig = f.owner + ":" + f.name + ":" + f.desc + ":" + (st ? "1" : "0");
                if (!idxMap.fldIdx.containsKey(sig)) {
                    int seq = idxMap.fldIdx.size();
                    idxMap.fldIdx.put(sig, seq);
                    rcp.fields.put(seq, new String[]{f.owner, f.name, f.desc, st ? "1" : "0"});
                }
            } else if (insn instanceof MethodInsnNode) {
                MethodInsnNode m = (MethodInsnNode) insn;
                boolean isStatic = m.getOpcode() == Opcodes.INVOKESTATIC;
                String sig = m.owner + ":" + m.name + ":" + m.desc + ":" + (isStatic ? "1" : "0");
                if (!idxMap.midIdx.containsKey(sig)) {
                    int seq = idxMap.midIdx.size();
                    idxMap.midIdx.put(sig, seq);
                    rcp.methods.put(seq, new String[]{m.owner, m.name, m.desc, isStatic ? "1" : "0"});
                }
            } else if (insn instanceof InvokeDynamicInsnNode) {
                InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) insn;
                if (!idxMap.indyIdx.containsKey(id)) {
                    int seq = idxMap.indyIdx.size();
                    idxMap.indyIdx.put(id, seq);
                    rcp.indies.put(seq, indyMeta(className, id));
                }
            }
        }
        return rcp;
    }

    // ---- bytecode serialisation (uses sequential CP indices) ----

    @SuppressWarnings("unchecked")
    private static byte[] serializeBytecode(MethodNode mn, CPIdxMap idxMap) {
        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
        Map<LabelNode, Integer> labelOffsets = new HashMap<>();
        // Pass 1: compute label offsets.
        int offset = 0;
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof LabelNode) {
                labelOffsets.put((LabelNode) insn, offset);
            } else if (!(insn instanceof FrameNode || insn instanceof LineNumberNode)) {
                offset += insnSize(insn);
            }
        }
        // Pass 2: write opcodes with sequential CP indices.
        for (AbstractInsnNode insn = mn.instructions.getFirst(); insn != null; insn = insn.getNext()) {
            if (insn instanceof FrameNode || insn instanceof LineNumberNode) continue;
            if (insn instanceof LabelNode) continue;
            writeInsn(bos, insn, labelOffsets, idxMap);
        }
        return bos.toByteArray();
    }

    private static void writeInsn(java.io.ByteArrayOutputStream bos,
                                  AbstractInsnNode insn,
                                  Map<LabelNode, Integer> labelOffsets,
                                  CPIdxMap idxMap) {
        int op = insn.getOpcode();
        if (op < 0) return;
        bos.write(op);
        int nop = op; // local alias for switch readability
        if (insn instanceof IntInsnNode) {
            IntInsnNode ii = (IntInsnNode) insn;
            if (op == Opcodes.BIPUSH) {
                // BIPUSH: opcode + 1-byte operand (matches C FETCH)
                bos.write(ii.operand & 0xFF);
            } else {
                // SIPUSH: opcode + 2-byte operand (matches C FETCH_S16)
                writeShort(bos, (short) ii.operand);
            }
        } else if (insn instanceof VarInsnNode) {
            bos.write(((VarInsnNode) insn).var);
        } else if (insn instanceof IincInsnNode) {
            IincInsnNode ii = (IincInsnNode) insn;
            bos.write(ii.var);
            bos.write(ii.incr);
        } else if (insn instanceof JumpInsnNode) {
            JumpInsnNode j = (JumpInsnNode) insn;
            Integer tgt = labelOffsets.get(j.label);
            // branchOff relative to opcode address (not after instruction).
            // bos.size() = opcode_addr + 1 (opcode was just written).
            int branchOff = tgt != null ? tgt - (bos.size() - 1) : 0;
            writeShort(bos, (short) branchOff);
        } else if (insn instanceof TypeInsnNode
                && (nop == Opcodes.NEW || nop == Opcodes.ANEWARRAY
                    || nop == Opcodes.CHECKCAST || nop == Opcodes.INSTANCEOF)) {
            String name = ((TypeInsnNode) insn).desc;
            Integer seq = idxMap.clsIdx.get(name);
            writeShort(bos, seq != null ? seq.shortValue() : 0);
        } else if (insn instanceof FieldInsnNode) {
            FieldInsnNode f = (FieldInsnNode) insn;
            boolean st = f.getOpcode() == Opcodes.GETSTATIC || f.getOpcode() == Opcodes.PUTSTATIC;
            String sig = f.owner + ":" + f.name + ":" + f.desc + ":" + (st ? "1" : "0");
            Integer seq = idxMap.fldIdx.get(sig);
            writeShort(bos, seq != null ? seq.shortValue() : 0);
        } else if (insn instanceof MethodInsnNode) {
            MethodInsnNode m = (MethodInsnNode) insn;
            boolean isStatic = m.getOpcode() == Opcodes.INVOKESTATIC;
            String sig = m.owner + ":" + m.name + ":" + m.desc + ":" + (isStatic ? "1" : "0");
            Integer seq = idxMap.midIdx.get(sig);
            writeShort(bos, seq != null ? seq.shortValue() : 0);
        } else if (insn instanceof LdcInsnNode) {
            LdcInsnNode ldc = (LdcInsnNode) insn;
            if (ldc.cst instanceof String) {
                Integer seq = idxMap.strIdx.get((String) ldc.cst);
                writeShort(bos, seq != null ? seq.shortValue() : 0);
            } else if (ldc.cst instanceof Integer) {
                Integer seq = idxMap.intIdx.get((Integer) ldc.cst);
                // Encode int index as: 0x8000 | seq (distinguishes from string idx)
                int tag = 0x8000 | (seq != null ? seq : 0);
                writeShort(bos, (short) tag);
            } else {
                writeShort(bos, (short) 0);
            }
        } else if (insn instanceof TableSwitchInsnNode) {
            // opcode already written at the top of writeInsn; payload follows.
            // start = position of the opcode byte (rel targets are relative to it).
            TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
            int start = bos.size() - 1;
            writeInt(bos, relOf(labelOffsets, ts.dflt, start));
            writeInt(bos, ts.min);
            writeInt(bos, ts.max);
            for (LabelNode lbl : ts.labels) writeInt(bos, relOf(labelOffsets, lbl, start));
        } else if (insn instanceof LookupSwitchInsnNode) {
            LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
            int start = bos.size() - 1;
            writeInt(bos, relOf(labelOffsets, ls.dflt, start));
            writeInt(bos, ls.keys.size());
            for (int i = 0; i < ls.keys.size(); i++) {
                writeInt(bos, ls.keys.get(i));
                writeInt(bos, relOf(labelOffsets, ls.labels.get(i), start));
            }
        } else if (insn instanceof MultiANewArrayInsnNode) {
            MultiANewArrayInsnNode ma = (MultiANewArrayInsnNode) insn;
            Integer seq = idxMap.clsIdx.get(ma.desc);
            writeShort(bos, seq != null ? seq.shortValue() : 0);
            bos.write(ma.dims);
        } else if (insn instanceof InvokeDynamicInsnNode) {
            InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) insn;
            Integer seq = idxMap.indyIdx.get(id);
            writeShort(bos, seq != null ? seq.shortValue() : 0);
            writeShort(bos, (short) 0); // second word is unused zero (matches insnSize)
        }
    }

    /** Absolute target offset of a label relative to the switch opcode position. */
    private static int relOf(Map<LabelNode, Integer> labelOffsets, LabelNode label, int start) {
        Integer t = labelOffsets.get(label);
        return (t != null) ? (t - start) : 0;
    }

    /** Writes a big-endian 32-bit integer. */
    private static void writeInt(java.io.ByteArrayOutputStream bos, int v) {
        bos.write((v >>> 24) & 0xff);
        bos.write((v >>> 16) & 0xff);
        bos.write((v >>> 8) & 0xff);
        bos.write(v & 0xff);
    }

    private static int insnSize(AbstractInsnNode insn) {
        int op = insn.getOpcode();
        if (insn instanceof IntInsnNode)
            return (op == Opcodes.BIPUSH) ? 2 : 3;  // BIPUSH=1-byte, SIPUSH=2-byte operand
        if (insn instanceof VarInsnNode) return (op == Opcodes.RET) ? 2 : 2;
        if (insn instanceof TypeInsnNode) return 3;
        if (insn instanceof FieldInsnNode) return 3;
        if (insn instanceof MethodInsnNode) return 3;
        if (insn instanceof JumpInsnNode) return 3;
        if (insn instanceof LdcInsnNode) return 3;  // 1-byte op + 2-byte sequential idx
        if (insn instanceof IincInsnNode) return 3;
        if (insn instanceof TableSwitchInsnNode) {
            // Padding-free encoding: op + 3x i32 header + (high-low+1) x i32 targets.
            TableSwitchInsnNode ts = (TableSwitchInsnNode) insn;
            int count = (int) ((long) ts.max - ts.min + 1);
            return 1 + 12 + Math.max(count, ts.labels.size()) * 4;
        }
        if (insn instanceof LookupSwitchInsnNode) {
            // Padding-free encoding: op + 2x i32 header + npairs x (key,target) i32.
            LookupSwitchInsnNode ls = (LookupSwitchInsnNode) insn;
            return 1 + 8 + ls.keys.size() * 8;
        }
        if (insn instanceof MultiANewArrayInsnNode) return 4;
        if (insn instanceof InvokeDynamicInsnNode) return 5;
        return 1;
    }

    private static void writeShort(java.io.ByteArrayOutputStream bos, short v) {
        bos.write((v >> 8) & 0xff);
        bos.write(v & 0xff);
    }

    // ---- helpers ----

    /** Counts the number of arguments in a JVM method descriptor like "(IILjava/lang/String;)V". */
    private static int countArgs(String desc) {
        int n = 0;
        int i = 1; // skip '('
        while (i < desc.length() && desc.charAt(i) != ')') {
            char c = desc.charAt(i);
            if (c == 'L') { while (i < desc.length() && desc.charAt(i) != ';') i++; }
            else if (c == '[') { while (i < desc.length() && desc.charAt(i) == '[') i++; if (i < desc.length() && desc.charAt(i) == 'L') while (i < desc.length() && desc.charAt(i) != ';') i++; }
            else if (c == 'D' || c == 'J') { /* wide, counts as 1 arg */ }
            i++; n++;
        }
        return n;
    }

    /** Returns the return type code character from a JVM method descriptor. 
     *  'V'=void, 'I'=int, 'J'=long, 'F'=float, 'D'=double, 'L'=object, '['=array. */
    private static char returnTypeCode(String desc) {
        int i = desc.indexOf(')');
        if (i < 0 || i + 1 >= desc.length()) return 'V';
        return desc.charAt(i + 1);
    }

    /** Returns the field-type code character from a JVM field descriptor. The native
     *  interpreter uses this to pick the correct {@code Get/Set*Field} JNI accessor
     *  for GETFIELD/PUTFIELD/GETSTATIC/PUTSTATIC. 'I' also covers boolean/byte/char/short
     *  (all returned via the int accessor on the JVM). */
    private static char fieldTypeCode(String desc) {
        if (desc == null || desc.isEmpty()) return 'L';
        char c = desc.charAt(0);
        switch (c) {
            case 'L': case '[': return 'L';
            case 'J': return 'J';
            case 'F': return 'F';
            case 'D': return 'D';
            default:  return 'I'; // I, Z, B, C, S
        }
    }

    private static String byteArrayLiteral(String name, byte[] data) {
        StringBuilder sb = new StringBuilder();
        sb.append("static const unsigned char ").append(name).append("[]={");
        for (int i = 0; i < data.length; i++) {
            if (i > 0) sb.append(',');
            sb.append(data[i] & 0xff);
        }
        sb.append("};\n");
        return sb.toString();
    }

    private static String escC(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') sb.append("\\\\");
            else if (c == '"') sb.append("\\\"");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else if (c == '\f') sb.append("\\f");
            else if (c == '\b') sb.append("\\b");
            else if (c >= 0x20 && c <= 0x7E) sb.append(c);
            else sb.append('\\').append(String.format("%03o", (int) c));
        }
        return sb.toString();
    }
}
