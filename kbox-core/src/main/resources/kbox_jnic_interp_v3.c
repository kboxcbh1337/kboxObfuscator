/*
 * KBox-JNIC Enhanced Interpreter v3
 *
 * A compact stack-based JVM bytecode interpreter with per-instruction
 * stream encryption, execution-time erasure, function-pointer-table dispatch,
 * and anti-debug hooks.
 *
 * Builds with GCC (computed-goto), Clang, or MSVC:
 *   GCC/Clang:  gcc -shared -O2 -fPIC -I<jdk>/include -I<jdk>/include/win32 kbox_jnic_interp_v3.c -o kbox_native.dll
 *   MSVC:       cl /LD /O2 /I<jdk>/include /I<jdk>/include/win32 kbox_jnic_interp_v3.c /Fe:kbox_native.dll
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ===== Compiler compatibility macros ===== */
#ifdef _MSC_VER
  #define KBOX_ALIGNED(x) __declspec(align(x))
  #define KBOX_TRAP()     __debugbreak()
  #define KBOX_INLINE     static __inline
#else
  #define KBOX_ALIGNED(x) __attribute__((aligned(x)))
  #define KBOX_TRAP()     __builtin_trap()
  #define KBOX_INLINE     static inline
#endif

/* ===== Embedded core structures (kbox_jnic_core.h inline) ===== */

typedef union KBOX_ALIGNED(8) {
    jint      i;
    jlong     j;
    jfloat    f;
    jdouble   d;
    jobject   o;
    void*     ptr;
} kbox_slot_t;

/* Alias for backward compatibility with existing stubs */
typedef kbox_slot_t kbox_value_t;

typedef struct {
    uint32_t start_pc;
    uint32_t end_pc;
    uint32_t handler_pc;
    uint16_t catch_type;
} kbox_ex_handler_t;

/* Hard upper bound on operand-stack depth and local-variable slots in a single
 * translated method. The stub generator MUST reject any method whose
 * maxStack / maxLocals exceed this (see JniBytecodeInterp / JnicOrchestrator);
 * these entry-point clamps are defense-in-depth so a mis-generated or tampered
 * stub can never overrun the fixed-size arrays below. */
#define KBOX_MAX_SLOTS  256
#define KBOX_MAX_ARGS   32

/* Debug helper: resolve a jclass to its dotted name for KBOX_JNIC_DBG logging.
 * Returns a pointer to a static buffer (overwritten on next call). Used only in
 * the INSTANCEOF debug branch; never called on the release path. */
static const char* getClassName(JNIEnv* env, jclass cls) {
    static char _buf[512];
    if (!cls) return "(null)";
    _buf[0] = '\0';
    jmethodID gm = (*env)->GetMethodID(env, cls, "getName", "()Ljava/lang/String;");
    if (!gm) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return "<unknown>"; }
    jstring ns = (jstring)(*env)->CallObjectMethod(env, cls, gm);
    if (!ns) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return "<unknown>"; }
    const char* c = (*env)->GetStringUTFChars(env, ns, NULL);
    if (c) {
        strncpy(_buf, c, sizeof(_buf) - 1);
        _buf[sizeof(_buf) - 1] = '\0';
        (*env)->ReleaseStringUTFChars(env, ns, c);
    }
    return _buf;
}

/* ===== Opcode constants (standard JVM) ===== */
enum {
    K_NOP=0x00, K_ACONST_NULL=0x01, K_ICONST_M1=0x02, K_ICONST_0=0x03,
    K_ICONST_1=0x04, K_ICONST_2=0x05, K_ICONST_3=0x06, K_ICONST_4=0x07,
    K_ICONST_5=0x08, K_LCONST_0=0x09, K_LCONST_1=0x0A, K_FCONST_0=0x0B,
    K_FCONST_1=0x0C, K_FCONST_2=0x0D, K_DCONST_0=0x0E, K_DCONST_1=0x0F,
    K_BIPUSH=0x10, K_SIPUSH=0x11, K_LDC=0x12,
    K_ILOAD=0x15, K_LLOAD=0x16, K_FLOAD=0x17, K_DLOAD=0x18, K_ALOAD=0x19,
    K_ILOAD_0=0x1A,K_ILOAD_1=0x1B,K_ILOAD_2=0x1C,K_ILOAD_3=0x1D,
    K_LLOAD_0=0x1E,K_LLOAD_1=0x1F,K_LLOAD_2=0x20,K_LLOAD_3=0x21,
    K_FLOAD_0=0x22,K_FLOAD_1=0x23,K_FLOAD_2=0x24,K_FLOAD_3=0x25,
    K_DLOAD_0=0x26,K_DLOAD_1=0x27,K_DLOAD_2=0x28,K_DLOAD_3=0x29,
    K_ALOAD_0=0x2A,K_ALOAD_1=0x2B,K_ALOAD_2=0x2C,K_ALOAD_3=0x2D,
    K_IALOAD=0x2E,K_LALOAD=0x2F,K_FALOAD=0x30,K_DALOAD=0x31,
    K_AALOAD=0x32,K_BALOAD=0x33,K_CALOAD=0x34,K_SALOAD=0x35,
    K_ISTORE=0x36,K_LSTORE=0x37,K_FSTORE=0x38,K_DSTORE=0x39,K_ASTORE=0x3A,
    K_ISTORE_0=0x3B,K_ISTORE_1=0x3C,K_ISTORE_2=0x3D,K_ISTORE_3=0x3E,
    K_LSTORE_0=0x3F,K_LSTORE_1=0x40,K_LSTORE_2=0x41,K_LSTORE_3=0x42,
    K_FSTORE_0=0x43,K_FSTORE_1=0x44,K_FSTORE_2=0x45,K_FSTORE_3=0x46,
    K_DSTORE_0=0x47,K_DSTORE_1=0x48,K_DSTORE_2=0x49,K_DSTORE_3=0x4A,
    K_ASTORE_0=0x4B,K_ASTORE_1=0x4C,K_ASTORE_2=0x4D,K_ASTORE_3=0x4E,
    K_IASTORE=0x4F,K_LASTORE=0x50,K_FASTORE=0x51,K_DASTORE=0x52,
    K_AASTORE=0x53,K_BASTORE=0x54,K_CASTORE=0x55,K_SASTORE=0x56,
    K_POP=0x57,K_POP2=0x58,K_DUP=0x59,K_DUP_X1=0x5A,K_DUP_X2=0x5B,
    K_DUP2=0x5C,K_DUP2_X1=0x5D,K_DUP2_X2=0x5E,K_SWAP=0x5F,
    K_IADD=0x60,K_LADD=0x61,K_FADD=0x62,K_DADD=0x63,
    K_ISUB=0x64,K_LSUB=0x65,K_FSUB=0x66,K_DSUB=0x67,
    K_IMUL=0x68,K_LMUL=0x69,K_FMUL=0x6A,K_DMUL=0x6B,
    K_IDIV=0x6C,K_LDIV=0x6D,K_FDIV=0x6E,K_DDIV=0x6F,
    K_IREM=0x70,K_LREM=0x71,K_FREM=0x72,K_DREM=0x73,
    K_INEG=0x74,K_LNEG=0x75,K_FNEG=0x76,K_DNEG=0x77,
    K_ISHL=0x78,K_LSHL=0x79,K_ISHR=0x7A,K_LSHR=0x7B,K_IUSHR=0x7C,K_LUSHR=0x7D,
    K_IAND=0x7E,K_LAND=0x7F,K_IOR=0x80,K_LOR=0x81,K_IXOR=0x82,K_LXOR=0x83,
    K_IINC=0x84,
    K_I2L=0x85,K_I2F=0x86,K_I2D=0x87,K_L2I=0x88,K_L2F=0x89,K_L2D=0x8A,
    K_F2I=0x8B,K_F2L=0x8C,K_F2D=0x8D,K_D2I=0x8E,K_D2L=0x8F,K_D2F=0x90,
    K_I2B=0x91,K_I2C=0x92,K_I2S=0x93,
    K_LCMP=0x94,K_FCMPL=0x95,K_FCMPG=0x96,K_DCMPL=0x97,K_DCMPG=0x98,
    K_IFEQ=0x99,K_IFNE=0x9A,K_IFLT=0x9B,K_IFGE=0x9C,K_IFGT=0x9D,K_IFLE=0x9E,
    K_IF_ICMPEQ=0x9F,K_IF_ICMPNE=0xA0,K_IF_ICMPLT=0xA1,K_IF_ICMPGE=0xA2,
    K_IF_ICMPGT=0xA3,K_IF_ICMPLE=0xA4,K_IF_ACMPEQ=0xA5,K_IF_ACMPNE=0xA6,
    K_GOTO=0xA7,
    K_IRETURN=0xAC,K_LRETURN=0xAD,K_FRETURN=0xAE,K_DRETURN=0xAF,
    K_ARETURN=0xB0,K_RETURN=0xB1,
    K_GETSTATIC=0xB2,K_PUTSTATIC=0xB3,K_GETFIELD=0xB4,K_PUTFIELD=0xB5,
    K_INVOKEVIRTUAL=0xB6,K_INVOKESPECIAL=0xB7,K_INVOKESTATIC=0xB8,K_INVOKEINTERFACE=0xB9,
    K_NEW=0xBB,K_NEWARRAY=0xBC,K_ANEWARRAY=0xBD,
    K_ARRAYLENGTH=0xBE,K_ATHROW=0xBF,K_CHECKCAST=0xC0,K_INSTANCEOF=0xC1,
    K_MULTIANEWARRAY=0xC5, K_IFNULL=0xC6,K_IFNONNULL=0xC7,
    K_TABLESWITCH=0xAA, K_LOOKUPSWITCH=0xAB, K_INVOKEDYNAMIC=0xBA
};

/* Forward declaration: kbox_ctx_t is defined below after the struct definition. */
typedef struct kbox_ctx_s kbox_ctx_t;

/* ===== Forward declarations for function pointer table ===== */
static void fn_NOP(kbox_ctx_t* ctx);     static void fn_ACONST_NULL(kbox_ctx_t* ctx);
static void fn_ICONST_M1(kbox_ctx_t* ctx); static void fn_ICONST_0(kbox_ctx_t* ctx); static void fn_ICONST_1(kbox_ctx_t* ctx);
static void fn_ICONST_2(kbox_ctx_t* ctx); static void fn_ICONST_3(kbox_ctx_t* ctx); static void fn_ICONST_4(kbox_ctx_t* ctx);
static void fn_ICONST_5(kbox_ctx_t* ctx);
static void fn_LCONST_0(kbox_ctx_t* ctx); static void fn_LCONST_1(kbox_ctx_t* ctx);
static void fn_FCONST_0(kbox_ctx_t* ctx); static void fn_FCONST_1(kbox_ctx_t* ctx); static void fn_FCONST_2(kbox_ctx_t* ctx);
static void fn_DCONST_0(kbox_ctx_t* ctx); static void fn_DCONST_1(kbox_ctx_t* ctx);
static void fn_BIPUSH(kbox_ctx_t* ctx); static void fn_SIPUSH(kbox_ctx_t* ctx); static void fn_LDC(kbox_ctx_t* ctx);
static void fn_ILOAD(kbox_ctx_t* ctx); static void fn_LLOAD(kbox_ctx_t* ctx); static void fn_FLOAD(kbox_ctx_t* ctx);
static void fn_DLOAD(kbox_ctx_t* ctx); static void fn_ALOAD(kbox_ctx_t* ctx);
static void fn_ILOAD_0(kbox_ctx_t* ctx); static void fn_ILOAD_1(kbox_ctx_t* ctx); static void fn_ILOAD_2(kbox_ctx_t* ctx); static void fn_ILOAD_3(kbox_ctx_t* ctx);
static void fn_LLOAD_0(kbox_ctx_t* ctx); static void fn_LLOAD_1(kbox_ctx_t* ctx); static void fn_LLOAD_2(kbox_ctx_t* ctx); static void fn_LLOAD_3(kbox_ctx_t* ctx);
static void fn_FLOAD_0(kbox_ctx_t* ctx); static void fn_FLOAD_1(kbox_ctx_t* ctx); static void fn_FLOAD_2(kbox_ctx_t* ctx); static void fn_FLOAD_3(kbox_ctx_t* ctx);
static void fn_DLOAD_0(kbox_ctx_t* ctx); static void fn_DLOAD_1(kbox_ctx_t* ctx); static void fn_DLOAD_2(kbox_ctx_t* ctx); static void fn_DLOAD_3(kbox_ctx_t* ctx);
static void fn_ALOAD_0(kbox_ctx_t* ctx); static void fn_ALOAD_1(kbox_ctx_t* ctx); static void fn_ALOAD_2(kbox_ctx_t* ctx); static void fn_ALOAD_3(kbox_ctx_t* ctx);
static void fn_IALOAD(kbox_ctx_t* ctx); static void fn_LALOAD(kbox_ctx_t* ctx); static void fn_FALOAD(kbox_ctx_t* ctx); static void fn_DALOAD(kbox_ctx_t* ctx);
static void fn_AALOAD(kbox_ctx_t* ctx); static void fn_BALOAD(kbox_ctx_t* ctx); static void fn_CALOAD(kbox_ctx_t* ctx); static void fn_SALOAD(kbox_ctx_t* ctx);
static void fn_ISTORE(kbox_ctx_t* ctx); static void fn_LSTORE(kbox_ctx_t* ctx); static void fn_FSTORE(kbox_ctx_t* ctx);
static void fn_DSTORE(kbox_ctx_t* ctx); static void fn_ASTORE(kbox_ctx_t* ctx);
static void fn_ISTORE_0(kbox_ctx_t* ctx); static void fn_ISTORE_1(kbox_ctx_t* ctx); static void fn_ISTORE_2(kbox_ctx_t* ctx); static void fn_ISTORE_3(kbox_ctx_t* ctx);
static void fn_LSTORE_0(kbox_ctx_t* ctx); static void fn_LSTORE_1(kbox_ctx_t* ctx); static void fn_LSTORE_2(kbox_ctx_t* ctx); static void fn_LSTORE_3(kbox_ctx_t* ctx);
static void fn_FSTORE_0(kbox_ctx_t* ctx); static void fn_FSTORE_1(kbox_ctx_t* ctx); static void fn_FSTORE_2(kbox_ctx_t* ctx); static void fn_FSTORE_3(kbox_ctx_t* ctx);
static void fn_DSTORE_0(kbox_ctx_t* ctx); static void fn_DSTORE_1(kbox_ctx_t* ctx); static void fn_DSTORE_2(kbox_ctx_t* ctx); static void fn_DSTORE_3(kbox_ctx_t* ctx);
static void fn_ASTORE_0(kbox_ctx_t* ctx); static void fn_ASTORE_1(kbox_ctx_t* ctx); static void fn_ASTORE_2(kbox_ctx_t* ctx); static void fn_ASTORE_3(kbox_ctx_t* ctx);
static void fn_IASTORE(kbox_ctx_t* ctx); static void fn_LASTORE(kbox_ctx_t* ctx); static void fn_FASTORE(kbox_ctx_t* ctx); static void fn_DASTORE(kbox_ctx_t* ctx);
static void fn_AASTORE(kbox_ctx_t* ctx); static void fn_BASTORE(kbox_ctx_t* ctx); static void fn_CASTORE(kbox_ctx_t* ctx); static void fn_SASTORE(kbox_ctx_t* ctx);
static void fn_POP(kbox_ctx_t* ctx); static void fn_POP2(kbox_ctx_t* ctx); static void fn_DUP(kbox_ctx_t* ctx);
static void fn_DUP_X1(kbox_ctx_t* ctx); static void fn_DUP2(kbox_ctx_t* ctx);
static void fn_DUP2_X1(kbox_ctx_t* ctx); static void fn_DUP2_X2(kbox_ctx_t* ctx); static void fn_SWAP(kbox_ctx_t* ctx);
static void fn_IADD(kbox_ctx_t* ctx); static void fn_LADD(kbox_ctx_t* ctx); static void fn_FADD(kbox_ctx_t* ctx); static void fn_DADD(kbox_ctx_t* ctx);
static void fn_ISUB(kbox_ctx_t* ctx); static void fn_LSUB(kbox_ctx_t* ctx); static void fn_FSUB(kbox_ctx_t* ctx); static void fn_DSUB(kbox_ctx_t* ctx);
static void fn_IMUL(kbox_ctx_t* ctx); static void fn_LMUL(kbox_ctx_t* ctx); static void fn_FMUL(kbox_ctx_t* ctx); static void fn_DMUL(kbox_ctx_t* ctx);
static void fn_IDIV(kbox_ctx_t* ctx); static void fn_LDIV(kbox_ctx_t* ctx); static void fn_FDIV(kbox_ctx_t* ctx); static void fn_DDIV(kbox_ctx_t* ctx);
static void fn_IREM(kbox_ctx_t* ctx); static void fn_LREM(kbox_ctx_t* ctx); static void fn_FREM(kbox_ctx_t* ctx); static void fn_DREM(kbox_ctx_t* ctx);
static void fn_INEG(kbox_ctx_t* ctx); static void fn_LNEG(kbox_ctx_t* ctx); static void fn_FNEG(kbox_ctx_t* ctx); static void fn_DNEG(kbox_ctx_t* ctx);
static void fn_ISHL(kbox_ctx_t* ctx); static void fn_LSHL(kbox_ctx_t* ctx); static void fn_ISHR(kbox_ctx_t* ctx); static void fn_LSHR(kbox_ctx_t* ctx);
static void fn_IUSHR(kbox_ctx_t* ctx); static void fn_LUSHR(kbox_ctx_t* ctx);
static void fn_IAND(kbox_ctx_t* ctx); static void fn_LAND(kbox_ctx_t* ctx); static void fn_IOR(kbox_ctx_t* ctx); static void fn_LOR(kbox_ctx_t* ctx);
static void fn_IXOR(kbox_ctx_t* ctx); static void fn_LXOR(kbox_ctx_t* ctx); static void fn_IINC(kbox_ctx_t* ctx);
static void fn_I2L(kbox_ctx_t* ctx); static void fn_I2F(kbox_ctx_t* ctx); static void fn_I2D(kbox_ctx_t* ctx);
static void fn_L2I(kbox_ctx_t* ctx); static void fn_L2F(kbox_ctx_t* ctx); static void fn_L2D(kbox_ctx_t* ctx);
static void fn_F2I(kbox_ctx_t* ctx); static void fn_F2L(kbox_ctx_t* ctx); static void fn_F2D(kbox_ctx_t* ctx);
static void fn_D2I(kbox_ctx_t* ctx); static void fn_D2L(kbox_ctx_t* ctx); static void fn_D2F(kbox_ctx_t* ctx);
static void fn_I2B(kbox_ctx_t* ctx); static void fn_I2C(kbox_ctx_t* ctx); static void fn_I2S(kbox_ctx_t* ctx);
static void fn_LCMP(kbox_ctx_t* ctx); static void fn_FCMPL(kbox_ctx_t* ctx); static void fn_FCMPG(kbox_ctx_t* ctx);
static void fn_DCMPL(kbox_ctx_t* ctx); static void fn_DCMPG(kbox_ctx_t* ctx);
static void fn_IFEQ(kbox_ctx_t* ctx); static void fn_IFNE(kbox_ctx_t* ctx); static void fn_IFLT(kbox_ctx_t* ctx);
static void fn_IFGE(kbox_ctx_t* ctx); static void fn_IFGT(kbox_ctx_t* ctx); static void fn_IFLE(kbox_ctx_t* ctx);
static void fn_IF_ICMPEQ(kbox_ctx_t* ctx); static void fn_IF_ICMPNE(kbox_ctx_t* ctx); static void fn_IF_ICMPLT(kbox_ctx_t* ctx);
static void fn_IF_ICMPGE(kbox_ctx_t* ctx); static void fn_IF_ICMPGT(kbox_ctx_t* ctx); static void fn_IF_ICMPLE(kbox_ctx_t* ctx);
static void fn_IF_ACMPEQ(kbox_ctx_t* ctx); static void fn_IF_ACMPNE(kbox_ctx_t* ctx);
static void fn_GOTO(kbox_ctx_t* ctx);
static void fn_IRETURN(kbox_ctx_t* ctx); static void fn_LRETURN(kbox_ctx_t* ctx); static void fn_FRETURN(kbox_ctx_t* ctx);
static void fn_DRETURN(kbox_ctx_t* ctx); static void fn_ARETURN(kbox_ctx_t* ctx); static void fn_RETURN(kbox_ctx_t* ctx);
static void fn_GETSTATIC(kbox_ctx_t* ctx); static void fn_PUTSTATIC(kbox_ctx_t* ctx);
static void fn_GETFIELD(kbox_ctx_t* ctx); static void fn_PUTFIELD(kbox_ctx_t* ctx);
static void fn_INVOKEVIRTUAL(kbox_ctx_t* ctx); static void fn_INVOKESPECIAL(kbox_ctx_t* ctx);
static void fn_INVOKESTATIC(kbox_ctx_t* ctx); static void fn_INVOKEINTERFACE(kbox_ctx_t* ctx);
static void fn_NEW(kbox_ctx_t* ctx); static void fn_NEWARRAY(kbox_ctx_t* ctx); static void fn_ANEWARRAY(kbox_ctx_t* ctx);
static void fn_ARRAYLENGTH(kbox_ctx_t* ctx); static void fn_ATHROW(kbox_ctx_t* ctx);
static void fn_CHECKCAST(kbox_ctx_t* ctx); static void fn_INSTANCEOF(kbox_ctx_t* ctx);
static void fn_IFNULL(kbox_ctx_t* ctx); static void fn_IFNONNULL(kbox_ctx_t* ctx);
static void fn_IF_ACMPEQ2(kbox_ctx_t* ctx); static void fn_IF_ACMPNE2(kbox_ctx_t* ctx);
static void fn_IFNULL2(kbox_ctx_t* ctx); static void fn_IFNONNULL2(kbox_ctx_t* ctx);
static void fn_TABLESWITCH(kbox_ctx_t* ctx); static void fn_LOOKUPSWITCH(kbox_ctx_t* ctx);
static void fn_MULTIANEWARRAY(kbox_ctx_t* ctx);
static void fn_INVOKEDYNAMIC(kbox_ctx_t* ctx);
static void fn_bogus(kbox_ctx_t* ctx);

/* ===== Crypto engine ===== */

/*
 * Per-instruction key stream derivation.
 * Each method has a unique key_seed; each byte at offset pc derives its
 * own key via a non-linear mixing function.  The actual algorithm is
 * chosen at obfuscation time; this is a representative implementation
 * based on a reduced-round mixer.
 *
 * When key_seed == 0, this function is NOT called — bytecode is plain.
 */
KBOX_INLINE uint8_t kbox_key_byte(uint32_t seed, uint32_t pc) {
    uint32_t k = seed;
    k ^= pc * 0x9E3779B9U;           /* golden-ratio increment */
    k  = (k ^ (k >> 16)) * 0x85EBCA6BU;
    k  = (k ^ (k >> 13)) * 0xC2B2AE35U;
    return (uint8_t)(k ^ (k >> 16));
}

/*
 * Fetch + decrypt + erase (if encrypted mode).
 * Returns the plain-text opcode byte and advances pc.
 *
 * SECURITY: the encrypted byte in memory is overwritten with 0 after
 * reading, so a memory dump at any later time contains no plaintext.
 * The key stream is deterministic (per seed+pc), so re-decrypting the
 * same offset yields the same plaintext — but the ciphertext itself
 * has been destroyed.
 */
KBOX_INLINE uint8_t kbox_fetch(const uint8_t* code, uint32_t* pc,
                                  uint32_t code_len, uint32_t key_seed,
                                  uint8_t* mutable_code) {
    uint32_t p = *pc;
    if (p >= code_len) {
        /* Out-of-bounds: trigger anti-debug artifact */
        return 0;
    }
    uint8_t cipher = code[p];
    uint8_t plain;
    if (key_seed != 0) {
        plain = cipher ^ kbox_key_byte(key_seed, p);
        /* Erase ciphertext after reading (if mutable) */
        if (mutable_code != NULL) {
            mutable_code[p] = 0;
        }
    } else {
        plain = cipher;
    }
    *pc = p + 1;
    return plain;
}

/* Fetch a signed 16-bit operand (2 encrypted bytes) */
KBOX_INLINE int16_t kbox_fetch_s16(const uint8_t* code, uint32_t* pc,
                                      uint32_t code_len, uint32_t key_seed,
                                      uint8_t* mutable_code) {
    int16_t hi = (int16_t)kbox_fetch(code, pc, code_len, key_seed, mutable_code);
    int16_t lo = (int16_t)kbox_fetch(code, pc, code_len, key_seed, mutable_code);
    return (int16_t)((hi << 8) | (lo & 0xFF));
}

/* Decrypt/read a single byte at an ABSOLUTE position p without advancing any
 * program counter. Used by TABLESWITCH/LOOKUPSWITCH to seek into their
 * variable-length payload (choose-case by absolute offset). The cipher at that
 * position is still erased after read, exactly like sequential fetches. */
KBOX_INLINE uint8_t kbox_fetch_at(const uint8_t* code, uint32_t p,
                                  uint32_t code_len, uint32_t key_seed,
                                  uint8_t* mutable_code) {
    if (p >= code_len) return 0;
    uint8_t cipher = code[p];
    if (key_seed != 0) {
        if (mutable_code != NULL) mutable_code[p] = 0;
        return (uint8_t)(cipher ^ kbox_key_byte(key_seed, p));
    }
    return cipher;
}

/* Read a signed 32-bit word from 4 absolute positions (byte-by-byte decrypt). */
KBOX_INLINE int32_t kbox_fetch_i32_at(const uint8_t* code, uint32_t p,
                                      uint32_t code_len, uint32_t key_seed,
                                      uint8_t* mutable_code) {
    uint32_t b0 = kbox_fetch_at(code, p+0, code_len, key_seed, mutable_code);
    uint32_t b1 = kbox_fetch_at(code, p+1, code_len, key_seed, mutable_code);
    uint32_t b2 = kbox_fetch_at(code, p+2, code_len, key_seed, mutable_code);
    uint32_t b3 = kbox_fetch_at(code, p+3, code_len, key_seed, mutable_code);
    return (int32_t)((b0 << 24) | (b1 << 16) | (b2 << 8) | b3);
}

/*
 * Bounds-safe argument collection for INVOKE* handlers.
 * Copies at most KBOX_MAX_ARGS slot values starting at `start` into `jargs`,
 * clamped to the operand-stack array so `jvalue jargs[32]` is never overrun and
 * no read happens before the stack base. Returns the actual count to pass to
 * the JNI Call*MethodA.
 */
KBOX_INLINE int kbox_collect_args(kbox_slot_t* stk, int len, int start, int ac, jvalue* jargs) {
    if (ac > KBOX_MAX_ARGS) ac = KBOX_MAX_ARGS;
    if (start < 0) { ac = 0; }
    else if (start + ac > len) { ac = ((int)(len - start) < 0) ? 0 : (int)(len - start); }
    for (int a = 0; a < ac; a++) jargs[a].l = (jobject)stk[start + a].ptr;
    return ac;
}

/* ===== Anti-debug layer ===== */

/* Global flag: set once, checked periodically. */
static volatile int g_debugged = -1;

/*
 * Detect JDWP / JVMTI attachment without crashing.
 * Checks JVM input arguments for debug-related flags.
 * Returns 1 if debugger suspected, 0 otherwise.
 */
static int kbox_detect_jdwp(void) {
    /* Check java.vm.name for known debug VM variants */
    /* This is a lightweight check; full checks use JVMTI-native API */
    return 0;  /* Stub: full implementation requires JVM TI native agent */
}

/*
 * Self-integrity: verify the first bytes of this function match
 * the expected prologue.  If an inline hook (Frida, etc.) has patched
 * the function entry, the hash will mismatch.
 *
 * We compute a simple checksum over the first 64 bytes of the
 * interpreter dispatch table.  The expected value is embedded at
 * obfuscation time; for now we use a placeholder.
 */
static int kbox_self_check(void) {
    /* Placeholder: in production this would verify a hash of the
     * interpreter's code section to detect patching. */
    return 1;
}

/*
 * Poison the operand stack: XOR the top value with 1.
 * This makes subsequent computations silently wrong instead of
 * crashing immediately, frustrating debuggers.
 */
static void kbox_poison_stack(kbox_slot_t* stack, int sp) {
    if (sp > 0) {
        stack[sp - 1].i ^= 0x1;
    }
}

/* ===== Global function pointer table ===== */

/*
 * g_insn_table maps each JVM opcode (0-255) to its handler function.
 * Unused slots are NULL.  The table is initialized once at first call.
 *
 * IDA/Ghidra cannot statically resolve indirect calls through this
 * table, forcing the analyst to trace runtime values.
 */
typedef void (*kbox_handler_t)(kbox_ctx_t*);
static kbox_handler_t g_insn_table[256];
static volatile int g_table_init = 0;

/* ===== Interpreter context (packed struct for stack allocation) ===== */

typedef struct kbox_ctx_s {
    /* CP arrays (pre-resolved at stub init time) */
    jclass*       cp_cls;      int cp_cls_n;
    const char**  cp_cls_names; int cp_cls_names_n;  /* internal class names (MULTIANEWARRAY descs) */
    const char**  cp_indy_meta; int cp_indy_n;       /* per-site packed invokedynamic metadata */
    const char**  cp_indy_argc; int cp_indy_argc_n;  /* per-site arg slot codes ("IJL...") */
    const char*   cp_indy_ret;  int cp_indy_ret_n;   /* per-site return code chars */
    jfieldID*     cp_fld;      int cp_fld_n;
    const char*   cp_fld_rt;   int cp_fld_rt_n;   /* field type codes: I/J/F/D/L */
    jclass*       cp_fld_cls;  int cp_fld_cls_n;  /* per-field OWNER class (static fields) */
    jmethodID*    cp_mid;      int cp_mid_n;
    const char**  cp_str;      int cp_str_n;
    const jint*   cp_int;      int cp_int_n;
    const int*    cp_mid_ac;   int cp_mid_ac_n;
    const char*   cp_mid_rt;   int cp_mid_rt_n;
    jclass*       cp_mid_cls;  int cp_mid_cls_n;

    /* Encryption state */
    uint32_t      key_seed;
    uint8_t*      mutable_code;  /* NULL if code is read-only */

    /* VM state */
    kbox_slot_t   stack[KBOX_MAX_SLOTS];
    int           sp;
    kbox_slot_t   locals[KBOX_MAX_SLOTS];
    const uint8_t* code;
    uint32_t      code_len;
    uint32_t      pc;

    /* Return value (set by RETURN instructions) */
    kbox_slot_t   retval;
    int           returned;

    JNIEnv*       env;
} kbox_ctx_t;

/* ===== Invokedynamic support (JNI boxing + JnicIndy resolver) =====
 * Invokedynamic call sites inside native-ized methods are forwarded to the
 * injected Java helper [com/kbox/runtime/JnicIndy] which reproduces the JVM
 * bootstrap protocol and returns the boxed result. These JNI ids are resolved
 * once per process (lazily) and cached as global references so they stay valid
 * for every subsequent invocation. */
static int      g_indy_inited = 0;
static jclass   g_indy_cls;          /* com.kbox.runtime.JnicIndy */
static jmethodID g_indy_invoke;      /* invoke(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object; */
static jclass   g_obj_cls;           /* java/lang/Object (NewObjectArray ELEMENT class) */
static jclass   g_int_cls;  static jmethodID g_mid_intValueOf,  g_mid_intValue;
static jclass   g_long_cls; static jmethodID g_mid_longValueOf, g_mid_longValue;
static jclass   g_float_cls;static jmethodID g_mid_floatValueOf,g_mid_floatValue;
static jclass   g_double_cls;static jmethodID g_mid_doubleValueOf,g_mid_doubleValue;

static void kbox_indy_init(JNIEnv* env) {
    if (g_indy_inited) return;
    jclass je = (*env)->FindClass(env, "com/kbox/runtime/JnicIndy");
    if (!je) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); }
    else { g_indy_cls = (jclass)(*env)->NewGlobalRef(env, je); }
    if (g_indy_cls) {
        g_indy_invoke = (*env)->GetStaticMethodID(env, g_indy_cls, "invoke",
                "(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/Object;");
        if (g_indy_invoke && (*env)->ExceptionCheck(env)) { (*env)->ExceptionClear(env); }
    }
    jclass oa = (*env)->FindClass(env, "java/lang/Object");
    if (oa) { g_obj_cls = (jclass)(*env)->NewGlobalRef(env, oa);
              if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); }

    jclass ic = (*env)->FindClass(env, "java/lang/Integer");
    g_int_cls = ic ? (jclass)(*env)->NewGlobalRef(env, ic) : NULL;
    if (ic) { g_mid_intValueOf = (*env)->GetStaticMethodID(env, ic, "valueOf", "(I)Ljava/lang/Integer;"); }
    if (ic) { g_mid_intValue   = (*env)->GetMethodID(env, ic, "intValue", "()I"); }

    jclass lc = (*env)->FindClass(env, "java/lang/Long");
    g_long_cls = lc ? (jclass)(*env)->NewGlobalRef(env, lc) : NULL;
    if (lc) { g_mid_longValueOf = (*env)->GetStaticMethodID(env, lc, "valueOf", "(J)Ljava/lang/Long;"); }
    if (lc) { g_mid_longValue   = (*env)->GetMethodID(env, lc, "longValue", "()J"); }

    jclass fc = (*env)->FindClass(env, "java/lang/Float");
    g_float_cls = fc ? (jclass)(*env)->NewGlobalRef(env, fc) : NULL;
    if (fc) { g_mid_floatValueOf = (*env)->GetStaticMethodID(env, fc, "valueOf", "(F)Ljava/lang/Float;"); }
    if (fc) { g_mid_floatValue   = (*env)->GetMethodID(env, fc, "floatValue", "()F"); }

    jclass dc = (*env)->FindClass(env, "java/lang/Double");
    g_double_cls = dc ? (jclass)(*env)->NewGlobalRef(env, dc) : NULL;
    if (dc) { g_mid_doubleValueOf = (*env)->GetStaticMethodID(env, dc, "valueOf", "(D)Ljava/lang/Double;"); }
    if (dc) { g_mid_doubleValue   = (*env)->GetMethodID(env, dc, "doubleValue", "()D"); }

    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    g_indy_inited = 1;
}

/* ===== Helper: read s16 from plain bytecode (no decrypt) ===== */
KBOX_INLINE int16_t read_plain_s16(const uint8_t* p) {
    return (int16_t)((p[0] << 8) | p[1]);
}

/* ===== Per-handler helper: fetch next operand byte ===== */
#define FETCH(ctx)       kbox_fetch((ctx)->code, &(ctx)->pc, (ctx)->code_len, (ctx)->key_seed, (ctx)->mutable_code)
#define FETCH_S16(ctx)   kbox_fetch_s16((ctx)->code, &(ctx)->pc, (ctx)->code_len, (ctx)->key_seed, (ctx)->mutable_code)

/* ===== Debug output (compiled out unless -DKBOX_VMP_DEBUG) =====
 * The interpreter must NEVER emit trace output or short-circuit execution in
 * production. All trace/printf calls are gated behind this macro so a
 * release build compiles them away entirely. */
#ifdef KBOX_VMP_DEBUG
  #define KBOX_DBG(...) fprintf(stderr, __VA_ARGS__)
#else
  #define KBOX_DBG(...) ((void)0)
#endif

/* ===== Opcode handler implementations ===== */

#define HANDLER(name) static void fn_##name(kbox_ctx_t* ctx)

HANDLER(NOP) { /* nothing */ }

HANDLER(ACONST_NULL) { ctx->stack[ctx->sp].ptr = NULL; ctx->sp++; }

HANDLER(ICONST_M1) { ctx->stack[ctx->sp].i = -1; ctx->sp++; }
HANDLER(ICONST_0)  { ctx->stack[ctx->sp].i = 0; ctx->sp++; }
HANDLER(ICONST_1)  { ctx->stack[ctx->sp].i = 1; ctx->sp++; }
HANDLER(ICONST_2)  { ctx->stack[ctx->sp].i = 2; ctx->sp++; }
HANDLER(ICONST_3)  { ctx->stack[ctx->sp].i = 3; ctx->sp++; }
HANDLER(ICONST_4)  { ctx->stack[ctx->sp].i = 4; ctx->sp++; }
HANDLER(ICONST_5)  { ctx->stack[ctx->sp].i = 5; ctx->sp++; }
HANDLER(LCONST_0)  { ctx->stack[ctx->sp].j = 0; ctx->sp++; }
HANDLER(LCONST_1)  { ctx->stack[ctx->sp].j = 1; ctx->sp++; }
HANDLER(FCONST_0)  { ctx->stack[ctx->sp].f = 0.0f; ctx->sp++; }
HANDLER(FCONST_1)  { ctx->stack[ctx->sp].f = 1.0f; ctx->sp++; }
HANDLER(FCONST_2)  { ctx->stack[ctx->sp].f = 2.0f; ctx->sp++; }
HANDLER(DCONST_0)  { ctx->stack[ctx->sp].d = 0.0; ctx->sp++; }
HANDLER(DCONST_1)  { ctx->stack[ctx->sp].d = 1.0; ctx->sp++; }

HANDLER(BIPUSH) {
    int8_t v = (int8_t)FETCH(ctx);
    ctx->stack[ctx->sp].i = (jint)v; ctx->sp++;
}
HANDLER(SIPUSH) {
    int16_t v = FETCH_S16(ctx);
    ctx->stack[ctx->sp].i = (jint)v; ctx->sp++;
}

HANDLER(LDC) {
    int16_t idx = FETCH_S16(ctx);
    if (idx & 0x8000) {
        int ii = idx & 0x7FFF;
        ctx->stack[ctx->sp].i = (ii < ctx->cp_int_n) ? ctx->cp_int[ii] : 0;
    } else {
        jstring s = NULL;
        if (idx < ctx->cp_str_n && ctx->cp_str[idx]) {
            s = (*ctx->env)->NewStringUTF(ctx->env, ctx->cp_str[idx]);
        }
        ctx->stack[ctx->sp].ptr = s;
    }
    ctx->sp++;
}

/* ---- Loads ---- */
#define LOAD_H(type, field) \
    HANDLER(type##LOAD) { int idx = FETCH(ctx); ctx->stack[ctx->sp].field = ctx->locals[idx].field; ctx->sp++; }
LOAD_H(I, i) LOAD_H(L, j) LOAD_H(F, f) LOAD_H(D, d)
LOAD_H(A, ptr)

#define LOAD_N(type, field, n) \
    HANDLER(type##LOAD_##n) { ctx->stack[ctx->sp].field = ctx->locals[n].field; ctx->sp++; }

LOAD_N(I,i,0) LOAD_N(I,i,1) LOAD_N(I,i,2) LOAD_N(I,i,3)
LOAD_N(L,j,0) LOAD_N(L,j,1) LOAD_N(L,j,2) LOAD_N(L,j,3)
LOAD_N(F,f,0) LOAD_N(F,f,1) LOAD_N(F,f,2) LOAD_N(F,f,3)
LOAD_N(D,d,0) LOAD_N(D,d,1) LOAD_N(D,d,2) LOAD_N(D,d,3)
LOAD_N(A,ptr,0) LOAD_N(A,ptr,1) LOAD_N(A,ptr,2) LOAD_N(A,ptr,3)

/* ---- Stores ---- */
#define STORE_H(type, field) \
    HANDLER(type##STORE) { int idx = FETCH(ctx); ctx->sp--; ctx->locals[idx].field = ctx->stack[ctx->sp].field; }
STORE_H(I,i) STORE_H(L,j) STORE_H(F,f) STORE_H(D,d)
STORE_H(A,ptr)

#define STORE_N(type, field, n) \
    HANDLER(type##STORE_##n) { ctx->sp--; ctx->locals[n].field = ctx->stack[ctx->sp].field; }

STORE_N(I,i,0) STORE_N(I,i,1) STORE_N(I,i,2) STORE_N(I,i,3)
STORE_N(L,j,0) STORE_N(L,j,1) STORE_N(L,j,2) STORE_N(L,j,3)
STORE_N(F,f,0) STORE_N(F,f,1) STORE_N(F,f,2) STORE_N(F,f,3)
STORE_N(D,d,0) STORE_N(D,d,1) STORE_N(D,d,2) STORE_N(D,d,3)
STORE_N(A,ptr,0) STORE_N(A,ptr,1) STORE_N(A,ptr,2) STORE_N(A,ptr,3)

/* ---- Stack manipulation ---- */
HANDLER(POP)      { ctx->sp--; }
HANDLER(POP2)     { ctx->sp -= 2; }
HANDLER(DUP)      { ctx->stack[ctx->sp] = ctx->stack[ctx->sp-1]; ctx->sp++; }
HANDLER(DUP_X1)   {
    kbox_slot_t v1 = ctx->stack[ctx->sp-1], v2 = ctx->stack[ctx->sp-2];
    ctx->stack[ctx->sp-2] = v1; ctx->stack[ctx->sp-1] = v2;
    ctx->stack[ctx->sp] = v1; ctx->sp++;
}
HANDLER(DUP2)     { ctx->stack[ctx->sp]=ctx->stack[ctx->sp-2];ctx->stack[ctx->sp+1]=ctx->stack[ctx->sp-1];ctx->sp+=2; }
HANDLER(SWAP)     { kbox_slot_t t=ctx->stack[ctx->sp-1];ctx->stack[ctx->sp-1]=ctx->stack[ctx->sp-2];ctx->stack[ctx->sp-2]=t; }

/* ---- Integer arithmetic ---- */
HANDLER(IADD) { ctx->sp--; ctx->stack[ctx->sp-1].i += ctx->stack[ctx->sp].i; }
HANDLER(ISUB) { ctx->sp--; ctx->stack[ctx->sp-1].i -= ctx->stack[ctx->sp].i; }
HANDLER(IMUL) { ctx->sp--; ctx->stack[ctx->sp-1].i *= ctx->stack[ctx->sp].i; }
HANDLER(IDIV) { ctx->sp--; ctx->stack[ctx->sp-1].i /= ctx->stack[ctx->sp].i; }
HANDLER(IREM) { ctx->sp--; ctx->stack[ctx->sp-1].i %= ctx->stack[ctx->sp].i; }
HANDLER(INEG) { ctx->stack[ctx->sp-1].i = -ctx->stack[ctx->sp-1].i; }
HANDLER(ISHL) { ctx->sp--; ctx->stack[ctx->sp-1].i <<= (ctx->stack[ctx->sp].i & 0x1F); }
HANDLER(ISHR) { ctx->sp--; ctx->stack[ctx->sp-1].i >>= (ctx->stack[ctx->sp].i & 0x1F); }
HANDLER(IUSHR){ ctx->sp--; ctx->stack[ctx->sp-1].i = (jint)(((uint32_t)ctx->stack[ctx->sp-1].i) >> (ctx->stack[ctx->sp].i & 0x1F)); }
HANDLER(IAND) { ctx->sp--; ctx->stack[ctx->sp-1].i &= ctx->stack[ctx->sp].i; }
HANDLER(IOR)  { ctx->sp--; ctx->stack[ctx->sp-1].i |= ctx->stack[ctx->sp].i; }
HANDLER(IXOR) { ctx->sp--; ctx->stack[ctx->sp-1].i ^= ctx->stack[ctx->sp].i; }
HANDLER(IINC) { int idx = FETCH(ctx); int8_t incr = (int8_t)FETCH(ctx); ctx->locals[idx].i += incr; }

/* ---- Long arithmetic ---- */
HANDLER(LADD) { ctx->sp--; ctx->stack[ctx->sp-1].j += ctx->stack[ctx->sp].j; }
HANDLER(LSUB) { ctx->sp--; ctx->stack[ctx->sp-1].j -= ctx->stack[ctx->sp].j; }
HANDLER(LMUL) { ctx->sp--; ctx->stack[ctx->sp-1].j *= ctx->stack[ctx->sp].j; }
HANDLER(LDIV) { ctx->sp--; ctx->stack[ctx->sp-1].j /= ctx->stack[ctx->sp].j; }
HANDLER(LREM) { ctx->sp--; ctx->stack[ctx->sp-1].j %= ctx->stack[ctx->sp].j; }
HANDLER(LNEG) { ctx->stack[ctx->sp-1].j = -ctx->stack[ctx->sp-1].j; }
HANDLER(LAND) { ctx->sp--; ctx->stack[ctx->sp-1].j &= ctx->stack[ctx->sp].j; }
HANDLER(LOR)  { ctx->sp--; ctx->stack[ctx->sp-1].j |= ctx->stack[ctx->sp].j; }
HANDLER(LXOR) { ctx->sp--; ctx->stack[ctx->sp-1].j ^= ctx->stack[ctx->sp].j; }
HANDLER(LSHL) { ctx->sp--; ctx->stack[ctx->sp-1].j <<= (ctx->stack[ctx->sp].i & 0x3F); }
HANDLER(LSHR) { ctx->sp--; ctx->stack[ctx->sp-1].j >>= (ctx->stack[ctx->sp].i & 0x3F); }
HANDLER(LUSHR){ ctx->sp--; ctx->stack[ctx->sp-1].j = (jlong)(((uint64_t)ctx->stack[ctx->sp-1].j) >> (ctx->stack[ctx->sp].i & 0x3F)); }

/* ---- Float ---- */
HANDLER(FADD) { ctx->sp--; ctx->stack[ctx->sp-1].f += ctx->stack[ctx->sp].f; }
HANDLER(FSUB) { ctx->sp--; ctx->stack[ctx->sp-1].f -= ctx->stack[ctx->sp].f; }
HANDLER(FMUL) { ctx->sp--; ctx->stack[ctx->sp-1].f *= ctx->stack[ctx->sp].f; }
HANDLER(FDIV) { ctx->sp--; ctx->stack[ctx->sp-1].f /= ctx->stack[ctx->sp].f; }
HANDLER(FNEG) { ctx->stack[ctx->sp-1].f = -ctx->stack[ctx->sp-1].f; }
HANDLER(FREM) {
    float a=ctx->stack[ctx->sp-2].f, b=ctx->stack[ctx->sp-1].f;
    ctx->stack[ctx->sp-2].f = a - ((jint)(a/b))*b; ctx->sp-=2;
}
HANDLER(FCMPL) {
    float a=ctx->stack[ctx->sp-2].f, b=ctx->stack[ctx->sp-1].f; ctx->sp-=2;
    if (a>b) ctx->stack[ctx->sp-1].i=1;
    else if (a==b) ctx->stack[ctx->sp-1].i=0;
    else ctx->stack[ctx->sp-1].i=-1;
    if (a!=a||b!=b) ctx->stack[ctx->sp-1].i=-1; /* NaN -> -1 for FCMPL */
}
HANDLER(FCMPG) {
    float a=ctx->stack[ctx->sp-2].f, b=ctx->stack[ctx->sp-1].f; ctx->sp-=2;
    if (a>b) ctx->stack[ctx->sp-1].i=1;
    else if (a==b) ctx->stack[ctx->sp-1].i=0;
    else ctx->stack[ctx->sp-1].i=-1;
    if (a!=a||b!=b) ctx->stack[ctx->sp-1].i=1; /* NaN -> 1 for FCMPG */
}

/* ---- Double ---- */
HANDLER(DADD) { ctx->sp--; ctx->stack[ctx->sp-1].d += ctx->stack[ctx->sp].d; }
HANDLER(DSUB) { ctx->sp--; ctx->stack[ctx->sp-1].d -= ctx->stack[ctx->sp].d; }
HANDLER(DMUL) { ctx->sp--; ctx->stack[ctx->sp-1].d *= ctx->stack[ctx->sp].d; }
HANDLER(DDIV) { ctx->sp--; ctx->stack[ctx->sp-1].d /= ctx->stack[ctx->sp].d; }
HANDLER(DNEG) { ctx->stack[ctx->sp-1].d = -ctx->stack[ctx->sp-1].d; }
HANDLER(DREM) {
    double a=ctx->stack[ctx->sp-2].d, b=ctx->stack[ctx->sp-1].d;
    ctx->stack[ctx->sp-2].d = a - ((jlong)(a/b))*b; ctx->sp--;
}
HANDLER(DCMPL) {
    double a=ctx->stack[ctx->sp-2].d, b=ctx->stack[ctx->sp-1].d; ctx->sp-=2;
    if (a>b) ctx->stack[ctx->sp].i=1;
    else if (a==b) ctx->stack[ctx->sp].i=0;
    else ctx->stack[ctx->sp].i=-1;
    if (a!=a||b!=b) ctx->stack[ctx->sp].i=-1; ctx->sp++;
}
HANDLER(DCMPG) {
    double a=ctx->stack[ctx->sp-2].d, b=ctx->stack[ctx->sp-1].d; ctx->sp-=2;
    if (a>b) ctx->stack[ctx->sp].i=1;
    else if (a==b) ctx->stack[ctx->sp].i=0;
    else ctx->stack[ctx->sp].i=-1;
    if (a!=a||b!=b) ctx->stack[ctx->sp].i=1; ctx->sp++;
}

/* ---- Type conversions ---- */
HANDLER(I2L) { ctx->stack[ctx->sp-1].j = (jlong)ctx->stack[ctx->sp-1].i; }
HANDLER(I2F) { ctx->stack[ctx->sp-1].f = (jfloat)ctx->stack[ctx->sp-1].i; }
HANDLER(I2D) { ctx->stack[ctx->sp-1].d = (jdouble)ctx->stack[ctx->sp-1].i; }
HANDLER(L2I) { ctx->stack[ctx->sp-1].i = (jint)ctx->stack[ctx->sp-1].j; }
HANDLER(L2F) { ctx->stack[ctx->sp-1].f = (jfloat)ctx->stack[ctx->sp-1].j; }
HANDLER(L2D) { ctx->stack[ctx->sp-1].d = (jdouble)ctx->stack[ctx->sp-1].j; }
HANDLER(F2I) { ctx->stack[ctx->sp-1].i = (jint)ctx->stack[ctx->sp-1].f; }
HANDLER(F2L) { ctx->stack[ctx->sp-1].j = (jlong)ctx->stack[ctx->sp-1].f; }
HANDLER(F2D) { ctx->stack[ctx->sp-1].d = (jdouble)ctx->stack[ctx->sp-1].f; }
HANDLER(D2I) { ctx->stack[ctx->sp-1].i = (jint)ctx->stack[ctx->sp-1].d; }
HANDLER(D2L) { ctx->stack[ctx->sp-1].j = (jlong)ctx->stack[ctx->sp-1].d; }
HANDLER(D2F) { ctx->stack[ctx->sp-1].f = (jfloat)ctx->stack[ctx->sp-1].d; }
HANDLER(I2B) { ctx->stack[ctx->sp-1].i = (jint)(int8_t)ctx->stack[ctx->sp-1].i; }
HANDLER(I2C) { ctx->stack[ctx->sp-1].i = (jint)(uint16_t)ctx->stack[ctx->sp-1].i; }
HANDLER(I2S) { ctx->stack[ctx->sp-1].i = (jint)(int16_t)ctx->stack[ctx->sp-1].i; }
HANDLER(LCMP) {
    jlong al=ctx->stack[ctx->sp-2].j, bl=ctx->stack[ctx->sp-1].j; ctx->sp-=2;
    ctx->stack[ctx->sp].i = (al>bl) ? 1 : (al==bl ? 0 : -1); ctx->sp++;
}

/* ---- Returns ---- */
HANDLER(IRETURN) { ctx->sp--; ctx->retval.i = ctx->stack[ctx->sp].i; ctx->returned = 1; }
HANDLER(LRETURN) { ctx->retval.j = ctx->stack[ctx->sp-1].j; ctx->returned = 1; }
HANDLER(FRETURN) { ctx->sp--; ctx->retval.f = ctx->stack[ctx->sp].f; ctx->returned = 1; }
HANDLER(DRETURN) { ctx->retval.d = ctx->stack[ctx->sp-1].d; ctx->returned = 1; }
HANDLER(ARETURN) { ctx->sp--; ctx->retval.ptr = ctx->stack[ctx->sp].ptr; ctx->returned = 1; }
HANDLER(RETURN)  { ctx->retval.i = 0; ctx->returned = 1; }

/* ---- Field access ---- */
/* Field type code (I/J/F/D/L) for JNI Get/Set*Field dispatch; defaults to object. */
static char field_kind(const kbox_ctx_t* ctx, int16_t idx) {
    if (idx < 0 || idx >= ctx->cp_fld_rt_n) return 'L';
    return ctx->cp_fld_rt[idx];
}
HANDLER(GETSTATIC) {
    int16_t idx = FETCH_S16(ctx);
    char k = field_kind(ctx, idx);
    /* Static fields must be read against their OWNING class, NOT the method's
     * own class (cp_cls[0]). cp_fld_cls is the per-field owner (a global ref). */
    jclass cls = (idx >= 0 && idx < ctx->cp_fld_cls_n && ctx->cp_fld_cls[idx])
                 ? ctx->cp_fld_cls[idx]
                 : ((ctx->cp_cls_n > 0) ? ctx->cp_cls[0] : NULL);
    if (idx < ctx->cp_fld_n && cls) {
        switch (k) {
        case 'J': ctx->stack[ctx->sp].j = (*ctx->env)->GetStaticLongField(ctx->env, cls, ctx->cp_fld[idx]); break;
        case 'F': ctx->stack[ctx->sp].f = (*ctx->env)->GetStaticFloatField(ctx->env, cls, ctx->cp_fld[idx]); break;
        case 'D': ctx->stack[ctx->sp].d = (*ctx->env)->GetStaticDoubleField(ctx->env, cls, ctx->cp_fld[idx]); break;
        case 'I': ctx->stack[ctx->sp].i = (*ctx->env)->GetStaticIntField(ctx->env, cls, ctx->cp_fld[idx]); break;
        default:  ctx->stack[ctx->sp].ptr = (*ctx->env)->GetStaticObjectField(ctx->env, cls, ctx->cp_fld[idx]); break;
        }
    } else ctx->stack[ctx->sp].ptr = NULL;
    ctx->sp++;
}
HANDLER(PUTSTATIC) {
    int16_t idx = FETCH_S16(ctx);
    char k = field_kind(ctx, idx);
    ctx->sp--;
    jclass cls = (idx >= 0 && idx < ctx->cp_fld_cls_n && ctx->cp_fld_cls[idx])
                 ? ctx->cp_fld_cls[idx]
                 : ((ctx->cp_cls_n > 0) ? ctx->cp_cls[0] : NULL);
    if (idx < ctx->cp_fld_n && cls) {
        switch (k) {
        case 'J': (*ctx->env)->SetStaticLongField(ctx->env, cls, ctx->cp_fld[idx], ctx->stack[ctx->sp].j); break;
        case 'F': (*ctx->env)->SetStaticFloatField(ctx->env, cls, ctx->cp_fld[idx], ctx->stack[ctx->sp].f); break;
        case 'D': (*ctx->env)->SetStaticDoubleField(ctx->env, cls, ctx->cp_fld[idx], ctx->stack[ctx->sp].d); break;
        case 'I': (*ctx->env)->SetStaticIntField(ctx->env, cls, ctx->cp_fld[idx], ctx->stack[ctx->sp].i); break;
        default:  (*ctx->env)->SetStaticObjectField(ctx->env, cls, ctx->cp_fld[idx], ctx->stack[ctx->sp].ptr); break;
        }
    }
}
HANDLER(GETFIELD) {
    int16_t idx = FETCH_S16(ctx);
    char k = field_kind(ctx, idx);
    ctx->sp--;
    jobject obj = (jobject)ctx->stack[ctx->sp].ptr;
    if (idx < ctx->cp_fld_n) {
        switch (k) {
        case 'J': ctx->stack[ctx->sp].j = (*ctx->env)->GetLongField(ctx->env, obj, ctx->cp_fld[idx]); break;
        case 'F': ctx->stack[ctx->sp].f = (*ctx->env)->GetFloatField(ctx->env, obj, ctx->cp_fld[idx]); break;
        case 'D': ctx->stack[ctx->sp].d = (*ctx->env)->GetDoubleField(ctx->env, obj, ctx->cp_fld[idx]); break;
        case 'I': ctx->stack[ctx->sp].i = (*ctx->env)->GetIntField(ctx->env, obj, ctx->cp_fld[idx]); break;
        default:  ctx->stack[ctx->sp].ptr = (*ctx->env)->GetObjectField(ctx->env, obj, ctx->cp_fld[idx]); break;
        }
    } else ctx->stack[ctx->sp].ptr = NULL;
    ctx->sp++;
}
HANDLER(PUTFIELD) {
    int16_t idx = FETCH_S16(ctx);
    char k = field_kind(ctx, idx);
    ctx->sp--;                                  /* sp -> value */
    jobject obj = (jobject)ctx->stack[ctx->sp - 1].ptr;
    if (idx < ctx->cp_fld_n) {
        switch (k) {
        case 'J': (*ctx->env)->SetLongField(ctx->env, obj, ctx->cp_fld[idx], ctx->stack[ctx->sp].j); break;
        case 'F': (*ctx->env)->SetFloatField(ctx->env, obj, ctx->cp_fld[idx], ctx->stack[ctx->sp].f); break;
        case 'D': (*ctx->env)->SetDoubleField(ctx->env, obj, ctx->cp_fld[idx], ctx->stack[ctx->sp].d); break;
        case 'I': (*ctx->env)->SetIntField(ctx->env, obj, ctx->cp_fld[idx], ctx->stack[ctx->sp].i); break;
        default:  (*ctx->env)->SetObjectField(ctx->env, obj, ctx->cp_fld[idx], ctx->stack[ctx->sp].ptr); break;
        }
    }
    ctx->sp--;                                  /* pop object */
}

/* ---- Method invocations ---- */
HANDLER(INVOKESTATIC) {
    int16_t idx = FETCH_S16(ctx);
    int ac = (idx < ctx->cp_mid_ac_n) ? ctx->cp_mid_ac[idx] : 0;
    char rt = (idx < ctx->cp_mid_rt_n) ? ctx->cp_mid_rt[idx] : 'V';
    jclass cls = (idx < ctx->cp_mid_cls_n) ? ctx->cp_mid_cls[idx] : NULL;
    jmethodID mid = (idx < ctx->cp_mid_n) ? ctx->cp_mid[idx] : NULL;
    jvalue jargs[KBOX_MAX_ARGS];
    int base = ctx->sp - ac;
    if (base < 0) base = 0;
    ac = kbox_collect_args(ctx->stack, KBOX_MAX_SLOTS, base, ac, jargs);
    ctx->sp = base;
    if (mid && cls) {
        switch (rt) {
        case 'V': (*ctx->env)->CallStaticVoidMethodA(ctx->env, cls, mid, jargs); break;
        case 'I': case 'Z': case 'B': case 'C': case 'S':
            ctx->stack[ctx->sp].i = (*ctx->env)->CallStaticIntMethodA(ctx->env, cls, mid, jargs); ctx->sp++; break;
        case 'J': ctx->stack[ctx->sp].j = (*ctx->env)->CallStaticLongMethodA(ctx->env, cls, mid, jargs); ctx->sp++; break;
        case 'F': ctx->stack[ctx->sp].f = (*ctx->env)->CallStaticFloatMethodA(ctx->env, cls, mid, jargs); ctx->sp++; break;
        case 'D': ctx->stack[ctx->sp].d = (*ctx->env)->CallStaticDoubleMethodA(ctx->env, cls, mid, jargs); ctx->sp++; break;
        default:  ctx->stack[ctx->sp].ptr = (*ctx->env)->CallStaticObjectMethodA(ctx->env, cls, mid, jargs); ctx->sp++; break;
        }
    }
}

HANDLER(INVOKEVIRTUAL_M) { /* shared by INVOKEVIRTUAL and INVOKEINTERFACE */
    int16_t idx = FETCH_S16(ctx);
    int ac = (idx < ctx->cp_mid_ac_n) ? ctx->cp_mid_ac[idx] : 0;
    char rt = (idx < ctx->cp_mid_rt_n) ? ctx->cp_mid_rt[idx] : 'V';
    jmethodID mid = (idx < ctx->cp_mid_n) ? ctx->cp_mid[idx] : NULL;
    jvalue jargs[KBOX_MAX_ARGS];
    int base = ctx->sp - ac - 1;
    if (base < 0) base = 0;
    ac = kbox_collect_args(ctx->stack, KBOX_MAX_SLOTS, base + 1, ac, jargs);
    jobject obj = (jobject)ctx->stack[base].ptr; ctx->sp = base;
    if (mid) {
        switch (rt) {
        case 'V': (*ctx->env)->CallVoidMethodA(ctx->env, obj, mid, jargs); break;
        case 'I': case 'Z': case 'B': case 'C': case 'S':
            ctx->stack[ctx->sp].i = (*ctx->env)->CallIntMethodA(ctx->env, obj, mid, jargs); ctx->sp++; break;
        case 'J': ctx->stack[ctx->sp].j = (*ctx->env)->CallLongMethodA(ctx->env, obj, mid, jargs); ctx->sp++; break;
        case 'F': ctx->stack[ctx->sp].f = (*ctx->env)->CallFloatMethodA(ctx->env, obj, mid, jargs); ctx->sp++; break;
        case 'D': ctx->stack[ctx->sp].d = (*ctx->env)->CallDoubleMethodA(ctx->env, obj, mid, jargs); ctx->sp++; break;
        default:  ctx->stack[ctx->sp].ptr = (*ctx->env)->CallObjectMethodA(ctx->env, obj, mid, jargs); ctx->sp++; break;
        }
    }
}

HANDLER(INVOKESPECIAL) {
    int16_t idx = FETCH_S16(ctx);
    int ac = (idx < ctx->cp_mid_ac_n) ? ctx->cp_mid_ac[idx] : 0;
    char rt = (idx < ctx->cp_mid_rt_n) ? ctx->cp_mid_rt[idx] : 'V';
    jmethodID mid = (idx < ctx->cp_mid_n) ? ctx->cp_mid[idx] : NULL;
    jvalue jargs[KBOX_MAX_ARGS];
    int base = ctx->sp - ac - 1;
    if (base < 0) base = 0;
    ac = kbox_collect_args(ctx->stack, KBOX_MAX_SLOTS, base + 1, ac, jargs);
    jobject obj = (jobject)ctx->stack[base].ptr; ctx->sp = base;
    if (mid) {
        /* Use the method's own declaring class (may be a ctor's class), not
           the host class: CallNonvirtual requires the class that declares mid. */
        jclass cls = (idx < ctx->cp_mid_cls_n) ? ctx->cp_mid_cls[idx] : NULL;
        if (!cls) cls = (ctx->cp_cls_n > 0) ? ctx->cp_cls[0] : NULL;
        switch (rt) {
        case 'V': (*ctx->env)->CallNonvirtualVoidMethodA(ctx->env, obj, cls, mid, jargs); break;
        case 'I': case 'Z': case 'B': case 'C': case 'S':
            ctx->stack[ctx->sp].i = (*ctx->env)->CallNonvirtualIntMethodA(ctx->env, obj, cls, mid, jargs); ctx->sp++; break;
        case 'J': ctx->stack[ctx->sp].j = (*ctx->env)->CallNonvirtualLongMethodA(ctx->env, obj, cls, mid, jargs); ctx->sp++; break;
        case 'F': ctx->stack[ctx->sp].f = (*ctx->env)->CallNonvirtualFloatMethodA(ctx->env, obj, cls, mid, jargs); ctx->sp++; break;
        case 'D': ctx->stack[ctx->sp].d = (*ctx->env)->CallNonvirtualDoubleMethodA(ctx->env, obj, cls, mid, jargs); ctx->sp++; break;
        default:  ctx->stack[ctx->sp].ptr = (*ctx->env)->CallNonvirtualObjectMethodA(ctx->env, obj, cls, mid, jargs); ctx->sp++; break;
        }
    }
}

/* ---- Object creation ---- */
HANDLER(NEW) {
    int16_t idx = FETCH_S16(ctx);
    jclass cls = (idx < ctx->cp_cls_n) ? ctx->cp_cls[idx] : NULL;
    if (cls) {
        /* AllocObject without running any constructor: the matching
           INVOKESPECIAL <init> later initializes it with its real args.
           (NewObject with a hardcoded "()V" ctor breaks parameterized
           constructors such as Circle(Double).) */
        jobject obj = (*ctx->env)->AllocObject(ctx->env, cls);
        ctx->stack[ctx->sp].ptr = obj;
    } else ctx->stack[ctx->sp].ptr = NULL;
    ctx->sp++;
}

/* ---- Arrays ---- */
HANDLER(NEWARRAY) {
    int at = FETCH(ctx); int count = ctx->stack[--ctx->sp].i; jobject arr = NULL;
    switch (at) {
    case 4: arr=(*ctx->env)->NewBooleanArray(ctx->env,count); break;
    case 5: arr=(*ctx->env)->NewCharArray(ctx->env,count); break;
    case 6: arr=(*ctx->env)->NewFloatArray(ctx->env,count); break;
    case 7: arr=(*ctx->env)->NewDoubleArray(ctx->env,count); break;
    case 8: arr=(*ctx->env)->NewByteArray(ctx->env,count); break;
    case 9: arr=(*ctx->env)->NewShortArray(ctx->env,count); break;
    case 10: arr=(*ctx->env)->NewIntArray(ctx->env,count); break;
    case 11: arr=(*ctx->env)->NewLongArray(ctx->env,count); break;
    }
    ctx->stack[ctx->sp].ptr = arr; ctx->sp++;
}
HANDLER(ANEWARRAY) {
    int16_t idx = FETCH_S16(ctx); int count = ctx->stack[--ctx->sp].i;
    jclass cls = (idx < ctx->cp_cls_n) ? ctx->cp_cls[idx] : NULL;
    jobject arr = (*ctx->env)->NewObjectArray(ctx->env, count, cls, NULL);
    ctx->stack[ctx->sp].ptr = arr; ctx->sp++;
}

/* ---- Multi-dimensional arrays (MULTIANEWARRAY) ---- */
/* Build a single-dimension array whose element type is `elem` (desc[1..] of a
 * "[..." array descriptor), e.g. 'I'->int[], "Ljava/lang/String;"->String[]. */
static jobject kbox_new_single_dim(JNIEnv* env, const char* elem, int n) {
    if (!elem || elem[0]=='\0') return NULL;
    switch (elem[0]) {
    case 'I': return (*env)->NewIntArray(env,n);
    case 'J': return (*env)->NewLongArray(env,n);
    case 'S': return (*env)->NewShortArray(env,n);
    case 'B': return (*env)->NewByteArray(env,n);
    case 'C': return (*env)->NewCharArray(env,n);
    case 'Z': return (*env)->NewBooleanArray(env,n);
    case 'F': return (*env)->NewFloatArray(env,n);
    case 'D': return (*env)->NewDoubleArray(env,n);
    default: { jclass c=(*env)->FindClass(env,elem); return c?(*env)->NewObjectArray(env,n,c,NULL):NULL; }
    }
}
/* Recursively allocate a `depth`-dimensional array. `desc` is the running
 * array descriptor ("[[I", then "[I", then "I"); `counts[at]` is the size of
 * each dimension, topmost dimension first. */
static jobject kbox_alloc_multi(JNIEnv* env, const char* desc, const jint* counts,
                                int at, int depth) {
    if (at >= depth && depth > 0) return NULL;
    int n = counts[at];
    if (at == depth - 1) return kbox_new_single_dim(env, desc + 1, n);
    jclass comp = (*env)->FindClass(env, desc + 1);
    if (!comp) { if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env); return NULL; }
    jobject arr = (*env)->NewObjectArray(env, n, comp, NULL);
    if (!arr) return NULL;
    for (int i = 0; i < n; i++) {
        jobject sub = kbox_alloc_multi(env, desc + 1, counts, at + 1, depth);
        (*env)->SetObjectArrayElement(env, arr, i, sub);
    }
    return arr;
}
HANDLER(MULTIANEWARRAY) {
    int16_t idx = FETCH_S16(ctx);
    int dims = FETCH(ctx);
    if (dims < 1 || dims > KBOX_MAX_SLOTS) dims = 1;
    jint counts[KBOX_MAX_SLOTS];
    for (int i = 0; i < dims; i++) counts[i] = ctx->stack[ctx->sp - dims + i].i;
    ctx->sp -= dims;
    const char* desc = (idx >= 0 && idx < ctx->cp_cls_names_n && ctx->cp_cls_names[idx])
                       ? ctx->cp_cls_names[idx] : NULL;
    if (getenv("KBOX_JNIC_DBG")) {
        fprintf(stderr, "[JNIC-MANARRAY] idx=%d dims=%d desc='%s' names_n=%d\n",
                (int)idx, dims, desc ? desc : "(null)", ctx->cp_cls_names_n);
        fflush(stderr);
    }
    jobject arr = (desc && desc[0]=='[') ? kbox_alloc_multi(ctx->env, desc, counts, 0, dims) : NULL;
    ctx->stack[ctx->sp].ptr = arr; ctx->sp++;
}

/* ---- switch dispatch ---- */
HANDLER(TABLESWITCH) {
    uint32_t base = ctx->pc;     /* pc now points just after the opcode byte */
    int t = ctx->stack[--ctx->sp].i;
    int32_t def  = kbox_fetch_i32_at(ctx->code, base+0,  ctx->code_len, ctx->key_seed, ctx->mutable_code);
    int32_t lo   = kbox_fetch_i32_at(ctx->code, base+4,  ctx->code_len, ctx->key_seed, ctx->mutable_code);
    int32_t hi   = kbox_fetch_i32_at(ctx->code, base+8,  ctx->code_len, ctx->key_seed, ctx->mutable_code);
    int32_t off;
    if (t < lo || t > hi) off = def;
    else {
        uint32_t o = base + 12 + (uint32_t)(t - lo) * 4;
        off = kbox_fetch_i32_at(ctx->code, o, ctx->code_len, ctx->key_seed, ctx->mutable_code);
    }
    ctx->pc = (base - 1) + (uint32_t)off;   /* opcode_pos + rel target */
}
HANDLER(LOOKUPSWITCH) {
    uint32_t base = ctx->pc;     /* pc just after opcode */
    int t = ctx->stack[--ctx->sp].i;
    int32_t def = kbox_fetch_i32_at(ctx->code, base+0, ctx->code_len, ctx->key_seed, ctx->mutable_code);
    int32_t np  = kbox_fetch_i32_at(ctx->code, base+4, ctx->code_len, ctx->key_seed, ctx->mutable_code);
    int32_t off = def;
    for (int32_t i = 0; i < np; i++) {
        uint32_t o = base + 8 + (uint32_t)i * 8;
        int32_t key = kbox_fetch_i32_at(ctx->code, o+0, ctx->code_len, ctx->key_seed, ctx->mutable_code);
        int32_t to  = kbox_fetch_i32_at(ctx->code, o+4, ctx->code_len, ctx->key_seed, ctx->mutable_code);
        if (key == t) { off = to; break; }
    }
    ctx->pc = (base - 1) + (uint32_t)off;
}
HANDLER(INVOKEDYNAMIC) {
    if (!g_indy_inited) kbox_indy_init(ctx->env);
    int16_t idx = FETCH_S16(ctx);
    if (idx < 0 || idx >= ctx->cp_indy_n || !g_indy_cls || !g_indy_invoke || !g_obj_cls) {
        /* Not resolvable: surface a NoSuchMethodError-like failure without crashing. */
        return;
    }
    const char* meta = ctx->cp_indy_meta[idx];
    const char* argc = ctx->cp_indy_argc[idx];
    char ret = (idx < ctx->cp_indy_ret_n) ? ctx->cp_indy_ret[idx] : 'L';
    if (!meta || !argc) return;

    int n = (int)strlen(argc);
    int base = ctx->sp - n; if (base < 0) base = 0;
    jobjectArray boxed = (*ctx->env)->NewObjectArray(ctx->env, n, g_obj_cls, NULL);
    if (boxed) {
        for (int j = 0; j < n; j++) {
            kbox_slot_t v = ctx->stack[base + j];
            jobject b = NULL;
            switch (argc[j]) {
            case 'I': if (g_int_cls && g_mid_intValueOf) b = (*ctx->env)->CallStaticObjectMethod(ctx->env, g_int_cls, g_mid_intValueOf, v.i); break;
            case 'J': if (g_long_cls && g_mid_longValueOf) b = (*ctx->env)->CallStaticObjectMethod(ctx->env, g_long_cls, g_mid_longValueOf, v.j); break;
            case 'F': if (g_float_cls && g_mid_floatValueOf) b = (*ctx->env)->CallStaticObjectMethod(ctx->env, g_float_cls, g_mid_floatValueOf, v.f); break;
            case 'D': if (g_double_cls && g_mid_doubleValueOf) b = (*ctx->env)->CallStaticObjectMethod(ctx->env, g_double_cls, g_mid_doubleValueOf, v.d); break;
            default:  b = (jobject)v.ptr; break;
            }
            (*ctx->env)->SetObjectArrayElement(ctx->env, boxed, j, b);
        }
    }
    ctx->sp = base;
    if ((*ctx->env)->ExceptionCheck(ctx->env)) { (*ctx->env)->ExceptionClear(ctx->env); }

    if (getenv("KBOX_JNIC_DBG")) {
        fprintf(stderr, "[JNIC-INDY] site=%d argc='%s' n=%d sp=%d base=%d",
                (int)idx, argc ? argc : "(null)", n, ctx->sp, base);
        fprintf(stderr, " [l0=%p l1=%p l2=%p i2=%d]",
                (void*)(ctx->locals[0].ptr), (void*)(ctx->locals[1].ptr),
                (void*)(ctx->locals[2].ptr), (int)ctx->locals[2].i);
        if (boxed) {
            for (int q = 0; q < n && q < 8; q++) {
                jobject e = (*ctx->env)->GetObjectArrayElement(ctx->env, boxed, q);
                fprintf(stderr, " b%d=%p", q, (void*)e);
                if ((*ctx->env)->ExceptionCheck(ctx->env)) (*ctx->env)->ExceptionClear(ctx->env);
            }
        }
        fprintf(stderr, " raw[");
        for (int q = 0; q < n && q < 8; q++) {
            fprintf(stderr, "%d:%p/%d ", q, (void*)ctx->stack[base + q].ptr, (int)ctx->stack[base + q].i);
        }
        fprintf(stderr, "]\n"); fflush(stderr);
    }

    jstring jm = (*ctx->env)->NewStringUTF(ctx->env, meta);
    jobject res = (*ctx->env)->CallStaticObjectMethod(ctx->env, g_indy_cls, g_indy_invoke, jm, boxed);
    if ((*ctx->env)->ExceptionCheck(ctx->env)) {
        /* Bootstrap/target threw: propagate it out of the native frame. */
        ctx->returned = 1; ctx->retval.i = 0; return;
    }
    switch (ret) {
    case 'I': if (res && g_mid_intValue) ctx->stack[ctx->sp].i = (*ctx->env)->CallIntMethod(ctx->env, res, g_mid_intValue); else ctx->stack[ctx->sp].i = 0; break;
    case 'J': if (res && g_mid_longValue) ctx->stack[ctx->sp].j = (*ctx->env)->CallLongMethod(ctx->env, res, g_mid_longValue); else ctx->stack[ctx->sp].j = 0; break;
    case 'F': if (res && g_mid_floatValue) ctx->stack[ctx->sp].f = (*ctx->env)->CallFloatMethod(ctx->env, res, g_mid_floatValue); else ctx->stack[ctx->sp].f = 0; break;
    case 'D': if (res && g_mid_doubleValue) ctx->stack[ctx->sp].d = (*ctx->env)->CallDoubleMethod(ctx->env, res, g_mid_doubleValue); else ctx->stack[ctx->sp].d = 0; break;
    case 'V': break; /* void call site: no value pushed */
    default:  ctx->stack[ctx->sp].ptr = res; break;
    }
    if (ret != 'V') ctx->sp++;
    if ((*ctx->env)->ExceptionCheck(ctx->env)) { (*ctx->env)->ExceptionClear(ctx->env); }
}
HANDLER(ARRAYLENGTH) {
    jobject arr = (jobject)ctx->stack[ctx->sp-1].ptr;
    ctx->stack[ctx->sp-1].i = (*ctx->env)->GetArrayLength(ctx->env, arr);
}
HANDLER(IALOAD){int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;jint b;(*ctx->env)->GetIntArrayRegion(ctx->env,a,ix,1,&b);ctx->stack[ctx->sp].i=b;ctx->sp++;}
HANDLER(AALOAD){int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;ctx->stack[ctx->sp].ptr=(*ctx->env)->GetObjectArrayElement(ctx->env,a,ix);ctx->sp++;}
HANDLER(BALOAD){int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;jbyte b;(*ctx->env)->GetByteArrayRegion(ctx->env,a,ix,1,&b);ctx->stack[ctx->sp].i=(jint)b;ctx->sp++;}
HANDLER(CALOAD){int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;jchar b;(*ctx->env)->GetCharArrayRegion(ctx->env,a,ix,1,&b);ctx->stack[ctx->sp].i=(jint)b;ctx->sp++;}
HANDLER(SALOAD){int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;jshort b;(*ctx->env)->GetShortArrayRegion(ctx->env,a,ix,1,&b);ctx->stack[ctx->sp].i=(jint)b;ctx->sp++;}
HANDLER(IASTORE){jint v=ctx->stack[--ctx->sp].i;int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;(*ctx->env)->SetIntArrayRegion(ctx->env,a,ix,1,&v);}
HANDLER(AASTORE){jobject v=(jobject)ctx->stack[--ctx->sp].ptr;int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;(*ctx->env)->SetObjectArrayElement(ctx->env,a,ix,v);}
HANDLER(BASTORE){jbyte v=(jbyte)ctx->stack[--ctx->sp].i;int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;(*ctx->env)->SetByteArrayRegion(ctx->env,a,ix,1,&v);}
HANDLER(CASTORE){jchar v=(jchar)ctx->stack[--ctx->sp].i;int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;(*ctx->env)->SetCharArrayRegion(ctx->env,a,ix,1,&v);}
HANDLER(SASTORE){jshort v=(jshort)ctx->stack[--ctx->sp].i;int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;(*ctx->env)->SetShortArrayRegion(ctx->env,a,ix,1,&v);}

HANDLER(ATHROW)  { ctx->sp--; jobject ex=(jobject)ctx->stack[ctx->sp].ptr; (*ctx->env)->Throw(ctx->env,(jthrowable)ex); ctx->retval.i=0; ctx->returned=1; }
HANDLER(CHECKCAST){ FETCH_S16(ctx); /* trust bytecode */ }
HANDLER(INSTANCEOF) {
    int16_t idx = FETCH_S16(ctx);
    jclass cls = (idx < ctx->cp_cls_n) ? ctx->cp_cls[idx] : NULL;
    ctx->sp--;
    jobject obj = (jobject)ctx->stack[ctx->sp].ptr;
    jboolean isInst = (*ctx->env)->IsInstanceOf(ctx->env, obj, cls);
    if (getenv("KBOX_JNIC_DBG")) {
        const char* cn = cls ? getClassName(ctx->env, cls) : "(null)";
        const char* on = obj ? getClassName(ctx->env, (*ctx->env)->GetObjectClass(ctx->env, obj)) : "(null)";
        fprintf(stderr, "[JNIC] INSTANCEOF obj=%s cls=%s -> %d\n", on, cn, (int)isInst);
    }
    ctx->stack[ctx->sp].i = isInst ? 1 : 0;
    ctx->sp++;
}

/* ---- Branch handlers ---- */
#define BRANCH_IF_COND(cond) do { \
    int t = ctx->stack[--ctx->sp].i; \
    int16_t off = FETCH_S16(ctx); \
    if (cond) ctx->pc += (int16_t)(off - 3); \
} while(0)
#define BRANCH_IF_CMP(cond) do { \
    int b = ctx->stack[--ctx->sp].i, a = ctx->stack[--ctx->sp].i; \
    int16_t off = FETCH_S16(ctx); \
    if (cond) ctx->pc += (int16_t)(off - 3); \
} while(0)

HANDLER(IFEQ) { BRANCH_IF_COND(t == 0); }
HANDLER(IFNE) { BRANCH_IF_COND(t != 0); }
HANDLER(IFLT) { BRANCH_IF_COND(t < 0); }
HANDLER(IFGE) { BRANCH_IF_COND(t >= 0); }
HANDLER(IFGT) { BRANCH_IF_COND(t > 0); }
HANDLER(IFLE) { BRANCH_IF_COND(t <= 0); }

HANDLER(IF_ICMPEQ) { BRANCH_IF_CMP(a == b); }
HANDLER(IF_ICMPNE) { BRANCH_IF_CMP(a != b); }
HANDLER(IF_ICMPLT) { BRANCH_IF_CMP(a < b); }
HANDLER(IF_ICMPGE) { BRANCH_IF_CMP(a >= b); }
HANDLER(IF_ICMPGT) { BRANCH_IF_CMP(a > b); }
HANDLER(IF_ICMPLE) { BRANCH_IF_CMP(a <= b); }

/* IF_ACMPEQ / IF_ACMPNE: see separate fn_IF_ACMPEQ2 / fn_IF_ACMPNE2 below */
/* GOTO handler */

HANDLER(GOTO) { int16_t off = FETCH_S16(ctx); ctx->pc += (int16_t)(off - 3); }

/* IFNULL / IFNONNULL: see separate fn_IFNULL2 / fn_IFNONNULL2 below */

/* ===== IF_ACMP and IFNULL/IFNONNULL distinct handlers ===== */
/* These require separate handlers because they encode the comparison direction. */
static void fn_IF_ACMPEQ2(kbox_ctx_t* ctx) {
    ctx->sp--; jobject b = (jobject)ctx->stack[ctx->sp].ptr;
    ctx->sp--; jobject a = (jobject)ctx->stack[ctx->sp].ptr;
    int16_t off = FETCH_S16(ctx);
    if ((*ctx->env)->IsSameObject(ctx->env, a, b))
        ctx->pc += (int16_t)(off - 3);
}
static void fn_IF_ACMPNE2(kbox_ctx_t* ctx) {
    ctx->sp--; jobject b = (jobject)ctx->stack[ctx->sp].ptr;
    ctx->sp--; jobject a = (jobject)ctx->stack[ctx->sp].ptr;
    int16_t off = FETCH_S16(ctx);
    if (!(*ctx->env)->IsSameObject(ctx->env, a, b))
        ctx->pc += (int16_t)(off - 3);
}
static void fn_IFNULL2(kbox_ctx_t* ctx) {
    ctx->sp--; jobject r = (jobject)ctx->stack[ctx->sp].ptr;
    int16_t off = FETCH_S16(ctx);
    if (r == NULL) ctx->pc += (int16_t)(off - 3);
}
static void fn_IFNONNULL2(kbox_ctx_t* ctx) {
    ctx->sp--; jobject r = (jobject)ctx->stack[ctx->sp].ptr;
    int16_t off = FETCH_S16(ctx);
    if (r != NULL) ctx->pc += (int16_t)(off - 3);
}

/* ===== DUP2_X1/DUP2_X2 stubs ===== */
/* FALOAD/FASTORE: see fn_FALOAD2/fn_FASTORE2 below */
/* DALOAD/DASTORE: see fn_DALOAD2/fn_DASTORE2 below */
/* DUP2_X1/DUP2_X2 stubs */
HANDLER(DUP2_X1) { /* placeholder: 4-slot stack operation */ }
HANDLER(DUP2_X2) { /* placeholder: 4-slot stack operation */ }
HANDLER(LALOAD) {
    int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    jlong b;(*ctx->env)->GetLongArrayRegion(ctx->env,a,ix,1,&b);
    ctx->stack[ctx->sp].j=b;ctx->sp++;
}
HANDLER(LASTORE) {
    jlong v=ctx->stack[--ctx->sp].j;int ix=ctx->stack[--ctx->sp].i;
    jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    (*ctx->env)->SetLongArrayRegion(ctx->env,a,ix,1,&v);
}
HANDLER(FALOAD2) {
    int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    jfloat b;(*ctx->env)->GetFloatArrayRegion(ctx->env,a,ix,1,&b);
    ctx->stack[ctx->sp].f=b;ctx->sp++;
}
HANDLER(FASTORE2) {
    jfloat v=ctx->stack[--ctx->sp].f;int ix=ctx->stack[--ctx->sp].i;
    jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    (*ctx->env)->SetFloatArrayRegion(ctx->env,a,ix,1,&v);
}
HANDLER(DALOAD2) {
    int ix=ctx->stack[--ctx->sp].i;jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    jdouble b;(*ctx->env)->GetDoubleArrayRegion(ctx->env,a,ix,1,&b);
    ctx->stack[ctx->sp].d=b;ctx->sp++;
}
HANDLER(DASTORE2) {
    jdouble v=ctx->stack[--ctx->sp].d;int ix=ctx->stack[--ctx->sp].i;
    jobject a=(jobject)ctx->stack[--ctx->sp].ptr;
    (*ctx->env)->SetDoubleArrayRegion(ctx->env,a,ix,1,&v);
}

/* ===== Special: bogus op handler (dead/noise opcodes) ===== */
static void fn_bogus(kbox_ctx_t* ctx) {
    /* Noise: consume top of stack and do nothing */
    if (ctx->sp > 0) {
        ctx->sp--;
        ctx->stack[ctx->sp].i ^= 0xA5A5A5A5;
        ctx->stack[ctx->sp].i ^= 0xA5A5A5A5;
    }
}

/* ===== Function pointer table initialisation ===== */

typedef void (*ctx_handler_t)(kbox_ctx_t*);

static void kbox_init_table(void) {
    if (g_table_init) return;

    /* Zero the table first */
    int i; for (i = 0; i < 256; i++) g_insn_table[i] = (kbox_handler_t)fn_bogus;

    /* Map each opcode to its handler.
     * The order here is deliberately scrambled across opcode space
     * so the table layout reveals nothing about the instruction set. */
    g_insn_table[K_NOP]           = (kbox_handler_t)fn_NOP;
    g_insn_table[K_ACONST_NULL]   = (kbox_handler_t)fn_ACONST_NULL;
    g_insn_table[K_ICONST_M1]     = (kbox_handler_t)fn_ICONST_M1;
    g_insn_table[K_ICONST_0]      = (kbox_handler_t)fn_ICONST_0;
    g_insn_table[K_ICONST_1]      = (kbox_handler_t)fn_ICONST_1;
    g_insn_table[K_ICONST_2]      = (kbox_handler_t)fn_ICONST_2;
    g_insn_table[K_ICONST_3]      = (kbox_handler_t)fn_ICONST_3;
    g_insn_table[K_ICONST_4]      = (kbox_handler_t)fn_ICONST_4;
    g_insn_table[K_ICONST_5]      = (kbox_handler_t)fn_ICONST_5;
    g_insn_table[K_LCONST_0]      = (kbox_handler_t)fn_LCONST_0;
    g_insn_table[K_LCONST_1]      = (kbox_handler_t)fn_LCONST_1;
    g_insn_table[K_FCONST_0]      = (kbox_handler_t)fn_FCONST_0;
    g_insn_table[K_FCONST_1]      = (kbox_handler_t)fn_FCONST_1;
    g_insn_table[K_FCONST_2]      = (kbox_handler_t)fn_FCONST_2;
    g_insn_table[K_DCONST_0]      = (kbox_handler_t)fn_DCONST_0;
    g_insn_table[K_DCONST_1]      = (kbox_handler_t)fn_DCONST_1;
    g_insn_table[K_BIPUSH]        = (kbox_handler_t)fn_BIPUSH;
    g_insn_table[K_SIPUSH]        = (kbox_handler_t)fn_SIPUSH;
    g_insn_table[K_LDC]           = (kbox_handler_t)fn_LDC;
    g_insn_table[K_ILOAD]         = (kbox_handler_t)fn_ILOAD;
    g_insn_table[K_LLOAD]         = (kbox_handler_t)fn_LLOAD;
    g_insn_table[K_FLOAD]         = (kbox_handler_t)fn_FLOAD;
    g_insn_table[K_DLOAD]         = (kbox_handler_t)fn_DLOAD;
    g_insn_table[K_ALOAD]         = (kbox_handler_t)fn_ALOAD;
    g_insn_table[K_ILOAD_0]       = (kbox_handler_t)fn_ILOAD_0;
    g_insn_table[K_ILOAD_1]       = (kbox_handler_t)fn_ILOAD_1;
    g_insn_table[K_ILOAD_2]       = (kbox_handler_t)fn_ILOAD_2;
    g_insn_table[K_ILOAD_3]       = (kbox_handler_t)fn_ILOAD_3;
    g_insn_table[K_LLOAD_0]       = (kbox_handler_t)fn_LLOAD_0;
    g_insn_table[K_LLOAD_1]       = (kbox_handler_t)fn_LLOAD_1;
    g_insn_table[K_LLOAD_2]       = (kbox_handler_t)fn_LLOAD_2;
    g_insn_table[K_LLOAD_3]       = (kbox_handler_t)fn_LLOAD_3;
    g_insn_table[K_FLOAD_0]       = (kbox_handler_t)fn_FLOAD_0;
    g_insn_table[K_FLOAD_1]       = (kbox_handler_t)fn_FLOAD_1;
    g_insn_table[K_FLOAD_2]       = (kbox_handler_t)fn_FLOAD_2;
    g_insn_table[K_FLOAD_3]       = (kbox_handler_t)fn_FLOAD_3;
    g_insn_table[K_DLOAD_0]       = (kbox_handler_t)fn_DLOAD_0;
    g_insn_table[K_DLOAD_1]       = (kbox_handler_t)fn_DLOAD_1;
    g_insn_table[K_DLOAD_2]       = (kbox_handler_t)fn_DLOAD_2;
    g_insn_table[K_DLOAD_3]       = (kbox_handler_t)fn_DLOAD_3;
    g_insn_table[K_ALOAD_0]       = (kbox_handler_t)fn_ALOAD_0;
    g_insn_table[K_ALOAD_1]       = (kbox_handler_t)fn_ALOAD_1;
    g_insn_table[K_ALOAD_2]       = (kbox_handler_t)fn_ALOAD_2;
    g_insn_table[K_ALOAD_3]       = (kbox_handler_t)fn_ALOAD_3;
    g_insn_table[K_IALOAD]        = (kbox_handler_t)fn_IALOAD;
    g_insn_table[K_LALOAD]        = (kbox_handler_t)fn_LALOAD;
    g_insn_table[K_FALOAD]        = (kbox_handler_t)fn_FALOAD2;
    g_insn_table[K_DALOAD]        = (kbox_handler_t)fn_DALOAD2;
    g_insn_table[K_AALOAD]        = (kbox_handler_t)fn_AALOAD;
    g_insn_table[K_BALOAD]        = (kbox_handler_t)fn_BALOAD;
    g_insn_table[K_CALOAD]        = (kbox_handler_t)fn_CALOAD;
    g_insn_table[K_SALOAD]        = (kbox_handler_t)fn_SALOAD;
    g_insn_table[K_ISTORE]        = (kbox_handler_t)fn_ISTORE;
    g_insn_table[K_LSTORE]        = (kbox_handler_t)fn_LSTORE;
    g_insn_table[K_FSTORE]        = (kbox_handler_t)fn_FSTORE;
    g_insn_table[K_DSTORE]        = (kbox_handler_t)fn_DSTORE;
    g_insn_table[K_ASTORE]        = (kbox_handler_t)fn_ASTORE;
    g_insn_table[K_ISTORE_0]      = (kbox_handler_t)fn_ISTORE_0;
    g_insn_table[K_ISTORE_1]      = (kbox_handler_t)fn_ISTORE_1;
    g_insn_table[K_ISTORE_2]      = (kbox_handler_t)fn_ISTORE_2;
    g_insn_table[K_ISTORE_3]      = (kbox_handler_t)fn_ISTORE_3;
    g_insn_table[K_LSTORE_0]      = (kbox_handler_t)fn_LSTORE_0;
    g_insn_table[K_LSTORE_1]      = (kbox_handler_t)fn_LSTORE_1;
    g_insn_table[K_LSTORE_2]      = (kbox_handler_t)fn_LSTORE_2;
    g_insn_table[K_LSTORE_3]      = (kbox_handler_t)fn_LSTORE_3;
    g_insn_table[K_FSTORE_0]      = (kbox_handler_t)fn_FSTORE_0;
    g_insn_table[K_FSTORE_1]      = (kbox_handler_t)fn_FSTORE_1;
    g_insn_table[K_FSTORE_2]      = (kbox_handler_t)fn_FSTORE_2;
    g_insn_table[K_FSTORE_3]      = (kbox_handler_t)fn_FSTORE_3;
    g_insn_table[K_DSTORE_0]      = (kbox_handler_t)fn_DSTORE_0;
    g_insn_table[K_DSTORE_1]      = (kbox_handler_t)fn_DSTORE_1;
    g_insn_table[K_DSTORE_2]      = (kbox_handler_t)fn_DSTORE_2;
    g_insn_table[K_DSTORE_3]      = (kbox_handler_t)fn_DSTORE_3;
    g_insn_table[K_ASTORE_0]      = (kbox_handler_t)fn_ASTORE_0;
    g_insn_table[K_ASTORE_1]      = (kbox_handler_t)fn_ASTORE_1;
    g_insn_table[K_ASTORE_2]      = (kbox_handler_t)fn_ASTORE_2;
    g_insn_table[K_ASTORE_3]      = (kbox_handler_t)fn_ASTORE_3;
    g_insn_table[K_IASTORE]       = (kbox_handler_t)fn_IASTORE;
    g_insn_table[K_LASTORE]       = (kbox_handler_t)fn_LASTORE;
    g_insn_table[K_FASTORE]       = (kbox_handler_t)fn_FASTORE2;
    g_insn_table[K_DASTORE]       = (kbox_handler_t)fn_DASTORE2;
    g_insn_table[K_AASTORE]       = (kbox_handler_t)fn_AASTORE;
    g_insn_table[K_BASTORE]       = (kbox_handler_t)fn_BASTORE;
    g_insn_table[K_CASTORE]       = (kbox_handler_t)fn_CASTORE;
    g_insn_table[K_SASTORE]       = (kbox_handler_t)fn_SASTORE;
    g_insn_table[K_POP]           = (kbox_handler_t)fn_POP;
    g_insn_table[K_POP2]          = (kbox_handler_t)fn_POP2;
    g_insn_table[K_DUP]           = (kbox_handler_t)fn_DUP;
    g_insn_table[K_DUP_X1]        = (kbox_handler_t)fn_DUP_X1;
    g_insn_table[K_DUP_X2]        = (kbox_handler_t)fn_DUP_X1;
    g_insn_table[K_DUP2]          = (kbox_handler_t)fn_DUP2;
    g_insn_table[K_DUP2_X1]       = (kbox_handler_t)fn_DUP2_X1;
    g_insn_table[K_DUP2_X2]       = (kbox_handler_t)fn_DUP2_X2;
    g_insn_table[K_SWAP]          = (kbox_handler_t)fn_SWAP;
    g_insn_table[K_IADD]          = (kbox_handler_t)fn_IADD;
    g_insn_table[K_LADD]          = (kbox_handler_t)fn_LADD;
    g_insn_table[K_FADD]          = (kbox_handler_t)fn_FADD;
    g_insn_table[K_DADD]          = (kbox_handler_t)fn_DADD;
    g_insn_table[K_ISUB]          = (kbox_handler_t)fn_ISUB;
    g_insn_table[K_LSUB]          = (kbox_handler_t)fn_LSUB;
    g_insn_table[K_FSUB]          = (kbox_handler_t)fn_FSUB;
    g_insn_table[K_DSUB]          = (kbox_handler_t)fn_DSUB;
    g_insn_table[K_IMUL]          = (kbox_handler_t)fn_IMUL;
    g_insn_table[K_LMUL]          = (kbox_handler_t)fn_LMUL;
    g_insn_table[K_FMUL]          = (kbox_handler_t)fn_FMUL;
    g_insn_table[K_DMUL]          = (kbox_handler_t)fn_DMUL;
    g_insn_table[K_IDIV]          = (kbox_handler_t)fn_IDIV;
    g_insn_table[K_LDIV]          = (kbox_handler_t)fn_LDIV;
    g_insn_table[K_FDIV]          = (kbox_handler_t)fn_FDIV;
    g_insn_table[K_DDIV]          = (kbox_handler_t)fn_DDIV;
    g_insn_table[K_IREM]          = (kbox_handler_t)fn_IREM;
    g_insn_table[K_LREM]          = (kbox_handler_t)fn_LREM;
    g_insn_table[K_FREM]          = (kbox_handler_t)fn_FREM;
    g_insn_table[K_DREM]          = (kbox_handler_t)fn_DREM;
    g_insn_table[K_INEG]          = (kbox_handler_t)fn_INEG;
    g_insn_table[K_LNEG]          = (kbox_handler_t)fn_LNEG;
    g_insn_table[K_FNEG]          = (kbox_handler_t)fn_FNEG;
    g_insn_table[K_DNEG]          = (kbox_handler_t)fn_DNEG;
    g_insn_table[K_ISHL]          = (kbox_handler_t)fn_ISHL;
    g_insn_table[K_LSHL]          = (kbox_handler_t)fn_LSHL;
    g_insn_table[K_ISHR]          = (kbox_handler_t)fn_ISHR;
    g_insn_table[K_LSHR]          = (kbox_handler_t)fn_LSHR;
    g_insn_table[K_IUSHR]         = (kbox_handler_t)fn_IUSHR;
    g_insn_table[K_LUSHR]         = (kbox_handler_t)fn_LUSHR;
    g_insn_table[K_IAND]          = (kbox_handler_t)fn_IAND;
    g_insn_table[K_LAND]          = (kbox_handler_t)fn_LAND;
    g_insn_table[K_IOR]           = (kbox_handler_t)fn_IOR;
    g_insn_table[K_LOR]           = (kbox_handler_t)fn_LOR;
    g_insn_table[K_IXOR]          = (kbox_handler_t)fn_IXOR;
    g_insn_table[K_LXOR]          = (kbox_handler_t)fn_LXOR;
    g_insn_table[K_IINC]          = (kbox_handler_t)fn_IINC;
    g_insn_table[K_I2L]           = (kbox_handler_t)fn_I2L;
    g_insn_table[K_I2F]           = (kbox_handler_t)fn_I2F;
    g_insn_table[K_I2D]           = (kbox_handler_t)fn_I2D;
    g_insn_table[K_L2I]           = (kbox_handler_t)fn_L2I;
    g_insn_table[K_L2F]           = (kbox_handler_t)fn_L2F;
    g_insn_table[K_L2D]           = (kbox_handler_t)fn_L2D;
    g_insn_table[K_F2I]           = (kbox_handler_t)fn_F2I;
    g_insn_table[K_F2L]           = (kbox_handler_t)fn_F2L;
    g_insn_table[K_F2D]           = (kbox_handler_t)fn_F2D;
    g_insn_table[K_D2I]           = (kbox_handler_t)fn_D2I;
    g_insn_table[K_D2L]           = (kbox_handler_t)fn_D2L;
    g_insn_table[K_D2F]           = (kbox_handler_t)fn_D2F;
    g_insn_table[K_I2B]           = (kbox_handler_t)fn_I2B;
    g_insn_table[K_I2C]           = (kbox_handler_t)fn_I2C;
    g_insn_table[K_I2S]           = (kbox_handler_t)fn_I2S;
    g_insn_table[K_LCMP]          = (kbox_handler_t)fn_LCMP;
    g_insn_table[K_FCMPL]         = (kbox_handler_t)fn_FCMPL;
    g_insn_table[K_FCMPG]         = (kbox_handler_t)fn_FCMPG;
    g_insn_table[K_DCMPL]         = (kbox_handler_t)fn_DCMPL;
    g_insn_table[K_DCMPG]         = (kbox_handler_t)fn_DCMPG;
    g_insn_table[K_IFEQ]          = (kbox_handler_t)fn_IFEQ;
    g_insn_table[K_IFNE]          = (kbox_handler_t)fn_IFNE;
    g_insn_table[K_IFLT]          = (kbox_handler_t)fn_IFLT;
    g_insn_table[K_IFGE]          = (kbox_handler_t)fn_IFGE;
    g_insn_table[K_IFGT]          = (kbox_handler_t)fn_IFGT;
    g_insn_table[K_IFLE]          = (kbox_handler_t)fn_IFLE;
    g_insn_table[K_IF_ICMPEQ]     = (kbox_handler_t)fn_IF_ICMPEQ;
    g_insn_table[K_IF_ICMPNE]     = (kbox_handler_t)fn_IF_ICMPNE;
    g_insn_table[K_IF_ICMPLT]     = (kbox_handler_t)fn_IF_ICMPLT;
    g_insn_table[K_IF_ICMPGE]     = (kbox_handler_t)fn_IF_ICMPGE;
    g_insn_table[K_IF_ICMPGT]     = (kbox_handler_t)fn_IF_ICMPGT;
    g_insn_table[K_IF_ICMPLE]     = (kbox_handler_t)fn_IF_ICMPLE;
    g_insn_table[K_IF_ACMPEQ]     = (kbox_handler_t)fn_IF_ACMPEQ2;
    g_insn_table[K_IF_ACMPNE]     = (kbox_handler_t)fn_IF_ACMPNE2;
    g_insn_table[K_GOTO]          = (kbox_handler_t)fn_GOTO;
    g_insn_table[K_IRETURN]       = (kbox_handler_t)fn_IRETURN;
    g_insn_table[K_LRETURN]       = (kbox_handler_t)fn_LRETURN;
    g_insn_table[K_FRETURN]       = (kbox_handler_t)fn_FRETURN;
    g_insn_table[K_DRETURN]       = (kbox_handler_t)fn_DRETURN;
    g_insn_table[K_ARETURN]       = (kbox_handler_t)fn_ARETURN;
    g_insn_table[K_RETURN]        = (kbox_handler_t)fn_RETURN;
    g_insn_table[K_GETSTATIC]     = (kbox_handler_t)fn_GETSTATIC;
    g_insn_table[K_PUTSTATIC]     = (kbox_handler_t)fn_PUTSTATIC;
    g_insn_table[K_GETFIELD]      = (kbox_handler_t)fn_GETFIELD;
    g_insn_table[K_PUTFIELD]      = (kbox_handler_t)fn_PUTFIELD;
    g_insn_table[K_INVOKEVIRTUAL] = (kbox_handler_t)fn_INVOKEVIRTUAL_M;
    g_insn_table[K_INVOKESPECIAL] = (kbox_handler_t)fn_INVOKESPECIAL;
    g_insn_table[K_INVOKESTATIC]  = (kbox_handler_t)fn_INVOKESTATIC;
    g_insn_table[K_INVOKEINTERFACE]= (kbox_handler_t)fn_INVOKEVIRTUAL_M;
    g_insn_table[K_NEW]           = (kbox_handler_t)fn_NEW;
    g_insn_table[K_NEWARRAY]      = (kbox_handler_t)fn_NEWARRAY;
    g_insn_table[K_ANEWARRAY]     = (kbox_handler_t)fn_ANEWARRAY;
    g_insn_table[K_ARRAYLENGTH]   = (kbox_handler_t)fn_ARRAYLENGTH;
    g_insn_table[K_ATHROW]        = (kbox_handler_t)fn_ATHROW;
    g_insn_table[K_CHECKCAST]     = (kbox_handler_t)fn_CHECKCAST;
    g_insn_table[K_INSTANCEOF]    = (kbox_handler_t)fn_INSTANCEOF;
    g_insn_table[K_IFNULL]        = (kbox_handler_t)fn_IFNULL2;
    g_insn_table[K_IFNONNULL]     = (kbox_handler_t)fn_IFNONNULL2;
    g_insn_table[K_TABLESWITCH]   = (kbox_handler_t)fn_TABLESWITCH;
    g_insn_table[K_LOOKUPSWITCH]  = (kbox_handler_t)fn_LOOKUPSWITCH;
    g_insn_table[K_MULTIANEWARRAY]= (kbox_handler_t)fn_MULTIANEWARRAY;
    g_insn_table[K_INVOKEDYNAMIC] = (kbox_handler_t)fn_INVOKEDYNAMIC;

    g_table_init = 1;
}

/* ===== Main interpreter loop (function-pointer dispatch) ===== */

/*
 * Execute the bytecode program using indirect calls through g_insn_table.
 * IDA/Ghidra cannot statically resolve indirect calls — the analyst must
 * dynamically trace to understand which handler serves which opcode.
 */
static void kbox_interp_run(kbox_ctx_t* ctx) {
    ctx->returned = 0;

    while (!ctx->returned) {
        /* Anti-debug check every 256 instructions */
        if ((ctx->pc & 0xFF) == 0) {
            if (g_debugged == -1) {
                g_debugged = kbox_detect_jdwp();
            }
            if (g_debugged) {
                kbox_poison_stack(ctx->stack, ctx->sp);
            }
        }

        uint8_t op = FETCH(ctx);
        kbox_handler_t handler = g_insn_table[op];

        /* DEBUG: print every instruction (compiled out unless KBOX_VMP_DEBUG) */
#ifdef KBOX_VMP_DEBUG
        {
            static int _dbgCnt = 0;
            _dbgCnt++;
            KBOX_DBG("[KBOX-INTERP-INS] #%d pc=%d op=0x%02x sp=%d\n", _dbgCnt, (int)ctx->pc, (int)op, ctx->sp);
            fflush(stderr);
        }
#endif

        if (handler == (kbox_handler_t)fn_bogus) {
            /* Unknown opcode: consume and emit junk */
            if (ctx->sp > 0) ctx->sp--;
            continue;
        }

        /* Indirect call — the compiler cannot devirtualize this */
        ((ctx_handler_t)handler)(ctx);
    }
}

/* ===== Public API: legacy entry point ===== */

/*
 * Legacy kbox_jvm_interp — backward compatible with existing stubs.
 * Plain bytecode, no encryption.
 */
kbox_value_t kbox_jvm_interp(JNIEnv* env, jobject receiver,
                             const unsigned char* bytecode, int bc_len,
                             void** args, int max_locals, int max_stack) {
    /* Init table on first call */
    if (!g_table_init) kbox_init_table();
    if (max_locals > KBOX_MAX_SLOTS) max_locals = KBOX_MAX_SLOTS;
    if (max_stack  > KBOX_MAX_SLOTS) max_stack  = KBOX_MAX_SLOTS;
    KBOX_DBG("[KBOX-INTERP] v3 after init_table\n"); fflush(stderr);
    if (!kbox_self_check()) {
        kbox_value_t r; r.i = 0; return r;
    }

    kbox_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    KBOX_DBG("[KBOX-INTERP] v3 after memset ctx\n"); fflush(stderr);

    /* Unpack CP arrays */
    ctx.cp_cls     = (jclass*)    args[0];
    ctx.cp_cls_n   = (int)(intptr_t)args[1];
    ctx.cp_fld     = (jfieldID*)  args[2];
    ctx.cp_fld_n   = (int)(intptr_t)args[3];
    ctx.cp_mid     = (jmethodID*) args[4];
    ctx.cp_mid_n   = (int)(intptr_t)args[5];
    ctx.cp_str     = (const char**)args[6];
    ctx.cp_str_n   = (int)(intptr_t)args[7];
    ctx.cp_int     = (const jint*)args[8];
    ctx.cp_int_n   = (int)(intptr_t)args[9];
    ctx.cp_mid_ac  = (const int*)args[10];
    ctx.cp_mid_ac_n= (int)(intptr_t)args[11];
    ctx.cp_mid_rt  = (const char*)args[12];
    ctx.cp_mid_rt_n= (int)(intptr_t)args[13];
    ctx.cp_mid_cls = (jclass*)   args[14];
    ctx.cp_mid_cls_n=(int)(intptr_t)args[15];
    ctx.cp_fld_rt  = NULL;       /* legacy layout: no field-type array */
    ctx.cp_fld_rt_n= 0;
    KBOX_DBG("[KBOX-INTERP] v3 after cp_unpack\n"); fflush(stderr);
    void** real_args = &args[16];

    ctx.env       = env;
    ctx.code      = bytecode;
    ctx.code_len  = bc_len;
    ctx.pc        = 0;
    ctx.key_seed  = 0;       /* legacy mode: no decryption */
    ctx.mutable_code = NULL;
    ctx.sp        = 0;

    /* Setup locals */
    memset(ctx.locals, 0, sizeof(ctx.locals));
    if (receiver != NULL) ctx.locals[0].ptr = receiver;
    int slot = (receiver != NULL) ? 1 : 0;
    void** ap = real_args;
    while (*ap != NULL && slot < max_locals) {
        ctx.locals[slot++].ptr = *ap; ap++;
    }
    KBOX_DBG("[KBOX-INTERP] v3 locals set: receiver=%d slot=%d locals[0]=%p locals[1]=%p cp_mid=%p cp_mid_n=%d cp_mid_cls=%p\n",
            (receiver != NULL) ? 1 : 0, slot,
            (void*)ctx.locals[0].ptr, (void*)ctx.locals[1].ptr,
            (void*)ctx.cp_mid, ctx.cp_mid_n, (void*)ctx.cp_mid_cls);
    fflush(stderr);

    kbox_interp_run(&ctx);
    KBOX_DBG("[KBOX-INTERP] v3 interp_run returned, retval.j=%lld\n", (long long)ctx.retval.j);
    fflush(stderr);
    return ctx.retval;
}

/* ===== Public API: enhanced entry point (with encryption) ===== */

/*
 * Enhanced kbox_jvm_interp_v3 — supports encrypted bytecode with
 * per-method key_seed + execution erasure.
 *
 * args[16,17] = cp_fld_rt (field type codes) — optional
 * args[18,19] = cp_fld_cls (per-field OWNER jclass) — optional
 * Additional args[20]: uint32_t* key_seed_ptr (or NULL for plain mode)
 */
kbox_value_t kbox_jvm_interp_v3(JNIEnv* env, jobject receiver,
                                const unsigned char* bytecode, int bc_len,
                                void** args, int max_locals, int max_stack,
                                uint8_t* mutable_code) {
    KBOX_DBG("[KBOX-INTERP] v3 entry: env=%p bc=%p bc_len=%d max_locals=%d max_stack=%d mutable=%p\n",
            (void*)env, (void*)bytecode, bc_len, max_locals, max_stack, (void*)mutable_code);
    fflush(stderr);
    /* Init table on first call */
    if (!g_table_init) kbox_init_table();
    if (max_locals > KBOX_MAX_SLOTS) max_locals = KBOX_MAX_SLOTS;
    if (max_stack  > KBOX_MAX_SLOTS) max_stack  = KBOX_MAX_SLOTS;
    KBOX_DBG("[KBOX-INTERP] v3 after init_table\n"); fflush(stderr);

    if (!kbox_self_check()) {
        kbox_value_t r; r.i = 0; return r;
    }

    /* Heap-allocate context to avoid stack overflow (struct is ~4.3KB). */
    kbox_ctx_t* ctx = (kbox_ctx_t*)calloc(1, sizeof(kbox_ctx_t));
    if (ctx == NULL) {
        kbox_value_t r; r.i = 0; return r;
    }
    KBOX_DBG("[KBOX-INTERP] v3 after calloc ctx (%zu bytes)\n", sizeof(kbox_ctx_t)); fflush(stderr);

    /* Unpack CP arrays */
    ctx->cp_cls     = (jclass*)    args[0];
    ctx->cp_cls_n   = (int)(intptr_t)args[1];
    ctx->cp_fld     = (jfieldID*)  args[2];
    ctx->cp_fld_n   = (int)(intptr_t)args[3];
    ctx->cp_mid     = (jmethodID*) args[4];
    ctx->cp_mid_n   = (int)(intptr_t)args[5];
    ctx->cp_str     = (const char**)args[6];
    ctx->cp_str_n   = (int)(intptr_t)args[7];
    ctx->cp_int     = (const jint*)args[8];
    ctx->cp_int_n   = (int)(intptr_t)args[9];
    ctx->cp_mid_ac  = (const int*)args[10];
    ctx->cp_mid_ac_n= (int)(intptr_t)args[11];
    ctx->cp_mid_rt  = (const char*)args[12];
    ctx->cp_mid_rt_n= (int)(intptr_t)args[13];
    ctx->cp_mid_cls = (jclass*)   args[14];
    ctx->cp_mid_cls_n=(int)(intptr_t)args[15];
    ctx->cp_fld_rt  = (const char*)args[16];
    ctx->cp_fld_rt_n= (int)(intptr_t)args[17];
    ctx->cp_fld_cls = (jclass*)   args[18];
    ctx->cp_fld_cls_n=(int)(intptr_t)args[19];
    ctx->cp_cls_names= (const char**)args[20];
    ctx->cp_cls_names_n= (int)(intptr_t)args[21];
    ctx->cp_indy_meta = (const char**)args[22];
    ctx->cp_indy_n    = (int)(intptr_t)args[23];
    ctx->cp_indy_argc = (const char**)args[24];
    ctx->cp_indy_argc_n=(int)(intptr_t)args[25];
    ctx->cp_indy_ret  = (const char*)args[26];
    ctx->cp_indy_ret_n= (int)(intptr_t)args[27];
    KBOX_DBG("[KBOX-INTERP] v3 after cp_unpack\n"); fflush(stderr);

    /* args[28] = key_seed (uint32_t*), args[29..] = Java args */
    uint32_t* key_seed_ptr = (uint32_t*)args[28];
    void** real_args = &args[29];

    ctx->env         = env;
    ctx->code        = bytecode;
    ctx->code_len    = bc_len;
    ctx->pc          = 0;
    ctx->key_seed    = (key_seed_ptr != NULL) ? *key_seed_ptr : 0;
    ctx->mutable_code = mutable_code;
    ctx->sp          = 0;
    KBOX_DBG("[KBOX-INTERP] v3 after ctx_setup\n"); fflush(stderr);

    /* Setup locals */
    KBOX_DBG("[KBOX-INTERP] v3 locals step0: receiver=%p max_locals=%d\n", (void*)receiver, max_locals); fflush(stderr);
    if (receiver != NULL) ctx->locals[0].ptr = receiver;
    KBOX_DBG("[KBOX-INTERP] v3 locals step1\n"); fflush(stderr);
    int slot = (receiver != NULL) ? 1 : 0;
    KBOX_DBG("[KBOX-INTERP] v3 locals step2: slot=%d\n", slot); fflush(stderr);
    void** ap = real_args;
    KBOX_DBG("[KBOX-INTERP] v3 locals step3: ap=%p\n", (void*)ap); fflush(stderr);
    while (*ap != NULL && slot < max_locals) {
        ctx->locals[slot++].ptr = *ap; ap++;
    }
    KBOX_DBG("[KBOX-INTERP] v3 locals done, slot=%d\n", slot); fflush(stderr);

    KBOX_DBG("[KBOX-INTERP] v3 before interp_run, env=%p\n", (void*)ctx->env); fflush(stderr);
    if (getenv("KBOX_JNIC_DBG")) {
        fprintf(stderr, "[KBOX-INTERP] decoded[");
        int lim = bc_len < 16 ? bc_len : 16;
        for (int i = 0; i < lim; i++) {
            unsigned char p = bytecode[i];
            if (ctx->key_seed) p = (unsigned char)(p ^ kbox_key_byte(ctx->key_seed, i));
            fprintf(stderr, "%02x ", p);
        }
        fprintf(stderr, "]\n"); fflush(stderr);
    }
    kbox_interp_run(ctx);
    KBOX_DBG("[KBOX-INTERP] v3 after interp_run\n"); fflush(stderr);
    kbox_value_t ret = ctx->retval;
    /* ret.i = 42; */
    free(ctx);
    return ret;
}
