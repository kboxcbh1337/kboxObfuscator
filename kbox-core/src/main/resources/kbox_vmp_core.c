/*
 * KBox-VMP Core Interpreter — Native VmpOp stack machine (rewritten)
 *
 * Replaces the earlier unused register-based skeleton. This is a faithful
 * C port of the Java stack-based VMP interpreter (VmpInterpreter). It keeps
 * the EXACT observable semantics of the boxed-Java-object interpreter so the
 * generated Java wrapper stubs (CHECKCAST <boxed>; xxxValue; <T>RETURN) keep
 * working unchanged, while moving the hot path — per-position ChaCha20 stream
 * decryption, the two-state XOR dispatch, and all pure arithmetic / stack /
 * branch micro-operations — into native code.
 *
 * Layered design (deep self-defense):
 *   L1  Native ChaCha20 (RFC 8439, byte-identical to ChaCha20.Keystream) —
 *       the per-run RESIDENT stream is decrypted one byte at a time; a
 *       contiguous plaintext instruction window never exists in memory.
 *   L2  Two-state XOR dispatch: slot = composite[twin ^ raw]; the real VmpOp
 *       is never materialized as a value — only an opaque handler SLOT.
 *   L3  Computed-goto dispatch table (GCC/Clang) / function-pointer table
 *       (MSVC) so IDA/ghidra F5 cannot reconstruct structured dispatch.
 *       The handler table is a per-call opaque pointer table re-keyed by the
 *       composite permutation.
 *   L4  Anti-debug / anti-hook: opcode fetch bounds check doubles as a canary,
 *       resident stream never copied, per-call g_scan counter allows the Java
 *       layer to arm a native module probe (see kbox_gateCheck).
 *
 * Correctness model (hybrid on purpose):
 *   The operand stack holds BOXED Java objects (jobject), matching the Java
 *   interpreter's Object[]. Pure ops (arith/conversion/compare/branch/stack)
 *   are computed natively by unboxing/boxing through cached JNI method IDs,
 *   reproducing toInt/toLong/toFloat/toDouble exactly. Object-model ops
 *   (fields, methods, ctors, arrays, strings, classes, monitors, athrow,
 *   returns) are delegated to trusted Java static helpers on VmpInterpreter —
 *   they reuse the hardened reflection/coerce/module-access/exception-table
 *   logic so correctness is not re-implemented in C.
 *
 * JNI bridge contract (must match VmpInterpreter/VmpInterpreterNative, t4):
 *   native Object execute(VmpMethod m, java.lang.Object instance,
 *                         java.lang.Object[] args);
 *   C reads m.resident / m.composite / m.twin / m.cipherLen / m.maxStack /
 *   m.maxLocals / m.ephSecret via jfieldID, and calls these static helpers on
 *   com/kbox/runtime/VmpInterpreter:
 *     int nlOnStatic  (VmpMethod,Object[],Object[],long[])  -- GETSTATIC
 *     int nlPutStatic (VmpMethod,Object[],Object[],long[])
 *     int nlGetField  (VmpMethod,Object[],Object[],long[])
 *     int nlPutField  (VmpMethod,Object[],Object[],long[])
 *     int nlInvoke    (VmpMethod,Object[],Object[],long[],int) -- 0..3 kind
 *     int nlNew       (VmpMethod,Object[],Object[],long[])
 *     int nlNewArray  (VmpMethod,Object[],Object[],long[],int) -- prim/newref
 *     int nlArrayIndex(VmpMethod,Object[],long[],int,int)  -- (get/set,op)
 *     int nlCheckCast (VmpMethod,Object[],Object[],long[])
 *     int nlInstanceOf(VmpMethod,Object[],Object[],long[])
 *     int nlResolve   (VmpMethod,Object[],long[])  -- push STRING/CLASS
 *     int nlMonitor   (VmpMethod,Object[],long[],int) -- enter/exit (throws)
 *     Object nlReturn (VmpMethod,Object[],long[],int)  -- boxes result
 *   Every helper gets cpu = long[]{pc,sp}, reads operands with m.i4(cpu[0]) /
 *   m.u2(cpu[0]), mutates stack[], and writes cpu[0]=pc, cpu[1]=sp. A helper
 *   that must unwind returns via C (RETURN/END) is signalled by cpu[2]=1.
 *
 * Builds with GCC, Clang or MSVC (mirrors kbox_jnic_interp.c).
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdio.h>

#if defined(_WIN32)
  #include <windows.h>
#else
  #include <sys/mman.h>
  #include <unistd.h>
#endif

#ifdef _MSC_VER
  #define KBOX_ALIGNED(x) __declspec(align(x))
  #define KBOX_INLINE     static __inline
  #define KBOX_ATT_DISP   0                         /* no computed-goto on MSVC */
  #define KBOX_NORET      __declspec(noreturn)
#else
  #define KBOX_ALIGNED(x) __attribute__((aligned(x)))
  #define KBOX_INLINE     static inline
  #define KBOX_ATT_DISP   1
  #define KBOX_NORET      __attribute__((noreturn))
#endif

/* =====================================================================
 * L1: SHA-256 (byte-identical to java.security.MessageDigest SHA-256) —
 * supply-free minimal implementation, must match Keystream.deriveKeyNonce.
 * ===================================================================== */

typedef struct { uint32_t h[8]; uint32_t w[64]; uint64_t len; uint8_t buf[64]; int buflen; } kbox_sha256;

static const uint32_t KBOX_SHA_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};

KBOX_INLINE uint32_t kbox_rotr(uint32_t x, int n){ return (x>>n)|(x<<(32-n)); }
#define KBOX_CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define KBOX_MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define KBOX_BSIG0(x) (kbox_rotr((x),2)^kbox_rotr((x),13)^kbox_rotr((x),22))
#define KBOX_BSIG1(x) (kbox_rotr((x),6)^kbox_rotr((x),11)^kbox_rotr((x),25))
#define KBOX_SSIG0(x) (kbox_rotr((x),7)^kbox_rotr((x),18)^((x)>>3))
#define KBOX_SSIG1(x) (kbox_rotr((x),17)^kbox_rotr((x),19)^((x)>>10))

static void kbox_sha256_init(kbox_sha256* s){
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len=0; s->buflen=0;
}

static void kbox_sha256_block(kbox_sha256* s, const uint8_t* p){
    int t;
    for (t=0;t<16;t++){
        s->w[t]=(uint32_t)p[t*4]<<24 | (uint32_t)p[t*4+1]<<16 | (uint32_t)p[t*4+2]<<8 | p[t*4+3];
    }
    for (t=16;t<64;t++) s->w[t]=KBOX_SSIG1(s->w[t-2])+s->w[t-7]+KBOX_SSIG0(s->w[t-15])+s->w[t-16];
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (t=0;t<64;t++){
        uint32_t T1=h+KBOX_BSIG1(e)+KBOX_CH(e,f,g)+KBOX_SHA_K[t]+s->w[t];
        uint32_t T2=KBOX_BSIG0(a)+KBOX_MAJ(a,b,c);
        h=g; g=f; f=e; e=d+T1; d=c; c=b; b=a; a=T1+T2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void kbox_sha256_update(kbox_sha256* s, const uint8_t* in, size_t n){
    s->len += n;
    while (n>0){
        int take = (int)(64-(size_t)s->buflen);
        if (take > (int)n) take=(int)n;
        memcpy(s->buf+s->buflen, in, (size_t)take);
        s->buflen+=take; in+=take; n-=(size_t)take;
        if (s->buflen==64){ kbox_sha256_block(s,s->buf); s->buflen=0; }
    }
}

static void kbox_sha256_final(kbox_sha256* s, uint8_t out[32]){
    uint64_t bits = s->len<<3;
    uint8_t pad=0x80;
    kbox_sha256_update(s,&pad,1);
    while (s->buflen!=56) { pad=0x00; kbox_sha256_update(s,&pad,1); }
    uint8_t b[8]; int i;
    for (i=0;i<8;i++) b[i]=(uint8_t)(bits>>(56-8*i));
    kbox_sha256_update(s,b,8);
    for (i=0;i<8;i++){
        out[i*4]=(uint8_t)(s->h[i]>>24); out[i*4+1]=(uint8_t)(s->h[i]>>16);
        out[i*4+2]=(uint8_t)(s->h[i]>>8); out[i*4+3]=(uint8_t)(s->h[i]);
    }
}

/* Must match ChaCha20.deriveKeyNonce(byte[] secret,...):
 *   key   = SHA256(secret)
 *   nonce = SHA256(secret || 0x01) [0..12]                        */
static void kbox_derive_key_nonce(const uint8_t* secret, size_t n,
                                  uint8_t key[32], uint8_t nonce[12]){
    kbox_sha256 s; kbox_sha256_init(&s);
    kbox_sha256_update(&s, secret, n);
    kbox_sha256_final(&s, key);
    kbox_sha256_init(&s);
    kbox_sha256_update(&s, secret, n);
    uint8_t one=0x01; kbox_sha256_update(&s,&one,1);
    uint8_t h2[32];
    kbox_sha256_final(&s, h2);
    memcpy(nonce, h2, 12);
}

/* =====================================================================
 * L1: ChaCha20 (RFC 8439) random-access keystream byte at abs pos.
 * Byte-identical to ChaCha20.Keystream .at(pos).
 * ===================================================================== */

#define KBOX_QR(x,a,b,c,d) \
    x[a]+=x[b]; x[d]=((x[d]^x[a])<<16)|((x[d]^x[a])>>16); \
    x[c]+=x[d]; x[b]=((x[b]^x[c])<<12)|((x[b]^x[c])>>20); \
    x[a]+=x[b]; x[d]=((x[d]^x[a])<<8)|((x[d]^x[a])>>24);   \
    x[c]+=x[d]; x[b]=((x[b]^x[c])<<7)|((x[b]^x[c])>>25);

typedef struct {
    uint32_t st[16];
    uint8_t  block[64];
    uint64_t blockCtr;   /* cached block counter */
    uint8_t  key[32];
    uint8_t  nonce[12];
} kbox_keystream;

KBOX_INLINE uint32_t kbox_le32(const uint8_t* p){
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}

static void kbox_chacha_block(kbox_keystream* ks, uint64_t ctr, uint8_t out[64]){
    /* const "expand 32-byte k" */
    static const uint32_t SIGMA[4]={0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t x[16]; int i;
    x[0]=SIGMA[0]; x[1]=SIGMA[1]; x[2]=SIGMA[2]; x[3]=SIGMA[3];
    x[4]=kbox_le32(ks->key+0);  x[5]=kbox_le32(ks->key+4);
    x[6]=kbox_le32(ks->key+8);  x[7]=kbox_le32(ks->key+12);
    x[8]=kbox_le32(ks->key+16); x[9]=kbox_le32(ks->key+20);
    x[10]=kbox_le32(ks->key+24);x[11]=kbox_le32(ks->key+28);
    x[12]=(uint32_t)ctr;
    x[13]=kbox_le32(ks->nonce+0);x[14]=kbox_le32(ks->nonce+4);x[15]=kbox_le32(ks->nonce+8);
    uint32_t s[16]; memcpy(s,x,sizeof(s));
    for (i=0;i<10;i++){
        KBOX_QR(x,0,4,8,12);  KBOX_QR(x,1,5,9,13);
        KBOX_QR(x,2,6,10,14); KBOX_QR(x,3,7,11,15);
        KBOX_QR(x,0,5,10,15); KBOX_QR(x,1,6,11,12);
        KBOX_QR(x,2,7,8,13);  KBOX_QR(x,3,4,9,14);
    }
    for (i=0;i<16;i++){
        uint32_t v=x[i]+s[i];
        out[i*4]=(uint8_t)v; out[i*4+1]=(uint8_t)(v>>8);
        out[i*4+2]=(uint8_t)(v>>16); out[i*4+3]=(uint8_t)(v>>24);
    }
}

static void kbox_ks_init(kbox_keystream* ks, const uint8_t* secret, int n){
    kbox_derive_key_nonce(secret,(size_t)n,ks->key,ks->nonce);
    ks->blockCtr = (uint64_t)-1;
    /* seed the cached block so at() is correct even if blockCtr sentinel fits */
    ks->blockCtr = (uint64_t)-1;
}

/* Random-access keystream byte at absolute stream position (must match .at()) */
KBOX_INLINE uint8_t kbox_ks_at(kbox_keystream* ks, int64_t pos){
    if (pos < 0) return 0;
    uint64_t bc = (uint64_t)((pos & (int64_t)0x7FFFFFFFFFFFFFFFLL) >> 6);
    /* Java: long bc = pos >>> 6 (logical shift); pos>=0 so == pos/64 */
    bc = ((uint64_t)pos) >> 6;
    if (bc != ks->blockCtr){
        ks->blockCtr = bc;
        kbox_chacha_block(ks, bc, ks->block);
    }
    return ks->block[(int)(pos & 63)];
}

/* =====================================================================
 * JNI method/field ID cache (resolved once, per JNIEnv-independent class;
 * method IDs are process-global once a class is loaded).
 * ===================================================================== */

typedef struct {
    jmethodID intValue, longValue, floatValue, doubleValue;
    jmethodID booleanValue, charValue, byteValue, shortValue;
    jmethodID integerValueOf, longValueOf, floatValueOf, doubleValueOf;
    jmethodID booleanValueOf, charValueOf, byteValueOf, shortValueOf;
    /* cached global refs to wrapper classes (avoid FindClass on hot coercion path) */
    jclass intCls, longCls, floatCls, doubleCls;
    jclass boolCls, charCls, byteCls, shortCls, objCls, cceCls;
    /* helper methods on VmpInterpreter */
    struct {
        jmethodID getStatic, putStatic, getField, putField, invoke;
        jmethodID new_, newArray, arrayIndex, checkCast, instanceOf;
        jmethodID resolve, monitor, ret, tryCatch;
    } h;
    jclass interpCls;      /* global ref to VmpInterpreter */
} kbox_vmp_native_ids;

static kbox_vmp_native_ids g_ids;
static int g_ids_init = 0;

/* ---- Java-side helper signatures (must match t4) ---- */
/* GETSTATIC:      (Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[Ljava/lang/Object;[J)I */
/* invoke:(...,[J,I)I   newArray:(...,[J,I)I   arrayIndex:(Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[JII)I
 * resolve:(...,[J)I  monitor:(...,[J,I)I  checkCast/instanceOf:(...,[J)I
 * ret:(Lcom/kbox/runtime/VmpMethod;[Ljava/lang/Object;[J)I   returns boxed pushed into stack by caller? no——ret returns value. */

/* Because JNI_GetStaticMethodID requires a jclass, we lazily-resolve ids on the
 * first native call (a call happens only after VmpMethod loads). Synchronization
 * is not needed for id resolution idempotency (assignment is idempotent). */

static jclass kbox_find_interp_class(JNIEnv* env){
    if (g_ids.interpCls) return g_ids.interpCls;
    jclass c = (*env)->FindClass(env, "com/kbox/runtime/VmpInterpreter");
    if (!c) return NULL;
    g_ids.interpCls = (jclass)(*env)->NewGlobalRef(env, c);
    (*env)->DeleteLocalRef(env, c);
    return g_ids.interpCls;
}

static void kbox_resolve_ids(JNIEnv* env){
    if (g_ids_init) return;
    jclass c = kbox_find_interp_class(env);
    if (!c) return;

    jclass ic = (*env)->FindClass(env, "java/lang/Integer");
    jclass lc = (*env)->FindClass(env, "java/lang/Long");
    jclass fc = (*env)->FindClass(env, "java/lang/Float");
    jclass dc = (*env)->FindClass(env, "java/lang/Double");
    jclass bc = (*env)->FindClass(env, "java/lang/Boolean");
    jclass cc = (*env)->FindClass(env, "java/lang/Character");
    jclass yc = (*env)->FindClass(env, "java/lang/Byte");
    jclass sc = (*env)->FindClass(env, "java/lang/Short");
    if (ic&&lc&&fc&&dc&&bc&&cc&&yc&&sc){
        g_ids.intValue  = (*env)->GetMethodID(env, ic, "intValue", "()I");
        g_ids.longValue = (*env)->GetMethodID(env, lc, "longValue", "()J");
        g_ids.floatValue= (*env)->GetMethodID(env, fc, "floatValue", "()F");
        g_ids.doubleValue=(*env)->GetMethodID(env, dc, "doubleValue", "()D");
        g_ids.booleanValue=(*env)->GetMethodID(env,bc,"booleanValue","()Z");
        g_ids.charValue  = (*env)->GetMethodID(env, cc, "charValue", "()C");
        g_ids.byteValue  = (*env)->GetMethodID(env, yc, "byteValue", "()B");
        g_ids.shortValue = (*env)->GetMethodID(env, sc, "shortValue", "()S");
        g_ids.integerValueOf=(*env)->GetStaticMethodID(env, ic,"valueOf","(I)Ljava/lang/Integer;");
        g_ids.longValueOf   =(*env)->GetStaticMethodID(env, lc,"valueOf","(J)Ljava/lang/Long;");
        g_ids.floatValueOf  =(*env)->GetStaticMethodID(env, fc,"valueOf","(F)Ljava/lang/Float;");
        g_ids.doubleValueOf =(*env)->GetStaticMethodID(env, dc,"valueOf","(D)Ljava/lang/Double;");
        g_ids.booleanValueOf=(*env)->GetStaticMethodID(env,bc,"valueOf","(Z)Ljava/lang/Boolean;");
        g_ids.charValueOf   =(*env)->GetStaticMethodID(env, cc,"valueOf","(C)Ljava/lang/Character;");
        g_ids.byteValueOf   =(*env)->GetStaticMethodID(env, yc,"valueOf","(B)Ljava/lang/Byte;");
        g_ids.shortValueOf  =(*env)->GetStaticMethodID(env, sc,"valueOf","(S)Ljava/lang/Short;");
        /* promote wrapper classes to global refs so hot coercions never FindClass */
        g_ids.intCls   = (jclass)(*env)->NewGlobalRef(env, ic);
        g_ids.longCls  = (jclass)(*env)->NewGlobalRef(env, lc);
        g_ids.floatCls = (jclass)(*env)->NewGlobalRef(env, fc);
        g_ids.doubleCls= (jclass)(*env)->NewGlobalRef(env, dc);
        g_ids.boolCls  = (jclass)(*env)->NewGlobalRef(env, bc);
        g_ids.charCls  = (jclass)(*env)->NewGlobalRef(env, cc);
        g_ids.byteCls  = (jclass)(*env)->NewGlobalRef(env, yc);
        g_ids.shortCls = (jclass)(*env)->NewGlobalRef(env, sc);
        g_ids.objCls   = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env,"java/lang/Object"));
        g_ids.cceCls   = (jclass)(*env)->NewGlobalRef(env, (*env)->FindClass(env,"java/lang/ClassCastException"));
    }
    if (ic)(*env)->DeleteLocalRef(env,ic); if (lc)(*env)->DeleteLocalRef(env,lc);
    if (fc)(*env)->DeleteLocalRef(env,fc); if (dc)(*env)->DeleteLocalRef(env,dc);
    if (bc)(*env)->DeleteLocalRef(env,bc); if (cc)(*env)->DeleteLocalRef(env,cc);
    if (yc)(*env)->DeleteLocalRef(env,yc); if (sc)(*env)->DeleteLocalRef(env,sc);

    /* These are string-literal concatenation macros (not variables): the JNI
     * signature is built from adjacent string literals, which C only folds at
     * compile time when each piece is a literal token. */
#define MR "Lcom/kbox/runtime/VmpInterpreter$VmpMethod;"
#define SJ "[Ljava/lang/Object;"
#define LJ "[J"
    g_ids.h.getStatic = (*env)->GetStaticMethodID(env,c, "nlGetStatic",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.putStatic = (*env)->GetStaticMethodID(env,c, "nlPutStatic",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.getField  = (*env)->GetStaticMethodID(env,c, "nlGetField",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.putField  = (*env)->GetStaticMethodID(env,c, "nlPutField",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.invoke    = (*env)->GetStaticMethodID(env,c, "nlInvoke",
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.new_      = (*env)->GetStaticMethodID(env,c, "nlNew",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.newArray  = (*env)->GetStaticMethodID(env,c, "nlNewArray",
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.arrayIndex= (*env)->GetStaticMethodID(env,c, "nlArrayIndex",
             "(" MR SJ LJ "II)I");
    g_ids.h.checkCast = (*env)->GetStaticMethodID(env,c, "nlCheckCast",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.instanceOf= (*env)->GetStaticMethodID(env,c, "nlInstanceOf",
             "(" MR SJ SJ LJ ")I");
    g_ids.h.resolve   = (*env)->GetStaticMethodID(env,c, "nlResolve",
             "(" MR SJ LJ ")I");
    g_ids.h.monitor   = (*env)->GetStaticMethodID(env,c, "nlMonitor",
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.ret       = (*env)->GetStaticMethodID(env,c, "nlReturn",
             "(" MR SJ SJ LJ "I)I");
    g_ids.h.tryCatch  = (*env)->GetStaticMethodID(env,c, "nlTryCatch",
             "(" MR SJ LJ "Ljava/lang/Object;I)I");
#undef MR
#undef SJ
#undef LJ
    /* NB: exceptions thrown by helpers are checked after each CallStaticIntMethod */

    g_ids_init = 1;
}

/* =====================================================================
 * Type coercion helpers — must reproduce VmpInterpreter.toInt/toLong/
 * toFloat/toDouble semantics. Return 0 on invalid (caller-visible as an
 * exception path via a pending ClassCastException).
 * ===================================================================== */

KBOX_INLINE jint kbox_toIntOrThrow(JNIEnv* env, jobject o){
    if (!o) { (*env)->ThrowNew(env, g_ids.cceCls, "KBox"); return 0; }
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) {
        return (*env)->CallIntMethod(env,o,g_ids.intValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.boolCls)) {
        jboolean z=(*env)->CallBooleanMethod(env,o,g_ids.booleanValue); return z?1:0;
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.charCls)) {
        return (jint)(*env)->CallCharMethod(env,o,g_ids.charValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.byteCls)) {
        return (jint)(*env)->CallByteMethod(env,o,g_ids.byteValue);
    }
    if ((*env)->IsInstanceOf(env,o,g_ids.shortCls)) {
        return (jint)(*env)->CallShortMethod(env,o,g_ids.shortValue);
    }
    (*env)->ThrowNew(env, g_ids.cceCls, "KBox");
    return 0;
}

KBOX_INLINE jlong kbox_toLongOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jlong)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jlong)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, "KBox");
    return 0;
}

KBOX_INLINE jfloat kbox_toFloatOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.floatCls)) return (jfloat)(*env)->CallFloatMethod(env,o,g_ids.floatValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jfloat)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jfloat)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, "KBox");
    return 0;
}

KBOX_INLINE jdouble kbox_toDoubleOrThrow(JNIEnv* env, jobject o){
    if ((*env)->IsInstanceOf(env,o,g_ids.doubleCls)) return (jdouble)(*env)->CallDoubleMethod(env,o,g_ids.doubleValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.floatCls)) return (jdouble)(*env)->CallFloatMethod(env,o,g_ids.floatValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.intCls)) return (jdouble)(*env)->CallIntMethod(env,o,g_ids.intValue);
    if ((*env)->IsInstanceOf(env,o,g_ids.longCls)) return (jdouble)(*env)->CallLongMethod(env,o,g_ids.longValue);
    (*env)->ThrowNew(env, g_ids.cceCls, "KBox");
    return 0;
}

/* Boxing factories (cached classes; returns local ref or NULL on error). */
KBOX_INLINE jobject kbox_boxInt(JNIEnv* env, jint v){
    return (*env)->CallStaticObjectMethod(env, g_ids.intCls, g_ids.integerValueOf, v);
}
KBOX_INLINE jobject kbox_boxLong(JNIEnv* env, jlong v){
    return (*env)->CallStaticObjectMethod(env, g_ids.longCls, g_ids.longValueOf, v);
}
KBOX_INLINE jobject kbox_boxFloat(JNIEnv* env, jfloat v){
    return (*env)->CallStaticObjectMethod(env, g_ids.floatCls, g_ids.floatValueOf, v);
}
KBOX_INLINE jobject kbox_boxDouble(JNIEnv* env, jdouble v){
    return (*env)->CallStaticObjectMethod(env, g_ids.doubleCls, g_ids.doubleValueOf, v);
}

/* =====================================================================
 * CPU frame + VmpMethod field access.
 * ===================================================================== */

typedef struct {
    JNIEnv*        env;
    jobject        m;            /* VmpMethod */
    jobjectArray   stack;        /* Object[] operand stack (maxStack+16) */
    jobjectArray   locals;       /* Object[] locals (maxLocals) */
    jlong          cpu[3];       /* pc, sp, unwindFlg */
    uint8_t*       resident;     /* cached copy of m.resident bytes */
    int32_t        cipherLen;
    uint8_t        codeSet;      /* resident cache valid */
    jint           twin;
    jintArray      composite;    /* cached global/int array ref if exposed */
    const int32_t* compositePtr; /* direct pointer into jintArray (we pin via GetIntArrayElements) */
    jint*          compositeEls;
    int            compositePinned;
    int            maxStack;
    int            maxLocals;
    int            retKind;      /* last *RETURN kind (5 = void) to recover result */
} kbox_cpu_t;

/* VmpMethod field IDs (resolved each native call — cheap, idempotent). */
typedef struct {
    jfieldID resident, cipherLen, twin, composite, invPerm,
             maxStack, maxLocals, ephKey;
} kbox_mfield_t;

static kbox_mfield_t g_mf;
static int g_mf_init = 0;

static void kbox_load_mfield(JNIEnv* env){
    if (g_mf_init) return;
    jclass c = (*env)->FindClass(env, "com/kbox/runtime/VmpInterpreter$VmpMethod");
    if (!c) return;
    g_mf.resident  = (*env)->GetFieldID(env,c,"resident","Ljava/nio/ByteBuffer;");
    g_mf.cipherLen = (*env)->GetFieldID(env,c,"cipherLen","I");
    g_mf.twin      = (*env)->GetFieldID(env,c,"twin","I");
    g_mf.composite = (*env)->GetFieldID(env,c,"composite","[I");
    g_mf.invPerm   = (*env)->GetFieldID(env,c,"invPerm","[I");
    g_mf.maxStack  = (*env)->GetFieldID(env,c,"maxStack","I");
    g_mf.maxLocals = (*env)->GetFieldID(env,c,"maxLocals","I");
    g_mf.ephKey    = (*env)->GetFieldID(env,c,"ephKey","[B");
    (*env)->DeleteLocalRef(env,c);
    g_mf_init = 1;
}

/* ==================================================================== */
/* Secure waveform allocation (wipe + unmap in one shot)                */
/* ==================================================================== */
/* Mirrors kbox_bf_loader.c's secureAlloc/secureFree so the working
 * ciphertext wave does NOT live in the Java heap nor in a malloc free-list
 * region: it is reserved as its own page-aligned virtual range (VirtualAlloc /
 * mmap) and wiped + unmapped the moment execution ends, so its address space
 * ceases to exist once consumed. Plaintext still never materializes (b()
 * decrypts one byte at a time), but even the ciphertext working copy is
 * isolated from both the Java heap and C heap scanners. */
static size_t g_vmpPage = 4096;
static size_t kbox_vmpPage(size_t n) {
    if (g_vmpPage == 0) g_vmpPage = 4096;
    return (n + g_vmpPage - 1) & ~(g_vmpPage - 1);
}
static void kbox_vmpWipe(void* p, size_t n) {
    if (p == NULL || n == 0) return;
    volatile uint8_t* v = (volatile uint8_t*)p;
    while (n--) *v++ = (uint8_t)0;
}
/* Grow-only secure arena. Wave buffers are carved from heap-less, self-mapped
 * pages that are (a) never reachable from Java heap scanners, and (b) reused
 * across executions instead of round-tripping VirtualAlloc/VirtualFree each
 * time (per-call alloc churn caused a ~12x slowdown). Backing pages are only
 * ever released at process exit; plaintext/keystream working copies are wiped
 * on release. Thread-safe via a cross-platform spinlock. */
typedef struct kbox_arena_blk {
    struct kbox_arena_blk* next;
    size_t                 cap;
    size_t                 used;
    uint8_t                data[];
} kbox_arena_blk;

static kbox_arena_blk*  g_blkHead = NULL;
static volatile long    g_arenaLock = 0;

static void kbox_vmpLock(void) {
    while (__sync_val_compare_and_swap(&g_arenaLock, 0, 1) != 0) { /* spin */ }
}
static void kbox_vmpUnlock(void) {
    __atomic_store_n(&g_arenaLock, 0, __ATOMIC_RELEASE);
}

static void* kbox_vmpAlloc(size_t n) {
    size_t cap = kbox_vmpPage(n > 0 ? n : 1);
    kbox_vmpLock();
    void* p = NULL;
    kbox_arena_blk* b = g_blkHead;
    if (b && cap <= b->cap - b->used) {
        p = b->data + b->used;
        b->used += cap;
    } else {
        size_t blkCap = cap;
        if (blkCap < ((size_t)1 << 20)) blkCap = ((size_t)1 << 20); /* 1MiB chunks */
        kbox_arena_blk* nb;
#if defined(_WIN32)
        nb = (kbox_arena_blk*)VirtualAlloc(NULL, sizeof(*nb) + blkCap,
                                             MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
        nb = (kbox_arena_blk*)mmap(NULL, sizeof(*nb) + blkCap,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (nb == MAP_FAILED) nb = NULL;
#endif
        if (nb) {
            nb->next = g_blkHead;
            nb->cap  = blkCap;
            nb->used = cap;
            g_blkHead = nb;
            p = nb->data;
        }
    }
    kbox_vmpUnlock();
    return p;
}
static void kbox_vmpFree(void* p, size_t used) {
    if (p == NULL) return;
    size_t cap = kbox_vmpPage(used > 0 ? used : 1);
    kbox_vmpWipe(p, cap);   /* wipe full page-rounded range */
    kbox_vmpLock();
    kbox_arena_blk* b = g_blkHead;
    if (b && (uint8_t*)p + cap == b->data + b->used) {
        /* last allocation in head block: LIFO rewind for immediate reuse.
         * Backing pages never leave the arena (guest-page swap cost is gone). */
        b->used -= cap;
    }
    kbox_vmpUnlock();
}

/* Per-position decrypted byte: b(pos) == wav[pos] ^ ksEph.at(pos).
 * The working wave (m.resident, per-run ciphertext) is copied ONCE into a
 * page-allocated secure native buffer (kbox_vmpAlloc) and never pinned from
 * the Java heap during the whole execution. The ephemeral keystream is derived
 * from m.ephKey (the 32-byte per-run key stored by the Java side). b() never
 * stores the plaintext — only this byte. */
typedef struct {
    uint8_t*      wav;       /* secure native copy of m.resident (ENCRYPTED) */
    size_t        waveLen;   /* number of bytes present in wav */
    kbox_keystream eph;
} kbox_stream_t;

static int kbox_prepare_stream(JNIEnv* env, jobject m, kbox_stream_t* st){
    st->wav = NULL; st->waveLen = 0;
    jobject resObj = (*env)->GetObjectField(env,m,g_mf.resident);
    if (!resObj) return 0;
    /* m.resident is an OFF-HEAP direct java.nio.ByteBuffer (②). Read it via its
     * native base address — never a Java heap byte[] — and copy into the secure
     * page arena (wiped+unmapped on release). Falls back to a legacy byte[] only
     * in case the field type was ever reverted. */
    void* dbase = (*env)->GetDirectBufferAddress(env, resObj);
    jlong dcap  = (*env)->GetDirectBufferCapacity(env, resObj);
    if (dbase != NULL && dcap > 0) {
        jsize srcLen = (jsize)dcap;
        st->wav = (uint8_t*)kbox_vmpAlloc((size_t)srcLen);
        if (!st->wav){ (*env)->DeleteLocalRef(env, resObj); return 0; }
        st->waveLen = (size_t)srcLen;
        if (srcLen > 0) memcpy(st->wav, dbase, (size_t)srcLen);
        (*env)->DeleteLocalRef(env, resObj);
    } else {
        /* legacy byte[] field fallback (defensive; not used by current build) */
        jbyteArray resArr = (jbyteArray)resObj;
        jsize rLen = (*env)->GetArrayLength(env, resArr);
        if (rLen < 1){ (*env)->DeleteLocalRef(env, resArr); return 0; }
        st->wav = (uint8_t*)kbox_vmpAlloc((size_t)rLen);
        if (!st->wav){ (*env)->DeleteLocalRef(env, resArr); return 0; }
        st->waveLen = (size_t)rLen;
        (*env)->GetByteArrayRegion(env, resArr, 0, rLen, (jbyte*)st->wav);
        (*env)->DeleteLocalRef(env, resArr);
    }
    /* ephemeral key from m.ephKey */
    jbyteArray ephArr = (jbyteArray)(*env)->GetObjectField(env,m,g_mf.ephKey);
    if (ephArr){
        jsize n = (*env)->GetArrayLength(env, ephArr);
        jbyte tmp[64]; int mv = (n>64)?64:n;
        (*env)->GetByteArrayRegion(env, ephArr, 0, mv, tmp);
        kbox_ks_init(&st->eph, (const uint8_t*)tmp, mv);
        (*env)->DeleteLocalRef(env, ephArr);
    } else {
        uint8_t z[32]; memset(z,0,32); kbox_ks_init(&st->eph,z,32);
    }
    return 1;
}

KBOX_INLINE int32_t kbox_b(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    if (pos < 0 || pos >= cipherLen) return 0;
    uint8_t res = (uint8_t)st->wav[pos];
    uint8_t ks  = kbox_ks_at(&st->eph, pos);
    return (int32_t)((res ^ ks) & 0xFF);
}

KBOX_INLINE int32_t kbox_i4(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    return (kbox_b(st,pos,cipherLen)<<24)
         | ((kbox_b(st,pos+1,cipherLen)&0xFF)<<16)
         | ((kbox_b(st,pos+2,cipherLen)&0xFF)<<8)
         | (kbox_b(st,pos+3,cipherLen)&0xFF);
}

KBOX_INLINE int32_t kbox_u2(kbox_stream_t* st, int32_t pos, int32_t cipherLen){
    return ((kbox_b(st,pos,cipherLen)&0xFF)<<8) | (kbox_b(st,pos+1,cipherLen)&0xFF);
}

/* ---- operand stack / locals access ---- */
KBOX_INLINE jobject kbox_pop(JNIEnv* env, kbox_cpu_t* cpu){
    int sp = (int)cpu->cpu[1] - 1;
    cpu->cpu[1] = sp;
    if (sp < 0) { (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/ArithmeticException"),"KBox"); return NULL; }
    return (*env)->GetObjectArrayElement(env, cpu->stack, sp);
}
KBOX_INLINE void kbox_push(JNIEnv* env, kbox_cpu_t* cpu, jobject v){
    int sp = (int)cpu->cpu[1]++;
    (*env)->SetObjectArrayElement(env, cpu->stack, sp, v);
}
KBOX_INLINE jobject kbox_load(JNIEnv* env, kbox_cpu_t* cpu, int idx){
    return (*env)->GetObjectArrayElement(env, cpu->locals, idx);
}
KBOX_INLINE void kbox_store(JNIEnv* env, kbox_cpu_t* cpu, int idx, jobject v){
    (*env)->SetObjectArrayElement(env, cpu->locals, idx, v);
}

/* =====================================================================
 * Object-model helper invocation (delegates to Java; returns 0 on success,
 * -1 means a pending JNI exception should abort the loop).
 * ===================================================================== */

/* The Java helper contract expects the CPU machine state as a long[] [pc,sp,flg]
 * so it can read inline operands (via VmpMethod.i4/u2 on pc) and set the unwind
 * flag. We marshal the C jlong[3] into a real Java long[] for the call and copy
 * it back afterwards. */
static jlongArray kbox_down_cpu(JNIEnv* env, kbox_cpu_t* cpu){
    jlongArray a = (*env)->NewLongArray(env, 3);
    if (!a) return NULL;
    (*env)->SetLongArrayRegion(env, a, 0, 3, cpu->cpu);
    return a;
}

static void kbox_up_cpu(JNIEnv* env, jlongArray a, kbox_cpu_t* cpu){
    if (a) (*env)->GetLongArrayRegion(env, a, 0, 3, cpu->cpu);
    if (a) (*env)->DeleteLocalRef(env, a);
}

/* Invoke a helper with signature (VmpMethod,Object[],Object[],long[])->int, no kind. */
static int kbox_helper4(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st,
                        jobjectArray lo, kbox_cpu_t* cpu){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, lo, c);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],Object[],long[],int)->int */
static int kbox_helper5(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st,
                        jobjectArray lo, kbox_cpu_t* cpu, jint kind){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, lo, c, kind);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],long[])->int */
static int kbox_helperStk(JNIEnv* env, jmethodID mid, jobject m, jobjectArray st, kbox_cpu_t* cpu){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), mid, m, st, c);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* (VmpMethod,Object[],long[],int,int)->int  (array index) */
static int kbox_helperArr(JNIEnv* env, jobject m, jobjectArray st, kbox_cpu_t* cpu, jint gs, jint op){
    jlongArray c = kbox_down_cpu(env, cpu);
    if (!c) return -1;
    (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env), g_ids.h.arrayIndex, m, st, c, gs, op);
    jint pend = (*env)->ExceptionCheck(env);
    kbox_up_cpu(env, c, cpu);
    return pend ? -1 : 0;
}

/* =====================================================================
 * Pure micro-op handlers (native). Each is a switch-case body operating on
 * cpu+stream. Returns 1 to unwind (a *RETURN/END ran and set cpu->cpu[2]).
 * We dispatch through computed-goto (GCC/Clang) or a function-pointer table
 * (MSVC) built from the composite permutation.
 * ===================================================================== */

typedef int (*kbox_handler_t)(kbox_cpu_t* cpu, kbox_stream_t* st);

static int h_ACONST_NULL(kbox_cpu_t* cpu,kbox_stream_t* st){ kbox_push(cpu->env,cpu,NULL); return 0; }
static int h_ICONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t v=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4;
    kbox_push(cpu->env,cpu,kbox_boxInt(cpu->env,v)); return 0;
}
static int h_LCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t hi=kbox_i4(st,(int32_t)cpu->cpu[0]+0,cpu->cipherLen);
    int32_t lo=kbox_i4(st,(int32_t)cpu->cpu[0]+4,cpu->cipherLen);
    cpu->cpu[0]+=8;
    /* Java: ((long)hi<<32) | (i4(pc+4) & 0xFFFFFFFFL) — mask lo so a negative
       low word cannot smear 1s into the high 32 bits. */
    jlong v=((jlong)hi<<32) | ((jlong)lo & 0xFFFFFFFFL);
    kbox_push(cpu->env,cpu,kbox_boxLong(cpu->env,v)); return 0;
}
static int h_FCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t bits=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4;
    jfloat f; memcpy(&f,&bits,4);
    kbox_push(cpu->env,cpu,kbox_boxFloat(cpu->env,f)); return 0;
}
static int h_DCONST(kbox_cpu_t* cpu,kbox_stream_t* st){
    int32_t hi=kbox_i4(st,(int32_t)cpu->cpu[0]+0,cpu->cipherLen);
    int32_t lo=kbox_i4(st,(int32_t)cpu->cpu[0]+4,cpu->cipherLen);
    cpu->cpu[0]+=8;
    /* Java: ((long)hi<<32) | (i4(pc+4) & 0xFFFFFFFFL) — same low-word masking */
    jlong lv=((jlong)hi<<32)|((jlong)lo & 0xFFFFFFFFL); jdouble d; memcpy(&d,&lv,8);
    kbox_push(cpu->env,cpu,kbox_boxDouble(cpu->env,d)); return 0;
}
/* STRING/CLASS -> Java resolve (pushes cp entry) */
static int h_STRING(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helperStk(cpu->env,g_ids.h.resolve,cpu->m,cpu->stack,cpu); /* reads m.i4(pc) itself */
}
static int h_CLASS(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helperStk(cpu->env,g_ids.h.resolve,cpu->m,cpu->stack,cpu);
}

/* ---- loads (copy from locals Object[]) ---- */
#define KBOX_LOAD(kind) static int h_##kind##_LOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=2; \
    kbox_push(cpu->env,cpu,kbox_load(cpu->env,cpu,idx)); return 0; }
KBOX_LOAD(IL) static int h_ILOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_IL_LOAD(cpu,st); }
KBOX_LOAD(LL) /* LLOAD */
KBOX_LOAD(FL) static int h_LLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_LL_LOAD(cpu,st); }
KBOX_LOAD(DL) static int h_FLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DL_LOAD(cpu,st); }
KBOX_LOAD(AL) static int h_ALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_AL_LOAD(cpu,st); }
static int h_DLOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DL_LOAD(cpu,st); }

/* stores */
#define KBOX_STORE(kind) static int h_##kind##_STORE(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=2; \
    jobject v=kbox_pop(cpu->env,cpu); if(!v && (*cpu->env)->ExceptionCheck(cpu->env)) return -1; \
    kbox_store(cpu->env,cpu,idx,v); return 0; }
/* The I/F/D/A store bodies are identical (Object copy), so emit all three via
 * one macro after the IS one is inlined above. */
#define KBOX_STORE_FOR_LL KBOX_STORE(FS) KBOX_STORE(DS) KBOX_STORE(AS)
KBOX_STORE(IS) static int h_ISTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_IS_STORE(cpu,st); }
KBOX_STORE(LS) KBOX_STORE_FOR_LL
static int h_LSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_LS_STORE(cpu,st); }
static int h_FSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_FS_STORE(cpu,st); }
static int h_DSTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_DS_STORE(cpu,st); }
static int h_ASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return h_AS_STORE(cpu,st); }

/* ---- int arithmetic (boxed) ---- */
#define KBOX_IBINOP(name, expr) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1; \
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    jint r=(expr); kbox_push(e,cpu,kbox_boxInt(e,r)); return 0; }
/* IDIV special-cases div-by-zero */
static int h_IDIV(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1;
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai/bi))); return 0;
}
static int h_IREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1;
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai%bi))); return 0;
}
KBOX_IBINOP(IADD, ai+bi)
KBOX_IBINOP(ISUB, ai-bi)
KBOX_IBINOP(IMUL, ai*bi)
KBOX_IBINOP(ISHL, (jint)(ai<<(bi&0x1F)))
KBOX_IBINOP(ISHR, (jint)(ai>>(bi&0x1F)))
KBOX_IBINOP(IUSHR,(jint)((uint32_t)ai>>(bi&0x1F)))
KBOX_IBINOP(IAND, ai&bi)
KBOX_IBINOP(IOR,  ai|bi)
KBOX_IBINOP(IXOR, ai^bi)
static int h_INEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv* e=cpu->env; jobject a=kbox_pop(e,cpu);
    jint ai=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1;
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(-ai))); return 0;
}
static int h_IINC(kbox_cpu_t* cpu,kbox_stream_t* st){
    int idx=kbox_u2(st,(int32_t)cpu->cpu[0],cpu->cipherLen);
    int32_t delta=kbox_i4(st,(int32_t)cpu->cpu[0]+2,cpu->cipherLen);
    cpu->cpu[0]+=6;
    jobject v=kbox_load(cpu->env,cpu,idx);
    jint val=kbox_toIntOrThrow(cpu->env,v); if((*cpu->env)->ExceptionCheck(cpu->env)) return -1;
    kbox_store(cpu->env,cpu,idx,kbox_boxInt(cpu->env,(jint)(val+delta))); return 0;
}

/* ---- conversions (Java casts, matching toInt/toLong/toFloat/toDouble) ---- */
#define KBOX_CONV(name, get, box, cast) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject a=kbox_pop(e,cpu); \
    jvalue v=get(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    kbox_push(e,cpu, box(e,(cast)v)); return 0; }
/* handled explicitly below to keep types right */
static int h_I2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_I2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_I2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_L2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_L2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_L2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_F2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_F2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_F2D(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)v)); return 0; }
static int h_D2I(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)v)); return 0; }
static int h_D2L(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxLong(e,(jlong)v)); return 0; }
static int h_D2F(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)v)); return 0; }
static int h_I2B(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jbyte)v)); return 0; }
static int h_I2C(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jchar)v)); return 0; }
static int h_I2S(kbox_cpu_t* cpu,kbox_stream_t* st){ JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; kbox_push(e,cpu,kbox_boxInt(e,(jint)(jshort)v)); return 0; }

/* ---- long arithmetic ---- */
#define KBOX_LBINOP(name, expr) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv* e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e)) return -1; \
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e)) return -1; \
    kbox_push(e,cpu,kbox_boxLong(e,(expr))); return 0; }
KBOX_LBINOP(LADD, ai+bi) KBOX_LBINOP(LSUB, ai-bi) KBOX_LBINOP(LMUL, ai*bi)
KBOX_LBINOP(LAND, ai&bi) KBOX_LBINOP(LOR, ai|bi) KBOX_LBINOP(LXOR, ai^bi)
static int h_LDIV(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxLong(e,(ai/bi))); return 0;
}
static int h_LREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    if (bi==0){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArithmeticException"),"/ by zero"); return -1; }
    kbox_push(e,cpu,kbox_boxLong(e,(ai%bi))); return 0;
}
static int h_LNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jlong v=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,(jlong)(-v))); return 0;
}
#define KBOX_LSHIFT(name, opshift) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxLong(e,(ai opshift (bi&0x3F)))); return 0; }
KBOX_LSHIFT(LSHL, <<) KBOX_LSHIFT(LSHR, >>)
static int h_LUSHR(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jint bi=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,(jlong)((uint64_t)ai>>(bi&0x3F)))); return 0;
}
static int h_LCMP(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jlong bi=kbox_toLongOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jlong ai=kbox_toLongOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxInt(e,(jint)(ai==bi?0:(ai<bi?-1:1)))); return 0;
}

/* ---- float/double arithmetic ---- */
#define KBOX_FBINOP(name, op, cast) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    cast v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    cast v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxFloat(e,(v1 op v2))); return 0; }
KBOX_FBINOP(FADD,+,jfloat) KBOX_FBINOP(FSUB,-,jfloat) KBOX_FBINOP(FMUL,*,jfloat) KBOX_FBINOP(FDIV,/,jfloat)
static int h_FREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,(float)fmod(v1,v2))); return 0;
}
static int h_FNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jfloat v=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,(jfloat)(-v))); return 0;
}
/* Replicate Java Float.compare / Double.compare exactly. */
static uint32_t kbox_fToBits(jfloat f){
    uint32_t b; memcpy(&b,&f,4);
    if (isnan(f)) b = 0x7fc00000u;
    return b;
}
static jint kbox_fcompare(jfloat f1, jfloat f2){
    if (f1 < f2) return -1;
    if (f1 > f2) return 1;
    int32_t b1=(int32_t)kbox_fToBits(f1), b2=(int32_t)kbox_fToBits(f2);
    return (b1 == b2) ? 0 : ((b1 < b2) ? -1 : 1);
}
static uint64_t kbox_dToBits(jdouble d){
    uint64_t b; memcpy(&b,&d,8);
    if (isnan(d)) b = 0x7ff8000000000000ULL;
    return b;
}
static jint kbox_dcompare(jdouble d1, jdouble d2){
    if (d1 < d2) return -1;
    if (d1 > d2) return 1;
    int64_t b1=(int64_t)kbox_dToBits(d1), b2=(int64_t)kbox_dToBits(d2);
    return (b1 == b2) ? 0 : ((b1 < b2) ? -1 : 1);
}
static int h_FCMPL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (isnan(v1)||isnan(v2)) r=-1; else if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* fcmpl: NaN->-1, +-0.0->0 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
static int h_FCMPG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jfloat v1=kbox_toFloatOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jfloat v2=kbox_toFloatOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* fcmpg: NaN falls through to +1 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
#define KBOX_DBINOP(name, op) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1; \
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1; \
    kbox_push(e,cpu,kbox_boxDouble(e,(v1 op v2))); return 0; }
KBOX_DBINOP(DADD,+) KBOX_DBINOP(DSUB,-) KBOX_DBINOP(DMUL,*) KBOX_DBINOP(DDIV,/)
static int h_DREM(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,(double)fmod(v1,v2))); return 0;
}
static int h_DNEG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject a=kbox_pop(e,cpu);
    jdouble v=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,(jdouble)(-v))); return 0;
}
static int h_DCMPL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (isnan(v1)||isnan(v2)) r=-1; else if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* dcmpl: NaN->-1, +-0.0->0 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}
static int h_DCMPG(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu);
    jdouble v1=kbox_toDoubleOrThrow(e,a); if((*e)->ExceptionCheck(e))return-1;
    jdouble v2=kbox_toDoubleOrThrow(e,b); if((*e)->ExceptionCheck(e))return-1;
    jint r; if (v1==v2) r=0; else if (v1<v2) r=-1; else r=1; /* dcmpg: NaN falls through to +1 */
    kbox_push(e,cpu,kbox_boxInt(e,r)); return 0;
}

/* ---- branches ---- */
#define KBOX_IFZOP(name, cond) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject a=kbox_pop(e,cpu); jint v=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return -1; \
    if (cond) cpu->cpu[0]=t; return 0; }
KBOX_IFZOP(IFEQ, v==0) KBOX_IFZOP(IFNE, v!=0) KBOX_IFZOP(IFLT, v<0)
KBOX_IFZOP(IFGE, v>=0) KBOX_IFZOP(IFGT, v>0) KBOX_IFZOP(IFLE, v<=0)
#define KBOX_IFICMP(name, cond) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    jint v1=kbox_toIntOrThrow(e,a); if((*e)->ExceptionCheck(e))return -1; \
    jint v2=kbox_toIntOrThrow(e,b); if((*e)->ExceptionCheck(e))return -1; \
    if (v1 cond v2) cpu->cpu[0]=t; return 0; }
KBOX_IFICMP(IF_ICMPEQ,==) KBOX_IFICMP(IF_ICMPNE,!=) KBOX_IFICMP(IF_ICMPLT,<)
KBOX_IFICMP(IF_ICMPGE,>=) KBOX_IFICMP(IF_ICMPGT,>) KBOX_IFICMP(IF_ICMPLE,<=)
#define KBOX_IFACMP(name, eq) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject b=kbox_pop(e,cpu); jobject a=kbox_pop(e,cpu); \
    if ((eq)) cpu->cpu[0]=t; return 0; }
KBOX_IFACMP(IF_ACMPEQ, a==b) KBOX_IFACMP(IF_ACMPNE, a!=b)
#define KBOX_IFACZ(name, nn) static int h_##name(kbox_cpu_t* cpu,kbox_stream_t* st){ \
    JNIEnv*e=cpu->env; int32_t t=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); cpu->cpu[0]+=4; \
    jobject a=kbox_pop(e,cpu); if ((nn)) cpu->cpu[0]=t; return 0; }
KBOX_IFACZ(IFNULL, a==NULL) KBOX_IFACZ(IFNONNULL, a!=NULL)
static int h_GOTO(kbox_cpu_t* cpu,kbox_stream_t* st){
    cpu->cpu[0]=kbox_i4(st,(int32_t)cpu->cpu[0],cpu->cipherLen); return 0;
}

/* ---- stack manipulation ---- */
static int h_POP(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[1]-=1; return 0; }
static int h_POP2(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[1]-=2; return 0; }
static int h_DUP(kbox_cpu_t* cpu,kbox_stream_t* st){
    int sp=(int)cpu->cpu[1]; jobject v=(*cpu->env)->GetObjectArrayElement(cpu->env,cpu->stack,sp-1);
    (*cpu->env)->SetObjectArrayElement(cpu->env,cpu->stack,sp,v); cpu->cpu[1]+=1; return 0;
}
static int h_DUP_X1(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    cpu->cpu[1]+=1; return 0;
}
static int h_DUP_X2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v1);
    cpu->cpu[1]+=1; return 0;
}
static int h_DUP2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v2);
    cpu->cpu[1]+=2; return 0;
}
static int h_DUP2_X1(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v2);
    cpu->cpu[1]+=2; return 0;
}
/* DUP2_X2 (JVMS 6.5): ..., v4, v3, v2, v1 -> ..., v2, v1, v4, v3, v2, v1.
 * Single-slot model collapses all four forms to this 4-slot rotation; must
 * stay byte-identical with VmpInterpreter.OP_HANDLER[0xCD] and the JNIC v3
 * interpreter (kbox_jnic_interp_v3.c DUP2_X2). */
static int h_DUP2_X2(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    jobject v3=(*e)->GetObjectArrayElement(e,cpu->stack,sp-3);
    jobject v4=(*e)->GetObjectArrayElement(e,cpu->stack,sp-4);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-4,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-3,v1);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v4);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v3);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp+1,v1);
    cpu->cpu[1]+=2; return 0;
}
static int h_SWAP(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; int sp=(int)cpu->cpu[1];
    jobject v1=(*e)->GetObjectArrayElement(e,cpu->stack,sp-1);
    jobject v2=(*e)->GetObjectArrayElement(e,cpu->stack,sp-2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-1,v2);
    (*e)->SetObjectArrayElement(e,cpu->stack,sp-2,v1);
    return 0;
}

/* ---- field access -> Java ---- */
static int h_GETSTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.getStatic,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_PUTSTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.putStatic,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_GETFIELD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.getField,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_PUTFIELD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.putField,cpu->m,cpu->stack,cpu->locals,cpu); }

/* ---- invocation -> Java ---- */
static int h_INVOKEVIRTUAL(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_INVOKESPECIAL(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_INVOKESTATIC(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,2); }
static int h_INVOKEINTERFACE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.invoke,cpu->m,cpu->stack,cpu->locals,cpu,3); }

/* ---- type / new / arrays -> Java ---- */
static int h_NEW(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.new_,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_NEWARRAY(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.newArray,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_ANEWARRAY(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.newArray,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_ARRAYLENGTH(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,0); }
static int h_AALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,1); }
static int h_AASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,1); }
static int h_IALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,2); }
static int h_IASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,2); }
static int h_BALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,3); }
static int h_BASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,3); }
static int h_CALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,4); }
static int h_CASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,4); }
static int h_SALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,0,5); }
static int h_SASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helperArr(cpu->env,cpu->m,cpu->stack,cpu,1,5); }
/* LALOAD/FALOAD/DALOAD/LASTORE/FASTORE/DASTORE — native, mirror Java's
 * Array.getLong/getFloat/getDouble/setLong/setFloat/setDouble semantics
 * (NPE on null array, ArrayIndexOutOfBoundsException on bad index). */
static int h_LALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jlong v=0; (*e)->GetLongArrayRegion(e,(jlongArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxLong(e,v)); return 0;
}
static int h_FALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jfloat v=0; (*e)->GetFloatArrayRegion(e,(jfloatArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxFloat(e,v)); return 0;
}
static int h_DALOAD(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    jdouble v=0; (*e)->GetDoubleArrayRegion(e,(jdoubleArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    kbox_push(e,cpu,kbox_boxDouble(e,v)); return 0;
}
static int h_LASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jlong v=kbox_toLongOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetLongArrayRegion(e,(jlongArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_FASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jfloat v=kbox_toFloatOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetFloatArrayRegion(e,(jfloatArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_DASTORE(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env; jobject bj=kbox_pop(e,cpu); jdouble v=kbox_toDoubleOrThrow(e,bj); if((*e)->ExceptionCheck(e))return-1;
    jobject idx=kbox_pop(e,cpu); jint i=kbox_toIntOrThrow(e,idx); if((*e)->ExceptionCheck(e))return-1;
    jobject a=kbox_pop(e,cpu);
    if(!a){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/NullPointerException"),"KBox"); return -1; }
    jint len=(*e)->GetArrayLength(e,(jarray)a);
    if(i<0||i>=len){ (*e)->ThrowNew(e,(*e)->FindClass(e,"java/lang/ArrayIndexOutOfBoundsException"),"KBox"); return -1; }
    (*e)->SetDoubleArrayRegion(e,(jdoubleArray)a,i,1,&v);
    if((*e)->ExceptionCheck(e))return-1;
    return 0;
}
static int h_CHECKCAST(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.checkCast,cpu->m,cpu->stack,cpu->locals,cpu); }
static int h_INSTANCEOF(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper4(cpu->env,g_ids.h.instanceOf,cpu->m,cpu->stack,cpu->locals,cpu); }

/* ---- monitor -> Java (throws) ---- */
static int h_MONITORENTER(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_MONITOREXIT(kbox_cpu_t* cpu,kbox_stream_t* st){ return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,1); }
/* ---- athrow -> Java (throws; must consult exception table) --- */
static int h_ATHROW(kbox_cpu_t* cpu,kbox_stream_t* st){
    return kbox_helper5(cpu->env,g_ids.h.monitor,cpu->m,cpu->stack,cpu->locals,cpu,2); /* kind=2 => athrow */
}

/* ---- returns -> Java boxes result, sets cpu[2]=1 ---- */
static int h_IRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=0; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,0); }
static int h_LRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=1; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,1); }
static int h_FRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=2; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,2); }
static int h_DRETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=3; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,3); }
static int h_ARETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=4; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,4); }
static int h_RETURN(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->retKind=5; return kbox_helper5(cpu->env,g_ids.h.ret,cpu->m,cpu->stack,cpu->locals,cpu,5); }
/* Illegal/unknown opcode -> fail-closed, mirroring the Java interpreter's
 * VmpInterpreter.execute(): `if (h == null) throw new RuntimeException("KBox")`.
 * Raising the generic KBox and returning -1 lets the dispatch loop's exception
 * path consult THIS method's exception table exactly like Java (a catch-all may
 * still handle it; otherwise it propagates as a generic KBox failure). The real
 * opcode is never disclosed. */
static int h_ILLEGAL(kbox_cpu_t* cpu,kbox_stream_t* st){
    JNIEnv*e=cpu->env;
    jclass rte=(*e)->FindClass(e,"java/lang/RuntimeException");
    if (rte){ (*e)->ThrowNew(e,rte,"KBox"); (*e)->DeleteLocalRef(e,rte); }
    return -1;
}
static int h_END(kbox_cpu_t* cpu,kbox_stream_t* st){ cpu->cpu[2]=1; return 1; }
/* NOP (VortexVM/L2 interleave filler, real VmpOp 0x45). The dispatch loop has
 * already advanced pc past this 1-byte opcode (opcode fetch advances pc+1 and
 * pure no-operand ops never touch pc again), so this is a pure no-op — the
 * exact counterpart of the Java interpreter's OP_HANDLER[0x45] = c -> false.
 * Its only purpose is proportional anti-analysis run-cost: an interleaved
 * globally-unpredictable number of no-ops per translated VM instruction. */
static int h_NOP(kbox_cpu_t* cpu,kbox_stream_t* st){ (void)cpu; (void)st; return 0; }

/* =====================================================================
 * Dispatch. Opaque pointer table indexed by handler SLOT (0..255). Slot is
 * the output of composite[twin ^ raw]; the real VmpOp is never formed.
 * ===================================================================== */

#if KBOX_ATT_DISP
/* computed-goto friendly default: use a table + switch dispatcher (portable) */
#define KBOX_DISP_TABLE 1
#endif

static const kbox_handler_t* g_handler_table = NULL;
static kbox_handler_t        g_handler_store[256];
static int                   g_handler_init = 0;

/* The handler table is keyed by REAL VmpOp; slot->handler is chosen by the
 * Java composite/microPerm. To keep the C table coincident with the Java
 * handlers[micro[op]] layout we simply fill by opcode; the SLOT value from
 * composite[twin^raw] equals micro[realOp], and we map slot -> handler by
 * inversing: handlerForSlot = table[invMicro[slotLower]]... To be robust we
 * derive the mapping purely in native from composite by NOT inverting; instead
 * the interpreter computes the REAL op from invPerm and looks up OP_HANDLER.
 *
 * IMPORTANT: to guarantee opcode semantic == Java semantic we decode the REAL
 * op (op = invPerm[twin ^ raw]) — matching Java's micro[real] slot ONLY maps
 * to a handler SLOT, but the C code here is keyed by real op. Both agree on
 * semantics; the native side materializes `op` transiently (single byte, wiped
 * at end of iteration) which is the same transient exposure Java has on its
 * error path. This is the pragmatic correctness-first choice; a pure slot-
 * dispatch variant can replace the table indirection later.
 */

static void kbox_init_handlers(void){
    if (g_handler_init) return;
    kbox_handler_t* T = g_handler_store;
    for (int i=0;i<256;i++) T[i]=h_ILLEGAL;   /* default: fail-closed (mirrors Java's null-slot "KBox") */
    T[0x01]=h_ACONST_NULL; T[0x02]=h_ICONST; T[0x03]=h_LCONST; T[0x04]=h_FCONST;
    T[0x05]=h_DCONST;      T[0x06]=h_STRING; T[0x07]=h_CLASS;
    T[0x10]=h_ILOAD; T[0x11]=h_LLOAD; T[0x12]=h_FLOAD; T[0x13]=h_DLOAD; T[0x14]=h_ALOAD;
    T[0x18]=h_ISTORE; T[0x19]=h_LSTORE; T[0x1A]=h_FSTORE; T[0x1B]=h_DSTORE; T[0x1C]=h_ASTORE;
    T[0x20]=h_IADD; T[0x21]=h_ISUB; T[0x22]=h_IMUL; T[0x23]=h_IDIV; T[0x24]=h_IREM;
    T[0x25]=h_INEG; T[0x26]=h_ISHL; T[0x27]=h_ISHR; T[0x28]=h_IUSHR;
    T[0x29]=h_IAND; T[0x2A]=h_IOR; T[0x2B]=h_IXOR; T[0x2C]=h_IINC;
    T[0x2D]=h_I2L; T[0x2E]=h_I2F; T[0x2F]=h_I2D;
    T[0xA0]=h_L2I; T[0xA1]=h_L2F; T[0xA2]=h_L2D;
    T[0xA3]=h_F2I; T[0xA4]=h_F2L; T[0xA5]=h_F2D;
    T[0xA6]=h_D2I; T[0xA7]=h_D2L; T[0xA8]=h_D2F;
    T[0xA9]=h_I2B; T[0xAA]=h_I2C; T[0xAB]=h_I2S;
    T[0xAC]=h_LCMP; T[0xAD]=h_LADD; T[0xAE]=h_LSUB; T[0xAF]=h_LMUL;
    T[0xB0]=h_LDIV; T[0xB1]=h_LREM; T[0xB2]=h_LNEG;
    T[0xB3]=h_LSHL; T[0xB4]=h_LSHR; T[0xB5]=h_LUSHR;
    T[0xB6]=h_LAND; T[0xB7]=h_LOR; T[0xB8]=h_LXOR;
    T[0xB9]=h_FADD; T[0xBA]=h_FSUB; T[0xBB]=h_FMUL; T[0xBC]=h_FDIV;
    T[0xBD]=h_FREM; T[0xBE]=h_FNEG;
    T[0xBF]=h_DADD; T[0xC0]=h_DSUB; T[0xC1]=h_DMUL; T[0xC2]=h_DDIV;
    T[0xC3]=h_DREM; T[0xC4]=h_DNEG;
    T[0xC5]=h_FCMPL; T[0xC6]=h_FCMPG; T[0xC7]=h_DCMPL; T[0xC8]=h_DCMPG;
    T[0x30]=h_IFEQ; T[0x31]=h_IFNE; T[0x32]=h_IFLT; T[0x33]=h_IFGE;
    T[0x34]=h_IFGT; T[0x35]=h_IFLE;
    T[0x36]=h_IF_ICMPEQ; T[0x37]=h_IF_ICMPNE; T[0x38]=h_IF_ICMPLT;
    T[0x39]=h_IF_ICMPGE; T[0x3A]=h_IF_ICMPGT; T[0x3B]=h_IF_ICMPLE;
    T[0x3C]=h_IFNULL; T[0x3D]=h_IFNONNULL;
    T[0x3E]=h_GOTO; T[0x3F]=h_IF_ACMPEQ; T[0xC9]=h_IF_ACMPNE;
    T[0x40]=h_POP; T[0x41]=h_POP2; T[0x42]=h_DUP; T[0x43]=h_DUP_X1;
    T[0xCA]=h_DUP_X2; T[0xCB]=h_DUP2; T[0xCC]=h_DUP2_X1; T[0xCD]=h_DUP2_X2; T[0x44]=h_SWAP;
    T[0x45]=h_NOP;   /* VortexVM/L2 interleave filler (no-op) */
    T[0x50]=h_GETSTATIC; T[0x51]=h_PUTSTATIC; T[0x52]=h_GETFIELD; T[0x53]=h_PUTFIELD;
    T[0x60]=h_INVOKEVIRTUAL; T[0x61]=h_INVOKESPECIAL; T[0x62]=h_INVOKESTATIC; T[0x63]=h_INVOKEINTERFACE;
    T[0x70]=h_NEW; T[0x71]=h_NEWARRAY; T[0x72]=h_ANEWARRAY; T[0x73]=h_ARRAYLENGTH;
    T[0x74]=h_AALOAD; T[0x75]=h_AASTORE; T[0x76]=h_IALOAD; T[0x77]=h_IASTORE;
    T[0x7A]=h_BALOAD; T[0x7B]=h_BASTORE; T[0x7C]=h_CALOAD; T[0x7D]=h_CASTORE;
    T[0x7E]=h_SALOAD; T[0x7F]=h_SASTORE;
    T[0x83]=h_LALOAD; T[0x84]=h_FALOAD; T[0x85]=h_DALOAD;
    T[0x86]=h_LASTORE; T[0x87]=h_FASTORE; T[0x88]=h_DASTORE;
    T[0x78]=h_CHECKCAST; T[0x79]=h_INSTANCEOF;
    T[0x80]=h_MONITORENTER; T[0x81]=h_MONITOREXIT; T[0x82]=h_ATHROW;
    T[0x90]=h_IRETURN; T[0x91]=h_LRETURN; T[0x92]=h_FRETURN; T[0x93]=h_DRETURN;
    T[0x94]=h_ARETURN; T[0x95]=h_RETURN;
    T[0xFF]=h_END;
    g_handler_init = 1;
}

/* =====================================================================
 * Public entry point — must mirror VmpInterpreterNative stage-1 bridge:
 *   static native Object execute(VmpMethod m, Object instance, Object[] args)
 * ===================================================================== */

JNIEXPORT jobject JNICALL Java_com_kbox_runtime_VmpInterpreterNative_execute(
        JNIEnv* env, jclass self, jobject m, jobject instance, jobjectArray args){
    kbox_resolve_ids(env);
    kbox_load_mfield(env);
    kbox_init_handlers();

    if (!g_ids_init || !g_mf_init){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"),
            "KBox");
        return NULL;
    }

    /* ---- create operand stack & locals arrays ---- */
    jint maxStack  = (*env)->GetIntField(env, m, g_mf.maxStack);
    jint maxLocals = (*env)->GetIntField(env, m, g_mf.maxLocals);
    jclass objCls = (*env)->FindClass(env, "java/lang/Object");

    jobjectArray stack  = (*env)->NewObjectArray(env, maxStack + 16, objCls, NULL);
    jobjectArray locals = (*env)->NewObjectArray(env, maxLocals, objCls, NULL);
    if (stack==NULL || locals==NULL) return NULL;
    (*env)->DeleteLocalRef(env, objCls);

    /* ---- load locals: instance first, then args ---- */
    int li = 0;
    if (instance != NULL){
        (*env)->SetObjectArrayElement(env, locals, li++, instance);
    }
    if (args != NULL){
        jsize na = (*env)->GetArrayLength(env, args);
        for (jsize i=0;i<na;i++){
            jobject a = (*env)->GetObjectArrayElement(env, args, i);
            (*env)->SetObjectArrayElement(env, locals, li++, a);
            (*env)->DeleteLocalRef(env, a);
        }
    }

    /* ---- CPU frame ---- */
    kbox_cpu_t cpu; memset(&cpu,0,sizeof(cpu));
    cpu.env = env; cpu.m = m;
    cpu.stack = stack; cpu.locals = locals;
    cpu.cpu[0]=0; cpu.cpu[1]=0; cpu.cpu[2]=0;   /* pc=0; operand-stack sp EMPTY (locals separate) */
    cpu.maxStack = maxStack; cpu.maxLocals = maxLocals;
    cpu.twin = (*env)->GetIntField(env, m, g_mf.twin);
    cpu.cipherLen = (*env)->GetIntField(env, m, g_mf.cipherLen);

    /* ---- stream (resident + eph keystream) ---- */
    kbox_stream_t st; memset(&st,0,sizeof(st));
    if (!kbox_prepare_stream(env, m, &st)){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"),
            "KBox");
        return NULL;
    }

    /* ---- composite array copy (plain ints) ---- */
    jintArray composite = (jintArray)(*env)->GetObjectField(env, m, g_mf.composite);
    jint compositeEls[256];
    if (composite){
        jint* ptr = (*env)->GetIntArrayElements(env, composite, NULL);
        jsize n = (*env)->GetArrayLength(env, composite);
        if (n>256) n=256;
        memcpy(compositeEls, ptr, (size_t)n*sizeof(jint));
        if (n<256) for (jsize k=n;k<256;k++) compositeEls[k]=(jint)k;
        (*env)->ReleaseIntArrayElements(env, composite, ptr, JNI_ABORT);
        (*env)->DeleteLocalRef(env, composite);
    } else {
        for (int k=0;k<256;k++) compositeEls[k]=(jint)k;
    }
    /* ---- invPerm copy (plain ints) ---- */
    jintArray invPermArr = (jintArray)(*env)->GetObjectField(env, m, g_mf.invPerm);
    jint invPermEls[256];
    if (invPermArr){
        jint* ptr = (*env)->GetIntArrayElements(env, invPermArr, NULL);
        jsize n = (*env)->GetArrayLength(env, invPermArr);
        if (n>256) n=256;
        memcpy(invPermEls, ptr, (size_t)n*sizeof(jint));
        if (n<256) for (jsize k=n;k<256;k++) invPermEls[k]=(jint)k;
        (*env)->ReleaseIntArrayElements(env, invPermArr, ptr, JNI_ABORT);
        (*env)->DeleteLocalRef(env, invPermArr);
    } else {
        for (int k=0;k<256;k++) invPermEls[k]=(jint)k;
    }

    /* Build the native handler table indexed by dispatch SLOT, replicating
     * Java's `m.handlers` layout:
     *   Java: handlers[micro[op]]         = OP_HANDLER[op]
     *         slot = composite[twin^raw]  = micro[inv[twin^raw]]
     *   C  :  for t in 0..255:            realOp = invPerm[t]
     *         T2[composite[t]]            = g_handler_store[realOp]
     * So dispatch slot = composite[twin^raw]:
     *   T2[slot] = g_handler_store[invPerm[twin^raw]]  matches Java EXACTLY,
     * and the real VmpOp is never materialized (slot-only dispatch, same as Java).
     * composite and invPerm are both permutations, so every slot 0..255 is set. */
    kbox_handler_t slotTable[256];
    for (int i=0;i<256;i++) slotTable[i]=h_ILLEGAL;
    for (int t=0;t<256;t++){
        int slot = compositeEls[t];
        if (slot>=0 && slot<256) slotTable[slot] = g_handler_store[invPermEls[t] & 0xFF];
    }

    /* dispatch: slot = composite[twin ^ raw]; run slotTable[slot]. Neither the
     * real VmpOp nor the micro-slot is held longer than one iteration.
     * Robustness closure: a step cap (bounded well above any legit run) turns a
     * tampered/runaway jump loop into a generic failure instead of an unbounded
     * busy-spin (DoS), so no crafted ciphertext can hang the process. */
    int64_t steps = 0;
    const int64_t VMP_MAX_STEPS = ((int64_t)1 << 31);
    int rc = 0;
    for (;;){
        if ((*env)->ExceptionCheck(env)){ rc=-1; break; }
        if (++steps > VMP_MAX_STEPS){
            rc = -2; break;                       /* runaway loop -> generic fail */
        }
        int32_t pc = (int32_t)cpu.cpu[0];
        if (pc < 0 || pc >= cpu.cipherLen) break;             /* END / past end */
        int raw = kbox_b(&st, pc, cpu.cipherLen);
        cpu.cpu[0] = pc + 1;                                   /* advance past opcode */
        int combo = compositeEls[(cpu.twin ^ raw) & 0xFF];
        kbox_handler_t h = slotTable[combo & 0xFF];
        int r = h(&cpu, &st);
        if (r < 0 && (*env)->ExceptionCheck(env)){
            /* Closed-state-machine exception handling: a helper surfaced a JNI
             * exception (an invoked callee threw, athrow, a coercing helper, ...).
             * Before unwinding, consult THIS method's exception table — if opcode
             * pc is covered and the catch type matches, clear the pending JNI
             * exception, push the (unwrapped) exception and jump to the handler,
             * exactly like the Java-fallback interpreter's post-dispatch catch.
             * If no local handler matches, re-raise the original exception so the
             * invoking context (or the JVM) sees it. */
            jobject exc = (*env)->ExceptionOccurred(env);
            (*env)->ExceptionClear(env);
            jint handled = 0;
            jlongArray c = kbox_down_cpu(env, &cpu);
            if (c){
                handled = (*env)->CallStaticIntMethod(env, kbox_find_interp_class(env),
                                g_ids.h.tryCatch, m, stack, c, exc, (jint)pc);
                kbox_up_cpu(env, c, &cpu);
                (*env)->DeleteLocalRef(env, c);
                if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
            }
            if (handled == 1){
                if (exc) (*env)->DeleteLocalRef(env, exc);
                continue;                          /* resume dispatch at handler pc */
            }
            if (exc){ (*env)->Throw(env, exc); (*env)->DeleteLocalRef(env, exc); }
            rc = -1; break;                        /* pending exception rethrown by JVM */
        }
        if (r < 0){ rc=-1; break; }                            /* exception propagated */
        if (r == 1) break;                                     /* END unwound */
        if (cpu.cpu[2]) break;                                 /* RETURN/ATHROW-unwind set by Java helper */
    }

    /* ---- release stream: wipe + unmap the secure wave buffer ---- */
    if (st.wav){ kbox_vmpFree(st.wav, st.waveLen); st.wav = NULL; st.waveLen = 0; }

    if (rc == -2){
        (*env)->ThrowNew(env, (*env)->FindClass(env,"java/lang/RuntimeException"), "KBox");
    }
    if (rc != 0){
        (*env)->DeleteLocalRef(env, stack);
        (*env)->DeleteLocalRef(env, locals);
        return NULL;                                          /* pending JNI exception rethrown by JVM */
    }

    /* Result is at the top of the operand stack (nlReturn left it there and set
     * cpu[2]=1). A void RETURN (retKind==5) produces no value. */
    jobject ret = NULL;
    if (cpu.cpu[2] && cpu.retKind != 5 && cpu.cpu[1] > 0){
        ret = (*env)->GetObjectArrayElement(env, stack, (jsize)(cpu.cpu[1]-1));
    }
    jobject global = (*env)->NewGlobalRef(env, ret);          /* survive DeleteLocalRef of stack */
    (*env)->DeleteLocalRef(env, stack);
    (*env)->DeleteLocalRef(env, locals);
    (*env)->DeleteLocalRef(env, self);
    return global;                                            /* caller releases via DeleteLocalRef in Java bridge */
}

/* =====================================================================
 * Explicit native binding for cross-ClassLoader execution.
 *
 * VmpInterpreterNative lives inside the BfSecureLoader blob, i.e. it is
 * defined by a child ClassLoader. Automatic JNI symbol resolution for such a
 * class only consults that child's library list, which -- because the VMP DLL
 * is loaded by System.load from NativeLoader (a parent-loader class) -- does
 * NOT contain the DLL, so execute() would never resolve. RegisterNatives with
 * the exact Class object binds the function regardless of which loader defined
 * the class. Called by VmpInterpreterNative.tryExecute() once, right after
 * loadVmp() succeeds, passing VmpInterpreterNative.class.
 * ===================================================================== */
JNIEXPORT void JNICALL Java_com_kbox_runtime_NativeLoader_registerVmpNatives0
    (JNIEnv* env, jclass loaderClass, jclass targetClass){
    (void)loaderClass;
    if (targetClass == NULL) return;
    JNINativeMethod nm;
    nm.name = "execute";
    nm.signature =
        "(Lcom/kbox/runtime/VmpInterpreter$VmpMethod;Ljava/lang/Object;"
        "[Ljava/lang/Object;)Ljava/lang/Object;";
    nm.fnPtr = (void*)Java_com_kbox_runtime_VmpInterpreterNative_execute;
    if ((*env)->RegisterNatives(env, targetClass, &nm, 1) != 0){
        /* Clear any exception; tryExecute will then observe UnsatisfiedLinkError
         * on the real call and degrade to the Java interpreter. */
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    }
}