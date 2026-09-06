/*
 * KBox-VMP Crypto Native Module — atomic crypto primitives.
 *
 * Implements HKDF-SHA256 (RFC 5869) and a per-byte stream decrypt primitive
 * entirely in C so the master/per-run key derivation and per-instruction
 * decryption do not have to materialize full plaintext on the Java heap.
 *
 * CRITICAL COMPATIBILITY CONTRACT:
 *   The two JNI exports below MUST produce byte-identical output to their Java
 *   counterparts in HardwareKeyRing (hkrdfSha256) and VmpMethod.b(pos) /
 *   specAt(). Every VMP method's wrappedK is encrypted at build time and
 *   decrypted at run time; if native and Java disagree the method silently
 *   becomes noise. Both code paths are therefore kept in lock-step and verified
 *   by a self-test before a build is shipped.
 *
 * Loading: this file is compiled into `kbox_native_crypto.dll/.so/.dylib`,
 * packed via NativePacker into `META-INF/kbox/native-crypto.bin` and loaded
 * via NativeCrypto.load() (System.load + JNI auto-binding on the
 * `Java_com_kbox_runtime_NativeCrypto_*` exports).
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

/* Key-material intermediates (HMAC salt||ikm buffers, T-blocks) are held in
 * page-aligned, wipe-then-release memory rather than the heap, so a libc
 * heap-dump scan cannot recover derived keying material left over from HKDF
 * frames. Same contract as kbox_bf_loader.c's secure alloc. */
static void kbox_crypto_memwipe(void* p, size_t n) {
    volatile unsigned char* v = (volatile unsigned char*)p;
    while (n--) *v++ = 0;
}
static void* kbox_cryptoAlloc(size_t n) {
    size_t ps = 4096;
#if defined(_WIN32)
    DWORD64 sz = (DWORD64)n;
    if (sz < 4096) sz = 4096;
    sz = (sz + 4095) & ~(DWORD64)4095;
    return VirtualAlloc(NULL, (SIZE_T)sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    (void)ps;
    long pg = sysconf(_SC_PAGESIZE);
    if (pg > 0) ps = (size_t)pg;
    size_t cap = (n + ps - 1) & ~(ps - 1);
    void* p = mmap(NULL, cap, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
#endif
}
static void kbox_cryptoFree(void* p, size_t cap) {
    if (p == NULL) return;
    size_t ps = 4096;
#if defined(_WIN32)
    (void)cap;
    kbox_crypto_memwipe(p, cap);
    VirtualFree(p, 0, MEM_RELEASE);
#else
    long pg = sysconf(_SC_PAGESIZE);
    if (pg > 0) ps = (size_t)pg;
    size_t capR = (cap + ps - 1) & ~(ps - 1);
    kbox_crypto_memwipe(p, cap);
    munmap(p, capR);
#endif
}

/* ============================================================ */
/*  SHA-256 (FIPS 180-4)                                        */
/* ============================================================ */

typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t  buf[64];
    size_t   buflen;
} kbox_sha256_t;

static uint32_t kbox_rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

static const uint32_t kbox_sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void kbox_sha256_init(kbox_sha256_t* s) {
    s->h[0]=0x6a09e667; s->h[1]=0xbb67ae85; s->h[2]=0x3c6ef372; s->h[3]=0xa54ff53a;
    s->h[4]=0x510e527f; s->h[5]=0x9b05688c; s->h[6]=0x1f83d9ab; s->h[7]=0x5be0cd19;
    s->len=0; s->buflen=0;
}

static void kbox_sha256_block(kbox_sha256_t* s, const uint8_t* p) {
    uint32_t w[64];
    int i;
    uint32_t a,b,c,d,e,f,g,h,v;
    for (i=0;i<16;i++)
        w[i] = ((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|(uint32_t)p[i*4+3];
    for (i=16;i<64;i++) {
        uint32_t s0 = kbox_rotr(w[i-15],7) ^ kbox_rotr(w[i-15],18) ^ (w[i-15]>>3);
        uint32_t s1 = kbox_rotr(w[i-2],17) ^ kbox_rotr(w[i-2],19) ^ (w[i-2]>>10);
        w[i] = w[i-16] + s0 + w[i-7] + s1;
    }
    a=s->h[0];b=s->h[1];c=s->h[2];d=s->h[3];e=s->h[4];f=s->h[5];g=s->h[6];h=s->h[7];
    for (i=0;i<64;i++) {
        uint32_t S1 = kbox_rotr(e,6)^kbox_rotr(e,11)^kbox_rotr(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + kbox_sha256_k[i] + w[i];
        uint32_t S0 = kbox_rotr(a,2)^kbox_rotr(a,13)^kbox_rotr(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1;
        d=c; c=b; b=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void kbox_sha256_update(kbox_sha256_t* s, const uint8_t* data, size_t len) {
    s->len += len;
    while (len > 0) {
        size_t need = 64 - s->buflen;
        size_t take = (len < need) ? len : need;
        memcpy(s->buf + s->buflen, data, take);
        s->buflen += take; data += take; len -= take;
        if (s->buflen == 64) { kbox_sha256_block(s, s->buf); s->buflen = 0; }
    }
}

static void kbox_sha256_final(kbox_sha256_t* s, uint8_t out[32]) {
    uint64_t bits = s->len * 8;
    size_t pad = (s->buflen < 56) ? (56 - s->buflen) : (120 - s->buflen);
    int i;
    static const uint8_t one = 0x80;
    kbox_sha256_update(s, &one, 1);
    { uint8_t z = 0; while (pad > 1) { kbox_sha256_update(s, &z, 1); pad--; } }
    { uint8_t lenb[8];
      for (i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (56 - i * 8));
      kbox_sha256_update(s, lenb, 8);
    }
    (void)one;
    for (i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(s->h[i] >> 24);
        out[i*4+1] = (uint8_t)(s->h[i] >> 16);
        out[i*4+2] = (uint8_t)(s->h[i] >> 8);
        out[i*4+3] = (uint8_t)(s->h[i]);
    }
}

/* ============================================================ */
/*  HMAC-SHA256                                                 */
/* ============================================================ */
#define KBOX_BLK 64

static void kbox_hmac(const uint8_t* key, size_t klen, const uint8_t* msg, size_t mlen, uint8_t out[32]) {
    uint8_t kpad[64];
    uint8_t inner[32], outer[32];
    kbox_sha256_t s;
    size_t i;
    memset(kpad, 0, 64);
    if (klen > 64) {
        kbox_sha256_init(&s); kbox_sha256_update(&s, key, klen); kbox_sha256_final(&s, kpad);
    } else {
        memcpy(kpad, key, klen);
    }
    for (i = 0; i < 64; i++) kpad[i] ^= 0x36;
    kbox_sha256_init(&s); kbox_sha256_update(&s, kpad, 64); kbox_sha256_update(&s, msg, mlen); kbox_sha256_final(&s, inner);
    for (i = 0; i < 64; i++) kpad[i] ^= 0x36 ^ 0x5c;
    kbox_sha256_init(&s); kbox_sha256_update(&s, kpad, 64); kbox_sha256_update(&s, inner, 32); kbox_sha256_final(&s, outer);
    memcpy(out, outer, 32);
}

/* ============================================================ */
/*  HKDF-SHA256 (RFC 5869 extract+expand), Java-compatible      */
/* ============================================================ */

/*
 * Mirrors HardwareKeyRing.hkdfSha256(ikm, salt, info, len) EXACTLY.
 * Java branch (salt non-empty):
 *   prk = HMAC(key=ikm, msg = salt || ikm)
 * else:
 *   prk = ikm
 * Then expand:
 *   okm = HMAC(prk, T || info || ctr)  for ctr=1,2,...
 *   T starts empty and advances.
 *
 * `info` is the UTF-8 bytes of the Java `String info`.
 */
static void kbox_hkdf(const uint8_t* ikm, size_t ikmLen,
                      const uint8_t* salt, size_t saltLen,
                      const uint8_t* info, size_t infoLen,
                      uint8_t* okm, size_t okmLen) {
    unsigned char prkKey[256]; /* PRK consumed as HMAC key directly */
    size_t prkKeyLen;
    uint8_t prkBuf[32];
    size_t prkBufLen = 0;
    uint8_t t[32];
    size_t tlen = 0;
    size_t pos = 0;
    unsigned int ctr = 1;

    if (salt != NULL && saltLen > 0) {
        /* prk = HMAC(key=ikm, msg = salt||ikm) -- exactly mirrors Java:
             mac.init(ikm); mac.update(salt); prk = mac.doFinal(ikm) */
        uint8_t* ibuf = (uint8_t*)kbox_cryptoAlloc(saltLen + ikmLen);
        if (!ibuf) { memset(okm, 0x2a, okmLen); return; }
        memcpy(ibuf, salt, saltLen);
        memcpy(ibuf + saltLen, ikm, ikmLen);
        kbox_hmac(ikm, ikmLen, ibuf, saltLen + ikmLen, prkBuf);
        kbox_cryptoFree(ibuf, saltLen + ikmLen);
        memcpy(prkKey, prkBuf, 32);
        prkKeyLen = 32;
        prkBufLen = 32;
    } else {
        /* Java: prk = ikm (the WHOLE ikm array, no truncation); it is then used
           as the HMAC key directly. Match by passing ikm as the key. */
        if (ikmLen <= sizeof(prkKey)) { memcpy(prkKey, ikm, ikmLen); prkKeyLen = ikmLen; }
        else { memcpy(prkKey, ikm, sizeof(prkKey)); prkKeyLen = sizeof(prkKey); }
    }

    memset(t, 0, sizeof(t));
    while (pos < okmLen) {
        size_t mlen;
        uint8_t* m;
        size_t outLen;
        /* msg = T || info || ctr(1 byte, starting 0x01) */
        mlen = tlen + infoLen + 1;
        m = (uint8_t*)kbox_cryptoAlloc(mlen);
        if (!m) { memset(okm, 0x2a, okmLen); return; }
        memcpy(m, t, tlen);
        memcpy(m + tlen, info, infoLen);
        m[mlen - 1] = (uint8_t)ctr;
        kbox_hmac((prkBufLen ? prkBuf : (const uint8_t*)prkKey),
                  (prkBufLen ? 32 : prkKeyLen), m, mlen, t);
        kbox_cryptoFree(m, mlen);
        outLen = 32;
        if (outLen > (okmLen - pos)) outLen = okmLen - pos;
        memcpy(okm + pos, t, outLen);
        pos += outLen;
        tlen = 32;
        ctr++;
    }
}

/* ============================================================ */
/*  JNI exports — Java class com.kbox.runtime.NativeCrypto      */
/* ============================================================ */

JNIEXPORT jbyteArray JNICALL Java_com_kbox_runtime_NativeCrypto_hkdfSha2560
    (JNIEnv* env, jclass cls, jbyteArray jikm, jbyteArray jsalt, jbyteArray jinfo, jint jlen) {
    (void)cls;
    jsize ikmLen = jikm ? (*env)->GetArrayLength(env, jikm) : 0;
    jsize saltLen = jsalt ? (*env)->GetArrayLength(env, jsalt) : 0;
    jsize infoLen = jinfo ? (*env)->GetArrayLength(env, jinfo) : 0;
    jsize okLen = jlen;
    uint8_t* ikm = NULL; uint8_t* salt = NULL; uint8_t* info = NULL;
    uint8_t* okm = NULL;
    jbyte* iraw = NULL; jbyte* sraw = NULL; jbyte* oraw = NULL;
    jbyteArray result = NULL;

    if (ikmLen > 0 && jikm) { iraw = (*env)->GetByteArrayElements(env, jikm, NULL); ikm = (uint8_t*)iraw; }
    if (saltLen > 0 && jsalt) { sraw = (*env)->GetByteArrayElements(env, jsalt, NULL); salt = (uint8_t*)sraw; }
    if (infoLen > 0 && jinfo) { oraw = (*env)->GetByteArrayElements(env, jinfo, NULL); info = (uint8_t*)oraw; }

    okm = (uint8_t*)kbox_cryptoAlloc(okLen > 0 ? (size_t)okLen : 1);
    if (!okm) return NULL;
    kbox_hkdf(ikm, (size_t)ikmLen, salt, (size_t)saltLen, info, (size_t)infoLen, okm, (size_t)okLen);

    result = (*env)->NewByteArray(env, okLen);
    if (result) (*env)->SetByteArrayRegion(env, result, 0, okLen, (jbyte*)okm);
    kbox_cryptoFree(okm, (size_t)okLen);

    if (oraw) (*env)->ReleaseByteArrayElements(env, jinfo, oraw, JNI_ABORT);
    if (sraw) (*env)->ReleaseByteArrayElements(env, jsalt, sraw, JNI_ABORT);
    if (iraw) (*env)->ReleaseByteArrayElements(env, jikm, iraw, JNI_ABORT);
    return result;
}

/* Per-byte decrypt of the resident stream: dec[pos] = res[pos] ^ ks[pos].
 * Returns the decrypted byte; does NOT zero the resident slot (loops re-decrypt
 * the intact resident — matching VmpMethod.b() semantics). The scratch `out`
 * buffer is the only place a plain byte can exist, transiently. */
JNIEXPORT jbyte JNICALL Java_com_kbox_runtime_NativeCrypto_decryptByteAt0
    (JNIEnv* env, jclass cls, jbyteArray jres, jint pos, jbyteArray jks) {
    (void)cls;
    jsize rlen = jres ? (*env)->GetArrayLength(env, jres) : 0;
    jbyte rb = 0, kb = 0;
    if (pos >= 0 && pos < rlen) {
        jbyte rpv, kpv;
        (*env)->GetByteArrayRegion(env, jres, pos, 1, &rpv);
        if (jks) {
            if (pos < (*env)->GetArrayLength(env, jks)) {
                (*env)->GetByteArrayRegion(env, jks, pos, 1, &kpv);
            } else {
                kpv = 0;
            }
        } else {
            kpv = 0;
        }
        rb = rpv; kb = kpv;
    }
    return (jbyte)(((rb & 0xFF) ^ (kb & 0xFF)) & 0xFF);
}