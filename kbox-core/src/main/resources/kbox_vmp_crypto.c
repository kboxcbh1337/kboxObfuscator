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
/*  KDF-SHA256 (RFC-5869-style expand, NON-RFC extract), Java-compatible */
/* ============================================================ */

/*
 * Mirrors HardwareKeyRing.hkdfSha256(ikm, salt, info, len) EXACTLY.
 * NOT RFC 5869: the extract stage deviates (see the Java javadoc) —
 * Java branch (salt non-empty):
 *   prk = HMAC(key=ikm, msg = salt || ikm)
 * else:
 *   prk = ikm
 * Then expand (this stage does follow RFC 5869):
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

/* ============================================================ */
/*  AES-256 (FIPS 197) + CTR stream — native string-decrypt sink */
/* ============================================================ */

/*
 * String-decryption sink for the AES-256-CTR holder decryptor. The plaintext
 * is produced inside page-aligned, wipe-on-free memory (kbox_cryptoAlloc),
 * converted to a jstring there, and the buffer is zeroed before it is freed —
 * the Java heap only ever receives the final String. Returns NULL on any
 * failure so the Java caller falls back to the byte-identical JCE path.
 *
 * CTR COMPATIBILITY CONTRACT with Java's AES/CTR/NoPadding (SunJCE):
 *   counter block  = the 16-byte IV
 *   keystream block = AES-256_encrypt(counter)
 *   counter is then incremented as a 128-bit big-endian integer, one per block.
 * Any divergence makes native decrypted strings differ from JCE output.
 */

static const uint8_t kbox_aes_sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static uint32_t kbox_aes_xtime(uint32_t x) {
    return (uint32_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t kbox_aes_xtime8(uint8_t x) {
    return (uint8_t)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

/* Expands a 32-byte AES-256 key into 60 32-bit round-key words. */
static void kbox_aes256_expand(const uint8_t key[32], uint32_t rk[60]) {
    static const uint8_t rcon[15] = {
        0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36,0x6c,0xd8,0xab,0x4d,0x9a
    };
    int i;
    uint32_t t;
    for (i = 0; i < 8; i++) {
        rk[i] = ((uint32_t)key[i*4] << 24) | ((uint32_t)key[i*4+1] << 16)
              | ((uint32_t)key[i*4+2] << 8)  |  (uint32_t)key[i*4+3];
    }
    for (i = 8; i < 60; i++) {
        t = rk[i-1];
        if ((i & 7) == 0) {
            /* RotWord(bytewise rotate left by one) + SubWord + Rcon:
             * new top byte = sbox[old byte2], ... last byte = sbox[old top]. */
            t = (kbox_aes_sbox[(t >> 16) & 0xff] << 24)
              | (kbox_aes_sbox[(t >> 8) & 0xff] << 16)
              | (kbox_aes_sbox[t & 0xff] << 8)
              |  kbox_aes_sbox[(t >> 24) & 0xff];
            t ^= ((uint32_t)rcon[i/8 - 1]) << 24;
        } else if ((i & 7) == 4) {
            t = (kbox_aes_sbox[(t >> 24) & 0xff] << 24)
              | (kbox_aes_sbox[(t >> 16) & 0xff] << 16)
              | (kbox_aes_sbox[(t >> 8) & 0xff] << 8)
              |  kbox_aes_sbox[t & 0xff];
        }
        rk[i] = rk[i-8] ^ t;
    }
}

static void kbox_aes256_encrypt(const uint32_t rk[60], const uint8_t in[16], uint8_t out[16]) {
    /* Textbook AES-256 (state[row][col], column-major input/output):
     *   in/out byte order = column 0..3, each column top row first —
     *   identical to the word-based layout (s[c] word, byte0=row0). */
    uint8_t s[4][4];
    int r, c, i;
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            s[r][c] = in[c * 4 + r];
    /* AddRoundKey(0): rk[c] word, byte0=row0 = top byte. */
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            s[r][c] ^= (uint8_t)(rk[c] >> (24 - r * 8));
    for (i = 1; i <= 14; i++) {
        /* SubBytes */
        for (r = 0; r < 4; r++)
            for (c = 0; c < 4; c++)
                s[r][c] = kbox_aes_sbox[s[r][c]];
        /* ShiftRows: row r rotates left by r. */
        for (r = 1; r < 4; r++) {
            uint8_t tmp[4];
            for (c = 0; c < 4; c++) tmp[c] = s[r][c];
            for (c = 0; c < 4; c++) s[r][c] = tmp[(c + r) % 4];
        }
        if (i < 14) {
            /* MixColumns (2*a=xtime(a), 3*a=a^xtime(a)) */
            for (c = 0; c < 4; c++) {
                uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
                s[0][c] = (uint8_t)(kbox_aes_xtime8(a0) ^ (a1 ^ kbox_aes_xtime8(a1)) ^ a2 ^ a3);
                s[1][c] = (uint8_t)(a0 ^ kbox_aes_xtime8(a1) ^ (a2 ^ kbox_aes_xtime8(a2)) ^ a3);
                s[2][c] = (uint8_t)(a0 ^ a1 ^ kbox_aes_xtime8(a2) ^ (a3 ^ kbox_aes_xtime8(a3)));
                s[3][c] = (uint8_t)((a0 ^ kbox_aes_xtime8(a0)) ^ a1 ^ a2 ^ kbox_aes_xtime8(a3));
            }
        }
        /* AddRoundKey(i) */
        for (c = 0; c < 4; c++)
            for (r = 0; r < 4; r++)
                s[r][c] ^= (uint8_t)(rk[i * 4 + c] >> (24 - r * 8));
    }
    for (c = 0; c < 4; c++)
        for (r = 0; r < 4; r++)
            out[c * 4 + r] = s[r][c];
}

/* Increments a 128-bit big-endian counter block by one. */
static void kbox_ctr_inc(uint8_t ctr[16]) {
    int i;
    for (i = 15; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

/* Standard UTF-8 -> UTF-16 decode, Java String(byte[], UTF_8) compatible for
 * well-formed input (malformed sequences become U+FFFD, as in Java). Returns
 * the number of UTF-16 units written. */
static size_t kbox_utf8_to_utf16(const uint8_t* s, size_t n, uint16_t* out) {
    size_t i = 0, o = 0;
    while (i < n) {
        uint8_t c = s[i];
        if (c < 0x80) {
            out[o++] = (uint16_t)c; i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 < n && (s[i+1] & 0xC0) == 0x80) {
                uint32_t cp = ((uint32_t)(c & 0x1F) << 6) | (s[i+1] & 0x3F);
                if (cp >= 0x80) { out[o++] = (uint16_t)cp; i += 2; }
                else { out[o++] = 0xFFFD; i += 2; }
            } else { out[o++] = 0xFFFD; i++; }
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 < n && (s[i+1] & 0xC0) == 0x80 && (s[i+2] & 0xC0) == 0x80) {
                uint32_t cp = ((uint32_t)(c & 0x0F) << 12) | ((uint32_t)(s[i+1] & 0x3F) << 6) | (s[i+2] & 0x3F);
                if (cp >= 0x800 && cp <= 0xD7FF) { out[o++] = (uint16_t)cp; }
                else if (cp >= 0xE000 && cp <= 0xFFFF) { out[o++] = (uint16_t)cp; }
                else { out[o++] = 0xFFFD; }
                i += 3;
            } else { out[o++] = 0xFFFD; i++; }
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 < n && (s[i+1] & 0xC0) == 0x80 && (s[i+2] & 0xC0) == 0x80 && (s[i+3] & 0xC0) == 0x80) {
                uint32_t cp = ((uint32_t)(c & 0x07) << 18) | ((uint32_t)(s[i+1] & 0x3F) << 12)
                            | ((uint32_t)(s[i+2] & 0x3F) << 6) | (s[i+3] & 0x3F);
                if (cp >= 0x10000 && cp <= 0x10FFFF) {
                    cp -= 0x10000;
                    out[o++] = (uint16_t)(0xD800 | (cp >> 10));
                    out[o++] = (uint16_t)(0xDC00 | (cp & 0x3FF));
                } else { out[o++] = 0xFFFD; }
                i += 4;
            } else { out[o++] = 0xFFFD; i++; }
        } else { out[o++] = 0xFFFD; i++; }
    }
    return o;
}

JNIEXPORT jstring JNICALL Java_com_kbox_runtime_NativeCrypto_decryptString0
    (JNIEnv* env, jclass cls, jbyteArray jenc, jbyteArray jkey) {
    (void)cls;
    jsize encLen = jenc ? (*env)->GetArrayLength(env, jenc) : 0;
    jsize keyLen = jkey ? (*env)->GetArrayLength(env, jkey) : 0;
    jstring result = NULL;
    if (encLen < 16 || keyLen != 32) return NULL;

    jbyte* encRaw = (*env)->GetByteArrayElements(env, jenc, NULL);
    jbyte* keyRaw = (*env)->GetByteArrayElements(env, jkey, NULL);
    if (!encRaw || !keyRaw) {
        if (encRaw) (*env)->ReleaseByteArrayElements(env, jenc, encRaw, JNI_ABORT);
        if (keyRaw) (*env)->ReleaseByteArrayElements(env, jkey, keyRaw, JNI_ABORT);
        return NULL;
    }

    jsize ctLen = encLen - 16;
    uint8_t* pt = (uint8_t*)kbox_cryptoAlloc((size_t)ctLen > 0 ? (size_t)ctLen : 1);
    uint32_t* rk = (uint32_t*)kbox_cryptoAlloc(60 * sizeof(uint32_t));
    if (pt && rk) {
        const uint8_t* iv = (const uint8_t*)encRaw;
        uint8_t ctr[16];
        uint8_t ks[16];
        jsize off;
        memcpy(ctr, iv, 16);
        kbox_aes256_expand((const uint8_t*)keyRaw, rk);
        for (off = 0; off + 16 <= ctLen; off += 16) {
            kbox_aes256_encrypt(rk, ctr, ks);
            {
                int b;
                for (b = 0; b < 16; b++) pt[off + b] = (uint8_t)((uint8_t)encRaw[16 + off + b] ^ ks[b]);
            }
            kbox_ctr_inc(ctr);
        }
        if (off < ctLen) {
            jsize rem = ctLen - off;
            int b;
            kbox_aes256_encrypt(rk, ctr, ks);
            for (b = 0; b < (int)rem; b++) pt[off + b] = (uint8_t)((uint8_t)encRaw[16 + off + b] ^ ks[b]);
        }
        /* UTF-8 -> UTF-16 (surrogate pairs need up to 2 units per 3/4-byte seq) */
        {
            size_t maxU = (size_t)ctLen * 2 + 1;
            uint16_t* u16 = (uint16_t*)kbox_cryptoAlloc(maxU * sizeof(uint16_t));
            if (u16) {
                size_t nU = kbox_utf8_to_utf16(pt, (size_t)ctLen, u16);
                if (nU > 0) result = (*env)->NewString(env, (const jchar*)u16, (jsize)nU);
                kbox_cryptoFree(u16, maxU * sizeof(uint16_t));
            }
        }
    }
    if (rk) kbox_cryptoFree(rk, 60 * sizeof(uint32_t));
    if (pt) kbox_cryptoFree(pt, (size_t)ctLen > 0 ? (size_t)ctLen : 1);

    (*env)->ReleaseByteArrayElements(env, jkey, keyRaw, JNI_ABORT);
    (*env)->ReleaseByteArrayElements(env, jenc, encRaw, JNI_ABORT);
    return result;
}