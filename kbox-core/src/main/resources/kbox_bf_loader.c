/*
 * KBox-Brainfuck native decoder — "Java Ultimate Chaos Obfuscation" loader.
 *
 * Per-class "non-落地" (never-resting) pipeline:
 *   classes.bf.rle  ->KBF2 header+chunk lookup by name
 *   [one entry]     --RLE decode--> Brainfuck text
 *                   --interpret (8-op tape model)--> raw-DEFLATE stream
 *                   --inflate (RFC 1951, self-contained)--> that entry's bytes
 *                   --JNI DefineClass / NewByteArray--> metaspace / Java heap
 *                   then every native buffer (BF text, deflated, plaintext,
 *                   tape) is zeroed and freed immediately.
 *
 * The archive is a "KBF2" container: a small header lists each class/resource's
 * name plus the (rleOff, rleLen, rawLen) of its OWN independent RLE chunk. There
 * is NO global DEFLATE stream and therefore NO full plaintext jar at any moment.
 * decodeEntryInto() inflates exactly one entry on demand, directly into a
 * guard-wrapped exposure box, hands its bytes to the VM, and wipes them right
 * after — so at any instant only the currently requested entry's plaintext
 * exists, and it does not rest anywhere.
 *
 * Full standard Brainfuck is implemented natively (tape + all 8 commands +, -,
 * >, <, [, ], ., ,). Each chunk is a real standalone BF program (a preamble even
 * uses every command once), so a naive "hunt for CAFEBABE" or "inflate the
 * blob" attempt finds no contiguous class bytes on disk and no whole payload in
 * memory.
 *
 * Security properties:
 *   * The protected jar on disk contains only RLE noise — no CAFEBABE magic.
 *   * The plaintext of a class exists only during its own define (native heap),
 *     and is zeroed immediately afterwards; no full jar blob is ever materialised.
 *   * A 6 TiB virtual-address reservation ("dump trap") is set up at library
 *     load to trip naive memory-dump / VA-walker tooling.
 *   * The name->(rleOff,rleLen) index lives only in native memory; Java never
 *     learns an offset, so no (offset,len) primitive exists to dump the archive.
 *
 * The shared library is packed (KBNL: DEFLATE + ChaCha20) into the jar as
 * META-INF/kbox/native.bin and unpacked at runtime by
 * com.kbox.runtime.NativeLoader (same blob format as the JNIC decoder).
 *
 * Only six JNI-named exports are used (all on com.kbox.runtime.BfSecureLoader):
 *   static native int      init(byte[] rle);
 *   native     Class<?>    defineClassFromBFImpl(String name);
 *   native     byte[]      getResourceBytes(String name);
 *   static native boolean  probeClassFromBF(String name);
 *   static native void     wipe();
 *   static native boolean  safeBoot(String[] jvmArgs);
 *
 * The agent/debugger gate is evaluated ENTIRELY in this native code (per-build
 * polymorphic native.bin), and re-checked at every class definition — the
 * plaintext Java bootstrap only forwards raw JVM arguments to one opaque call
 * and holds no detection pattern of its own.
 */
#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#if defined(_MSC_VER)
#include <intrin.h>
#endif

/* ==================================================================== */
/* L1 RangeTable: address meta-model (terrain registry)                 */
/* ==================================================================== */
/* Every memory region the shield owns (or watches) is registered here with
 * its Terrain from the L1 meta-model, so the scattered anti-debug / anti-dump
 * checks collapse into one verifiable state machine:
 *   KBOX_TER_CRYPT  — static ciphertext (packed blobs / image data): read-only
 *   KBOX_TER_MAYBE  — a plaintext window between decrypt and consume: RW while
 *                     alive, NOACCESS once wiped (see kbox_exboxMake)
 *   KBOX_TER_OPAQUE — VM ciphertext stream: only the VM decodes it; NOACCESS
 *                     while dormant
 *   KBOX_TER_HOT    — executable plaintext hook (mapped native module code
 *                     sections): RX
 * kbox_terrainCheck() re-verifies every registered range still carries the
 * protection its terrain demands. A memory tool that flips a MAYBE window
 * RW→RO to read plaintext, or a HOT hook RX→RW to patch it, is caught by the
 * same probe pass that already verifies the exposure-box guard pages
 * (kbox_probePageAttrs). Defined before the reflective-loader include so the
 * module mapper (kbox_reflect_loader.c) can register its RX code sections. */
typedef enum {
    KBOX_TER_CRYPT = 0,
    KBOX_TER_MAYBE = 1,
    KBOX_TER_OPAQUE = 2,
    KBOX_TER_HOT = 3
} kbox_terrain_t;

#define KBOX_RANGE_MAX 64
static uintptr_t g_rLo[KBOX_RANGE_MAX];
static uintptr_t g_rHi[KBOX_RANGE_MAX];
static int g_rTer[KBOX_RANGE_MAX];
static int g_rN = 0;

static void kbox_rangeMap(uintptr_t lo, uintptr_t hi, int terrain) {
    if (g_rN >= KBOX_RANGE_MAX) return;
    g_rLo[g_rN] = lo; g_rHi[g_rN] = hi; g_rTer[g_rN] = terrain; g_rN++;
}

/* Drop the registration for [lo,hi) — called when a MAYBE window or a mapped
 * HOT section is torn down, so the registry never holds stale pointers to
 * unmapped memory (a later VirtualQuery there would false-positive). */
static void kbox_rangeUnmap(uintptr_t lo, uintptr_t hi) {
    for (int i = g_rN - 1; i >= 0; i--) {
        if (g_rLo[i] == lo && g_rHi[i] == hi) {
            for (int j = i; j < g_rN - 1; j++) {
                g_rLo[j] = g_rLo[j + 1];
                g_rHi[j] = g_rHi[j + 1];
                g_rTer[j] = g_rTer[j + 1];
            }
            g_rN--;
            return;
        }
    }
}

/* Expected per-terrain page attributes (read/write/execute booleans). MAYBE
 * and CRYPT are data; HOT is executable; OPAQUE is dormant NOACCESS. */
static void kbox_terExpected(int t, int* rd, int* wr, int* ex) {
    *rd = *wr = *ex = 0;
    switch (t) {
        case KBOX_TER_MAYBE:  *rd = 1; *wr = 1; break;
        case KBOX_TER_CRYPT:  *rd = 1; break;
        case KBOX_TER_OPAQUE: break;               /* NOACCESS while dormant */
        case KBOX_TER_HOT:    *rd = 1; *ex = 1; break;
        default: break;
    }
}

/* Re-verify every registered range's current protection against its terrain.
 * Returns 0 when all ranges still match, 1 on any discrepancy. Only the data
 * pages are inspected; guard pages stay on the dedicated trap registry. */
static int kbox_terrainCheck(void) {
#if defined(_WIN32)
    for (int i = 0; i < g_rN; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)g_rLo[i], &mbi, sizeof(mbi)) == 0) return 1;
        DWORD prot = mbi.Protect & 0xFF;
        int rd, wr, ex;
        kbox_terExpected(g_rTer[i], &rd, &wr, &ex);
        int hasR = (prot & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY
                            | PAGE_EXECUTE_WRITECOPY)) != 0;
        int hasW = (prot & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE
                            | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
        int hasX = (prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ
                            | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        /* A MAYBE window that was just wiped may legitimately be NOACCESS. */
        if (g_rTer[i] == KBOX_TER_MAYBE && prot == PAGE_NOACCESS) continue;
        if (rd && !hasR) return 1;
        if (wr && !hasW) return 1;
        if (ex && !hasX) return 1;
        /* Non-writable terrains must never become writable (patch target). */
        if (!wr && hasW) return 1;
    }
#endif
    return 0;
}

/* ==================================================================== */
/* L4.3 Global integrity epoch (entropy fusing)                         */
/* ==================================================================== */
/* A single per-process "integrity epoch" page is the shared fuse under every
 * fail-closed path. It holds a monotonic counter and a magic. On ANY security
 * violation (guard-page fault, gate failure, probe trigger, watchdog tick) the
 * counter is atomically incremented, every live plaintext window
 * (MAYBE/OPAQUE terrain in the RangeTable) is batch-wiped, and the process
 * hard-terminates — an attacker can never harvest plaintext from a recovered
 * dump, and neutering one guard leaves the epoch logic (itself inside the
 * image-self-hash region) to fire on the next violation. The page holds no
 * secrets, only counters, so it never enters the RangeTable as a plaintext
 * window. */
#define KBOX_EPOCH_MAGIC 0x4B45504Fu /* 'KEPO' */
typedef struct {
    volatile uint32_t magic;
    volatile uint32_t epoch;
    volatile uint32_t hbW1;   /* watchdog W1 heartbeat (mutual-sentinel tick) */
    volatile uint32_t hbW2;   /* watchdog W2 heartbeat (mutual-sentinel tick) */
} kbox_epoch_t;

static kbox_epoch_t* g_epoch = NULL;

/* Env-gated diagnostic (KBOX_WD_DBG=1): which probe tripped which fail-closed
 * gate. Stays silent by default so a normal run has zero stderr. */
static void kbox_wdDiag(const char* reason) {
    static int en = -1;
    if (en < 0) {
        const char* e = getenv("KBOX_WD_DBG");
        en = (e != NULL && e[0] != '\0') ? 1 : 0;
    }
    if (en) { fprintf(stderr, "[KBOX-WD] %s\n", reason); fflush(stderr); }
}

static void kbox_epochInit(void) {
    if (g_epoch != NULL) return;
    void* p;
#if defined(_WIN32)
    p = VirtualAlloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) p = NULL;
#endif
    if (p == NULL) return;
    kbox_epoch_t* e = (kbox_epoch_t*)p;
    e->magic = KBOX_EPOCH_MAGIC;
    e->epoch = 0;
    e->hbW1 = 0;
    e->hbW2 = 0;
    g_epoch = e;
}

/* Tamper check on the epoch page itself. An attacker that zeroes the page to
 * "disable the fuse" flips the magic; every watchdog tick consulting the epoch
 * treats that as a violation and hard-kills (and the image-self-hash catches
 * the patch to this checker itself). Returns 1 when the fuse is armed. */
static int kbox_epochArmed(void) {
    if (g_epoch == NULL) return 0;   /* not initialised yet: no fuse */
    return (g_epoch->magic == KBOX_EPOCH_MAGIC) ? 1 : 0;
}

/* The shared fuse. Atomically increments the epoch counter and batch-wipes
 * every live plaintext window (MAYBE/OPAQUE) in the RangeTable, then
 * hard-terminates the process with `code`. TerminateProcess/_exit do not
 * return, so after this call no protected plaintext survives the violation. */
static void kbox_epochBump(uint32_t code) {
    kbox_epochInit();
    if (g_epoch != NULL) {
#if defined(_WIN32)
        InterlockedIncrement((volatile LONG*)&g_epoch->epoch);
#else
        __sync_fetch_and_add(&g_epoch->epoch, 1u);
#endif
        g_epoch->magic = KBOX_EPOCH_MAGIC;   /* keep the fuse armed */
    }
    /* Batch-erase live plaintext windows before dying. */
    for (int i = 0; i < g_rN; i++) {
        if (g_rTer[i] == KBOX_TER_MAYBE || g_rTer[i] == KBOX_TER_OPAQUE) {
            volatile unsigned char* p =
                (volatile unsigned char*)(uintptr_t)g_rLo[i];
            size_t n = (size_t)(g_rHi[i] - g_rLo[i]);
            while (n--) { *p++ = 0; }
        }
    }
#if defined(_WIN32)
    TerminateProcess(GetCurrentProcess(), code);
#else
    fflush(NULL);
    _exit(code);
#endif
}

/* Fail-closed wipe without termination: increments the epoch and batch-erases
 * the same MAYBE/OPAQUE windows, used by the weak-signal gate paths (VM / weak
 * debugger / agent module) that refuse work without killing a legitimate
 * cloud/headless run. After this, no live plaintext window remains. */
static void kbox_epochWipeMaybes(void) {
    kbox_epochInit();
    if (g_epoch != NULL) {
#if defined(_WIN32)
        InterlockedIncrement((volatile LONG*)&g_epoch->epoch);
#else
        __sync_fetch_and_add(&g_epoch->epoch, 1u);
#endif
        g_epoch->magic = KBOX_EPOCH_MAGIC;
    }
    for (int i = 0; i < g_rN; i++) {
        if (g_rTer[i] == KBOX_TER_MAYBE || g_rTer[i] == KBOX_TER_OPAQUE) {
            volatile unsigned char* p =
                (volatile unsigned char*)(uintptr_t)g_rLo[i];
            size_t n = (size_t)(g_rHi[i] - g_rLo[i]);
            while (n--) { *p++ = 0; }
        }
    }
}

#include "kbox_reflect_loader.c"
#else
#include <sys/mman.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <dlfcn.h>
#if defined(__linux__) || defined(__linux)
#include <sys/syscall.h>
#include <link.h>
#endif
#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif
#endif
#ifndef MAP_NORESERVE
#define MAP_NORESERVE 0
#endif

/* ==================================================================== */
/* Per-build encrypted material (injected by BfNativeBuilder)            */
/* ==================================================================== */
/* Detection signatures (agent/debugger module names, JVM argument needles)
 * and the BF operator alphabet ship XOR-encrypted: BfNativeBuilder replaces
 * the region between KBOX_BF_ENCRYPTED_BEGIN/END with per-build random keys
 * and ciphertext, so a strings/static scan of the shipped native.bin yields no
 * plaintext pattern. Every probe decrypts one entry into a stack buffer, uses
 * it, and wipes it immediately. The default (standalone compile, no injection)
 * keeps the plaintext fallbacks later in this file, so direct gcc debugging
 * still works. */
static void kbox_xdec(char* out, const unsigned char* enc, size_t n,
                      const unsigned char* key) {
    for (size_t i = 0; i < n; i++) out[i] = (char)(enc[i] ^ key[i & 15]);
    out[n] = 0;
}
/* KBOX_BF_ENCRYPTED_BEGIN */
/* KBOX_BF_ENCRYPTED_END */

/* ==================================================================== */
/* Per-build Brainfuck symbol permutation                               */
/* ==================================================================== */
/* The full 8-command Brainfuck alphabet. BfNativeBuilder injects a fresh
 * random mapping for every build (KBOX_BF_* as decimal byte values), so no two
 * builds decode with the same symbol set — build-to-build polymorphism for the
 * native side, mirroring VMP's per-build virtual instruction set. The defaults
 * below keep the source compilable standalone (e.g. direct gcc debugging). */
#ifndef KBOX_BF_PLUS
#define KBOX_BF_PLUS '+'
#endif
#ifndef KBOX_BF_MINUS
#define KBOX_BF_MINUS '-'
#endif
#ifndef KBOX_BF_RIGHT
#define KBOX_BF_RIGHT '>'
#endif
#ifndef KBOX_BF_LEFT
#define KBOX_BF_LEFT '<'
#endif
#ifndef KBOX_BF_OPEN
#define KBOX_BF_OPEN '['
#endif
#ifndef KBOX_BF_CLOSE
#define KBOX_BF_CLOSE ']'
#endif
#ifndef KBOX_BF_DOT
#define KBOX_BF_DOT '.'
#endif
#ifndef KBOX_BF_COMMA
#define KBOX_BF_COMMA ','
#endif
#ifndef KBOX_BF_SEED
#define KBOX_BF_SEED 0x13579BDF
#endif
/* Per-build semantic dispatch permutation: canonical op i is executed by
 * handler slot KBOX_BF_DISP_i. Defaults are the identity so the source compiles
 * and runs standalone (direct gcc debugging); BfNativeBuilder injects a fresh
 * random permutation per build. */
#ifndef KBOX_BF_DISP_0
#define KBOX_BF_DISP_0 0
#define KBOX_BF_DISP_1 1
#define KBOX_BF_DISP_2 2
#define KBOX_BF_DISP_3 3
#define KBOX_BF_DISP_4 4
#define KBOX_BF_DISP_5 5
#define KBOX_BF_DISP_6 6
#define KBOX_BF_DISP_7 7
#endif
/* KBOX_BF_DINV_k = the canonical semantic executed by handler slot k — the
 * inverse of the dispatch permutation (DINV[DISP[s]] == s). BfNativeBuilder
 * injects a fresh inverse per build so every build assigns each switch case a
 * different opcode, while DISP and DINV always cancel at run time. */
#ifndef KBOX_BF_DINV_0
#define KBOX_BF_DINV_0 0
#define KBOX_BF_DINV_1 1
#define KBOX_BF_DINV_2 2
#define KBOX_BF_DINV_3 3
#define KBOX_BF_DINV_4 4
#define KBOX_BF_DINV_5 5
#define KBOX_BF_DINV_6 6
#define KBOX_BF_DINV_7 7
#endif

/* Canonical symbol order: 0=plus,1=minus,2=right,3=left,4=open,5=close,6=dot,7=comma.
 * Injected builds ship the 8 symbol bytes XOR-encrypted (KBOX_CANON_ENC ^
 * KBOX_CANON_KEY) so the operator alphabet never appears in plaintext in the
 * shipped binary; canonAt() decrypts one byte on the stack on demand. Standalone
 * compiles (no injection) fall back to the plaintext KBOX_BF_* constants. */
#ifdef KBOX_BF_ENCRYPTED
static unsigned char canonAt(int i) {
    return (unsigned char)(KBOX_CANON_ENC[i] ^ KBOX_CANON_KEY[i & 15]);
}
#else
static const unsigned char CANON[8] = {
    (unsigned char)KBOX_BF_PLUS,  (unsigned char)KBOX_BF_MINUS,
    (unsigned char)KBOX_BF_RIGHT, (unsigned char)KBOX_BF_LEFT,
    (unsigned char)KBOX_BF_OPEN,  (unsigned char)KBOX_BF_CLOSE,
    (unsigned char)KBOX_BF_DOT,   (unsigned char)KBOX_BF_COMMA };
static unsigned char canonAt(int i) { return CANON[i]; }
#endif

/* Lossless 32-bit mixer — must match BrainfuckPacker.mix() bit-for-bit so the
 * per-chunk op permutation derived here equals the one used to encode. */
static uint32_t mix32(uint32_t h) {
    h ^= h >> 16;
    h *= 0x85EBCA6B;
    h ^= h >> 13;
    h *= 0xC2B2AE35;
    h ^= h >> 16;
    return h;
}

/* Derives this chunk's 8-op permutation from the per-build seed and the chunk's
 * absolute RLE offset — identical algorithm to BrainfuckPacker.deriveOpPerm. */
static void deriveOpPerm(uint32_t seed, uint32_t rleOff, int p[8]) {
    for (int i = 0; i < 8; i++) p[i] = i;
    uint32_t s = mix32(seed ^ rleOff);
    for (int i = 7; i > 0; i--) {
        s = mix32(s + (uint32_t)(i * 0x9E3779B9));
        uint32_t j = (s >> 24) & 0xFF;
        j %= (uint32_t)(i + 1);      /* j in [0, i] */
        int t = p[i]; p[i] = p[j]; p[j] = t;
    }
}

/* The *effective* per-chunk op lookup: input unit byte -> dealt dispatch id
 * (0..7) or -1. Reset per decodeEntryInto against that chunk's own permuted
 * table, so the operator table only ever lives inside native decode memory. */
static int g_chunkConfigured = 0;
static signed char g_chunkOp[256];

/* Per-build semantic->handler dispatch permutation: the canonical semantic op
 * a unit decodes to (0..7) is executed by handler slot DISP_TAB[sem]. Each
 * switch case k below performs the opcode of semantic DINV_TAB[k]; because DINV
 * is the inverse of DISP, slot DISP_TAB[sem] falls onto the case that runs the
 * opcode of exactly that semantic — correct for any per-build permutation. */
static const int DISP_TAB[8] = {
    KBOX_BF_DISP_0, KBOX_BF_DISP_1, KBOX_BF_DISP_2, KBOX_BF_DISP_3,
    KBOX_BF_DISP_4, KBOX_BF_DISP_5, KBOX_BF_DISP_6, KBOX_BF_DISP_7 };
/* Inverse dispatch (semantic executed by each handler slot). */
static const int DINV_TAB[8] = {
    KBOX_BF_DINV_0, KBOX_BF_DINV_1, KBOX_BF_DINV_2, KBOX_BF_DINV_3,
    KBOX_BF_DINV_4, KBOX_BF_DINV_5, KBOX_BF_DINV_6, KBOX_BF_DINV_7 };

/* Maps a code unit to its canonical semantic (0..7) or -1. When a chunk is
 * configured, the per-chunk permutation is applied (the payload was encoded
 * with that chunk's re-dealt symbol order). The returned value is the SEMANTIC
 * in canonical order (0=plus..7=comma), shared by the bracket matcher and the
 * dispatch loop, so both agree for any per-build DISP. */
static int bfOpIndex(unsigned char c) {
    if (g_chunkConfigured) return (int)g_chunkOp[c];
    for (int i = 0; i < 8; i++) if (canonAt(i) == c) return i;
    return -1;
}

/* Builds the effective 256-entry unit->semantic table for one chunk. The packer
 * emitted semantic op s as the symbol canon[perm[s]]; a unit at canonical slot k
 * therefore carries semantic inv[k] (perm's inverse). This table exists only in
 * this native decode frame. */
static void configureChunkOps(uint32_t seed, uint32_t rleOff) {
    for (int i = 0; i < 256; i++) g_chunkOp[i] = -1;
    int perm[8], inv[8];
    deriveOpPerm(seed, rleOff, perm);
    for (int i = 0; i < 8; i++) inv[perm[i]] = i;   /* inv[s] = canonical slot holding semantic s */
    for (int k = 0; k < 8; k++) {
        g_chunkOp[canonAt(k)] = (signed char)inv[k];  /* char at canonical slot k carries semantic inv[k] */
    }
    g_chunkConfigured = 1;
}

/* Zero-then-release helper (defined later; declared here for early use). */
static void wipeBuffer(void* p, size_t n);
/* Wipe + unmap a secure allocation (defined below; declared here so the
 * grow helper can call it before the definition). */
static void secureFree(void* p, size_t cap);

/* ==================================================================== */
/* Secure allocation (wipe + unmap in one shot)                          */
/* ==================================================================== */
/* malloc/free is deliberately NOT used for plaintext-class buffers: after
 * free() the region stays mapped inside the process heap (free list), so a
 * native memory scanner can still read its (wiped-or-not) bytes. secureAlloc
 * instead reserves a dedicated page-aligned virtual range via VirtualAlloc /
 * mmap; secureFree wipes it and immediately unmaps the whole range with
 * VirtualFree / munmap, so the plaintext's address space ceases to exist the
 * moment it is consumed. */
static size_t g_pageSize = 4096;
static size_t roundPage(size_t n) {
    if (g_pageSize == 0) g_pageSize = 4096;
    return (n + g_pageSize - 1) & ~(g_pageSize - 1);
}
static void* secureAlloc(size_t n) {
    if (g_pageSize == 0) g_pageSize = 4096;
    size_t cap = roundPage(n > 0 ? n : 1);
#if defined(_WIN32)
    return VirtualAlloc(NULL, (SIZE_T)cap, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
#else
    void* p = mmap(NULL, cap, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return (p == MAP_FAILED) ? NULL : p;
#endif
}
/* Grows a secure allocation: allocate new, copy the used bytes, unmap old.
 * `oldCap` MUST be the page-rounded allocation size of `old` (see secureFree). */
static void* secureGrow(void* old, size_t oldUsed, size_t oldCap, size_t newCap) {
    void* n = secureAlloc(newCap);
    if (n == NULL) return NULL;
    if (old != NULL && oldUsed > 0) memcpy(n, old, oldUsed);
    if (old != NULL) secureFree(old, oldCap);
    return n;
}
/* Frees a secure allocation. `cap` MUST be the page-rounded allocation size of
 * the buffer (the capacity that was allocated), NOT its used length — passing
 * a smaller value would let POSIX munmap release only the head of the region
 * and leave the tail still mapped (and scannable). Wiping `cap` bytes is safe:
 * fresh secure pages are already zero, and beyond the used length holds no
 * secrets. Either way the whole region is released, so the plaintext's address
 * space ceases to exist the moment the buffer is consumed. */
static void secureFree(void* p, size_t cap) {
    if (p == NULL) return;
    wipeBuffer(p, cap);
    size_t capR = roundPage(cap > 0 ? cap : 1);
#if defined(_WIN32)
    VirtualFree(p, 0, MEM_RELEASE);
#else
    munmap(p, capR);
#endif
}

/* ==================================================================== */
/* Guarded "exposure box" + VEH (anti-dump trap pages)                  */
/* ==================================================================== */
/* The plaintext of a class exists for a few microseconds between the
 * decode frame and DefineClass. To turn a scanner probing that window into
 * a fatal anti-debug event, the plaintext is re-housed in an "exposure box":
 * a page-aligned data region wrapped by one PAGE_NOACCESS / PROT_NONE guard
 * page above and below. A linear sweep that steps one byte outside the data
 * (or a VA-walker reading the neighbors) faults on a guard page; a
 * vectored exception handler installed once recognises the fault address as
 * a guard page we own and hard-terminates the process (0x52) — probing the
 * plaintext window becomes a self-destruct. Only the outer two pages are
 * never-readable; the data pages themselves stay RW so DefineClass reads
 * them normally without tripping our own VEH. */
#define KBOX_TRAP_MAX 24
static uintptr_t g_trapLo[KBOX_TRAP_MAX];
static uintptr_t g_trapHi[KBOX_TRAP_MAX];
static int g_trapN = 0;
static int g_vehInstalled = 0;

typedef struct {
    unsigned char* data;   /* plaintext region (RW) */
    size_t         dataCap;/* page-rounded data size */
    unsigned char* base;   /* guard+data+guard allocation base */
    size_t         total;  /* full allocation size */
} kbox_exbox_t;

/* Any guard-page access — the signal that a dump tool is sweeping the buffer
 * neighbours — kills the process before the scanner reads the plaintext. */
#if defined(_WIN32)
static LONG WINAPI kbox_veh(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        uintptr_t a = (uintptr_t)ep->ExceptionRecord->ExceptionInformation[1];
        for (int i = 0; i < g_trapN; i++) {
            if (a >= g_trapLo[i] && a < g_trapHi[i]) {
                /* Guard-page sweep = active dump attempt: fuse the epoch,
                 * wipe live plaintext windows, then die (0x52). */
                kbox_epochBump(0x52);
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}
#endif

static void kbox_vehEnsure(void) {
#if defined(_WIN32)
    if (!g_vehInstalled) {
        AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)kbox_veh);
        g_vehInstalled = 1;
    }
#endif
}

static void kbox_trapRegister(uintptr_t lo, uintptr_t hi) {
    if (g_trapN + 2 > KBOX_TRAP_MAX) return;
    g_trapLo[g_trapN] = lo; g_trapHi[g_trapN] = hi; g_trapN++;
}

/* Remove a server-trap entry once its guarded region is freed, so a later
 * terrain/guard probe never VirtualQuery's an address that has been recycled
 * by the allocator into an arbitrary RW region (would false-positive). */
static void kbox_trapUnregister(uintptr_t lo, uintptr_t hi) {
    if (lo == 0) return;
    for (int i = 0; i < g_trapN; i++) {
        if (g_trapLo[i] == lo && g_trapHi[i] == hi) {
            for (int j = i; j < g_trapN - 1; j++) {
                g_trapLo[j] = g_trapLo[j + 1];
                g_trapHi[j] = g_trapHi[j + 1];
            }
            g_trapN--;
            return;
        }
    }
}

/* Allocates a guarded plaintext region of at least useLen bytes. Returns 0 on
 * success and fills *x; returns -1 on failure. */
static int kbox_exboxMake(kbox_exbox_t* x, size_t useLen) {
    size_t page = (g_pageSize > 0) ? g_pageSize : 4096;
    if (g_pageSize == 0) g_pageSize = 4096;
    size_t dataCap = roundPage(useLen > 0 ? useLen : 1);
    size_t total = dataCap + 2 * page;
    unsigned char* base;
#if defined(_WIN32)
    base = (unsigned char*)VirtualAlloc(NULL, total, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (base == NULL) return -1;
#else
    base = (unsigned char*)mmap(NULL, total, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) return -1;
#endif
    unsigned char* head = base;
    unsigned char* data = base + page;
    unsigned char* tail = data + dataCap;
#if defined(_WIN32)
    DWORD old;
    VirtualProtect(head, page, PAGE_NOACCESS, &old);
    VirtualProtect(tail, page, PAGE_NOACCESS, &old);
#else
    mprotect(head, page, PROT_NONE);
    mprotect(tail, page, PROT_NONE);
#endif
    kbox_trapRegister((uintptr_t)head, (uintptr_t)(head + page));
    kbox_trapRegister((uintptr_t)tail, (uintptr_t)(tail + page));
    /* L1: the plaintext data window is a MAYBE terrain — RW while alive, and
     * its re-protection (RO/RX for dumping, RWX for patching) is caught by
     * kbox_terrainCheck() through kbox_probePageAttrs. */
    kbox_rangeMap((uintptr_t)data, (uintptr_t)(data + dataCap), KBOX_TER_MAYBE);
    kbox_vehEnsure();
    x->data = data; x->dataCap = dataCap; x->base = base; x->total = total;
    return 0;
}

/* Forward decl: non-elidable secure clear (defined below the exposure box). */
static void kbox_secmem_clear(void* p, size_t n);

/* Wipes the data pages and tears the whole exposure box down (guard pages
 * disappear with the unmap, so once gone the fault trap is naturally gone too). */
static void kbox_exboxFree(kbox_exbox_t* x) {
    if (x->base) {
        /* L1: drop the MAYBE registration before the region ceases to exist,
         * so kbox_terrainCheck never VirtualQuery's freed memory. */
        kbox_rangeUnmap((uintptr_t)x->data, (uintptr_t)(x->data + x->dataCap));
        /* L1/L3: drop the guard-page trap registrations too — the whole
         * allocation is about to be released and may be recycled by the
         * allocator into an arbitrary RW region, which would otherwise make
         * probePageAttrs / the VEH trip on stale addresses. */
        size_t page = (g_pageSize > 0) ? (size_t)g_pageSize : 4096;
        kbox_trapUnregister((uintptr_t)x->base, (uintptr_t)(x->base + page));
        kbox_trapUnregister((uintptr_t)(x->data + x->dataCap),
                            (uintptr_t)(x->data + x->dataCap + page));
        /* D9: non-elidable secure clear of the plaintext exposure window before
         * the unmap — the optimizer cannot elide this, so the dump sees erase. */
        kbox_secmem_clear(x->data, x->dataCap);
#if defined(_WIN32)
        VirtualFree(x->base, 0, MEM_RELEASE);
#else
        munmap(x->base, x->total);
#endif
        x->base = NULL; x->data = NULL; x->dataCap = 0;
    }
}

/* ==================================================================== */
/* 6 TiB virtual-address "dump trap"                                     */
/* ==================================================================== */
static void* g_dumpTrap = NULL;

static void setupDumpTrap(void) {
    if (g_dumpTrap != NULL) return;
    /* Detect the real OS page size so secureAlloc/mprotect stay aligned on
     * platforms where it is not 4096 (e.g. 64 KiB pages on ARM64). */
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwPageSize > 0) g_pageSize = si.dwPageSize;
#else
    long ps = sysconf(_SC_PAGESIZE);
    if (ps > 0) g_pageSize = (size_t)ps;
#endif
    /* 6 TiB = 6 * 2^40 bytes. Reserve virtual address space WITHOUT committing
     * any physical memory: on Windows MEM_RESERVE, on POSIX PROT_NONE +
     * MAP_NORESERVE. The reservation is deliberately never touched, so no page
     * file / RAM is consumed; it only occupies the 64-bit virtual address
     * space and forces heap-dump / VA-walker tools to page through a huge,
     * unreadable region. */
    const uint64_t SIZE = 6ULL * 1024ULL * 1024ULL * 1024ULL * 1024ULL;
#if defined(_WIN32)
    g_dumpTrap = VirtualAlloc(NULL, (SIZE_T)SIZE, MEM_RESERVE, PAGE_NOACCESS);
#else
    void* p = mmap(NULL, (size_t)SIZE, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    g_dumpTrap = (p == MAP_FAILED) ? NULL : p;
#endif
    /* Keep the pointer live (prevents dead-store elision). */
    (void)sizeof(g_dumpTrap);
}

/* ==================================================================== */
/* RLE -> Brainfuck text (per-entry chunk)                               */
/* ==================================================================== */
/* Parses "12+3-2." style RLE into a full Brainfuck program. Returns a
 * malloc'd, NUL-terminated buffer (caller frees) or NULL on malformed input.
 * Any char that maps to one of the 8 BF ops is a valid op; digits are the
 * run-length prefix (counts). */
static char* rleDecode(const unsigned char* rle, size_t rleLen,
                       size_t* outLen, size_t* outCap) {
    size_t cap = roundPage(rleLen * 4 + 64);
    char* bf = (char*)secureAlloc(cap);
    if (bf == NULL) return NULL;
    size_t bfLen = 0;
    size_t i = 0;
    while (i < rleLen) {
        unsigned char c = rle[i];
        if (c >= '0' && c <= '9') {
            uint32_t n = 0;
            while (i < rleLen && rle[i] >= '0' && rle[i] <= '9') {
                n = n * 10u + (uint32_t)(rle[i] - '0');
                if (n > 2000000000u) { secureFree(bf, cap); return NULL; }
                i++;
            }
            if (i >= rleLen) { secureFree(bf, cap); return NULL; } /* digits w/o op */
            c = rle[i];
            if (bfOpIndex(c) < 0) { secureFree(bf, cap); return NULL; }
            i++;
            if (bfLen + (size_t)n + 1 > cap) {
                size_t ncap = roundPage(bfLen + (size_t)n + 64);
                char* nb = (char*)secureGrow(bf, bfLen, cap, ncap);
                if (nb == NULL) { secureFree(bf, cap); return NULL; }
                bf = nb; cap = ncap;
            }
            memset(bf + bfLen, (int)c, (size_t)n);
            bfLen += (size_t)n;
        } else if (bfOpIndex(c) >= 0) {
            if (bfLen + 2 > cap) {
                size_t ncap = roundPage(cap * 2 + 64);
                char* nb = (char*)secureGrow(bf, bfLen, cap, ncap);
                if (nb == NULL) { secureFree(bf, cap); return NULL; }
                bf = nb; cap = ncap;
            }
            bf[bfLen++] = (char)c;
            i++;
        } else {
            secureFree(bf, cap); return NULL; /* invalid RLE char */
        }
    }
    bf[bfLen] = 0;
    *outLen = bfLen;
    *outCap = cap;
    return bf;
}

/* ==================================================================== */
/* Brainfuck interpreter (full tape model, all 8 commands)               */
/* ==================================================================== */
#define BF_TAPE_SIZE 65536

/* The 8 opcode bodies, one macro per canonical semantic (0=+ 1=- 2=> 3=< 4=[ 5=]
 * 6=. 7=,). Handlers share bfRun's locals (tape/ptr/i/o/pi/out/outCap/mat/pad/...).
 * BF_IMPL(sem) pastes onto BFH_<sem>, selecting the opcode at COMPILE time — so a
 * build whose DISP differs ships a different case->opcode assignment, yet every
 * build still decodes the same language. */
#define BFH_0() do { tape[ptr]++; } while (0)
#define BFH_1() do { tape[ptr]--; } while (0)
#define BFH_2() do { if (ptr + 1 >= BF_TAPE_SIZE) { fail = 1; } else ptr++; } while (0)
#define BFH_3() do { if (ptr - 1 < 0) { fail = 1; } else ptr--; } while (0)
#define BFH_4() do { if (tape[ptr] == 0) i = (size_t)match[i]; } while (0)
#define BFH_5() do { if (tape[ptr] != 0) i = (size_t)match[i]; } while (0)
#define BFH_6() do { if (o >= outCap) { fail = 1; } else out[o++] = tape[ptr]; } while (0)
#define BFH_7() do { tape[ptr] = (pi < padLen) ? pad[pi++] : 0; } while (0)
#define BFH_CAT2(a, b) a##b
#define BFH_CAT(a, b)  BFH_CAT2(a, b)
#define BF_IMPL(sem)   BFH_CAT(BFH_, sem)()

/* Runs the Brainfuck program. Every '.' emits tape[ptr]; ',' reads one byte
 * from `pad` (advancing *padUsed; EOF reads 0). Loops honour bracket matching.
 * Returns 0 on success, -1 on malformed program / buffer / tape overflow. */
static int bfRun(const char* bf, size_t bfLen,
                 const unsigned char* pad, size_t padLen, size_t* padUsed,
                 unsigned char* out, size_t outCap, size_t* outLen) {
    unsigned char* tape = (unsigned char*)secureAlloc(BF_TAPE_SIZE);
    if (tape == NULL) return -1;
    const size_t ixBytes = ((size_t)bfLen + 1) * sizeof(int);
    int* match = (int*)secureAlloc(ixBytes);
    if (match == NULL) { secureFree(tape, BF_TAPE_SIZE); return -1; }
    int* stack = (int*)secureAlloc(ixBytes);
    if (stack == NULL) {
        secureFree(match, ixBytes);
        secureFree(tape, BF_TAPE_SIZE);
        return -1;
    }
    int sp = 0;
    for (size_t j = 0; j < bfLen; j++) match[j] = -1;
    for (size_t j = 0; j < bfLen; j++) {
        int op = bfOpIndex((unsigned char)bf[j]);
        if (op == 4) {            /* '[' */
            stack[sp++] = (int)j;
        } else if (op == 5) {     /* ']' */
            if (sp == 0) {
                secureFree(stack, ixBytes); secureFree(match, ixBytes);
                secureFree(tape, BF_TAPE_SIZE);
                return -1;
            }
            int open = stack[--sp];
            match[open] = (int)j;
            match[j] = open;
        }
    }
    if (sp != 0) {
        secureFree(stack, ixBytes); secureFree(match, ixBytes);
        secureFree(tape, BF_TAPE_SIZE);
        return -1;
    }
    /* NOTE: `stack` is deliberately NOT freed here — it is wiped+unmapped
     * exactly once in the common exit paths below. A premature free would
     * leave a dangling pointer that the later secureFree() would memset on
     * already-unmapped memory (write AV). */

    size_t o = 0;
    size_t pi = 0;
    int ptr = 0;
    size_t i = 0;
    int fail = 0;
    int stepOverflow = 0;
    int64_t steps = 0;
    const int64_t BF_MAX_STEPS = ((int64_t)1 << 31); /* runaway-loop guard (④) */
    while (i < bfLen) {
        if (++steps > BF_MAX_STEPS) { stepOverflow = 1; break; }
        int op = bfOpIndex((unsigned char)bf[i]);  /* canonical semantic (0..7) or -1 */
        /* Data-driven dispatch: semantic op is dealt to handler slot DISP_TAB[op].
         * Case k performs opcode DINV_TAB[k]; since DINV is DISP's inverse, slot
         * DISP_TAB[op] lands on the case executing opcode `op`. Static analysis
         * must invert the hidden per-build DISP before it can bind a case to a
         * Brainfuck command. */
        int slot = (op >= 0 && op < 8) ? DISP_TAB[op] : -1;
        switch (slot) {
            case 0: BF_IMPL(KBOX_BF_DINV_0); break;
            case 1: BF_IMPL(KBOX_BF_DINV_1); break;
            case 2: BF_IMPL(KBOX_BF_DINV_2); break;
            case 3: BF_IMPL(KBOX_BF_DINV_3); break;
            case 4: BF_IMPL(KBOX_BF_DINV_4); break;
            case 5: BF_IMPL(KBOX_BF_DINV_5); break;
            case 6: BF_IMPL(KBOX_BF_DINV_6); break;
            case 7: BF_IMPL(KBOX_BF_DINV_7); break;
            default: if (op < 0) fail = 1; break; /* unknown unit -> not BF */
        }
        if (fail) {
            secureFree(stack, ixBytes); secureFree(match, ixBytes);
            secureFree(tape, BF_TAPE_SIZE);
            return -1;
        }
        i++;
    }
    if (stepOverflow) {
        secureFree(stack, ixBytes); secureFree(match, ixBytes);
        secureFree(tape, BF_TAPE_SIZE);
        return -1;
    }
    *outLen = o;
    *padUsed = pi;
    secureFree(stack, ixBytes);
    secureFree(match, ixBytes);
    secureFree(tape, BF_TAPE_SIZE);
    return 0;
}

/* ==================================================================== */
/* Self-contained raw-DEFLATE inflate (RFC 1951)                         */
/* ==================================================================== */
typedef struct {
    const unsigned char* in;
    size_t inLen;
    size_t pos;      /* byte position */
    int bitbuf;      /* bit accumulator (LSB-first) */
    int bitcnt;      /* valid bits in bitbuf */
    int err;
} zbits_t;

static void bitsInit(zbits_t* z, const unsigned char* in, size_t inLen) {
    z->in = in; z->inLen = inLen; z->pos = 0; z->bitbuf = 0; z->bitcnt = 0; z->err = 0;
}

static int bitsGet(zbits_t* z, int n) {
    while (z->bitcnt < n) {
        if (z->pos >= z->inLen) { z->err = 1; return 0; }
        z->bitbuf |= (int)z->in[z->pos++] << z->bitcnt;
        z->bitcnt += 8;
    }
    int v = z->bitbuf & ((1 << n) - 1);
    z->bitbuf >>= n;
    z->bitcnt -= n;
    return v;
}

/* Canonical Huffman decode table (puff-style). */
typedef struct {
    int count[16];   /* count[l] = number of codes of length l (l = 1..15) */
    int symbol[288 + 32];
    int maxBits;
} huff_t;

/* Builds a canonical Huffman table from code lengths (RFC 1951 3.2.2).
 * Returns 0 on success, -1 on oversubscribed/invalid input. */
static int huffBuild(huff_t* h, const unsigned char* lens, int n) {
    int l;
    memset(h->count, 0, sizeof(h->count));
    h->maxBits = 0;
    for (l = 0; l < n; l++) {
        int len = lens[l];
        if (len > 15) return -1;
        if (len > 0) {
            h->count[len]++;
            if (len > h->maxBits) h->maxBits = len;
        }
    }
    /* Verify the code set is complete (not oversubscribed). */
    int left = 1;
    for (l = 1; l <= h->maxBits; l++) {
        left <<= 1;
        left -= h->count[l];
        if (left < 0) return -1;
    }
    /* Canonical symbol ordering: shorter lengths first, symbols in order. */
    int offs[16];
    offs[1] = 0;
    for (l = 1; l < 15; l++) offs[l + 1] = offs[l] + h->count[l];
    for (l = 0; l < n; l++) {
        int len = lens[l];
        if (len == 0) continue;
        h->symbol[offs[len]++] = l;
    }
    return 0;
}

/* Decodes one symbol, or -1 on error / incomplete code. */
static int huffDecode(zbits_t* z, const huff_t* h) {
    int code = 0;
    int first = 0;
    int index = 0;
    int len;
    for (len = 1; len <= h->maxBits; len++) {
        int bit = bitsGet(z, 1);
        if (z->err) return -1;
        code |= bit;
        int count = h->count[len];
        if (code - first < count) {
            return h->symbol[index + (code - first)];
        }
        index += count;
        first = (first + count) << 1;
        code <<= 1;
    }
    z->err = 1; /* incomplete code */
    return -1;
}

/* RFC 1951 3.2.5 length / distance bases + extra bits. */
static const int LEN_BASE[29]  = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
static const int LEN_EXTRA[29] = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
static const int DIST_BASE[30] = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
static const int DIST_EXTRA[30]= {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};

/* RFC 1951 3.2.6 fixed code lengths. */
static void fixedTables(unsigned char ll[288], unsigned char dist[30]) {
    int i;
    for (i = 0; i < 144; i++) ll[i] = 8;
    for (i = 144; i < 256; i++) ll[i] = 9;
    for (i = 256; i < 280; i++) ll[i] = 7;
    for (i = 280; i < 288; i++) ll[i] = 8;
    for (i = 0; i < 30; i++) dist[i] = 5;
}

/* inflateInto(): inflates a raw-DEFLATE stream (no zlib header) directly into
 * a caller-provided buffer of capacity outCap, with no allocation or growth —
 * the ONLY inflate path, so plaintext lands straight in the guard-wrapped
 * exposure box (classes) or an exact-size secure buffer (resources). The exact
 * decoded size is known from the KBF2 index, so a stream that would overflow
 * outCap (corruption or a tampered chunk) is simply refused. Returns 0 on
 * success, -1 on corrupt input or overflow; *outLen is set only on success. */
static int inflateInto(const unsigned char* in, size_t inLen,
                       unsigned char* out, size_t outCap, size_t* outLen) {
    zbits_t z;
    bitsInit(&z, in, inLen);
    huff_t ll, dist;
    size_t o = 0;
    int final = 0;

    while (!final) {
        final = bitsGet(&z, 1);
        int type = bitsGet(&z, 2);
        if (z.err) return -1;
        if (type == 0) {
            /* Stored block: byte-aligned, LEN/NLEN. */
            z.bitcnt = 0; z.bitbuf = 0;
            if (z.pos + 4 > z.inLen) return -1;
            int len = z.in[z.pos] | (z.in[z.pos + 1] << 8);
            int nlen = z.in[z.pos + 2] | (z.in[z.pos + 3] << 8);
            z.pos += 4;
            if ((len & 0xFFFF) != ((~nlen) & 0xFFFF)) return -1;
            if (z.pos + (size_t)len > z.inLen) return -1;
            if (o + (size_t)len > outCap) return -1;
            memcpy(out + o, z.in + z.pos, (size_t)len);
            o += (size_t)len;
            z.pos += (size_t)len;
        } else if (type == 1 || type == 2) {
            if (type == 1) {
                unsigned char fll[288], fdist[30];
                fixedTables(fll, fdist);
                if (huffBuild(&ll, fll, 288)) return -1;
                if (huffBuild(&dist, fdist, 30)) return -1;
            } else {
                int hlit = bitsGet(&z, 5) + 257;
                int hdist = bitsGet(&z, 5) + 1;
                int hclen = bitsGet(&z, 4) + 4;
                if (z.err || hlit > 286 || hdist > 30) return -1;
                static const int ORDER[19] = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
                unsigned char clens[19];
                int i;
                for (i = 0; i < 19; i++) clens[i] = 0;
                for (i = 0; i < hclen; i++) clens[ORDER[i]] = (unsigned char)bitsGet(&z, 3);
                huff_t clenHuff;
                if (huffBuild(&clenHuff, clens, 19)) return -1;

                unsigned char lens[288 + 32];
                int nlen = hlit + hdist;
                int cur = 0;
                while (cur < nlen) {
                    int sym = huffDecode(&z, &clenHuff);
                    if (sym < 0) return -1;
                    if (sym < 16) {
                        lens[cur++] = (unsigned char)sym;
                    } else if (sym == 16) {
                        if (cur == 0) return -1;
                        int rep = bitsGet(&z, 2) + 3;
                        if (cur + rep > nlen) return -1;
                        unsigned char prev = lens[cur - 1];
                        while (rep-- > 0) lens[cur++] = prev;
                    } else if (sym == 17) {
                        int rep = bitsGet(&z, 3) + 3;
                        if (cur + rep > nlen) return -1;
                        while (rep-- > 0) lens[cur++] = 0;
                    } else { /* 18 */
                        int rep = bitsGet(&z, 7) + 11;
                        if (cur + rep > nlen) return -1;
                        while (rep-- > 0) lens[cur++] = 0;
                    }
                }
                if (huffBuild(&ll, lens, hlit)) return -1;
                if (huffBuild(&dist, lens + hlit, hdist)) return -1;
            }
            for (;;) {
                int sym = huffDecode(&z, &ll);
                if (sym < 0) return -1;
                if (sym == 256) break;
                if (sym < 256) {
                    if (o >= outCap) return -1;
                    out[o++] = (unsigned char)sym;
                } else {
                    int li = sym - 257;
                    if (li >= 29) return -1;
                    int len = LEN_BASE[li] + bitsGet(&z, LEN_EXTRA[li]);
                    int dsym = huffDecode(&z, &dist);
                    if (dsym < 0 || dsym >= 30) return -1;
                    int d = DIST_BASE[dsym] + bitsGet(&z, DIST_EXTRA[dsym]);
                    if (d <= 0 || (size_t)d > o) return -1;
                    if (o + (size_t)len > outCap) return -1;
                    size_t src = o - (size_t)d;
                    int k;
                    for (k = 0; k < len; k++) out[o++] = out[src + k];
                }
            }
        } else {
            return -1; /* reserved block type 3 */
        }
    }
    *outLen = o;
    return 0;
}

/* ==================================================================== */
/* Native decode state (native heap only — never mirrored to Java)       */
/* ==================================================================== */
typedef struct {
    unsigned char* rle;      /* whole classes.bf.rle archive (header + chunks) */
    size_t rleLen;
    size_t rleCap;           /* page-rounded allocation size (for protection) */
    int    indexOk;
} bf_state_t;

/* The native decode state. Declared here (before rleProtect, which toggles
 * the archive's page protection) so the archive can be made NOACCESS as soon
 * as it is stored; the parse/read helpers below only touch it via JNI calls. */
static bf_state_t g_state;

static void wipeBuffer(void* p, size_t n) {
    if (p != NULL && n > 0) memset(p, 0, n);
}

/* D9: non-elidable secure clear. A plain memset on a buffer that is about to be
 * unmapped/freed can be dead-code-eliminated (or partially hoisted) by an
 * optimizing compiler, leaving plaintext crumbs in the dump. Volatile byte-wise
 * stores are observable side effects the optimizer cannot remove, so the wipe
 * is guaranteed to execute. Used for every plaintext exposure box and any
 * transient class-byte buffer so a procdump/capture sees maximal erase. */
static void kbox_secmem_clear(void* p, size_t n) {
    if (p == NULL || n == 0) return;
    volatile unsigned char* v = (volatile unsigned char*)p;
    for (size_t i = 0; i < n; i++) v[i] = 0;
}

/* ==================================================================== */
/* Idle NOACCESS protection of the encoded archive                       */
/* ==================================================================== */
/* The whole classes.bf.rle payload (encoded classes + the KBF2 name index)
 * is kept mprotect(PROT_NONE) / VirtualProtect(PAGE_NOACCESS) whenever it is
 * NOT being decoded. A native memory scanner (ReadProcessMemory, /proc/pid/mem
 * page walker, debugger read) therefore cannot even read the encoded blob or
 * enumerate the class index while the app idles — it is only transiently made
 * writable for the few microseconds of one class define. */
static int g_rleWritable = 0;

static void rleProtect(int rw) {
    if (g_state.rle == NULL || g_state.rleCap == 0) return;
    if (rw == g_rleWritable) return;
#if defined(_WIN32)
    DWORD old;
    if (VirtualProtect(g_state.rle, (SIZE_T)g_state.rleCap,
                       rw ? PAGE_READWRITE : PAGE_NOACCESS, &old)) {
        g_rleWritable = rw;
    }
#else
    if (mprotect(g_state.rle, g_state.rleCap,
                 rw ? (PROT_READ | PROT_WRITE) : PROT_NONE) == 0) {
        g_rleWritable = rw;
    }
#endif
}

/* Embedded KBF2 index entry/table types + forward declarations. The helpers
 * are defined after the parse; the typedefs sit here so the prototypes can
 * reference them (C requires the struct tags to be visible at the prototype). */
typedef struct kbf2_ent_s {
    const unsigned char* name;  /* points into g_state.rle (header region) */
    int    nameLen;
    size_t rleOff;              /* absolute offset of this entry's RLE chunk */
    size_t rleLen;
    size_t rawLen;              /* expected plaintext length after inflate */
} kbf2_ent_t;

typedef struct kbf2_itab_s {
    kbf2_ent_t* e;
    int n;
} kbf2_itab_t;

static void indexClear(void);
static int indexParse(void);
static const kbf2_ent_t* indexFind(const kbf2_itab_t* t, const char* name);
static int decodeEntryInto(const kbf2_ent_t* it,
                           unsigned char* dst, size_t dstCap, size_t* outLen);
/* Agent/debugger gate (defined after the exports): per-class fail-closed
 * re-check. Forward-declared here so the JNI exports can call it. */
static int kbox_gateCheck(void);
/* Runtime attach watchdog (defined after the exports). */
static void startWatchdog(void);

/* ==================================================================== */
/* Embedded KBF2 name->chunk index (parsed from the archive head)        */
/* ==================================================================== */
static kbf2_itab_t g_classes;
static kbf2_itab_t g_res;

static uint32_t rdU32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* Frees the in-memory index tables. Safe to call on wipe()/re-parse. */
static void indexClear(void) {
    free(g_classes.e); g_classes.e = NULL; g_classes.n = 0;
    free(g_res.e);     g_res.e = NULL;     g_res.n = 0;
    g_state.indexOk = 0;
}

/* Parses the KBF2 header at the head of g_state.rle:
 *   [4 "KBF2"][u32 classCount][class records][u32 resCount][res records]
 * Record = u32 nameLen, utf8 name, u32 rleOff, u32 rleLen, u32 rawLen.
 * Names/offsets live inside g_state.rle; Java never sees this map. */
/* Compile-time XOR masks for the container header magic. The stored bytes are
 * NOT the ASCII "KBF2" (see BrainfuckPacker.writeMagic); both sides hold only the
 * masked bytes, so neither the jar's container header nor the native binary's
 * rodata contains a grep-able "KBF2" fingerprint string (坑④: container magic not
 * directly readable). The header is still validated by checking masked==expected. */
#define KBF2_M0 ((unsigned char)('K' ^ 0xA5))   /* 'K'^0xA5 */
#define KBF2_M1 ((unsigned char)('B' ^ 0x3C))   /* 'B'^0x3C */
#define KBF2_M2 ((unsigned char)('F' ^ 0x77))   /* 'F'^0x77 */
#define KBF2_M3 ((unsigned char)('2' ^ 0xD8))   /* '2'^0xD8 */

static int indexParse(void) {
    indexClear();
    const unsigned char* r = g_state.rle;
    size_t rlen = g_state.rleLen;
    if (rlen < 8) return -1;
    if (r[0] != KBF2_M0 || r[1] != KBF2_M1 || r[2] != KBF2_M2 || r[3] != KBF2_M3) return -1;
    size_t p = 4;
    uint32_t cc = rdU32(r + p); p += 4;
    if (cc > 1024u * 1024u) return -1;
    kbf2_ent_t* ce = (kbf2_ent_t*)malloc(((size_t)cc) * sizeof(kbf2_ent_t));
    if (cc > 0 && ce == NULL) return -1;
    memset(ce, 0, ((size_t)cc) * sizeof(kbf2_ent_t));
    for (uint32_t i = 0; i < cc; i++) {
        if (p + 4 > rlen) { free(ce); return -1; }
        uint32_t nl = rdU32(r + p); p += 4;
        if (p + (size_t)nl + 12 > rlen) { free(ce); return -1; }
        ce[i].name = r + p; ce[i].nameLen = (int)nl; p += (size_t)nl;
        uint32_t off = rdU32(r + p); p += 4;
        uint32_t ln  = rdU32(r + p); p += 4;
        ce[i].rawLen = (size_t)rdU32(r + p); p += 4;
        if ((size_t)off + (size_t)ln > rlen) { free(ce); return -1; }
        ce[i].rleOff = (size_t)off;
        ce[i].rleLen = (size_t)ln;
    }
    g_classes.e = ce; g_classes.n = (int)cc;
    if (p + 4 > rlen) { return -1; }
    uint32_t rc = rdU32(r + p); p += 4;
    if (rc > 1024u * 1024u) return -1;
    kbf2_ent_t* re = (kbf2_ent_t*)malloc(((size_t)rc) * sizeof(kbf2_ent_t));
    if (rc > 0 && re == NULL) { indexClear(); return -1; }
    memset(re, 0, ((size_t)rc) * sizeof(kbf2_ent_t));
    for (uint32_t i = 0; i < rc; i++) {
        if (p + 4 > rlen) { free(re); indexClear(); return -1; }
        uint32_t nl = rdU32(r + p); p += 4;
        if (p + (size_t)nl + 12 > rlen) { free(re); indexClear(); return -1; }
        re[i].name = r + p; re[i].nameLen = (int)nl; p += (size_t)nl;
        uint32_t off = rdU32(r + p); p += 4;
        uint32_t ln  = rdU32(r + p); p += 4;
        re[i].rawLen = (size_t)rdU32(r + p); p += 4;
        if ((size_t)off + (size_t)ln > rlen) { free(re); indexClear(); return -1; }
        re[i].rleOff = (size_t)off;
        re[i].rleLen = (size_t)ln;
    }
    g_res.e = re; g_res.n = (int)rc;
    g_state.indexOk = 1;
    return 0;
}

/* Finds an entry by exact name. Returns NULL when absent (NOT an error). */
static const kbf2_ent_t* indexFind(const kbf2_itab_t* t, const char* name) {
    int nl = (int)strlen(name);
    for (int i = 0; i < t->n; i++) {
        if (t->e[i].nameLen == nl && memcmp(t->e[i].name, name, (size_t)nl) == 0)
            return &t->e[i];
    }
    return NULL;
}

/* ==================================================================== */
/* On-demand per-entry decode (RLE -> BF -> tape -> deflate -> inflate)  */
/* Every intermediate buffer is zeroed and freed before returning. The    */
/* plaintext is written DIRECTLY into the caller-provided destination     */
/* (for classes, the guard-page-wrapped exposure box; for resources, the  */
/* exact-size secure buffer handed to Java), so no intermediate unguarded */
/* allocation ever holds the plaintext during the decode frame. No global */
/* jar blob ever exists.                                                  */
/* ==================================================================== */
/* Decodes entry `it` into dst (capacity dstCap) and sets *outLen. The
 * DEFLATE stream is inflated straight into dst via inflateInto; a stream
 * that would overflow dstCap (corruption or a tampered chunk) is refused,
 * and a stream whose length mismatches the index's rawLen is refused too. */
static int decodeEntryInto(const kbf2_ent_t* it,
                           unsigned char* dst, size_t dstCap, size_t* outLen) {
    *outLen = 0;
    /* Derive this chunk's operator table from the per-build seed and this
     * entry's absolute RLE offset — the same (seed, rleOff) the packer encoded
     * with. The table exists only in this native decode frame. */
    configureChunkOps(KBOX_BF_SEED, (uint32_t)it->rleOff);
    const unsigned char* rle = g_state.rle + it->rleOff;

    size_t bfLen = 0, bfCap = 0;
    char* bf = rleDecode(rle, it->rleLen, &bfLen, &bfCap);
    if (bf == NULL) return -1;

    /* Input pad: the Brainfuck preamble reads exactly one ',' byte whose value
     * is discarded by the following [-] — so a single zero pad suffices. */
    static const unsigned char pad[1] = { 0 };
    size_t padUsed = 0;
    size_t defCap = roundPage(bfLen + 16);
    unsigned char* defl = (unsigned char*)secureAlloc(defCap);
    if (defl == NULL) { secureFree(bf, bfCap); return -1; }
    size_t defLen = 0;
    if (bfRun(bf, bfLen, pad, 1, &padUsed, defl, defCap, &defLen) != 0) {
        secureFree(defl, defCap);
        secureFree(bf, bfCap);
        return -1;
    }
    /* Wipe + unmap the Brainfuck text — never leave a program around. */
    secureFree(bf, bfCap);

    size_t o = 0;
    int rc = inflateInto(defl, defLen, dst, dstCap, &o);
    /* Wipe + unmap the DEFLATE stream immediately after inflate. */
    secureFree(defl, defCap);
    if (rc != 0 || o != it->rawLen) return -1; /* corrupt or tampered chunk */
    *outLen = o;
    return 0;
}

/* ==================================================================== */
/* JNI exports (only JNI_OnLoad is exported; everything else is bound    */
/* dynamically via RegisterNatives below and compiled with               */
/* -fvisibility=hidden, so the export table holds a single entry point   */
/* and no function maps to a Java method by name)                        */
/* ==================================================================== */

/* Forward declarations for the dynamically-registered native methods. */
static jint JNICALL kbox_bf_init(JNIEnv* env, jclass cls, jbyteArray rle);
static jint JNICALL kbox_bf_initDirect(JNIEnv* env, jclass cls, jobject buf, jint len);
static jclass JNICALL kbox_bf_defineClassFromBF(JNIEnv* env, jobject thisLoader, jstring name);
static jobject JNICALL kbox_bf_getResourceBytes(JNIEnv* env, jobject thisLoader, jstring name);
static jboolean JNICALL kbox_bf_probeClassFromBF(JNIEnv* env, jclass cls, jstring name);
static void JNICALL kbox_bf_wipe(JNIEnv* env, jclass cls);
static void JNICALL kbox_bf_wipeResource(JNIEnv* env, jclass cls, jobject buf);
static jint JNICALL kbox_bf_selfWipeNative(JNIEnv* env, jclass cls, jint mask);
static jboolean JNICALL kbox_bf_safeBoot(JNIEnv* env, jclass cls, jobjectArray args);
static jboolean JNICALL kbox_bf_mapModule(JNIEnv* env, jclass cls, jbyteArray pe,
                                          jstring binderName);
static jstring JNICALL kbox_bf_purgeSelf(JNIEnv* env, jclass cls, jstring path);
static jbyteArray JNICALL kbox_bf_sessionEpoch(JNIEnv* env, jclass cls);

/* Java method table. The C symbols carry no Java identity: a static reader
 * of the export table (which holds only JNI_OnLoad) cannot map any function
 * to a Java method without executing the registrar. */
static const JNINativeMethod kbox_bf_methods[] = {
    { "init",              "([B)I",                          (void*)kbox_bf_init },
    { "initDirect",        "(Ljava/nio/ByteBuffer;I)I",      (void*)kbox_bf_initDirect },
    { "defineClassFromBFImpl", "(Ljava/lang/String;)Ljava/lang/Class;", (void*)kbox_bf_defineClassFromBF },
    { "getResourceBytes",  "(Ljava/lang/String;)Ljava/nio/ByteBuffer;", (void*)kbox_bf_getResourceBytes },
    { "probeClassFromBF",  "(Ljava/lang/String;)Z",          (void*)kbox_bf_probeClassFromBF },
    { "wipe",              "()V",                            (void*)kbox_bf_wipe },
    { "wipeResource",      "(Ljava/nio/ByteBuffer;)V",       (void*)kbox_bf_wipeResource },
    { "safeBoot",          "([Ljava/lang/String;)Z",         (void*)kbox_bf_safeBoot },
    { "mapModule",         "([BLjava/lang/String;)Z",        (void*)kbox_bf_mapModule },
    { "purgeSelf",         "(Ljava/lang/String;)Ljava/lang/String;", (void*)kbox_bf_purgeSelf },
    { "epoch",             "()[B",                          (void*)kbox_bf_sessionEpoch },
    { "nativeSelfWipe",    "(I)I",                          (void*)kbox_bf_selfWipeNative },
};

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    (void)reserved;
    setupDumpTrap();
    startWatchdog();
    /* Bind the BfSecureLoader native methods here rather than exporting six
     * Java-named symbols. FindClass works because BfSecureLoader is the
     * Main-Class currently being initialized (its <clinit> triggered
     * NativeLoader.load() -> System.load -> JNI_OnLoad), so the class is
     * already defined under the same app class loader that loaded this lib. */
    JNIEnv* env = NULL;
    if ((*vm)->GetEnv(vm, (void**)&env, JNI_VERSION_1_8) != JNI_OK || env == NULL) {
        return JNI_ERR;
    }
    jclass cls = (*env)->FindClass(env, "com/kbox/runtime/BfSecureLoader");
    if (cls == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return JNI_ERR;
    }
    if ((*env)->RegisterNatives(env, cls, kbox_bf_methods,
            (jint)(sizeof(kbox_bf_methods) / sizeof(kbox_bf_methods[0]))) != 0) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        return JNI_ERR;
    }
    return JNI_VERSION_1_8;
}

/* int BfSecureLoader.init(byte[] rle) — dynamically registered, not exported. */
static jint JNICALL kbox_bf_init
    (JNIEnv* env, jclass cls, jbyteArray rle) {
    (void)cls;
    if (rle == NULL) return -1;
    jsize n = (*env)->GetArrayLength(env, rle);
    jbyte* data = (*env)->GetByteArrayElements(env, rle, NULL);
    if (data == NULL) return -1;

    /* Make the previous archive writable, wipe it, unmap it. */
    rleProtect(1);
    if (g_state.rle != NULL) {
        secureFree(g_state.rle, g_state.rleCap);
        g_state.rle = NULL; g_state.rleLen = 0; g_state.rleCap = 0;
        g_rleWritable = 0;
    }
    /* Store the archive in a dedicated page-aligned range so it can be
     * protected NOACCESS while idle (see rleProtect). */
    size_t alloc = (size_t)n + 1;
    g_state.rle = (unsigned char*)secureAlloc(alloc);
    if (g_state.rle == NULL) {
        (*env)->ReleaseByteArrayElements(env, rle, data, JNI_ABORT);
        return -1;
    }
    memcpy(g_state.rle, data, (size_t)n);
    g_state.rle[n] = 0;
    /* JNI_ABORT: the Java byte[] is RLE noise anyway, do not copy back. */
    (*env)->ReleaseByteArrayElements(env, rle, data, JNI_ABORT);
    g_state.rleLen = (size_t)n;
    g_state.rleCap = roundPage(alloc);
    g_state.indexOk = 0;
    /* The archive is encoded noise; keep it unreadable when idle. */
    rleProtect(0);
    return (jint)n;
}

/* Direct-buffer variant of the above: the whole blob is streamed off-heap
 * (java.nio.ByteBuffer.allocateDirect) so it never rests in the Java heap.
 * Native copies it into page-secure memory, then wipes the out buffer. The
 * direct buffer trick also removes the intermediate Java byte[] that the
 * byte[]-based path could leave resident until GC. */
static jint JNICALL kbox_bf_initDirect
    (JNIEnv* env, jclass cls, jobject buf, jint len) {
    (void)cls;
    if (buf == NULL) return -1;
    unsigned char* data = (unsigned char*)(*env)->GetDirectBufferAddress(env, buf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, buf);
    if (data == NULL || len < 0 || (jlong)len > cap) return -1;
    size_t n = (size_t)len;

    rleProtect(1);
    if (g_state.rle != NULL) {
        secureFree(g_state.rle, g_state.rleCap);
        g_state.rle = NULL; g_state.rleLen = 0; g_state.rleCap = 0;
        g_rleWritable = 0;
    }
    size_t alloc = n + 1;
    g_state.rle = (unsigned char*)secureAlloc(alloc);
    if (g_state.rle == NULL) return -1;
    memcpy(g_state.rle, data, n);
    g_state.rle[n] = 0;
    /* Wipe the out buffer immediately so no noise lingers off-heap behind a
     * still-Java-reachable direct buffer. */
    memset(data, 0, (size_t)n);
    g_state.rleLen = n;
    g_state.rleCap = roundPage(alloc);
    g_state.indexOk = 0;
    rleProtect(0);
    return (jint)n;
}

/* Class<?> BfSecureLoader.defineClassFromBF(String name) — class-only, name-based.
 * The name is resolved through the embedded KBF2 index; an (rle) offset is
 * never accepted from Java, so a reflected caller cannot dump arbitrary chunks.
 * The class's plaintext is decoded on demand, defined, and unmap-wiped
 * immediately. */
static jclass kbox_defineClassImpl(JNIEnv* env, jobject thisLoader, jstring name) {
    jclass ex6 = NULL;
    /* Per-class native re-gate: an agent attached after the boot gate (dynamic
     * attach) or a bootstrap that had safeBoot() stripped is caught here, and
     * the whole decode state is wiped (fail-closed). */
    if (kbox_gateCheck()) {
        ex6 = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }
    if (thisLoader == NULL) {
        ex6 = (*env)->FindClass(env, "java/lang/NullPointerException");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }
    if (g_state.rle == NULL || !g_state.indexOk) {
        if (indexParse() != 0) {
            ex6 = (*env)->FindClass(env, "java/io/IOException");
            if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
            return NULL;
        }
    }
    if (name == NULL) {
        ex6 = (*env)->FindClass(env, "java/io/IOException");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }
    const char* nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) return NULL;
    const kbf2_ent_t* it = indexFind(&g_classes, nameStr);
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    if (it == NULL) {
        ex6 = (*env)->FindClass(env, "java/lang/ClassNotFoundException");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }

    /* Decode exactly this one class DIRECTLY into a guarded exposure box, so
     * the plaintext never rests in an unguarded allocation: any out-of-bounds
     * scanner sweep faults on a guard page and the VEH hard-terminates the
     * process — the decode window itself becomes an anti-dump tripwire. */
    kbox_exbox_t box;
    if (kbox_exboxMake(&box, it->rawLen) != 0) {
        ex6 = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }
    size_t rawLen = 0;
    if (decodeEntryInto(it, box.data, box.dataCap, &rawLen) != 0) {
        kbox_exboxFree(&box);
        ex6 = (*env)->FindClass(env, "java/io/IOException");
        if (ex6 != NULL) (*env)->ThrowNew(env, ex6, "KBox");
        return NULL;
    }
    /* Name is the JNI-internal name already (slashes); pass NULL so the VM
     * derives it from the CAFEBABE bytecode rather than trusting caller input. */
    jclass c = (*env)->DefineClass(env, NULL, thisLoader,
                                   (const jbyte*)box.data, (jsize)rawLen);
    /* H3.1: flush the instruction cache over the just-consumed decode box
     * before freeing it, so any JIT pre-fetch / decode side-channel of the
     * class's transient bytes is invalidated the instant after DefineClass
     * commits them to metaspace, and nothing re-readable survives in the
     * code-stream. kbox_exboxFree below then wipes + unmaps the whole box. */
    FlushInstructionCache(GetCurrentProcess(), box.data, (SIZE_T)rawLen);
    /* The plaintext never rests: wipe + unmap the full exposure box (guard
     * pages included) immediately after the class bytes are committed to
     * metaspace, so no copy lingers in the process. */
    kbox_exboxFree(&box);
    return c;
}

static jclass JNICALL kbox_bf_defineClassFromBF
    (JNIEnv* env, jobject thisLoader, jstring name) {
    /* Only the few microseconds of this one define have the archive readable. */
    rleProtect(1);
    jclass r = kbox_defineClassImpl(env, thisLoader, name);
    rleProtect(0);
    return r;
}

/* byte[] BfSecureLoader.getResourceBytes(String name) — non-class resources
 * (images, configs, ...) by exact name; returns NULL when unknown. Resources are
 * decoded on demand and copied to the Java heap; the native plaintext is
 * wipe+unmap'd immediately after the copy (only CLASS bytecode stays
 * temporarily, and it too is wiped in defineClassFromBF). */
static jobject kbox_getResourceImpl(JNIEnv* env, jobject thisLoader, jstring name) {
    (void)thisLoader;
    /* Per-class native re-gate, same as defineClassFromBF. */
    if (kbox_gateCheck()) {
        jclass ex = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (ex != NULL) (*env)->ThrowNew(env, ex, "KBox");
        return NULL;
    }
    if (g_state.rle == NULL || !g_state.indexOk) {
        if (indexParse() != 0) {
            jclass ex = (*env)->FindClass(env, "java/io/IOException");
            if (ex != NULL) (*env)->ThrowNew(env, ex, "KBox");
            return NULL;
        }
    }
    if (name == NULL) return NULL;
    const char* nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) return NULL;
    /* FAIL-CLOSED for ".class" reads: a class's plaintext must never be copied
     * out of the blob into a Java byte[] (that is exactly how a native memory
     * scanner ends up finding the full plaintext class resting in the heap).
     * Self-integrity checks must use probeClassFromBF() instead, which decodes
     * transiently in native secure memory and returns a boolean. */
    size_t nl = strlen(nameStr);
    if (nl > 6 && memcmp(nameStr + nl - 6, ".class", 6) == 0) {
        (*env)->ReleaseStringUTFChars(env, name, nameStr);
        return NULL;
    }
    const kbf2_ent_t* it = indexFind(&g_res, nameStr);
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    if (it == NULL) return NULL;

    /* Decode DIRECTLY into an exact-size secure block and serve it as an
     * OFF-HEAP direct ByteBuffer — never a Java heap byte[]: the plaintext
     * must not rest in the heap where a heap dump / native memory scanner
     * could find it, and no intermediate decode buffer exists to be scanned.
     * wipeResource() wipes + unmaps the whole page-rounded range from the
     * buffer's exposed capacity alone. */
    size_t rawLen = it->rawLen;
    unsigned char* buf = (unsigned char*)secureAlloc(rawLen);
    if (buf == NULL) return NULL;
    size_t outLen = 0;
    if (decodeEntryInto(it, buf, rawLen, &outLen) != 0) {
        secureFree(buf, rawLen);
        return NULL;
    }
    jobject bb = (*env)->NewDirectByteBuffer(env, buf, (jlong)rawLen);
    if (bb == NULL) { secureFree(buf, rawLen); return NULL; }
    return bb;
}

static jobject JNICALL kbox_bf_getResourceBytes
    (JNIEnv* env, jobject thisLoader, jstring name) {
    rleProtect(1);
    jobject r = kbox_getResourceImpl(env, thisLoader, name);
    rleProtect(0);
    return r;
}

/* void BfSecureLoader.wipeResource(ByteBuffer buf)
 *
 * Wipes + unmaps the off-heap direct buffer that getResourceBytes returned.
 * The buffer was allocated with secureAlloc(len) — one page-rounded range — so
 * freeing it from its exposed capacity alone is exact. The resource stream
 * calls this as soon as the buffer is fully consumed or closed (whichever
 * comes first), so the plaintext's address space ceases to exist promptly. */
static void JNICALL kbox_bf_wipeResource(JNIEnv* env, jclass cls, jobject buf) {
    (void)env; (void)cls;
    if (buf == NULL) return;
    void* addr = (*env)->GetDirectBufferAddress(env, buf);
    jlong cap = (*env)->GetDirectBufferCapacity(env, buf);
    if (addr != NULL && cap > 0) {
        secureFree(addr, (size_t)cap);
    }
}

/* boolean BfSecureLoader.probeClassFromBF(String name)
 *
 * Existence + integrity probe for a CLASS without ever materialising its
 * plaintext into the Java heap. This is the anti-leak replacement for the old
 * self-check pattern of reading "<cls>.class" via getResourceBytes(): that path
 * decoded the class and copied a full jbyteArray into the Java heap, leaving the
 * complete plaintext resting in process memory (findable by a native memory
 * scanner). probeClassFromBF instead decodes the entry entirely in native secure
 * memory, validates its expected length, wipe+unmaps it, and returns one boolean
 * — no plaintext byte ever reaches the Java heap. A trailing ".class" is
 * tolerated and stripped, so callers may pass either the internal name or the
 * resource-style name. */
static jboolean kbox_probeClassImpl(JNIEnv* env, jstring name) {
    /* Per-class native re-gate, same as defineClassFromBF. */
    if (kbox_gateCheck()) {
        jclass ex = (*env)->FindClass(env, "java/lang/IllegalStateException");
        if (ex != NULL) (*env)->ThrowNew(env, ex, "KBox");
        return JNI_FALSE;
    }
    if (g_state.rle == NULL || !g_state.indexOk) {
        if (indexParse() != 0) return JNI_FALSE;
    }
    if (name == NULL) return JNI_FALSE;
    const char* nameStr = (*env)->GetStringUTFChars(env, name, NULL);
    if (nameStr == NULL) return JNI_FALSE;
    /* Strip an optional ".class" suffix so both name styles are accepted. */
    size_t nl = strlen(nameStr);
    if (nl > 6 && memcmp(nameStr + nl - 6, ".class", 6) == 0) nl -= 6;
    const kbf2_ent_t* it = NULL;
    if (g_classes.n > 0 && g_classes.e != NULL) {
        for (int i = 0; i < g_classes.n; i++) {
            if (g_classes.e[i].nameLen == (int)nl &&
                memcmp(g_classes.e[i].name, nameStr, nl) == 0) {
                it = &g_classes.e[i];
                break;
            }
        }
    }
    (*env)->ReleaseStringUTFChars(env, name, nameStr);
    if (it == NULL) return JNI_FALSE;

    /* Decode transiently in a guarded exposure box and validate the length;
     * the plaintext never crosses into the Java heap and is wiped+unmapped
     * (guard pages included) before this call returns. */
    kbox_exbox_t box;
    if (kbox_exboxMake(&box, it->rawLen) != 0) return JNI_FALSE;
    size_t outLen = 0;
    int rc = decodeEntryInto(it, box.data, box.dataCap, &outLen);
    kbox_exboxFree(&box);
    /* decodeEntryInto already refused outLen != it->rawLen. */
    return (rc == 0) ? JNI_TRUE : JNI_FALSE;
}

static jboolean JNICALL kbox_bf_probeClassFromBF
    (JNIEnv* env, jclass cls, jstring name) {
    (void)cls;
    rleProtect(1);
    jboolean r = kbox_probeClassImpl(env, name);
    rleProtect(0);
    return r;
}

/* void BfSecureLoader.wipe() — best-effort release of native state. */
static void JNICALL kbox_bf_wipe
    (JNIEnv* env, jclass cls) {
    (void)env; (void)cls;
    rleProtect(1);
    indexClear();
    secureFree(g_state.rle, g_state.rleCap);
    g_state.rle = NULL; g_state.rleLen = 0; g_state.rleCap = 0;
    g_rleWritable = 0;
}

/* int BfSecureLoader.nativeSelfWipe(int mask) — D7 cold-section self-wipe.
 *
 * Light-scrub (any mask): flush the instruction cache for the whole process
 * (scrubs the transient class-byte icache side-channel after a define) and
 * wipe the mutable native scratch pages that static analysis might harvest.
 * Explicit purge (mask & 0xFF == 0xFF): additionally release the live encoded
 * archive (g_state.rle) — ONLY safe at JVM shutdown / after the archive is
 * no longer needed, because it is required for every remaining class define.
 * The plaintext class window itself is ALREADY wiped+unmapped by
 * kbox_exboxFree per define, so this closes the icache/scratch residue layer
 * on top of the existing .data guard-page + NOACCESS protection. */
static jint JNICALL kbox_bf_selfWipeNative
    (JNIEnv* env, jclass cls, jint mask) {
    (void)env; (void)cls;
#if defined(_WIN32)
    FlushInstructionCache(GetCurrentProcess(), NULL, 0);
#else
    /* POSIX: best-effort icache sync for the current process (mprotect loops
     * already happen on each decode; a cross-arch fsync here is optional). */
    __builtin___clear_cache((char*)0, (char*)0);
#endif
    if ((mask & 0xFF) == 0xFF) {
        rleProtect(1);
        indexClear();
        secureFree(g_state.rle, g_state.rleCap);
        g_state.rle = NULL; g_state.rleLen = 0; g_state.rleCap = 0;
        g_rleWritable = 0;
    }
    return (jint)1;
}

/* boolean BfSecureLoader.safeBoot(String[] jvmArgs)
 *
 * Opaque single-call boot gate, evaluated ENTIRELY in this native code. A
 * boot-time -javaagent (or a late-attached agent) that has already hooked
 * ClassLoader.defineClass must be refused BEFORE any protected class is defined;
 * otherwise the loader would define classes straight into the hook and the
 * attacker collects plaintext bytecode from this run (fail-closed). All marker
 * tables live in per-build native.bin, so the readable plaintext bootstrap class
 * holds no detection pattern, and every class definition re-checks natively.
 *
 *   Windows: GetModuleHandle for instrument/jdwp/dt_socket/hprof.
 *   POSIX  : scan /proc/self/maps for libinstrument/libdt_socket/libjdwp/libhprof.
 * Returns JNI_TRUE when any marker is present, JNI_FALSE otherwise.
 */

/* 1 = any agent/debugger/attach shared library mapped into this process.
 * The module-name tables ship XOR-encrypted per build (KBOX_WMODS/KBOX_MAC/
 * KBOX_LIN plus per-group keys, injected by BfNativeBuilder): each name is
 * decrypted into a stack buffer only for the duration of its own probe and
 * wiped immediately, so a strings/static scan of the shipped binary yields no
 * plaintext detection pattern. Standalone compiles fall back to the plaintext
 * tables below. */
static int kbox_probeAgentModules(void) {
#if defined(_WIN32)
    /* On Windows a clean JVM maps none of these; each only appears when the
     * corresponding agent / debugger / attach feature is actually turned on.
     * instrument.dll is the key marker for a dynamic Attach-API agent: the
     * target JVM loads it when a jar agent's agentmain runs. attach.dll is the
     * Attach bridge the attaching JVM loads (and it is also present in the
     * target when the agent round-trips), jdwp/dt_socket catch debuggers. */
#ifdef KBOX_BF_ENCRYPTED
    char buf[128];
    for (size_t i = 0; i < sizeof(KBOX_WMODS) / sizeof(KBOX_WMODS[0]); i++) {
        kbox_xdec(buf, KBOX_WMODS[i].enc, (size_t)KBOX_WMODS[i].len, KBOX_WMODS_KEY);
        int hit = (GetModuleHandleA(buf) != NULL);
        wipeBuffer(buf, sizeof(buf));
        if (hit) return 1;
    }
#else
    static const char* mods[] = {
        "instrument.dll",   /* -javaagent / Attach-API instrumentation */
        "attach.dll",       /* Attach API bridge (Windows) */
        "jdk.attach.dll",   /* Attach API native (some JDK builds) */
        "jdwp.dll",         /* -Xrunjdwp debugger */
        "dt_socket.dll",    /* JDWP socket transport */
        "dt_shmem.dll",     /* JDWP shared-memory transport */
        "hprof.dll"         /* -Xrunhprof profiler */
    };
    for (size_t i = 0; i < sizeof(mods) / sizeof(mods[0]); i++) {
        if (GetModuleHandleA(mods[i]) != NULL) return 1;
    }
#endif
    return 0;
#else
#if defined(__APPLE__)
    /* macOS has no /proc/self/maps; enumerate the dyld image list instead.
     * A mapped agent/debugger library persists for the process lifetime, so a
     * boot-time premain that already dlopen'd libinstrument shows up here, and
     * a dynamic Attach-API agent (libinstrument / libattach / jdk.attach)
     * appears as a new image the next tick. */
#ifdef KBOX_BF_ENCRYPTED
    char buf[128];
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name == NULL) continue;
        for (size_t j = 0; j < sizeof(KBOX_MAC) / sizeof(KBOX_MAC[0]); j++) {
            kbox_xdec(buf, KBOX_MAC[j].enc, (size_t)KBOX_MAC[j].len, KBOX_MAC_KEY);
            int hit = (strstr(name, buf) != NULL);
            wipeBuffer(buf, sizeof(buf));
            if (hit) return 1;
        }
    }
#else
    static const char* markers[] = {
        "libinstrument", "libattach", "jdk.attach",
        "libdt_socket",  "libjdwp",   "libhprof"
    };
    uint32_t cnt = _dyld_image_count();
    for (uint32_t i = 0; i < cnt; i++) {
        const char* name = _dyld_get_image_name(i);
        if (name == NULL) continue;
        for (size_t j = 0; j < sizeof(markers) / sizeof(markers[0]); j++) {
            if (strstr(name, markers[j]) != NULL) return 1;
        }
    }
#endif
    return 0;
#else
    /* Linux: a mapped shared library persists for the process lifetime, so
     * scanning /proc/self/maps at this early point sees boot-time agents that
     * premain has already dlopen'd, and at run time a dynamic attach agent
     * (libinstrument / libattach / a jdk.attach-module lib) appears here too. */
    FILE* f = fopen("/proc/self/maps", "r");
    if (f == NULL) return 0;  /* not a Linux we can scan; fail open */
#ifdef KBOX_BF_ENCRYPTED
    char buf[128];
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        for (size_t i = 0; i < sizeof(KBOX_LIN) / sizeof(KBOX_LIN[0]); i++) {
            kbox_xdec(buf, KBOX_LIN[i].enc, (size_t)KBOX_LIN[i].len, KBOX_LIN_KEY);
            int hit = (strstr(line, buf) != NULL);
            wipeBuffer(buf, sizeof(buf));
            if (hit) { fclose(f); return 1; }
        }
    }
#else
    static const char* markers[] = {
        "libinstrument.so", "libinstrument.dylib",
        "libattach.so",     "libattach.dylib",
        "jdk.attach",       "/jdk.attach",
        "libdt_socket.so",  "libjdwp.so",   "libjdwp.dylib",
        "libhprof.so"
    };
    char line[1024];
    while (fgets(line, sizeof(line), f) != NULL) {
        for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
            if (strstr(line, markers[i]) != NULL) {
                fclose(f);
                return 1;
            }
        }
    }
#endif
    fclose(f);
    return 0;
#endif
#endif
}

/* ==================================================================== */
/* Extended native anti-debug (beyond the module probe)                 */
/* ==================================================================== */
/* Complements kbox_probeAgentModules() with direct debugger signals.
 * Returns a bitmask:
 *   bit0 (strong): high-confidence debugger presence — IsDebuggerPresent
 *                  (PEB BeingDebugged), ProcessDebugPort /
 *                  ProcessDebugObjectHandle (ntdll resolved at run time so the
 *                  static import table stays clean), hardware breakpoints
 *                  (DR0..DR3 enabled in DR7), and on Linux TracerPid != 0.
 *                  Strong signals always hard-terminate the process.
 *   bit1 (weak)  : timing anomaly (a single-stepping / tracing debugger
 *                  inflates a short spin well past its clean sub-ms cost) or an
 *                  INT3 (0xCC) planted at the entry of a critical decoder
 *                  function. Weak signals are fail-closed (refuse to define,
 *                  wipe decode state) instead of killing the process, so a rare
 *                  scheduling hiccup degrades to a denial rather than a crash
 *                  of legitimate users.
 *
 * The .text image self-hash (kbox_selfCheck) remains the primary anti-patch
 * mechanism; this probe is defence-in-depth for signals the hash cannot see
 * (debugger presence) and for degraded builds where the hash fell back to a
 * runtime baseline. */
static int kbox_selfCheck(void); /* integrity re-hash, defined below */
static int kbox_gateCheck(void); /* fail-closed define gate, defined below */
#if defined(_WIN32)
static DWORD WINAPI kbox_watchdog(LPVOID arg); /* attach watchdog, below */
#else
static void* kbox_watchdog(void* arg);
#endif
static jboolean JNICALL kbox_bf_safeBoot(JNIEnv* env, jclass cls,
                                         jobjectArray args);

/* Monotonic clock with millisecond resolution (QPC on Windows, CLOCK_MONOTONIC
 * elsewhere). Used by the timing anomaly probe. */
static uint64_t kbox_nowMs(void) {
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    if (QueryPerformanceFrequency(&f) && QueryPerformanceCounter(&c) &&
        f.QuadPart > 0)
        return (uint64_t)((c.QuadPart * 1000) / f.QuadPart);
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/* ==================================================================== */
/* Multi-source counter (L3 time-anomaly hardening)                     */
/* ==================================================================== */
/* The old kbox_timingCheck() trusted ONE clock (kbox_nowMs). A debugger that
 * hooks/patches QueryPerformanceCounter or GetTickCount64 only has to make that
 * single source look plausible to defeat it. Here we cross-check THREE
 * independent monotonic sources around the same spin:
 *   - RDTSC  (direct TSC, calibrated per build; never a syscall)
 *   - QPC    (Windows performance counter) / clock_gettime (POSIX)
 *   - tick   (GetTickCount64 / CLOCK_MONOTONIC coarse)
 * Any two that disagree by more than a jitter window flag an anomaly. Deliberate
 * call sites don't enter the static import table (RDTSC is inline asm; QPC/tick
 * are already resolved by kbox_probeHooks' resolver where needed); an attacker
 * would have to patch all three instruments AND stay byte-identical in the
 * image self-hash region. */

#if defined(__GNUC__) || defined(__clang__)
static uint64_t kbox_rdtsc(void) {
#if defined(_MSC_VER) && !defined(__clang__)
    return __rdtsc();
#else
    uint32_t lo, hi;
#if defined(__x86_64__) || defined(_M_X64)
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
#else
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi) :: "memory");
#endif
    return ((uint64_t)hi << 32) | lo;
#endif
}
#else
static uint64_t kbox_rdtsc(void) {
#if defined(_MSC_VER)
    return __rdtsc();
#else
    return 0;
#endif
}
#endif

static uint64_t kbox_qpcNow(void) {
#if defined(_WIN32)
    LARGE_INTEGER f, c;
    if (QueryPerformanceFrequency(&f) && QueryPerformanceCounter(&c) &&
        f.QuadPart > 0)
        return (uint64_t)((long double)c.QuadPart * 1000.0L / (long double)f.QuadPart);
    return 0;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

static uint64_t kbox_tickNow(void) {
#if defined(_WIN32)
    return (uint64_t)GetTickCount64();
#else
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
#endif
}

/* TSC ticks per millisecond, calibrated once per process against QPC (which
 * is high-resolution). A frozen/hooked QPC that never advances would hang a
 * naive wait, so the calibration wait is bounded by RDTSC itself. */
static uint64_t g_tscPerMs = 0;
static uint64_t kbox_tscPerMs(void) {
    if (g_tscPerMs == 0) {
        uint64_t r0 = kbox_rdtsc();
        uint64_t w0 = kbox_qpcNow();
        uint64_t r = r0;
        /* Wait until QPC advances >= 1ms, or ~8s at 1GHz (frozen-clock bound). */
        while (kbox_qpcNow() == w0 && (r - r0) < (1ull << 33)) {
            r = kbox_rdtsc();
        }
        uint64_t qd = kbox_qpcNow() - w0;
        uint64_t rdt = r - r0;
        if (qd > 0 && rdt > 0) g_tscPerMs = rdt / qd;
        if (g_tscPerMs == 0) g_tscPerMs = 2500000u; /* ~2.5GHz fallback */
    }
    return g_tscPerMs;
}

/* Cross-source timing anomaly. Runs a calibration spin once per probe so the
 * three counters are sampled back-to-back around the SAME work. Returns 1 for
 * two and only two conditions:
 *   1) Pathological duration — the spin normally costs sub-ms to a few ms; a
 *      single-stepping / suspended thread inflates it past 250ms on any clock.
 *   2) Frozen wall clock — both fine-grained clocks report ZERO elapsed over a
 *      run that (by the RDTSC calibration) really spanned >= 2ms of real time.
 *
 * The ms-truncated QPC (1ms resolution) and the ~15.6ms-granularity
 * GetTickCount64 MUST NOT be compared against each other on a sub-second
 * scale: a normal 1..15ms spin legitimately shows qd>=1 while td==0. Flagging
 * that asymmetry false-positives on every ordinary run, so no QPC-vs-tick
 * cross-comparison is performed below a pathological bound. */
static int kbox_multiCounterCheck(void) {
    uint64_t r0 = kbox_rdtsc();
    uint64_t q0 = kbox_qpcNow();
    uint64_t t0 = kbox_tickNow();
    volatile uint32_t acc = 0x9E3779B9u;
    for (int i = 0; i < 400000; i++) { acc ^= (acc << 5) + (acc >> 2); }
    uint64_t r1 = kbox_rdtsc();
    uint64_t q1 = kbox_qpcNow();
    uint64_t t1 = kbox_tickNow();

    uint64_t qd = (q1 >= q0) ? (q1 - q0) : 0;
    uint64_t td = (t1 >= t0) ? (t1 - t0) : 0;

    /* 1) Pathological: stepping / suspension blows the spin far past its cost.
     *    A clean spin is ~0.5ms; a genuine single-stepper inflates it by
     *    ~4-6 orders of magnitude (seconds). A scheduler deschedule of the
     *    JVM main thread during startup is at most a few hundred ms, so the
     *    bound sits well above any legitimate preemption but far below a real
     *    single-step trace. */
    if (qd > 250 || td > 250) { kbox_wdDiag("time:pathological"); return 1; }

    /* 2) Frozen clock: zero elapsed on both wall clocks while RDTSC proves a
     *    LONG real run. A normal sub-ms spin also shows qd==0&&td==0 with a
     *    tiny TSC advance, so this is gated on calibrated real elapsed time,
     *    never on a bare RDTSC advance. The >=100ms bound is robust against
     *    ordinary scheduler descheduling (a thread suspended for 100ms during
     *    a ~0.5ms spin is vanishingly rare), while a true single-step / hook
     *    that freezes QPC & GetTickCount while RDTSC keeps running passes it.*/
    if (qd == 0 && td == 0) {
        uint64_t perMs = kbox_tscPerMs();
        if (perMs != 0 && (r1 - r0) / perMs >= 100) { kbox_wdDiag("time:frozen"); return 1; }
    }

    (void)acc;
    return 0;
}

/* Weak timing anomaly: a single-stepping / tracing debugger inflates a short
 * arithmetic spin (clean cost well under 1 ms) by several orders of magnitude.
 * Now delegates to the three-source cross-check (RDTSC + QPC + tick) so a
 * single hooked/paused clock cannot defeat it. */
static int kbox_timingCheck(void) {
    return kbox_multiCounterCheck();
}

#if defined(_WIN32)
/* 1 = a software breakpoint (INT3 / 0xCC) is planted at the entry of one of
 * the decoder's critical functions. The image self-hash catches any byte edit
 * anywhere, but this is a cheap explicit check that also protects degraded
 * (un-hashed) builds. Function-entry bytes are never 0xCC in a clean compile
 * on any toolchain (GCC/clang pad with 0x90 nops; MSVC pads BETWEEN functions,
 * never at a body start), so there is no false positive. */
static int kbox_scanSoftBreakpoints(void) {
    static const uint8_t* const entries[] = {
        (const uint8_t*)(uintptr_t)(void*)&kbox_bf_safeBoot,
        (const uint8_t*)(uintptr_t)(void*)&kbox_gateCheck,
        (const uint8_t*)(uintptr_t)(void*)&kbox_watchdog,
        (const uint8_t*)(uintptr_t)(void*)&kbox_selfCheck,
        (const uint8_t*)(uintptr_t)(void*)&kbox_probeAgentModules,
    };
    for (size_t i = 0; i < sizeof(entries) / sizeof(entries[0]); i++) {
        const uint8_t* p = entries[i];
        if (p[0] == 0xCC || p[1] == 0xCC || p[2] == 0xCC || p[3] == 0xCC) {
            kbox_wdDiag("soft:INT3");
            return 1;
        }
    }
    return 0;
}
#endif

#if defined(_WIN32)
/* Page-attribute tamper probe (L3/L4.1). Re-reads the OS's own view of the
 * guard pages that fence every plaintext exposure box. A memory tool that
 * flattens page protection to RWX so it can sweep/dump the buffer has to
 * change these pages away from PAGE_NOACCESS; VirtualQuery is not hookable by
 * userland API hooking in the same way as GetProcAddress, and the image
 * self-hash covers the code but not the dynamically-allocated data pages, so
 * this is the only check that sees a re-protected guard. Returns 1 on any
 * guard page that is no longer PAGE_NOACCESS (tamper) or a query failure. */
static int kbox_probePageAttrs(void) {
    for (int i = 0; i < g_trapN; i++) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T r = VirtualQuery((LPCVOID)g_trapLo[i], &mbi, sizeof(mbi));
        if (r == 0) return 1;                       /* query failed: suspicious */
        DWORD prot = mbi.Protect & 0xFF;            /* low byte = protection */
        if (prot != PAGE_NOACCESS && prot != PAGE_GUARD)
            return 1;
    }
    /* L1 terrain re-verification: every registered CRYPT/MAYBE/OPAQUE/HOT
     * range must still carry the protection its terrain demands. A memory
     * tool that flattens a guard page OR re-protects a watched window is
     * caught by the same pass. */
    if (kbox_terrainCheck()) return 1;
    return 0;
}
#endif

static int kbox_probeDebugger(int doWeak) {
    int flags = 0;
#if defined(_WIN32)
    /* 1) PEB BeingDebugged. */
    if (IsDebuggerPresent()) { kbox_wdDiag("dbg:IsDebuggerPresent"); flags |= 1; }
    /* 2) Debug port / debug object handle via ntdll. Resolved at run time so
     *    nothing new enters the static import table. */
    {
        typedef LONG (NTAPI* PFN_NtQueryInformationProcess)(
            HANDLE, ULONG, PVOID, ULONG, PULONG);
        HMODULE nt = GetModuleHandleA("ntdll.dll");
        if (nt != NULL) {
            PFN_NtQueryInformationProcess q =
                (PFN_NtQueryInformationProcess)GetProcAddress(
                    nt, "NtQueryInformationProcess");
            if (q != NULL) {
                DWORD_PTR v = 0;
                ULONG len = 0;
                /* ProcessDebugPort = 7 */
                if (q(GetCurrentProcess(), 7, &v, sizeof(v), &len) >= 0 &&
                    v != 0) { kbox_wdDiag("dbg:DebugPort"); flags |= 1; }
                else {
                    /* ProcessDebugObjectHandle = 0x1E */
                    v = 0; len = 0;
                    if (q(GetCurrentProcess(), 0x1E, &v, sizeof(v), &len) >= 0 &&
                        v != 0) { kbox_wdDiag("dbg:DebugObject"); flags |= 1; }
                }
                /* ProcessDebugFlags = 0x1F: the "no debug inherit" flag; 0 means
                 * the process is being debugged. A debugger that zeroes the
                 * debug port / object handle cannot restore this inherited
                 * flag, so it closes the NtQuery trio — any one of the three
                 * can be faked, but not all together. */
                {
                    DWORD_PTR df = 1;
                    ULONG dlen = 0;
                    if (q(GetCurrentProcess(), 0x1F, &df, sizeof(df), &dlen) >= 0 &&
                        df == 0) { kbox_wdDiag("dbg:DebugFlags"); flags |= 1; }
                }
            }
        }
    }
    /* 3) Hardware breakpoints: DR0..DR3 enabled through DR7 (low byte = the
     *    four local/global enable bits). A debugger using hardware BPs sets
     *    these even without any code patch, which the image hash can't see. */
    {
        CONTEXT ctx;
        memset(&ctx, 0, sizeof(ctx));
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        HANDLE th = GetCurrentThread();
        if (th != NULL && GetThreadContext(th, &ctx)) {
            if ((ctx.Dr7 & 0x000000FFu) != 0) { kbox_wdDiag("dbg:HardwareBP"); flags |= 1; }
        }
    }
    /* 4) Guard-page protection re-check: any re-protected plaintext box is a
     *    strong tamper signal (a dump tool that flattened protections). */
    if (kbox_probePageAttrs()) { kbox_wdDiag("dbg:PageAttrs"); flags |= 1; }
    if (doWeak && kbox_scanSoftBreakpoints()) flags |= 2;
#else
    /* Linux: TracerPid != 0 means a ptrace debugger is attached. */
#if defined(__linux__) || defined(__linux)
    {
        FILE* f = fopen("/proc/self/status", "r");
        if (f != NULL) {
            char line[256];
            while (fgets(line, sizeof(line), f) != NULL) {
                if (strncmp(line, "TracerPid:", 10) == 0) {
                    if (strtol(line + 10, NULL, 10) != 0) flags |= 1;
                    break;
                }
            }
            fclose(f);
        }
    }
#endif
#endif
    if (doWeak && kbox_timingCheck()) flags |= 2;
    return flags;
}

/* ==================================================================== */
/* Anti-VM (CPUID hypervisor detection)                                 */
/* ==================================================================== */
/* Detects a virtual machine through the CPUID interface:
 *   leaf 1, ECX bit 31   — the "hypervisor present" bit, set on any
 *                          Hyper-V / VMware / VirtualBox / KVM / QEMU guest
 *   leaf 0x40000000      — the hypervisor vendor string (12 bytes in
 *                          EBX:ECX:EDX), matched against the well-known
 *                          fingerprints via FNV-1a so no plaintext vendor
 *                          string ever rests in the shipped binary.
 * Fail-closed stance: a VM is denied at boot (safeBoot) and the decode state
 * is wiped at define-time (gateCheck) — a denial, not a random kill — and it
 * is deliberately NOT polled from the background watchdog, so a legitimate
 * user whose production host happens to be a cloud VM is never killed by the
 * 100 ms poller. */
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
static void kbox_cpuid(uint32_t leaf, uint32_t sub,
                       uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
#if defined(_MSC_VER)
    int regs[4];
    __cpuidex(regs, (int)leaf, (int)sub);
    *a = (uint32_t)regs[0]; *b = (uint32_t)regs[1];
    *c = (uint32_t)regs[2]; *d = (uint32_t)regs[3];
#else
    uint32_t a0 = 0, b0 = 0, c0 = 0, d0 = 0;
    __asm__ volatile("cpuid"
                     : "=a"(a0), "=b"(b0), "=c"(c0), "=d"(d0)
                     : "a"(leaf), "c"(sub));
    *a = a0; *b = b0; *c = c0; *d = d0;
#endif
}

/* FNV-1a (32-bit) over a byte buffer — an in-process fingerprint only, so the
 * hypervisor vendor strings never appear as plaintext in the binary. */
static uint32_t kbox_fnv32(const void* p, size_t n) {
    const unsigned char* b = (const unsigned char*)p;
    uint32_t h = 0x811c9dc5u;
    for (size_t i = 0; i < n; i++) { h ^= b[i]; h *= 0x01000193u; }
    return h;
}

/* 1 = running inside a guest VM (unambiguous external hypervisor). 0 =
 * bare metal or an undetectable / host-level hypervisor.
 *
 * Deliberately NOT treated as a VM signal:
 *   - leaf 1 ECX bit 31  ("hypervisor present"): Windows sets this even on
 *     PHYSICAL hosts that enable VBS / Core-Isolation / HVCI, because the
 *     Hyper-V hypervisor is always resident. Flagging it would break every
 *     legitimate user on a modern secure-boot Windows box.
 *   - "Microsoft Hv" vendor: Hyper-V exposes this string identically whether
 *     it is hosting a GUEST (analysis sandbox) or protecting a PHYSICAL host
 *     via VBS. It is therefore not a reliable guest indicator.
 * Only unambiguous EXTERNAL guest hypervisors (VMware / VirtualBox / KVM /
 * Xen / QEMU-TCG / Bochs / Parallels) trip the probe. This keeps anti-VM
 * effective against real analysis sandboxes without denying legit users on
 * VBS-enabled physical hardware. */
static int kbox_probeVM(void) {
    uint32_t a = 0, b = 0, c = 0, d = 0;
    kbox_cpuid(0x40000000, 0, &a, &b, &c, &d);
    if (a == 0 && b == 0 && c == 0 && d == 0) return 0; /* no leaf -> bare */
    unsigned char vnd[12];
    uint32_t tmp[3] = { b, c, d };
    memcpy(vnd, tmp, 12);
    switch (kbox_fnv32(vnd, 12)) {
    case 0x1148211du: /* VMwareVMware  */ return 1;
    case 0x063611bau: /* VBoxVBoxVBox  */ return 1;
    case 0x1b350931u: /* KVMKVMKVM     */ return 1;
    case 0xa7c94cb1u: /* XenVMMXenVMM  */ return 1;
    case 0x71fb35c5u: /* TCGTCGTCGTCG  */ return 1;
    case 0xa53286a3u: /* BochsBXPC     */ return 1;
    case 0xd7c7c893u: /* prl hyperv    */ return 1;
    default: break;
    }
    return 0;
}
#else
/* Non-x86 (e.g. ARM64): no CPUID; return 0 (no VM signal). */
static int kbox_probeVM(void) { return 0; }
#endif

/* ==================================================================== */
/* API-hook detection (Windows)                                         */
/* ==================================================================== */
/* Detects user-land interception of the exact primitives a dumper / hooker
 * needs (memory read/write, virtual protect/alloc, process query, export
 * resolution). Two complementary signals:
 *   1) prologue check — a hooked export starts with a trampoline: E9 (near
 *      jmp rel32), EB (short jmp), FF 25 (jmp [mem]) or an INT3 (0xCC)
 *      breakpoint at entry. The legitimate prologues of these ntdll/kernel32
 *      functions never begin with any of those on supported Windows releases.
 *   2) export-table cross-check — the address GetProcAddress returns is
 *      compared with the address derived by walking the module's export
 *      directory. A mismatch means the export entry (or GetProcAddress
 *      itself) was rewritten, i.e. an import-address-table / API hook.
 * The watched module!export pairs ship XOR-encrypted per build (KBOX_HOOKS),
 * so the shipped binary reveals neither which functions are watched nor their
 * names. POSIX builds have no in-process API interception surface of the same
 * kind and return 0. */
#if defined(_WIN32)
/* 1 = the bytes at the prologue of a critical export look like a trampoline. */
static int kbox_probeHookBytes(const void* fn) {
    if (fn == NULL) return 0;
    const unsigned char* p = (const unsigned char*)fn;
    if (p[0] == 0xE9 || p[0] == 0xEB || p[0] == 0xCC) return 1;
    if (p[0] == 0xFF && p[1] == 0x25) return 1;
    return 0;
}

/* Walks a module's export directory to find the canonical address of an export
 * by name. Returns NULL for unknown names and for forwarded exports (whose RVA
 * points at a forwarder string outside the image and is resolved by the loader
 * to another module — never a hooking signal). */
static FARPROC kbox_exportAddr(HMODULE mod, const char* name) {
    if (mod == NULL || name == NULL) return NULL;
    const unsigned char* base = (const unsigned char*)mod;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_DATA_DIRECTORY* dd =
        &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd->VirtualAddress == 0 || dd->Size == 0) return NULL;
    const unsigned char* edBase = base + dd->VirtualAddress;
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)edBase;
    const DWORD* funcs  = (const DWORD*)(base + ed->AddressOfFunctions);
    const WORD*  ords   = (const WORD*)(base + ed->AddressOfNameOrdinals);
    const DWORD* names  = (const DWORD*)(base + ed->AddressOfNames);
    for (DWORD k = 0; k < ed->NumberOfNames; k++) {
        const char* nm = (const char*)(base + names[k]);
        if (strcmp(nm, name) == 0) {
            DWORD rva = funcs[ords[k]];
            if (rva >= nt->OptionalHeader.SizeOfImage) return NULL; /* forwarder */
            return (FARPROC)(base + rva);
        }
    }
    return NULL;
}

static int kbox_probeHooks(void) {
#ifdef KBOX_BF_ENCRYPTED
    char nd[128];
    for (size_t i = 0; i < sizeof(KBOX_HOOKS) / sizeof(KBOX_HOOKS[0]); i++) {
        kbox_xdec(nd, KBOX_HOOKS[i].enc, (size_t)KBOX_HOOKS[i].len, KBOX_HOOKS_KEY);
        char* sep = strchr(nd, '!');
        if (sep == NULL) { wipeBuffer(nd, sizeof(nd)); continue; }
        *sep = 0;
        HMODULE mod = GetModuleHandleA(nd);
        const char* exp = sep + 1;
        if (mod != NULL) {
            FARPROC fn = GetProcAddress(mod, exp);
            if (kbox_probeHookBytes((const void*)fn)) {
                wipeBuffer(nd, sizeof(nd));
                return 1;
            }
            FARPROC canon = kbox_exportAddr(mod, exp);
            if (canon != NULL && fn != canon) {
                wipeBuffer(nd, sizeof(nd));
                return 1;
            }
        }
        wipeBuffer(nd, sizeof(nd));
    }
    return 0;
#else
    static const char* hooks[] = {
        "kernel32.dll!VirtualProtect",
        "kernel32.dll!VirtualAlloc",
        "kernel32.dll!ReadProcessMemory",
        "kernel32.dll!WriteProcessMemory",
        "kernel32.dll!GetProcAddress",
        "kernel32.dll!LoadLibraryA",
        "kernel32.dll!GetModuleHandleA",
        "kernel32.dll!IsDebuggerPresent",
        "kernel32.dll!GetThreadContext",
        "kernel32.dll!QueryPerformanceCounter",
        "ntdll.dll!NtQueryInformationProcess",
        "ntdll.dll!NtQuerySystemInformation",
        "ntdll.dll!NtReadVirtualMemory",
        "ntdll.dll!NtWriteVirtualMemory",
        "ntdll.dll!NtProtectVirtualMemory",
        "ntdll.dll!NtAllocateVirtualMemory"
    };
    for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
        char nd[128];
        strncpy(nd, hooks[i], sizeof(nd) - 1);
        nd[sizeof(nd) - 1] = 0;
        char* sep = strchr(nd, '!');
        if (sep == NULL) continue;
        *sep = 0;
        HMODULE mod = GetModuleHandleA(nd);
        const char* exp = sep + 1;
        if (mod != NULL) {
            FARPROC fn = GetProcAddress(mod, exp);
            if (kbox_probeHookBytes((const void*)fn)) return 1;
            FARPROC canon = kbox_exportAddr(mod, exp);
            if (canon != NULL && fn != canon) return 1;
        }
    }
    return 0;
#endif
}
#else
/* POSIX: no same-kind in-process API interception surface; return 0. */
static int kbox_probeHooks(void) { return 0; }
#endif

/* 1 = any JVM input argument enables an agent / debugger / profiler.
 * Case-insensitive substring scan, in native so the patterns are not readable
 * from the plaintext bootstrap class. The needles ship XOR-encrypted per build
 * (KBOX_ARGS + KBOX_ARGS_KEY); each is decrypted into a stack buffer for its
 * own scan and wiped immediately. */
static int kbox_scanArgs(const char* const* args, int argc) {
#ifdef KBOX_BF_ENCRYPTED
    char nd[64];
    for (int i = 0; i < argc; i++) {
        const char* a = args[i];
        if (a == NULL) continue;
        size_t al = strlen(a);
        for (size_t n = 0; n < sizeof(KBOX_ARGS) / sizeof(KBOX_ARGS[0]); n++) {
            kbox_xdec(nd, KBOX_ARGS[n].enc, (size_t)KBOX_ARGS[n].len, KBOX_ARGS_KEY);
            size_t nl = strlen(nd);
            int hit = 0;
            if (al >= nl) {
                for (size_t k = 0; k <= al - nl && !hit; k++) {
                    size_t m = 0;
                    while (m < nl) {
                        char x = a[k + m], y = nd[m];
                        if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
                        if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
                        if (x != y) break;
                        m++;
                    }
                    if (m == nl) hit = 1;
                }
            }
            wipeBuffer(nd, sizeof(nd));
            if (hit) return 1;
        }
    }
    return 0;
#else
    static const char* needles[] = {
        "-agentlib:", "-javaagent", "-agentpath",
        "-xrunjdwp",  "jdwp=",      "transport=dt_socket"
    };
    for (int i = 0; i < argc; i++) {
        const char* a = args[i];
        if (a == NULL) continue;
        size_t al = strlen(a);
        for (size_t n = 0; n < sizeof(needles) / sizeof(needles[0]); n++) {
            const char* nd = needles[n];
            size_t nl = strlen(nd);
            if (al < nl) continue;
            for (size_t k = 0; k <= al - nl; k++) {
                size_t m = 0;
                while (m < nl) {
                    char x = a[k + m], y = nd[m];
                    if (x >= 'A' && x <= 'Z') x = (char)(x - 'A' + 'a');
                    if (y >= 'A' && y <= 'Z') y = (char)(y - 'A' + 'a');
                    if (x != y) break;
                    m++;
                }
                if (m == nl) return 1;
            }
        }
    }
    return 0;
#endif
}

/* ==================================================================== */
/* .text integrity self-check (anti-patch)                              */
/* ==================================================================== */
/* Detects a runtime patch of the decoder's own code section (.text) — the
 * classic move to neutralise watchdog/gateCheck/JNI_OnLoad without touching
 * the encrypted payload tables. A baseline FNV-1a hash of the whole .text
 * section is established on the first self-check, and re-computed on every
 * gateCheck and every watchdog tick; any mismatch (the section's bytes were
 * altered since our own code baseline) hard-dies the process. Because the
 * salt KBOX_TEXT_SALT is compiled in per-build and the section to hash is
 * located from within (GetModuleHandleEx FROM_ADDRESS, not the exe base), a
 * static tracer can't trivially redirect the baseline to a forgery.
 *
 * POSIX has no standard in-process section-address export, so the real hash
 * is Windows-only; elsewhere the self-check no-ops (agent gate + watchdog
 * remain the active defences). */
#ifndef KBOX_TEXT_SALT
#define KBOX_TEXT_SALT 0x12345678u
#endif
/* Build-time injected expected image hash.
 *
 * BfNativeBuilder computes the expected FNV-1a over the FINAL compiled image
 * (all read-only, non-discardable sections) and patches it into this dedicated
 * read-only section (.kboxexp) AFTER compilation. Because kbox_hashImage()
 * skips .kboxexp by name, the hash of a clean image is INDEPENDENT of the
 * constant's own value — so a runtime patch can no longer re-baseline it. The
 * attacker's classic "patch the check call sites, then let the first check
 * re-establish the baseline from the already-patched image" move now flips the
 * hash and is caught (hard die via kbox_selfDie). Patching the export table
 * (.edata), the JNI_OnLoad code or any read-only data is detected the same way.
 *
 * Layout (one 64-bit value, patched as 8 bytes in file order):
 *   low 32 bits  = expected image hash (uint32, LE)
 *   high 32 bits = magic sentinel KBOX_EXPECTED_MAGIC ('KBOX' LE) proving the
 *                  constant was injected. A zero magic means an unhardened
 *                  build (patch failed) -> kbox_selfCheck() falls back to a
 *                  runtime baseline so the app still works.
 *
 * MSVC: #pragma section + __declspec(allocate) creates a dedicated section.
 * GCC/clang: __attribute__((section)). On ELF the constant sits in a read-only
 * data section OUTSIDE the PF_X code segments the ELF self-hash covers, so it
 * is excluded naturally and the same patching logic applies. */
#if defined(_MSC_VER)
#pragma section(".kboxexp", read)
__declspec(allocate(".kboxexp")) static const uint64_t KBOX_EXPECTED = 0x0u;
#elif defined(__GNUC__) || defined(__clang__)
/* 'used' is mandatory for GCC/clang PE/COFF output: without it GNU ld folds a
 * read-only custom section into .rdata and the dedicated .kboxexp section
 * disappears, so the build-time hash could never be patched in. */
__attribute__((section(".kboxexp"), used)) static const uint64_t KBOX_EXPECTED = 0x0u;
#else
static const uint64_t KBOX_EXPECTED = 0x0u;
#endif
#define KBOX_EXPECTED_MAGIC (0x4B424F58u ^ 0x2D7E1A93u) /* masked, NOT 'KBOX' */
/* FNV-1a over [p,n); salted so two builds hash differently. */
static uint32_t kbox_textHash(uint32_t salt, const uint8_t* p, size_t n) {
    uint32_t h = salt ^ 0x811c9dc5u;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x01000193u;
    }
    return h;
}

/* Integrity baseline over the whole protected (non-writable) image, not just
 * .text. The attacker's two favourite edit points are covered:
 *   - the implementation (JNI_OnLoad / gateCheck / watchdog code),
 *   - the export table (.edata) that the JVM consults to bind JNI_OnLoad,
 *     and the read-only constant/import-name data (.rdata).
 * Writable data (.data/.bss, the import address table) and discardable
 * sections are excluded — they legitimately change after load (relocations,
 * uninitialised data, resolved IAT), so hashing them would false-positive. */
static uint32_t g_imageHash = 0;

/* Resolves this module's base from our own function address (POSIX analogue
 * of GetModuleHandleEx FROM_ADDRESS). */
static uintptr_t kbox_selfBase(void) {
#if defined(_WIN32)
    HMODULE h = NULL;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                           GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                           (LPCWSTR)(uintptr_t)kbox_selfBase, &h) == 0) return 0;
    return (uintptr_t)h;
#else
    Dl_info di;
    memset(&di, 0, sizeof(di));
    if (dladdr((void*)(uintptr_t)kbox_selfBase, &di) == 0 || di.dli_fbase == NULL) return 0;
    return (uintptr_t)di.dli_fbase;
#endif
}

#if defined(_WIN32)
/* Base-relocation target RVAs (DIR64/HIGHLOW) of this module, parsed once from
 * the mapped image. These bytes legitimately change between the on-disk file
 * and the in-memory image whenever the loader applies a fixup (i.e. the module
 * was mapped at anything other than its preferred base). The integrity hash
 * must skip exactly those bytes on BOTH sides (BfNativeBuilder's patchPe does
 * the same from the file) or the build-time expected value would never match a
 * relocated load. .idata is skipped wholesale below because import resolution
 * rewrites the IAT at fixed RVAs that are NOT base relocations. */
#define KBOX_MAX_RELOC 1024
static DWORD g_relocRva[KBOX_MAX_RELOC];
static int g_relocCount = 0;
static int g_relocInit = 0;

static void kbox_collectRelocs(uintptr_t base) {
    g_relocInit = 1;
    g_relocCount = 0;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    DWORD er = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD esz = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!er || !esz) return;
    DWORD off = 0;
    while (off + 8 <= esz && g_relocCount < KBOX_MAX_RELOC) {
        IMAGE_BASE_RELOCATION* br = (IMAGE_BASE_RELOCATION*)(base + er + off);
        if (br->SizeOfBlock == 0) break;
        DWORD cnt = (br->SizeOfBlock - 8) / 2;
        const unsigned short* ents = (const unsigned short*)(br + 1);
        for (DWORD j = 0; j < cnt && g_relocCount < KBOX_MAX_RELOC; j++) {
            unsigned short e = ents[j];
            unsigned short t = e >> 12;
            /* IMAGE_REL_BASED_HIGHLOW=2, IMAGE_REL_BASED_DIR64=10 (skip ABSOLUTE) */
            if (t == 2 || t == 10) {
                g_relocRva[g_relocCount++] = br->VirtualAddress + (e & 0xFFF);
            }
        }
        off += br->SizeOfBlock;
    }
}

/* Fold FNV-1a over every non-writable, non-discardable section of a PE.
 * Sections whose bytes change between file and memory are excluded by name:
 *   .kboxexp  build-time expected hash (self-referential otherwise),
 *   .idata    the IAT / import thunks, rewritten by import resolution at load,
 * and individual base-relocation targets inside hashed sections are skipped so
 * the expected value holds regardless of the mapped load base. */
static int kbox_hashImage(uintptr_t base, uint32_t salt, uint32_t* out) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return -1;
    if (!g_relocInit) kbox_collectRelocs(base);
    IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    uintptr_t end = base + (uintptr_t)nt->OptionalHeader.SizeOfImage;
    uint32_t h = salt ^ 0x811c9dc5u;
    int ri = 0;
    for (int i = 0; i < (int)nt->FileHeader.NumberOfSections; i++) {
        DWORD ch = sec[i].Characteristics;
        if ((ch & (IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE)) != 0) continue;
        /* .kboxexp: build-time expected hash (see kbox_selfCheck comment above).
         * .idata: the IAT is rewritten by import resolution at load time, so its
         * memory content never equals the file — folding it would false-positive. */
        if (strncmp((const char*)sec[i].Name, ".kboxexp", 8) == 0) continue;
        if (strncmp((const char*)sec[i].Name, ".idata", 8) == 0) continue;
        uintptr_t va = base + (uintptr_t)sec[i].VirtualAddress;
        size_t n = sec[i].Misc.VirtualSize;
        if (va + n > end) n = end - va;
        if (n == 0) continue;
        h ^= (uint32_t)sec[i].VirtualAddress;
        h ^= ch;
        h *= 0x01000193u;
        const uint8_t* p = (const uint8_t*)va;
        for (size_t j = 0; j < n; j++) {
            DWORD rva = sec[i].VirtualAddress + (DWORD)j;
            while (ri < g_relocCount && g_relocRva[ri] < rva) ri++;
            if (ri < g_relocCount && g_relocRva[ri] == rva) continue; /* relocated byte */
            h ^= p[j];
            h *= 0x01000193u;
        }
    }
    *out = h;
    return 0;
}
#else
/* POSIX self-hash of our own loaded shared object. dladdr gives the load bias;
 * dl_iterate_phdr ("the POSIX section iterator") yields the program headers so
 * we fold the executable (PF_X, non-writable) load segments. Only code is
 * hashed on POSIX: read-only data segments may hold RELRO/got tables that the
 * dynamic linker legitimately mutates at runtime, so hashing them could false-
 * positive. Kept to the code region = still detects the implementation-patch
 * attack (watchdog/gateCheck/JNI_OnLoad live in code). */
struct kbox_elf_ctx { uint32_t salt; uint32_t hash; int found; };
static uintptr_t g_selfBase = 0;

#if defined(__linux__) || defined(__linux)
static int kbox_phdr_cb(struct dl_phdr_info* info, size_t sz, void* data) {
    (void)sz;
    struct kbox_elf_ctx* ctx = (struct kbox_elf_ctx*)data;
    if ((uintptr_t)info->dlpi_addr != g_selfBase) return 0;
    ctx->found = 1;
    uint32_t h = ctx->salt ^ 0x811c9dc5u;
    for (int i = 0; i < (int)info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD) continue;
        if ((ph->p_flags & PF_W) != 0 || !(ph->p_flags & PF_X)) continue;
        if (ph->p_filesz == 0) continue;
        const uint8_t* p = (const uint8_t*)(info->dlpi_addr + ph->p_vaddr);
        h ^= (uint32_t)ph->p_vaddr;
        h ^= ph->p_flags;
        h *= 0x01000193u;
        for (uint32_t j = 0; j < ph->p_filesz; j++) { h ^= p[j]; h *= 0x01000193u; }
    }
    ctx->hash = h;
    return 1;
}
static int kbox_hashImage(uintptr_t base, uint32_t salt, uint32_t* out) {
    g_selfBase = base;
    struct kbox_elf_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.salt = salt;
    dl_iterate_phdr(kbox_phdr_cb, &ctx);
    if (!ctx.found) return -1;
    *out = ctx.hash;
    return 0;
}
#else
static int kbox_hashImage(uintptr_t base, uint32_t salt, uint32_t* out) {
    (void)base; (void)salt; (void)out;
    return -1; /* no POSIX address-info iterator on this platform */
}
#endif
#endif /* _WIN32 */

/* Establish the integrity baseline once. Returns 0 on success, -1 if the
 * image layout is unavailable (self-check then no-ops). */
static int kbox_selfCheckInit(void) {
    if (g_imageHash != 0) return 0;
    uintptr_t base = kbox_selfBase();
    if (base == 0) return -1;
    uint32_t h;
    if (kbox_hashImage(base, KBOX_TEXT_SALT, &h) != 0) return -1;
    g_imageHash = h;
    return 0;
}

/* Re-hash the protected image and compare with the expected value. Returns 1
 * when a read-only section/code segment was patched (caller must terminate), 0
 * when intact, -1 when undeterminable (self-check then no-ops).
 *
 * Priority: the build-time injected constant (KBOX_EXPECTED, magic present) is
 * authoritative — it is compiled in by BfNativeBuilder and CANNOT be re-derived
 * from a patched image, so neutralising one (or all) check call sites no longer
 * lets the check re-baseline itself. Only when the constant was not injected
 * (degraded build) does it fall back to a runtime baseline. */
static int kbox_selfCheck(void) {
    uintptr_t base = kbox_selfBase();
    if (base == 0) return -1;
    uint32_t h;
    if (kbox_hashImage(base, KBOX_TEXT_SALT, &h) != 0) return -1;
    uint32_t expHash  = (uint32_t)KBOX_EXPECTED;
    uint32_t expMagic = (uint32_t)(KBOX_EXPECTED >> 32);
    if (expMagic == KBOX_EXPECTED_MAGIC) return (h != expHash) ? 1 : 0;
    if (g_imageHash == 0 && kbox_selfCheckInit() != 0) return -1;
    return (h != g_imageHash) ? 1 : 0;
}

/* Abort process without running any agent/cleanup code (self-check hit).
 * L4.3: every hard-die funnels through the integrity epoch — the counter is
 * bumped, live plaintext windows are wiped, then the process is terminated. */
static void kbox_selfDie(void) {
    kbox_epochBump(0x51);
}

/* Wipe the whole native decode state so no further define can succeed. Used
 * by the fail-closed gate paths (weak debugger / VM / agent module). Also
 * fuses the epoch and batch-erases any live MAYBE/OPAQUE plaintext windows. */
static void kbox_wipeDecodeState(void) {
    kbox_epochWipeMaybes();
    rleProtect(1);
    indexClear();
    secureFree(g_state.rle, g_state.rleCap);
    g_state.rle = NULL; g_state.rleLen = 0; g_state.rleCap = 0;
    g_rleWritable = 0;
}

/* Fail-closed define-time gate: cheap module probe re-run on EVERY class /
 * resource definition, so an agent attached after the boot gate (dynamic attach,
 * jcmd) or a bootstrap that had safeBoot() stripped still gets caught here.
 * On detection the whole native decode state is wiped and further defines die. */
static int kbox_gateCheck(void) {
    if (kbox_selfCheck() == 1) { kbox_wdDiag("gate selfCheck"); kbox_selfDie(); return 1; }
    /* API-hook detection is a strong signal: a trampoline / IAT rewrite on a
     * memory primitive means active instrumentation — hard-die like a debugger. */
    if (kbox_probeHooks()) { kbox_wdDiag("gate probeHooks"); kbox_selfDie(); return 1; }
    /* Extended native anti-debug: a strong debugger signal hard-dies before
     * any plaintext is handed over; a weak signal (timing / INT3) wipes the
     * decode state and refuses the define (fail-closed, no process kill). */
    int dbg = kbox_probeDebugger(1);
    if (dbg & 1) { kbox_wdDiag("gate probeDebugger-strong"); kbox_selfDie(); return 1; }
    if (dbg & 2) { kbox_wdDiag("gate probeDebugger-weak"); kbox_wipeDecodeState(); return 1; }
    /* A VM is a denial (fail-closed wipe), not a kill — a legitimate user on a
     * cloud host is refused work rather than silently terminated. */
    if (kbox_probeVM()) { kbox_wdDiag("gate probeVM"); kbox_wipeDecodeState(); return 1; }
    if (!kbox_probeAgentModules()) return 0;
    kbox_wdDiag("gate agent-modules");
    kbox_wipeDecodeState();
    return 1;
}

/* ==================================================================== */
/* L4.2 Dual watchdog (W1 + W2 mutual sentinels)                        */
/* ==================================================================== */
/* The boot gate (safeBoot) and the per-define gate (kbox_gateCheck) both
 * only run on explicit class definitions. A dynamic agent that attaches after
 * boot can otherwise: sit silently and wait for the next define, or call
 * retransformClasses to dump ALREADY-loaded classes out of metaspace without
 * ever triggering a new define. Two independent native threads close that
 * window and watch each other:
 *   W1 (kbox_watchdog):  whole-image self-hash (native .text + 派发表/export
 *                        table via kbox_selfCheck) + strong debugger / hooks /
 *                        agent-module probes + heartbeat.
 *   W2 (kbox_watchdog2): epoch-fuse integrity + an INDEPENDENT whole-image
 *                        hash (so a patch to W1's body, or a dead W1, still
 *                        fires) + per-range CRC of the HOT terrain (the VM
 *                        handler 区: RX code of reflectively loaded vmp.bin /
 *                        jnic.bin) + protection re-verify (HOT stays RX) +
 *                        a byte-CRC of W1's own code region (label-bounded on
 *                        GCC/clang) + heartbeat.
 * Each watchdog randomises its poll interval (never a fixed cadence a
 * synchronised dumper can pace around) and cross-validates the OTHER's
 * heartbeat: if either thread is killed or frozen, its peer's counter stops
 * advancing and the surviving watchdog funnels into the L4.3 epoch fuse. The
 * W1<->W2 cross-check only arms after the peer has provably ticked once, so a
 * failed thread create never kills a legitimate run. */
#define KBOX_WD_JITTER_LO   40u
#define KBOX_WD_JITTER_SPAN 100u  /* poll interval = [40, 140) ms, randomised */
#define KBOX_WD_STALL       6     /* peer dead after this many stalled polls */

/* xorshift32 — dependency-free poll-jitter source. */
static uint32_t kbox_wdRand(uint32_t* s) {
    uint32_t x = *s;
    if (x == 0) x = 0x9E3779B9u;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    *s = x;
    return x;
}

/* Per-process jitter seed: mix a time/thread source so two runs (and the two
 * watchdogs) never share a poll phase. */
static uint32_t kbox_wdSeed(void) {
    uint32_t s;
#if defined(_WIN32)
    s = GetTickCount();
    s ^= (uint32_t)(uintptr_t)&s;
    s ^= (uint32_t)GetCurrentThreadId();
#else
    s = (uint32_t)time(NULL) ^ (uint32_t)getpid();
    s ^= (uint32_t)(uintptr_t)&s;
#endif
    return s | 1u;
}

/* Randomised poll delay (ms) for a watchdog tick. */
static uint32_t kbox_wdDelay(uint32_t* seed) {
    return KBOX_WD_JITTER_LO + (kbox_wdRand(seed) % KBOX_WD_JITTER_SPAN);
}

/* Mutual-watchdog heartbeat liveness. `p` arms only after the peer has
 * provably ticked at least once (hb != 0); thereafter a peer whose counter
 * stalls for KBOX_WD_STALL consecutive observations is declared dead.
 * Returns 1 alive, 0 dead (caller must funnel into the epoch fuse). */
typedef struct { uint32_t last; int stalls; int armed; } kbox_wdPeer_t;

static int kbox_wdPeerAlive(volatile uint32_t* hb, kbox_wdPeer_t* p) {
    uint32_t now = *hb;
    if (!p->armed) {
        if (now == 0) return 1;           /* peer not started yet: grace */
        p->last = now; p->armed = 1; return 1;
    }
    if (now == p->last) {
        if (++p->stalls > KBOX_WD_STALL) return 0;
    } else {
        p->last = now; p->stalls = 0;
    }
    return 1;
}

/* FNV-1a over one registered HOT range (RX code of a mapped module). */
static uint32_t kbox_hotRangeHash(uintptr_t lo, uintptr_t hi) {
    uint32_t h = 0x811c9dc5u;
    h ^= (uint32_t)lo; h *= 0x01000193u;
    const uint8_t* p = (const uint8_t*)lo;
    size_t n = (size_t)(hi - lo);
    for (size_t j = 0; j < n; j++) { h ^= p[j]; h *= 0x01000193u; }
    return h;
}

/* Per-range CRC of every registered HOT range (the "VM handler 区": code of
 * reflectively loaded vmp.bin / jnic.bin). Newly mapped ranges are snapshotted
 * on first observation; removed ranges (kbox_rangeUnmap on module teardown)
 * drop out; only a CHANGE to a settled range returns 1. */
#define KBOX_HOT_WATCH_MAX 16
typedef struct { uintptr_t lo, hi; uint32_t hash; } kbox_hotWatch_t;
static kbox_hotWatch_t g_hotWatch[KBOX_HOT_WATCH_MAX];
static int g_hotWatchN = 0;

static int kbox_hotCheck(void) {
    for (int i = 0; i < g_rN; i++) {
        if (g_rTer[i] != KBOX_TER_HOT) continue;
        uintptr_t lo = g_rLo[i], hi = g_rHi[i];
        int idx = -1;
        for (int j = 0; j < g_hotWatchN; j++) {
            if (g_hotWatch[j].lo == lo && g_hotWatch[j].hi == hi) { idx = j; break; }
        }
        if (idx < 0) {
            if (g_hotWatchN >= KBOX_HOT_WATCH_MAX) continue;
            g_hotWatch[g_hotWatchN].lo = lo;
            g_hotWatch[g_hotWatchN].hi = hi;
            g_hotWatch[g_hotWatchN].hash = kbox_hotRangeHash(lo, hi);
            g_hotWatchN++;
        } else {
            if (kbox_hotRangeHash(lo, hi) != g_hotWatch[idx].hash) return 1;
        }
    }
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
/* Label-bounded address range of W1's own code, captured by W1 on its first
 * tick. W2 re-hashes these exact bytes every tick — a patch to W1's body that
 * NOPs its probes / selfCheck is caught by W2's byte-CRC even if W1's own
 * checks were neutralised (true mutual sentinel). On non-GNU compilers (MSVC)
 * W2 falls back to the independent whole-image hash, which covers the same
 * bytes. */
static uintptr_t g_wd1Lo = 0;
static uintptr_t g_wd1Hi = 0;
static uint32_t g_wd1Base = 0;
#endif

#if defined(_WIN32)
static DWORD WINAPI kbox_watchdog(LPVOID arg) {
    (void)arg;
    kbox_epochInit();
    uint32_t seed = kbox_wdSeed();
    kbox_wdPeer_t peer2; memset(&peer2, 0, sizeof(peer2));
#if defined(__GNUC__) || defined(__clang__)
    if (g_wd1Lo == 0) {
        g_wd1Lo = (uintptr_t)&&kbox_wd1_begin;
        g_wd1Hi = (uintptr_t)&&kbox_wd1_end;
    }
    kbox_wd1_begin:;
#endif
    for (;;) {
        Sleep(kbox_wdDelay(&seed));
        /* L4.3: the integrity fuse itself must stay armed. If an attacker
         * zeroes the epoch page to "disable the fusing", the magic flips and
         * this tick hard-kills before any further probe can be neutralised. */
        if (!kbox_epochArmed()) { kbox_wdDiag("W1 epoch-not-armed"); kbox_epochBump(0x59); }
        /* L4.2 heartbeat: monotonic counter into the shared epoch page. */
        if (g_epoch != NULL) {
            uint32_t hb = g_epoch->hbW1 + 1;
            g_epoch->hbW1 = hb;
        }
        if (kbox_selfCheck() == 1) {
            /* .text section was patched — hard kill before any reused code. */
            kbox_wdDiag("W1 selfCheck-mismatch"); kbox_epochBump(0x51);
        }
        /* Strong debugger signals only: a hardware breakpoint / debug port /
         * PEB flag means an active debugger, which must die now. The weak
         * timing probe is deliberately NOT run here — this background thread
         * can be descheduled for >250 ms on a busy box and would false-positive
         * into killing a legitimate run. */
        if ((kbox_probeDebugger(0) & 1) != 0) {
            kbox_wdDiag("W1 probeDebugger-strong"); kbox_epochBump(0x41);
        }
        /* API hooks are high-confidence active instrumentation and are polled
         * here too (unlike the VM probe, which is deliberately absent so a
         * cloud-VM user is never killed by the poller). */
        if (kbox_probeHooks()) {
            kbox_wdDiag("W1 probeHooks"); kbox_epochBump(0x4C);
        }
        if (kbox_probeAgentModules()) {
            /* Hard kill: skip all cleanup so no agent code runs afterwards. */
            kbox_wdDiag("W1 agent-modules"); kbox_epochBump(0x4B);
        }
        /* W2 heartbeat liveness (mutual sentinel). */
        if (!kbox_wdPeerAlive(&g_epoch->hbW2, &peer2)) { kbox_wdDiag("W1 peer-W2-dead"); kbox_epochBump(0x5A); }
    }
#if defined(__GNUC__) || defined(__clang__)
    kbox_wd1_end:;
#endif
    return 0;
}
#else
static void* kbox_watchdog(void* arg) {
    (void)arg;
    kbox_epochInit();
    uint32_t seed = kbox_wdSeed();
    kbox_wdPeer_t peer2; memset(&peer2, 0, sizeof(peer2));
#if defined(__GNUC__) || defined(__clang__)
    if (g_wd1Lo == 0) {
        g_wd1Lo = (uintptr_t)&&kbox_wd1_begin;
        g_wd1Hi = (uintptr_t)&&kbox_wd1_end;
    }
    kbox_wd1_begin:;
#endif
    for (;;) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = (long)kbox_wdDelay(&seed) * 1000L * 1000L;
        nanosleep(&ts, NULL);
        if (!kbox_epochArmed()) { kbox_wdDiag("W1p epoch-not-armed"); kbox_epochBump(0x59); }
        if (g_epoch != NULL) {
            uint32_t hb = g_epoch->hbW1 + 1;
            g_epoch->hbW1 = hb;
        }
        if (kbox_selfCheck() == 1) {
            kbox_wdDiag("W1p selfCheck-mismatch"); kbox_epochBump(0x51);
        }
        if ((kbox_probeDebugger(0) & 1) != 0) {
            kbox_wdDiag("W1p probeDebugger-strong"); kbox_epochBump(0x41);
        }
        if (kbox_probeHooks()) {
            kbox_wdDiag("W1p probeHooks"); kbox_epochBump(0x4C);
        }
        if (kbox_probeAgentModules()) {
            kbox_wdDiag("W1p agent-modules"); kbox_epochBump(0x4B);
        }
        if (!kbox_wdPeerAlive(&g_epoch->hbW2, &peer2)) { kbox_wdDiag("W1p peer-W2-dead"); kbox_epochBump(0x5A); }
    }
#if defined(__GNUC__) || defined(__clang__)
    kbox_wd1_end:;
#endif
    return NULL;
}
#endif

/* W2: independent sentinel. Its whole-image hash and HOT-range CRC keep
 * running even if W1's thread is killed or W1's checks are NOPed. */
#if defined(_WIN32)
static DWORD WINAPI kbox_watchdog2(LPVOID arg) {
    (void)arg;
    kbox_epochInit();
    uint32_t seed = kbox_wdSeed();
    kbox_wdPeer_t peer1; memset(&peer1, 0, sizeof(peer1));
    for (;;) {
        Sleep(kbox_wdDelay(&seed));
        if (!kbox_epochArmed()) kbox_epochBump(0x59);
        if (g_epoch != NULL) {
            uint32_t hb = g_epoch->hbW2 + 1;
            g_epoch->hbW2 = hb;
        }
        /* Independent whole-image hash: catches a patch to W1's body or the
         * shared checks even if W1's thread is dead / W1's checks were NOPed. */
        if (kbox_selfCheck() == 1) kbox_epochBump(0x51);
        /* VM-handler region: per-range CRC of the registered HOT code. */
        if (kbox_hotCheck()) kbox_epochBump(0x54);
        /* HOT must stay executable-and-not-writable (hook/dump probe). */
        if (kbox_terrainCheck()) kbox_epochBump(0x55);
#if defined(__GNUC__) || defined(__clang__)
        /* Independent byte-CRC of W1's own code region (label-bounded). */
        if (g_wd1Lo != 0 && g_wd1Hi > g_wd1Lo) {
            uint32_t h = kbox_textHash(KBOX_TEXT_SALT ^ 0x7D1u,
                                       (const uint8_t*)g_wd1Lo,
                                       (size_t)(g_wd1Hi - g_wd1Lo));
            if (g_wd1Base == 0) g_wd1Base = h;
            else if (h != g_wd1Base) { kbox_wdDiag("W2 W1-code-CRC"); kbox_epochBump(0x57); }
        }
#endif
        /* W1 heartbeat liveness (mutual sentinel). */
        if (!kbox_wdPeerAlive(&g_epoch->hbW1, &peer1)) { kbox_wdDiag("W2 peer-W1-dead"); kbox_epochBump(0x5A); }
    }
    return 0;
}
#else
static void* kbox_watchdog2(void* arg) {
    (void)arg;
    kbox_epochInit();
    uint32_t seed = kbox_wdSeed();
    kbox_wdPeer_t peer1; memset(&peer1, 0, sizeof(peer1));
    for (;;) {
        struct timespec ts;
        ts.tv_sec = 0;
        ts.tv_nsec = (long)kbox_wdDelay(&seed) * 1000L * 1000L;
        nanosleep(&ts, NULL);
        if (!kbox_epochArmed()) { kbox_wdDiag("W2 epoch-not-armed"); kbox_epochBump(0x59); }
        if (g_epoch != NULL) {
            uint32_t hb = g_epoch->hbW2 + 1;
            g_epoch->hbW2 = hb;
        }
        if (kbox_selfCheck() == 1) { kbox_wdDiag("W2 selfCheck-mismatch"); kbox_epochBump(0x51); }
        if (kbox_hotCheck()) { kbox_wdDiag("W2 hotCheck"); kbox_epochBump(0x54); }
        if (kbox_terrainCheck()) { kbox_wdDiag("W2 terrainCheck"); kbox_epochBump(0x55); }
#if defined(__GNUC__) || defined(__clang__)
        if (g_wd1Lo != 0 && g_wd1Hi > g_wd1Lo) {
            uint32_t h = kbox_textHash(KBOX_TEXT_SALT ^ 0x7D1u,
                                       (const uint8_t*)g_wd1Lo,
                                       (size_t)(g_wd1Hi - g_wd1Lo));
            if (g_wd1Base == 0) g_wd1Base = h;
            else if (h != g_wd1Base) kbox_epochBump(0x57);
        }
#endif
        if (!kbox_wdPeerAlive(&g_epoch->hbW1, &peer1)) kbox_epochBump(0x5A);
    }
    return NULL;
}
#endif

/* Starts both detached watchdog threads. Best-effort: if thread creation fails
 * the per-define gate still fails closed, so this is defense-in-depth only. */
static void startWatchdog(void) {
#if defined(_WIN32)
    CreateThread(NULL, 0, kbox_watchdog, NULL, 0, NULL);
    CreateThread(NULL, 0, kbox_watchdog2, NULL, 0, NULL);
#else
    pthread_t tid;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) return;
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, kbox_watchdog, NULL) != 0) {
        pthread_attr_destroy(&attr);
        return;
    }
    if (pthread_create(&tid, &attr, kbox_watchdog2, NULL) != 0) {
        pthread_attr_destroy(&attr);
        return;
    }
    pthread_attr_destroy(&attr);
#endif
}

static jboolean JNICALL kbox_bf_safeBoot
    (JNIEnv* env, jclass cls, jobjectArray args) {
    (void)env; (void)cls;
    /* Fail-closed boot: any strong OR weak debugger signal refuses to boot
     * before a single protected class is defined. Strong = active debugger /
     * hardware breakpoint; weak = timing / INT3 anomaly (boot context is the
     * JVM main thread, so the timing probe is safe here). A VM or an API-hook
     * on a memory primitive also refuses boot outright. */
    if (kbox_probeDebugger(1) != 0) { kbox_wdDiag("safeBoot probeDebugger"); return JNI_TRUE; }
    if (kbox_probeHooks()) { kbox_wdDiag("safeBoot probeHooks"); return JNI_TRUE; }
    if (kbox_probeVM()) { kbox_wdDiag("safeBoot probeVM"); return JNI_TRUE; }
    if (kbox_probeAgentModules()) { kbox_wdDiag("safeBoot agent-modules"); return JNI_TRUE; }
    if (args != NULL) {
        jsize argc = (*env)->GetArrayLength(env, args);
        if (argc > 0) {
            const char** av = (const char**)calloc((size_t)argc, sizeof(char*));
            if (av != NULL) {
                for (jsize i = 0; i < argc; i++) {
                    jstring s = (jstring)(*env)->GetObjectArrayElement(env, args, i);
                    if (s != NULL) av[i] = (*env)->GetStringUTFChars(env, s, NULL);
                }
                int hit = kbox_scanArgs(av, (int)argc);
                for (jsize i = 0; i < argc; i++) {
                    if (av[i] != NULL) {
                        jstring s = (jstring)(*env)->GetObjectArrayElement(env, args, i);
                        (*env)->ReleaseStringUTFChars(env, s, av[i]);
                    }
                }
                free(av);
                if (hit) return JNI_TRUE;
            }
        }
    }
    return JNI_FALSE;
}

/* per-run native session epoch. Mixed from the loader's load-time time base
 * (QPC/RDTSC-grade on Windows, CLOCK_MONOTONIC on POSIX) so it differs across
 * process loads. Consumed by the Java session layer only (KbnlKey.sessionEpoch)
 * to strengthen cross-run key separation. MUST NOT enter domainSeed: the blob
 * keys derive() produces are baked at pack time (NativePacker) and must be
 * re-derived identically at run time, so any per-load entropy there would make
 * native.bin/jnic.bin/vmp.bin/native-crypto.bin permanently undecryptable. */
static jbyteArray JNICALL kbox_bf_sessionEpoch(JNIEnv* env, jclass cls) {
    (void)cls;
    unsigned char buf[32];
    uint64_t a, b;
#if defined(_WIN32)
    LARGE_INTEGER pc, freq;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&pc);
    a = ((uint64_t)(pc.QuadPart | 0)) ^ (((uint64_t)GetTickCount64()) << 32);
    b = ((uint64_t)freq.QuadPart) * 2654435761u;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    a = ((uint64_t)ts.tv_sec * 1000000000ull) + (uint64_t)ts.tv_nsec;
    b = ((uint64_t)(uint32_t)(a >> 32)) * 2654435761u;
#endif
    uint64_t x = mix32((uint32_t)a) ^ (b + 0x4b6b5f5fu);
    int i;
    for (i = 0; i < 32; i++) {
        x ^= x >> 12; x ^= x << 25; x ^= x >> 27;
        buf[i] = (unsigned char)((x * 2685821657736338717ull) >> 32);
    }
    jbyteArray out = (*env)->NewByteArray(env, 32);
    if (out != NULL) {
        (*env)->SetByteArrayRegion(env, out, 0, 32, (const jbyte*)buf);
    }
    volatile unsigned char* w = buf;
    for (i = 0; i < 32; i++) w[i] = 0;
    return out;
}

/* Zero the Java heap byte[] that holds a decrypted module (vmp.bin/jnic.bin
 * PE or .so) and release it with commit mode 0. The prior code released with
 * JNI_ABORT, which only drops the native (maybe-copied) buffer WITHOUT writing
 * anything back — so however the decryption handed it over, the plaintext
 * module kept resting in the JVM heap until GC. Zeroing the buffer first and
 * committing writes the wipe into the backing array, so neither the direct
 * pinned pointer (zeroed in place) nor a JVM copy (written back) can leave a
 * plaintext .so/PE behind for a heap-dump / mem-scan. */
static void kbox_wipe_bytearray(JNIEnv* env, jbyteArray a, jbyte* data, jsize n){
    if (data == NULL) return;
    if (n > 0) {
        volatile jbyte* p = data;
        jsize i;
        for (i = 0; i < n; ++i) p[i] = 0;
    }
    (*env)->ReleaseByteArrayElements(env, a, data, 0);
}

/* ====================================================================
 * In-memory module loading (reflective). Map the decrypted PE for vmp.bin /
 * jnic.bin straight from the heap byte[] — never written to disk — then bind
 * its exported registrar onto NativeLoader via RegisterNatives. Windows only:
 * on non-Windows (or any failure) return JNI_FALSE so NativeLoader falls back
 * to the writeToTemp+System.load+purge path.
 *
 * Note the binding model: kbox_reflect_loader.c maps the PE (relocations,
 * imports, per-section protections, TLS) and kbox_refl_getproc walks its
 * export table. Because NativeLoader.registerNatives0 / registerVmpNatives0 are
 * exported by the module (jnic.bin / vmp.bin), once bound the existing Java
 * flow continues to call them as before — no PEB insertion is required since
 * all native registration in this engine is upside-down (RegisterNatives).
 * ==================================================================== */
static jboolean JNICALL kbox_bf_mapModule(JNIEnv* env, jclass cls, jbyteArray pe,
                                          jstring binderName) {
    (void)cls;
#if defined(_WIN32)
    if (pe == NULL || binderName == NULL) return JNI_FALSE;
    jsize n = (*env)->GetArrayLength(env, pe);
    if (n <= 0) return JNI_FALSE;
    jbyte* data = (*env)->GetByteArrayElements(env, pe, NULL);
    if (data == NULL) return JNI_FALSE;

    void* base = kbox_refl_map((const BYTE*)data, (size_t)n);
    /* Keep the array intact (JNI_ABORT) so the Java-side writeToTemp fallback
     * still has the live plaintext if any step here fails. Wipe only on final
     * success below. */
    (*env)->ReleaseByteArrayElements(env, pe, data, JNI_ABORT);
    if (base == NULL) return JNI_FALSE;

    /* Run the module's JNI_OnLoad (side effects only; native methods are not
     * registered there — each module registers via the binder). */
    kbox_refl_run_jnionload(env, base);

    const char* bname = (*env)->GetStringUTFChars(env, binderName, NULL);
    if (bname == NULL) { kbox_refl_unmap(base); return JNI_FALSE; }
    int isVmp = (strstr(bname, "registerVmpNatives0") != NULL);
    void* binder = kbox_refl_getproc(base, bname);
    (*env)->ReleaseStringUTFChars(env, binderName, bname);
    if (binder == NULL) { kbox_refl_unmap(base); return JNI_FALSE; }

    /* Register the module binder onto NativeLoader itself, so the existing Java
     * call NativeLoader.registerVmpNatives0(Class) resolves to it. The binder
     * has signature (Ljava/lang/Class;)V. NOTE: mapModule lives on BfSecureLoader
     * (the jclass passed in), but the binder must land on NativeLoader. */
    jclass nl = (*env)->FindClass(env, "com/kbox/runtime/NativeLoader");
    if (nl == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        kbox_refl_unmap(base);
        return JNI_FALSE;
    }
    JNINativeMethod nm;
    nm.name = isVmp ? "registerVmpNatives0" : "registerNatives0";
    nm.signature = "(Ljava/lang/Class;)V";
    nm.fnPtr = binder;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if ((*env)->RegisterNatives(env, nl, &nm, 1) != 0) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        kbox_refl_unmap(base);
        return JNI_FALSE;
    }

    /* The mapping must stay alive as long as the registered natives reference
     * it; the JVM teardown releases process memory at exit, so we simply keep
     * a reference to it for the module lifetime. */
    (void)base;
    /* Anti-dump: the module binder is now bound onto NativeLoader, so the
     * mapped image's PE headers + export table are dead weight. Scrub them so
     * a memory-dump parser cannot anchor onto this module by its MZ/PE. */
    kbox_refl_scrub(base);
    /* Module fully mapped + bound + scrubbed. The plaintext PE must not rest in
     * the Java heap; re-acquire the decrypted byte[] and zero its backing array
     * now that no fallback can need it. Safe both when GetByteArrayElements
     * pinned the real array (zeroed in place) or returned a copy (commit writes
     * the wipe back). */
    {
        jbyte* zero = (*env)->GetByteArrayElements(env, pe, NULL);
        if (zero != NULL) kbox_wipe_bytearray(env, pe, zero, n);
    }
    return JNI_TRUE;
#elif defined(__linux__) || defined(__linux)
    /* Diskless Linux loading via a memfd-backed in-memory .so, mirroring the
     * Windows MapViewOfFile path. mkstemp+writeToTemp+purge on mac/iOS stays as
     * the (already required by Apple) fallback; on Linux we never touch disk.
     * If any step fails we return JNI_FALSE so the Java side transparently
     * degrades to writeToTemp+System.load — never a hard failure. */
    if (pe == NULL || binderName == NULL) return JNI_FALSE;
    jsize n = (*env)->GetArrayLength(env, pe);
    if (n <= 0) return JNI_FALSE;
    jbyte* data = (*env)->GetByteArrayElements(env, pe, NULL);
    if (data == NULL) return JNI_FALSE;

#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif
    int fd = (int)syscall(__NR_memfd_create, "kbox", 0);
    if (fd < 0) { (*env)->ReleaseByteArrayElements(env, pe, data, JNI_ABORT); return JNI_FALSE; }
    size_t off = 0;
    while (off < (size_t)n) {
        ssize_t w = write(fd, (const char*)data + off, (size_t)n - off);
        if (w <= 0) { close(fd); (*env)->ReleaseByteArrayElements(env, pe, data, JNI_ABORT); return JNI_FALSE; }
        off += (size_t)w;
    }
    /* Keep the array intact (JNI_ABORT) so the Java-side writeToTemp fallback
     * still has the live plaintext if any step below fails. Wipe only on final
     * success. */
    (*env)->ReleaseByteArrayElements(env, pe, data, JNI_ABORT);

    const char* bname = (*env)->GetStringUTFChars(env, binderName, NULL);
    if (bname == NULL) { close(fd); return JNI_FALSE; }
    char dlp[96];
    snprintf(dlp, sizeof(dlp), "/proc/self/fd/%d", fd);
    void* h = dlopen(dlp, RTLD_NOW);
    if (h == NULL) { (*env)->ReleaseStringUTFChars(env, binderName, bname); close(fd); return JNI_FALSE; }

    /* Side-effect JNI_OnLoad first (native methods register via the binder). */
    void* jol = dlsym(h, "JNI_OnLoad");
    if (jol != NULL) {
        JavaVM* vm = NULL;
        if ((*env)->GetJavaVM(env, &vm) == 0 && vm != NULL) {
            ((jint(*)(JavaVM*, void*))jol)(vm, NULL);
        }
    }

    int isVmp = (strstr(bname, "registerVmpNatives0") != NULL);
    void* binder = dlsym(h, bname);
    (*env)->ReleaseStringUTFChars(env, binderName, bname);
    if (binder == NULL) { close(fd); return JNI_FALSE; }

    jclass nl = (*env)->FindClass(env, "com/kbox/runtime/NativeLoader");
    if (nl == NULL) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        close(fd); return JNI_FALSE;
    }
    JNINativeMethod nm;
    nm.name = isVmp ? "registerVmpNatives0" : "registerNatives0";
    nm.signature = "(Ljava/lang/Class;)V";
    nm.fnPtr = binder;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    if ((*env)->RegisterNatives(env, nl, &nm, 1) != 0) {
        if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
        close(fd); return JNI_FALSE;
    }
    /* The memfd stays open for the module lifetime (its inode keeps the mapping
     * alive); closing is deferred to process exit where the fd is released. */
    (void)fd;
    /* Module fully loaded + bound. Wipe the decrypted .so out of the Java heap
     * now that no fallback can need it. */
    {
        jbyte* zero = (*env)->GetByteArrayElements(env, pe, NULL);
        if (zero != NULL) kbox_wipe_bytearray(env, pe, zero, n);
    }
    return JNI_TRUE;
#else
    /* macOS / other POSIX: no portable diskless loader — the Java side ALREADY
     * falls back to writeToTemp(.dylib)+System.load+schedulePurge, so returning
     * FALSE here is the correct, safe degradation. */
    (void)env; (void)pe; (void)binderName;
    return JNI_FALSE;
#endif
}

/* ==================================================================== *
 * String BfSecureLoader.purgeSelf(String path) — purge the temporary
 * bootstrap PE (native.bin) from disk immediately after System.load mapped
 * it. Returns the on-disk path still needing cleanup at exit (the renamed
 * random hidden name) or NULL when the file was fully removed.
 *
 * The resident decoder cannot be loaded in-memory (it IS the thing that
 * provides mapModule), so it must pass through System.load from a temp file.
 * Windows refuses to delete a file while an image section keeps it mapped
 * (delete-pending and DeleteFileW both return ACCESS_DENIED — verified on
 * this target), so this removes the predictable directory entry by RENAMING
 * the loaded module to a random hidden name — the one operation Windows does
 * permit on a mapped image — and additionally commits a POSIX delete-pending
 * (frees the content once the section closes) plus a delete-at-reboot
 * request. Java purges the returned path at exit. On POSIX, plain unlink
 * works because a loaded .so keeps its inode alive until unmapped.
 * ==================================================================== */
#if defined(_WIN32)
static wchar_t* kbox_bf_renameHidden(const wchar_t* wpath) {
    const wchar_t* slash = wcsrchr(wpath, L'\\');
    if (slash == NULL) return NULL;
    size_t dirlen = (size_t)(slash - wpath + 1); /* include trailing backslash */
    wchar_t* wnew = (wchar_t*)malloc((dirlen + 32) * sizeof(wchar_t));
    if (wnew == NULL) return NULL;
    wcsncpy(wnew, wpath, dirlen);
    static volatile LONG g_cnt = 0;
    LONG cnt = InterlockedIncrement(&g_cnt);
    ULONGLONG t = GetTickCount64() ^ (ULONGLONG)(uintptr_t)wpath
                  ^ (ULONGLONG)GetCurrentProcessId();
    wsprintfW(wnew + dirlen, L".kbox~%08X%02X.tmp",
              (DWORD)t, (DWORD)(cnt & 0xFF));
    if (!MoveFileExW(wpath, wnew, MOVEFILE_REPLACE_EXISTING)) {
        free(wnew);
        return NULL;
    }
    SetFileAttributesW(wnew, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY);
    return wnew;
}
#endif

static jstring JNICALL kbox_bf_purgeSelf(JNIEnv* env, jclass cls, jstring path) {
    (void)cls;
    if (path == NULL) return NULL;
    const jchar* chars = (*env)->GetStringChars(env, path, NULL);
    if (chars == NULL) return NULL;
    jsize len = (*env)->GetStringLength(env, path);
    jstring result = NULL;
#if defined(_WIN32)
    wchar_t* wpath = (wchar_t*)malloc(((size_t)len + 1) * sizeof(wchar_t));
    if (wpath != NULL) {
        for (jsize i = 0; i < len; i++) wpath[i] = (wchar_t)chars[i];
        wpath[len] = 0;
        typedef BOOL (WINAPI *FnSetFileInfo)(HANDLE, DWORD, LPVOID, DWORD);
        FnSetFileInfo fn = (FnSetFileInfo)(void*)GetProcAddress(
                GetModuleHandleW(L"kernel32.dll"), "SetFileInformationByHandle");

        /* 1) Plain delete-pending — works when the loader opened the image with
         *    FILE_SHARE_DELETE (some Windows builds); ACCESS_DENIED here. */
        int deleted = 0;
        HANDLE h = CreateFileW(wpath, DELETE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            if (fn != NULL) {
                struct { BOOLEAN DeleteFile; } di;
                di.DeleteFile = TRUE;
                deleted = fn(h, 4 /* FileDispositionInfo */, &di, sizeof(di));
            }
            CloseHandle(h);
        }

        if (!deleted) {
            /* 2) Commit a POSIX delete-pending on the original name — accepted
             *    even while the image is mapped; frees the content once the
             *    section closes at teardown. */
            if (fn != NULL) {
                HANDLE h2 = CreateFileW(wpath, DELETE,
                                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
                if (h2 != INVALID_HANDLE_VALUE) {
                    struct { DWORD Flags; } diEx;
                    diEx.Flags = 0x2 /* FILE_DISPOSITION_POSIX_SEMANTICS */;
                    fn(h2, 21 /* FileDispositionInfoEx */, &diEx, sizeof(diEx));
                    CloseHandle(h2);
                }
            }
            /* 3) Rename to a random hidden name — the only reliable way to
             *    remove the predictable temp entry while the module is mapped. */
            wchar_t* wnew = kbox_bf_renameHidden(wpath);
            if (wnew != NULL) {
                /* Best-effort: deletion still fails while mapped; schedule the
                 * renamed file for delete at next reboot, and hand it back to
                 * Java so a shutdown hook can purge it at exit. */
                DeleteFileW(wnew);
                MoveFileExW(wnew, NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
                result = (*env)->NewString(env, (const jchar*)wnew,
                                           (jsize)wcslen(wnew));
                free(wnew);
            }
        }
        free(wpath);
    }
#else
    char* u = (char*)malloc((size_t)len + 1);
    if (u != NULL) {
        for (jsize i = 0; i < len; i++) u[i] = (char)chars[i];
        u[len] = 0;
        remove(u);
        free(u);
    }
#endif
    (*env)->ReleaseStringChars(env, path, chars);
    return result;
}