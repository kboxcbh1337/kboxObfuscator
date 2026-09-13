/* ====================================================================
 * Reflective in-memory PE32+ loader (Windows only) for vmp.bin / jnic.bin.
 *
 * Loads a decrypted PE straight from a heap byte[] without ever writing it to
 * disk (no writeToTemp / System.load). Because every native function in this
 * engine is bound upside-down via RegisterNatives (kbox_bf_loader registers
 * BfSecureLoader's methods; each module's binder registers execute/RG onto its
 * class), the mapped module must NOT appear in either the PEB module list or the
 * JVM's library registry. We simply:
 *   1. map the PE (headers / sections / relocations / imports / TLS / per-section
 *      page protections),
 *   2. run its JNI_OnLoad if exported (side effects only),
 *   3. resolve the module's exported *binder* symbol
 *      (Java_..._NativeLoader_registerVmpNatives0 / ..._registerNatives0) straight
 *      from the mapped export table and RegisterNatives it onto NativeLoader.
 * After that, the existing Java flow keeps calling NativeLoader.registerVmpNatives0/
 * registerNatives0, which now resolve to the module's C binder. No GetProcAddress
 * of the JVM, no PEB surgery.
 *
 * Guarded for Windows: on non-Windows the wrapper returns JNI_FALSE so
 * NativeLoader falls back to the temp-file + purge path.
 * ==================================================================== */

#if defined(_WIN32)
#ifndef KBOX_REFLECT_LOADER_C_INCLUDED
#define KBOX_REFLECT_LOADER_C_INCLUDED

/* ---- minimal image constants that may be absent on older mingw sdks ---- */
#ifndef IMAGE_DIRECTORY_ENTRY_TLS
#define IMAGE_DIRECTORY_ENTRY_TLS 9
#endif
#ifndef IMAGE_REL_BASED_DIR64
#define IMAGE_REL_BASED_DIR64 10
#endif
#ifndef IMAGE_SCN_MEM_WRITE
#define IMAGE_SCN_MEM_WRITE 0x80000000
#endif
#ifndef IMAGE_SCN_MEM_EXECUTE
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#endif

/* ---- L1 HOT registration (backed by kbox_bf_loader.c's RangeTable) ---- */
/* The mapped module's pure-RX code sections are registered as KBOX_TER_HOT so
 * kbox_terrainCheck() re-verifies they stay executable-and-not-writable (a
 * hook/dump tool that clears the X bit or adds W is caught by probePageAttrs).
 * g_reflHotMark snapshots g_hotN at map time; kbox_refl_unmap rolls back
 * exactly the ranges that map call added, so several resident modules never
 * cross-contaminate each other's registrations. */
#define KBOX_REFL_HOT_MAX 16
static uintptr_t g_hotLo[KBOX_REFL_HOT_MAX];
static uintptr_t g_hotHi[KBOX_REFL_HOT_MAX];
static int g_hotN = 0;
static int g_reflHotMark = -1;

static void kbox_refl_hotAdd(uintptr_t lo, uintptr_t hi) {
    if (g_hotN >= KBOX_REFL_HOT_MAX) return;
    g_hotLo[g_hotN] = lo; g_hotHi[g_hotN] = hi; g_hotN++;
}

static void kbox_refl_hotRollback(void) {
    if (g_reflHotMark >= 0) {
        for (int i = g_hotN - 1; i >= g_reflHotMark; i--) {
            kbox_rangeUnmap(g_hotLo[i], g_hotHi[i]);
        }
        g_hotN = g_reflHotMark;
        g_reflHotMark = -1;
    }
}


/* Map a PE32+ (x64) image from a memory buffer. On success returns the image
 * base (page-granular, per-section finals protections applied, imports resolved,
 * TLS callbacks run). Returns NULL on any failure. Caller owns the mapping and
 * must kbox_refl_unmap() it (or keep it alive for the module lifetime). */
static void* kbox_refl_map(const BYTE* buf, size_t buflen){
    if (buf == NULL || buflen < 0x1000) return NULL;
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buf;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    if (dos->e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) > (long)buflen) return NULL;
    const IMAGE_NT_HEADERS64* nt = (const IMAGE_NT_HEADERS64*)(buf + (long)dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;
    IMAGE_OPTIONAL_HEADER64 oh = nt->OptionalHeader;
    if (oh.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return NULL;

    /* Prefer the image's preferred base; fall back to free placement
     * (relocated below) when that address is already owned. */
    SIZE_T imageSize = oh.SizeOfImage;
    BYTE* base = (BYTE*)VirtualAlloc((LPVOID)(uintptr_t)oh.ImageBase, imageSize,
                                     MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (base == NULL) {
        base = (BYTE*)VirtualAlloc(NULL, imageSize,
                                   MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    if (base == NULL) return NULL;

    /* Headers */
    size_t hs = oh.SizeOfHeaders < buflen ? oh.SizeOfHeaders : buflen;
    memcpy(base, buf, hs);

    /* Sections */
    const IMAGE_SECTION_HEADER* sec =
        (const IMAGE_SECTION_HEADER*)((const BYTE*)nt + sizeof(IMAGE_NT_HEADERS64));
    DWORD nSec = nt->FileHeader.NumberOfSections;
    DWORD i;
    for (i = 0; i < nSec; i++){
        if (sec[i].PointerToRawData + sec[i].SizeOfRawData <= buflen){
            memcpy(base + sec[i].VirtualAddress, buf + sec[i].PointerToRawData,
                   sec[i].SizeOfRawData);
        }
    }

    /* Relocations */
    long long delta = (long long)((uintptr_t)base - (uintptr_t)oh.ImageBase);
    DWORD er = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    DWORD esz = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (delta != 0 && er && esz){
        DWORD off = 0;
        while (off + 8 <= esz){
            const IMAGE_BASE_RELOCATION* br =
                (const IMAGE_BASE_RELOCATION*)(base + er + off);
            if (br->SizeOfBlock == 0) break;
            DWORD count = (br->SizeOfBlock - 8) / 2;
            const unsigned short* ents = (const unsigned short*)(br + 1);
            for (DWORD j = 0; j < count; j++){
                unsigned short e = ents[j];
                unsigned short t = e >> 12, o = e & 0xFFF;
                if (t == IMAGE_REL_BASED_DIR64){
                    *(long long*)((BYTE*)base + br->VirtualAddress + o) += delta;
                } else if (t == IMAGE_REL_BASED_HIGHLOW){
                    *(int*)((BYTE*)base + br->VirtualAddress + o) += (int)delta;
                }
                /* ABSOLUTE(0)=noop; other types ignored */
            }
            off += br->SizeOfBlock;
        }
    }

    /* Imports -> resolve into the IAT */
    DWORD ii = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (ii){
        IMAGE_IMPORT_DESCRIPTOR* id = (IMAGE_IMPORT_DESCRIPTOR*)(base + ii);
        for (; id->Name; id++){
            HMODULE dep = LoadLibraryA((const char*)(base + id->Name));
            DWORD look = id->OriginalFirstThunk ? id->OriginalFirstThunk : id->FirstThunk;
            DWORD iat  = id->FirstThunk;
            DWORD idx = 0;
            for (;;){
                unsigned long long ivo;
                memcpy(&ivo, (BYTE*)base + look + idx*8, 8);
                if (!ivo) break;
                FARPROC fp;
                if (ivo & 0x8000000000000000ULL){
                    fp = dep ? GetProcAddress(dep, (LPCSTR)(ivo & 0xFFFF)) : NULL;
                } else {
                    const IMAGE_IMPORT_BY_NAME* ibn =
                        (const IMAGE_IMPORT_BY_NAME*)((BYTE*)base + (unsigned long)ivo);
                    fp = dep ? GetProcAddress(dep, (LPCSTR)ibn->Name) : NULL;
                }
                *(unsigned long long*)((BYTE*)base + iat + idx*8) = (unsigned long long)fp;
                idx++;
            }
        }
    }

    /* Per-section final protections (imports already resolved). Calling into a
     * READWRITE (no EXECUTE) page faults on NX, so mirror section flags. */
    {
        DWORD old;
        for (i = 0; i < nSec; i++){
            DWORD prot = PAGE_READONLY;
            DWORD ch = sec[i].Characteristics;
            if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
            if (ch & IMAGE_SCN_MEM_WRITE){
                prot = (ch & IMAGE_SCN_MEM_EXECUTE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
            }
            DWORD vlen = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
            if (vlen) VirtualProtect(base + sec[i].VirtualAddress, vlen, prot, &old);
        }
    }

    /* L1 HOT registration: pure-RX code sections (executable & NOT writable)
     * become terrain-HOT ranges so kbox_terrainCheck() can re-verify they stay
     * executable-and-not-writable. Writable code sections are skipped — their
     * RWX is legitimate and would false-positive the invariant. */
    {
        g_reflHotMark = g_hotN;
        for (i = 0; i < nSec; i++){
            DWORD ch = sec[i].Characteristics;
            if ((ch & IMAGE_SCN_MEM_EXECUTE) && !(ch & IMAGE_SCN_MEM_WRITE)){
                DWORD vlen = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
                if (vlen){
                    uintptr_t lo = (uintptr_t)(base + sec[i].VirtualAddress);
                    uintptr_t hi = lo + vlen;
                    kbox_rangeMap(lo, hi, KBOX_TER_HOT);
                    kbox_refl_hotAdd(lo, hi);
                }
            }
        }
    }

    /* TLS callbacks (VA fields already relocated above) */
    DWORD ti = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
    if (ti){
        IMAGE_TLS_DIRECTORY64* tls = (IMAGE_TLS_DIRECTORY64*)(base + ti);
        unsigned long long cbs = (unsigned long long)(uintptr_t)tls->AddressOfCallBacks;
        if (cbs){
            unsigned long long* cbp = (unsigned long long*)(uintptr_t)cbs;
            for (; *cbp; cbp++){
                typedef void (__stdcall *cb)(void*, DWORD, void*);
                cb f = (cb)(uintptr_t)*cbp;
                if (f) f((void*)base, DLL_PROCESS_ATTACH, NULL);
            }
        }
    }

    return base;
}

/* Export-table walk: return the mapped address of an exported symbol, or NULL. */
static void* kbox_refl_getproc(void* base, const char* name){
    if (base == NULL || name == NULL) return NULL;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)((BYTE*)base + dos->e_lfanew);
    DWORD er = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!er) return NULL;
    IMAGE_EXPORT_DIRECTORY* ed = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)base + er);
    DWORD* names  = (DWORD*)((BYTE*)base + ed->AddressOfNames);
    unsigned short* ords = (unsigned short*)((BYTE*)base + ed->AddressOfNameOrdinals);
    DWORD* funcs  = (DWORD*)((BYTE*)base + ed->AddressOfFunctions);
    DWORD k;
    for (k = 0; k < ed->NumberOfNames; k++){
        const char* n = (const char*)((BYTE*)base + names[k]);
        if (strcmp(n, name) == 0) return (BYTE*)base + funcs[ords[k]];
    }
    return NULL;
}

static void kbox_refl_unmap(void* base){
    /* Roll back the HOT terrain registrations this map call added, so the
     * RangeTable never points at the region we are about to release. */
    kbox_refl_hotRollback();
    if (base) VirtualFree(base, 0, MEM_RELEASE);
}

/* Anti-dump: after a module's export binder has been resolved and registered,
 * the DOS/NT headers and the export directory in the MAPPED image are dead
 * weight. A memory-dump/parse tool anchors onto a module by scanning for the
 * IMAGE_DOS_SIGNATURE and NT signature, then walks the optional header to find
 * its sections (the classic DumpBin/PE-parser entry point). Scrubbing them from
 * the mapped copy removes that anchor: the image pages stay alive and the code
 * keeps running (binder/native methods are already bound via RegisterNatives;
 * nothing re-reads the headers after this point), but a dump scanner can no
 * longer even locate the module, let alone enumerate its sections. Only the
 * header region and the export data region are cleared — never the code. */
static void kbox_refl_scrub(void* base){
    if (base == NULL) return;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return;
    BYTE* ntbytes = (BYTE*)base + dos->e_lfanew;
    IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)ntbytes;
    if (nt->Signature != IMAGE_NT_SIGNATURE) return;
    SIZE_T hdr = nt->OptionalHeader.SizeOfHeaders;
    if (hdr < 0x1000) hdr = 0x1000;
    /* Two reasons a raw SecureZeroMemory here misfires:
     *  (a) overrun — the wipe target can sit right at/past SizeOfImage (the
     *      mapping is committed exactly up to that bound), touching the
     *      uncommitted guard page -> AV;
     *  (b) protection — per-section final protections set .edata/.rdata pages
     *      to READONLY, so writing to the export directory faults too.
     * Clamp to the committed image AND transiently VirtualProtect RW -> wipe ->
     * restore, so the header/export scrub is safe on any PE layout. Only the
     * header region and the export data region are cleared — never live code. */
    SIZE_T image = nt->OptionalHeader.SizeOfImage;
    DWORD er = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD es = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
#define KBOX_SCRUB_WIPE(p, n) do {                                          \
        if ((n)) {                                                          \
            void* _p = (p); SIZE_T _n = (n); DWORD _old = 0, _tmp = 0;      \
            if (VirtualProtect(_p, _n, PAGE_READWRITE, &_old)) {            \
                SecureZeroMemory(_p, _n);                                   \
                VirtualProtect(_p, _n, _old, &_tmp);                        \
            }                                                               \
        }                                                                   \
    } while (0)
    /* 1) Wipe the mapped headers: MZ, NT signature, optional header, and all
     *    section headers — the PE anchor is gone. */
    SIZE_T n0 = (hdr <= 0x1000000 && hdr <= image) ? hdr : 0;
    KBOX_SCRUB_WIPE(base, n0);
    /* 2) Wipe the export directory data so the symbol table cannot be walked
     *    as an alternative anchor (limits VA-walkers using the .edata). */
    if (er && es && (uintptr_t)er < 0x1000000) {
        SIZE_T start = (SIZE_T)er, n = (SIZE_T)es;
        if (start >= image)      n = 0;                       /* wholly past image */
        else if (start + n > image) n = image - start;        /* clamp to tail */
        if (n) KBOX_SCRUB_WIPE((BYTE*)base + start, n);
    }
#undef KBOX_SCRUB_WIPE
}

/* Run the mapped module's JNI_OnLoad, if exported. Returns its version code,
 * or 0 if absent. Clears any JNI exception before returning. */
static jint kbox_refl_run_jnionload(JNIEnv* env, void* base){
    JavaVM* vm = NULL;
    if ((*env)->GetJavaVM(env, &vm) != JNI_OK || vm == NULL) return 0;
    void* p = kbox_refl_getproc(base, "JNI_OnLoad");
    if (p == NULL) return 0;
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    /* JNI_OnLoad(JavaVM*, void* reserved) -> jint */
    jint (__stdcall* onload)(JavaVM*, void*) = (jint (__stdcall*)(JavaVM*, void*))p;
    jint ver = onload(vm, NULL);
    if ((*env)->ExceptionCheck(env)) (*env)->ExceptionClear(env);
    return ver ? ver : 0;
}

#endif /* KBOX_REFLECT_LOADER_C_INCLUDED */
#endif /* _WIN32 */