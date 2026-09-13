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

#if defined(_WIN32)
/* ===== KBox native-shell M3: manual IAT (private resolver) ===== */
/* No kernel32/ntdll API name is imported directly; every call is
   resolved at runtime off the PEB + export directories. Keys,
   ciphertext and slot layout change per build. */
static unsigned kksfnvstr(const char* s){unsigned h=0x811c9dc5u;if(!s)return h;for(;*s;s++){unsigned char c=(unsigned char)*s;if(c>='A'&&c<='Z')c=(unsigned char)(c+32);h=(h^c)*0x01000193u;}return h;}
static unsigned kksfnvmod(const unsigned short*w,int n){unsigned h=0x811c9dc5u;for(int i=0;i<n;i++){unsigned c=w[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return h;}
static const unsigned char _ks3K[16]={0x43,0xF9,0xF9,0x25,0x18,0x7A,0x9A,0xD7,0xE0,0xF2,0x66,0xD5,0x0B,0xB1,0xF0,0x2B};
static const unsigned char _ks3D[247]={0x15,0x90,0x8B,0x51,0x6D,0x1B,0xF6,0x96,0x8C,0x9E,0x09,0xB6,0x5D,0xD8,0x82,0x5F,0x36,0x98,0x95,0x63,0x6A,0x1F,0xFF,0x81,0x89,0x80,0x12,0xA0,0x6A,0xDD,0xA0,0x59,0x2C,0x8D,0x9C,0x46,0x6C,0x39,0xE8,0xB2,0x81,0x86,0x03,0x81,0x63,0xC3,0x95,0x4A,0x27,0xBA,0x95,0x4A,0x6B,0x1F,0xD2,0xB6,0x8E,0x96,0x0A,0xB0,0x5F,0xD4,0x82,0x46,0x2A,0x97,0x98,0x51,0x7D,0x2A,0xE8,0xB8,0x83,0x97,0x15,0xA6,0x4C,0xD4,0x84,0x68,0x36,0x8B,0x8B,0x40,0x76,0x0E,0xCA,0xA5,0x8F,0x91,0x03,0xA6,0x78,0xF6,0x95,0x5F,0x00,0x8C,0x8B,0x57,0x7D,0x14,0xEE,0x87,0x92,0x9D,0x05,0xB0,0x78,0xC2,0xB9,0x4F,0x0A,0x8A,0xBD,0x40,0x7A,0x0F,0xFD,0xB0,0x85,0x80,0x36,0xA7,0x6E,0xC2,0x95,0x45,0x37,0xBE,0x9C,0x51,0x55,0x15,0xFE,0xA2,0x8C,0x97,0x2E,0xB4,0x65,0xD5,0x9C,0x4E,0x06,0x81,0xAE,0x69,0x77,0x1B,0xFE,0x9B,0x89,0x90,0x14,0xB4,0x79,0xC8,0xB1,0x7C,0x31,0x90,0x8D,0x40,0x48,0x08,0xF5,0xB4,0x85,0x81,0x15,0x98,0x6E,0xDC,0x9F,0x59,0x3A,0xBE,0x9C,0x51,0x5B,0x0F,0xE8,0xA5,0x85,0x9C,0x12,0x81,0x63,0xC3,0x95,0x4A,0x27,0xBE,0x9C,0x51,0x4C,0x12,0xE8,0xB2,0x81,0x96,0x25,0xBA,0x65,0xC5,0x95,0x53,0x37,0xAF,0x90,0x57,0x6C,0x0F,0xFB,0xBB,0xB1,0x87,0x03,0xA7,0x72,0xDA,0x95,0x59,0x2D,0x9C,0x95,0x16,0x2A,0x54,0xFE,0xBB,0x8C,0x99,0x03,0xA7,0x65,0xD4,0x9C,0x49,0x22,0x8A,0x9C,0x0B,0x7C,0x16,0xF6};
static const unsigned short _ks3O[17]={0,12,23,37,49,60,76,93,112,129,147,159,177,193,209,221,233};
static const unsigned char _ks3L[17]={12,11,14,12,11,16,17,19,17,18,12,18,16,16,12,12,14};
static char _ks3P[248];
static void* _ks3S[17];
static void* _ks3C;static unsigned _ks3H;
static const char* ksDec(int i){int o=_ks3O[i],l=_ks3L[i],j;for(j=0;j<l;j++)_ks3P[o+j]=(char)(_ks3D[o+j]^_ks3K[(o+j)&15]);_ks3P[o+l]=0;return _ks3P+o;}
static void* ksGetModByHash(unsigned target){
  if(_ks3C&&_ks3H==target)return _ks3C;
  void*peb=0;
#if defined(_WIN64)
  __asm__ __volatile__("movq %%gs:0x60,%0":"=r"(peb));
  enum{LDR_OFF=0x18,INLOAD=0x10,DL=0x30,SLEN=0x58,SBUF=0x60};
#else
  __asm__ __volatile__("movl %%fs:0x30,%0":"=r"(peb));
  enum{LDR_OFF=0x0C,INLOAD=0x0C,DL=0x18,SLEN=0x24,SBUF=0x28};
#endif
  if(!peb)return 0;
  void*ldr=*(void**)((unsigned char*)peb+LDR_OFF);
  if(!ldr)return 0;
  unsigned char*head=(unsigned char*)ldr+INLOAD;
  unsigned char*cur=*(unsigned char**)head;
  for(int k=0;cur&&cur!=head&&k<1024;k++,cur=*(unsigned char**)cur){
    void*db=*(void**)(cur+DL);
    if(db){unsigned short ln=*(unsigned short*)(cur+SLEN);
      unsigned short*bf=*(unsigned short**)(cur+SBUF);
      if(bf&&ln>=2&&kksfnvmod(bf,ln>>1)==target){_ks3C=db;_ks3H=target;return db;}}
  }
  return 0;
}
static void* ksExpByNameD(void*mod,const char*name,int depth){
  if(!mod||!name||depth>=8)return 0;
  IMAGE_DOS_HEADER*dos=(IMAGE_DOS_HEADER*)mod;
  if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;
  IMAGE_NT_HEADERS*nt=(IMAGE_NT_HEADERS*)((unsigned char*)mod+dos->e_lfanew);
  if(nt->Signature!=IMAGE_NT_SIGNATURE)return 0;
  IMAGE_DATA_DIRECTORY*dd=&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if(!dd->VirtualAddress||!dd->Size)return 0;
  IMAGE_EXPORT_DIRECTORY*ed=(IMAGE_EXPORT_DIRECTORY*)((unsigned char*)mod+dd->VirtualAddress);
  const DWORD*fns=(const DWORD*)((unsigned char*)mod+ed->AddressOfFunctions);
  const DWORD*nms=(const DWORD*)((unsigned char*)mod+ed->AddressOfNames);
  const WORD*ords=(const WORD*)((unsigned char*)mod+ed->AddressOfNameOrdinals);
  DWORD i,lo=dd->VirtualAddress,hi=dd->VirtualAddress+dd->Size;
  for(i=0;i<ed->NumberOfNames;i++){
    const char*nm2=(const char*)((unsigned char*)mod+nms[i]);
    if(strcmp(nm2,name)==0){
      DWORD rva=fns[ords[i]];
      if(rva>=nt->OptionalHeader.SizeOfImage)return 0;
      /* Forwarder export (kernel32 -> kernelbase on modern Win): the
         function RVA lies inside the export-data section and holds a
         "DLL.Function" string. Calling it directly would jump into a
         non-executable page (DEP fault); chase the real target instead. */
      if(rva>=lo&&rva<hi){
        const char*fwd=(const char*)((unsigned char*)mod+rva);
        const char*dot=fwd?strchr(fwd,'.'):0;
        if(dot&&dot>fwd&&dot[1]){
          char mb[80];DWORD j,L=(DWORD)(dot-fwd);
          if(L>=sizeof(mb)-4)return 0;
          for(j=0;j<L;j++)mb[j]=fwd[j];
          /* Forwarder module name is bare ("KERNELBASE", no extension) but
             the PEB lists the loaded image as "kernelbase.dll"; append the
             suffix unless the name already carries a '.' extension. */
          if(L<4||mb[L-4]!='.'){mb[L]='.';mb[L+1]='d';mb[L+2]='l';mb[L+3]='l';L+=4;}
          mb[L]=0;
          void*m=ksGetModByHash(kksfnvstr(mb));
          if(m)return ksExpByNameD(m,dot+1,depth+1);
        }
        return 0;
      }
      return (void*)((unsigned char*)mod+rva);
    }
  }
  return 0;
}
static void* ksExpByName(void*mod,const char*name){return ksExpByNameD(mod,name,0);}
static void* ksK32(void){void*b;b=ksGetModByHash(kksfnvstr(ksDec(15)));if(b)return b;return ksGetModByHash(kksfnvstr(ksDec(16)));}
static void* ksProc(int i){void*p=_ks3S[i];if(!p){const char*s=ksDec(i);char nm[64];int j=0;while((nm[j]=s[j])&&j+1<63)j++;nm[j]=0;void*k32=ksK32();if(k32)p=ksExpByName(k32,nm);_ks3S[i]=p;}return p;}
enum{KS_I_0,KS_I_1,KS_I_2,KS_I_3,KS_I_4,KS_I_5,KS_I_6,KS_I_7,KS_I_8,KS_I_9,KS_I_10,KS_I_11,KS_I_12,KS_I_13,KS_I_14,KS_I_15,KS_I_16};
#define VirtualAlloc kimp_VirtualAlloc
#define VirtualFree kimp_VirtualFree
#define VirtualProtect kimp_VirtualProtect
#define CreateThread kimp_CreateThread
#define CloseHandle kimp_CloseHandle
#define TerminateProcess kimp_TerminateProcess
#define GetCurrentProcess kimp_GetCurrentProcess
#define GetCurrentProcessId kimp_GetCurrentProcessId
#define IsDebuggerPresent kimp_IsDebuggerPresent
#define GetModuleHandleExW kimp_GetModuleHandleExW
#define LoadLibraryA kimp_LoadLibraryA
#define WriteProcessMemory kimp_WriteProcessMemory
#define GetCurrentThread kimp_GetCurrentThread
#define GetThreadContext kimp_GetThreadContext
#define VirtualQuery kimp_VirtualQuery
#define GetProcAddress kimp_GetProcAddress
#define GetModuleHandleA kimp_GetModuleHandleA
#define GetModuleHandleW kimp_GetModuleHandleW
static __attribute__((unused)) void* kimp_VirtualAlloc(void* a,size_t b,unsigned long c,unsigned long d){void*_kf=ksProc(KS_I_0);if(!_kf)return 0;
  return ((void*(*)(void*,size_t,unsigned long,unsigned long))_kf)(a,b,c,d);}
static __attribute__((unused)) int kimp_VirtualFree(void* a,size_t b,unsigned long c){void*_kf=ksProc(KS_I_1);if(!_kf)return 0;
  return ((int(*)(void*,size_t,unsigned long))_kf)(a,b,c);}
static __attribute__((unused)) int kimp_VirtualProtect(void* a,size_t b,unsigned long c,unsigned long* d){void*_kf=ksProc(KS_I_2);if(!_kf)return 0;
  return ((int(*)(void*,size_t,unsigned long,unsigned long*))_kf)(a,b,c,d);}
static __attribute__((unused)) void* kimp_CreateThread(void* a,void* b,void* c,void* d,void* e,void* f){void*_kf=ksProc(KS_I_3);if(!_kf)return 0;
  return ((void*(*)(void*,void*,void*,void*,void*,void*))_kf)(a,b,c,d,e,f);}
static __attribute__((unused)) int kimp_CloseHandle(void* a){void*_kf=ksProc(KS_I_4);if(!_kf)return 0;
  return ((int(*)(void*))_kf)(a);}
static __attribute__((unused)) int kimp_TerminateProcess(void* a,unsigned b){void*_kf=ksProc(KS_I_5);if(!_kf)return 0;
  return ((int(*)(void*,unsigned))_kf)(a,b);}
static __attribute__((unused)) void* kimp_GetCurrentProcess(){void*_kf=ksProc(KS_I_6);if(!_kf)return 0;
  return ((void*(*)(void))_kf)();}
static __attribute__((unused)) unsigned kimp_GetCurrentProcessId(){void*_kf=ksProc(KS_I_7);if(!_kf)return 0;
  return ((unsigned(*)(void))_kf)();}
static __attribute__((unused)) int kimp_IsDebuggerPresent(){void*_kf=ksProc(KS_I_8);if(!_kf)return 0;
  return ((int(*)(void))_kf)();}
static __attribute__((unused)) int kimp_GetModuleHandleExW(unsigned long a,const void* b,void* c){void*_kf=ksProc(KS_I_9);if(!_kf)return 0;
  return ((int(*)(unsigned long,const void*,void*))_kf)(a,b,c);}
static __attribute__((unused)) void* kimp_LoadLibraryA(const char* a){void*_kf=ksProc(KS_I_10);if(!_kf)return 0;
  return ((void*(*)(const char*))_kf)(a);}
static __attribute__((unused)) int kimp_WriteProcessMemory(void* a,void* b,const void* c,size_t d,size_t* e){void*_kf=ksProc(KS_I_11);if(!_kf)return 0;
  return ((int(*)(void*,void*,const void*,size_t,size_t*))_kf)(a,b,c,d,e);}
static __attribute__((unused)) void* kimp_GetCurrentThread(){void*_kf=ksProc(KS_I_12);if(!_kf)return 0;
  return ((void*(*)(void))_kf)();}
static __attribute__((unused)) int kimp_GetThreadContext(void* a,void* b){void*_kf=ksProc(KS_I_13);if(!_kf)return 0;
  return ((int(*)(void*,void*))_kf)(a,b);}
static __attribute__((unused)) size_t kimp_VirtualQuery(const void* a,void* b,size_t c){void*_kf=ksProc(KS_I_14);if(!_kf)return 0;
  return ((size_t(*)(const void*,void*,size_t))_kf)(a,b,c);}
static __attribute__((unused)) void* kimp_GetModuleHandleA(const char*name){return name?ksGetModByHash(kksfnvstr(name)):0;}
static __attribute__((unused)) void* kimp_GetModuleHandleW(const unsigned short*name){if(!name)return 0;unsigned h=0x811c9dc5u;for(int i=0;name[i];i++){unsigned c=name[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return ksGetModByHash(h);}
static __attribute__((unused)) void* kimp_GetProcAddress(void*mod,const char*name){return ksExpByName(mod,name);}
#endif
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