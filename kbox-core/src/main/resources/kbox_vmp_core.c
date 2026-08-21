/*
 * KBox-VMP Core Interpreter — Register-based VM
 *
 * A custom 32-bit register-machine VM that runs translated Java method
 * bodies.  Unlike JNIC (which interprets standard JVM bytecodes), VMP
 * uses a proprietary instruction set with per-build opcode remapping.
 *
 * Architecture:
 *   - 10 general-purpose 32-bit registers: R0-R7, RPC (PC), RSP (stack ptr)
 *   - R0 is hardwired to 0 (MIPS-style $zero)
 *   - Flags: ZF (zero), SF (sign), OF (overflow)
 *   - 32-bit fixed-length instruction: [Op8|Dst4|Src1_4|Src2_4|Imm12]
 *   - Computed-goto dispatch (GCC extension, anti-IDA)
 *   - Per-instruction stream encryption + execution erasure
 *   - JNI helper table for object operations (fields, methods, arrays)
 *   - Opcode remapping table decrypted at JNI_OnLoad
 *
 * Instruction subset:
 *   0x00  NOP             0x01  MOV  Rd,Rs
 *   0x02  MOVI Rd,#imm12  0x10  ADD  Rd,Rs1,Rs2
 *   0x11  SUB  Rd,Rs1,Rs2 0x12  MUL  Rd,Rs1,Rs2
 *   0x13  DIV  Rd,Rs1,Rs2 0x14  REM  Rd,Rs1,Rs2
 *   0x20  AND, OR, XOR    0x21  SHL, SHR, SAR
 *   0x30  CMP  Rs1,Rs2    0x31  JMP  #off12
 *   0x32  JZ   #off12     0x33  JNZ  #off12
 *   0x40  LOAD Rd,[Rs+imm]0x41  STORE [Rd+imm],Rs
 *   0x50  INVOKE #imm12   0x51  RET  Rs
 *   0x60  VM_ENTER        0x61  VM_EXIT
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ===== Compiler compatibility macros ===== */
#ifdef _MSC_VER
  #define KBOX_ALIGNED(x) __declspec(align(x))
  #define KBOX_INLINE     static __inline
#else
  #define KBOX_ALIGNED(x) __attribute__((aligned(x)))
  #define KBOX_INLINE     KBOX_INLINE
#endif

/* VMP-local slot type (for virtual stack, JNI data interchange) */
typedef union KBOX_ALIGNED(8) {
    jint      i;
    jlong     j;
    jfloat    f;
    jdouble   d;
    jobject   o;
    void*     ptr;
} kbox_slot_t;

/* ===== Register indices ===== */
enum {
    R0=0, R1=1, R2=2, R3=3, R4=4, R5=5, R6=6, R7=7,
    RPC=8, RSP=9, RFLAGS=10
};
#define NUM_REGS 11

/* ===== Flag bits ===== */
#define FLAG_ZF  0x01
#define FLAG_SF  0x02
#define FLAG_OF  0x04

/* ===== Instruction decode macros ===== */
#define VMI_OP(insn)    (((insn) >> 24) & 0xFF)
#define VMI_DST(insn)   (((insn) >> 20) & 0x0F)
#define VMI_SRC1(insn)  (((insn) >> 16) & 0x0F)
#define VMI_SRC2(insn)  (((insn) >> 12) & 0x0F)
#define VMI_IMM12(insn) ((insn) & 0xFFF)
/* Sign-extend 12-bit immediate */
#define VMI_SIMM12(insn) \
    ((int32_t)(((insn) & 0xFFF) | (((insn) & 0x800) ? 0xFFFFF000 : 0)))

/* ===== Logical opcode constants (remapped at init) ===== */
enum {
    VOP_NOP=0x00,   VOP_MOV=0x01,   VOP_MOVI=0x02,
    VOP_ADD=0x10,   VOP_SUB=0x11,   VOP_MUL=0x12,   VOP_DIV=0x13,
    VOP_REM=0x14,   VOP_NEG=0x15,
    VOP_AND=0x20,   VOP_OR=0x21,    VOP_XOR=0x22,
    VOP_SHL=0x23,   VOP_SHR=0x24,   VOP_SAR=0x25,   VOP_NOT=0x26,
    VOP_CMP=0x30,   VOP_JMP=0x31,   VOP_JZ=0x32,    VOP_JNZ=0x33,
    VOP_JS=0x34,    VOP_JNS=0x35,
    VOP_LOAD=0x40,  VOP_STORE=0x41,
    VOP_INVOKE=0x50,VOP_RET=0x51,
    VOP_VM_ENTER=0x60, VOP_VM_EXIT=0x61,
    VOP_FADD=0x70,  VOP_FSUB=0x71,  VOP_FMUL=0x72,  VOP_FDIV=0x73,
    VOP_DADD=0x74,  VOP_DSUB=0x75,  VOP_DMUL=0x76,  VOP_DDIV=0x77
};

/* ===== VM context ===== */
typedef struct {
    /* Architected state */
    uint32_t  r[NUM_REGS];   /* R0-R7 + RPC, RSP, RFLAGS */

    /* Instruction memory */
    uint32_t* code;          /* encrypted instruction array */
    uint32_t  code_len;
    uint32_t  key;           /* per-method decryption key seed */

    /* JNI bridge */
    JNIEnv*   env;
    jobject   receiver;      /* 'this' for virtual methods */

    /* Virtual stack (for JNI calling convention) */
    kbox_slot_t* vstack;
    uint32_t     vstack_size;
    uint32_t     vsp;        /* virtual stack pointer */

    /* Return value */
    uint32_t  retval;
    int       returned;
} kbox_vm_t;

/* ===== JNI helper function table ===== */
/* Indexed by IMM12 field of INVOKE instructions.
 * Each helper receives the VM context. */
typedef void (*kbox_vm_jni_helper_t)(kbox_vm_t* vm);

static kbox_vm_jni_helper_t g_vm_helpers[256];
static int g_vm_helpers_init = 0;

/* ===== Crypto: instruction stream decrypt + erase ===== */

KBOX_INLINE uint32_t kbox_vm_key_byte(uint32_t key, uint32_t pc) {
    uint32_t k = key;
    k ^= pc * 0x9E3779B9U;
    k  = (k ^ (k >> 16)) * 0x85EBCA6BU;
    k  = (k ^ (k >> 13)) * 0xC2B2AE35U;
    return k ^ (k >> 16);
}

/*
 * Fetch, decrypt, and erase a 32-bit VM instruction.
 * Returns the plain-text instruction word.
 */
KBOX_INLINE uint32_t kbox_vm_fetch(kbox_vm_t* vm) {
    uint32_t pc = vm->r[RPC];
    if (pc >= vm->code_len) return 0;
    uint32_t cipher = vm->code[pc];
    uint32_t plain = cipher ^ (vm->key + kbox_vm_key_byte(vm->key, pc));
    vm->code[pc] = 0;  /* erase after execution */
    vm->r[RPC] = pc + 1;
    return plain;
}

/* ===== Opcode remapping table ===== */
/*
 * Maps logical opcodes (VOP_*) to physical byte values found in the
 * instruction stream.  Initialized at JNI_OnLoad from an encrypted
 * table embedded in the binary.
 */
static uint8_t g_l2p[256];  /* logical → physical */
static uint8_t g_p2l[256];  /* physical → logical (reverse) */

static void kbox_vm_init_remap(const uint8_t* encrypted_map, uint32_t map_key) {
    int i;
    for (i = 0; i < 256; i++) {
        uint8_t phys = encrypted_map[i] ^ (uint8_t)(map_key >> ((i % 4) * 8));
        uint8_t log  = (uint8_t)i;
        g_l2p[log]   = phys;
        g_p2l[phys]  = log;
    }
}

/* ===== Computed-goto label forward declarations ===== */
#define VMI_LABEL(x) &&vmi_##x

/* ===== VM entry point (computed-goto main loop) ===== */

/*
 * Execute the VMP program using GCC's computed goto extension.
 * The dispatch table maps physical opcodes to handler labels.
 * IDA F5 cannot produce structured pseudocode for computed-goto.
 */
static void kbox_vm_run(kbox_vm_t* vm) {
    vm->returned = 0;

    /* Build dispatch table on stack (volatile each call) */
    static const void* base_dispatch[256]; /* populated once */
    static int base_init = 0;

    if (!base_init) {
        int i;
        for (i = 0; i < 256; i++) base_dispatch[i] = VMI_LABEL(NOP); /* default */
        base_dispatch[VOP_MOV]   = VMI_LABEL(MOV);
        base_dispatch[VOP_MOVI]  = VMI_LABEL(MOVI);
        base_dispatch[VOP_ADD]   = VMI_LABEL(ADD);
        base_dispatch[VOP_SUB]   = VMI_LABEL(SUB);
        base_dispatch[VOP_MUL]   = VMI_LABEL(MUL);
        base_dispatch[VOP_DIV]   = VMI_LABEL(DIV);
        base_dispatch[VOP_REM]   = VMI_LABEL(REM);
        base_dispatch[VOP_NEG]   = VMI_LABEL(NEG);
        base_dispatch[VOP_AND]   = VMI_LABEL(AND);
        base_dispatch[VOP_OR]    = VMI_LABEL(OR);
        base_dispatch[VOP_XOR]   = VMI_LABEL(XOR);
        base_dispatch[VOP_SHL]   = VMI_LABEL(SHL);
        base_dispatch[VOP_SHR]   = VMI_LABEL(SHR);
        base_dispatch[VOP_SAR]   = VMI_LABEL(SAR);
        base_dispatch[VOP_NOT]   = VMI_LABEL(NOT);
        base_dispatch[VOP_CMP]   = VMI_LABEL(CMP);
        base_dispatch[VOP_JMP]   = VMI_LABEL(JMP);
        base_dispatch[VOP_JZ]    = VMI_LABEL(JZ);
        base_dispatch[VOP_JNZ]   = VMI_LABEL(JNZ);
        base_dispatch[VOP_JS]    = VMI_LABEL(JS);
        base_dispatch[VOP_JNS]   = VMI_LABEL(JNS);
        base_dispatch[VOP_LOAD]  = VMI_LABEL(LOAD);
        base_dispatch[VOP_STORE] = VMI_LABEL(STORE);
        base_dispatch[VOP_INVOKE]= VMI_LABEL(INVOKE);
        base_dispatch[VOP_RET]   = VMI_LABEL(RET);
        base_dispatch[VOP_VM_ENTER]= VMI_LABEL(VM_ENTER);
        base_dispatch[VOP_VM_EXIT] = VMI_LABEL(VM_EXIT);
        base_dispatch[VOP_FADD]  = VMI_LABEL(FADD);
        base_dispatch[VOP_FSUB]  = VMI_LABEL(FSUB);
        base_dispatch[VOP_FMUL]  = VMI_LABEL(FMUL);
        base_dispatch[VOP_FDIV]  = VMI_LABEL(FDIV);
        base_dispatch[VOP_DADD]  = VMI_LABEL(DADD);
        base_dispatch[VOP_DSUB]  = VMI_LABEL(DSUB);
        base_dispatch[VOP_DMUL]  = VMI_LABEL(DMUL);
        base_dispatch[VOP_DDIV]  = VMI_LABEL(DDIV);
        base_init = 1;
    }

    /* Aliases for cleaner code */
    uint32_t* R = vm->r;
    uint32_t  insn;

    /* Fetch first instruction */
    R[RPC] = 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_NOP:
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_MOV:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)];
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_MOVI:
    R[VMI_DST(insn)] = VMI_SIMM12(insn);
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_ADD:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] + R[VMI_SRC2(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_SUB:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] - R[VMI_SRC2(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    R[RFLAGS] |= (R[VMI_DST(insn)] & 0x80000000) ? FLAG_SF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_MUL:
    {
        uint64_t prod = (uint64_t)R[VMI_SRC1(insn)] * (uint64_t)R[VMI_SRC2(insn)];
        R[VMI_DST(insn)] = (uint32_t)prod;
        R[RFLAGS] = (prod > 0xFFFFFFFFULL) ? FLAG_OF : 0;
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_DIV:
    if (R[VMI_SRC2(insn)] == 0) {
        /* Division by zero: throw ArithmeticException via JNI */
        jclass ex = (*vm->env)->FindClass(vm->env, "java/lang/ArithmeticException");
        (*vm->env)->ThrowNew(vm->env, ex, "/ by zero");
        vm->retval = 0;
        vm->returned = 1;
        return;
    }
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] / R[VMI_SRC2(insn)];
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_REM:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] % R[VMI_SRC2(insn)];
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_NEG:
    R[VMI_DST(insn)] = -(int32_t)R[VMI_SRC1(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- Bitwise ops ---- */
vmi_AND:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] & R[VMI_SRC2(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_OR:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] | R[VMI_SRC2(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_XOR:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] ^ R[VMI_SRC2(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_SHL:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] << (R[VMI_SRC2(insn)] & 0x1F);
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_SHR:
    R[VMI_DST(insn)] = R[VMI_SRC1(insn)] >> (R[VMI_SRC2(insn)] & 0x1F);
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_SAR:
    R[VMI_DST(insn)] = (uint32_t)((int32_t)R[VMI_SRC1(insn)] >> (R[VMI_SRC2(insn)] & 0x1F));
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_NOT:
    R[VMI_DST(insn)] = ~R[VMI_SRC1(insn)];
    R[RFLAGS] = (R[VMI_DST(insn)] == 0) ? FLAG_ZF : 0;
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- Compare & branch ---- */
vmi_CMP:
    {
        int32_t a = (int32_t)R[VMI_SRC1(insn)];
        int32_t b = (int32_t)R[VMI_SRC2(insn)];
        uint32_t f = 0;
        if (a == b) f |= FLAG_ZF;
        if (a < b)  f |= FLAG_SF;
        R[RFLAGS] = f;
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_JMP:
    R[RPC] += VMI_SIMM12(insn);
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_JZ:
    if (R[RFLAGS] & FLAG_ZF) {
        R[RPC] += VMI_SIMM12(insn);
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_JNZ:
    if (!(R[RFLAGS] & FLAG_ZF)) {
        R[RPC] += VMI_SIMM12(insn);
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_JS:
    if (R[RFLAGS] & FLAG_SF) {
        R[RPC] += VMI_SIMM12(insn);
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_JNS:
    if (!(R[RFLAGS] & FLAG_SF)) {
        R[RPC] += VMI_SIMM12(insn);
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- Load/Store (virtual register ↔ virtual stack) ---- */
vmi_LOAD:
    {
        uint32_t addr = R[VMI_SRC1(insn)] + VMI_IMM12(insn);
        if (addr < vm->vstack_size) {
            R[VMI_DST(insn)] = vm->vstack[addr].i;
        }
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_STORE:
    {
        uint32_t addr = R[VMI_DST(insn)] + VMI_IMM12(insn);
        if (addr < vm->vstack_size) {
            vm->vstack[addr].i = R[VMI_SRC1(insn)];
        }
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- JNI helper invocation ---- */
vmi_INVOKE:
    {
        uint32_t idx = VMI_IMM12(insn);
        if (idx < 256 && g_vm_helpers[idx] != NULL) {
            g_vm_helpers[idx](vm);
        }
        if (vm->returned) return;
    }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- Return ---- */
vmi_RET:
    vm->retval = R[VMI_SRC1(insn)];
    vm->returned = 1;
    return;

/* ---- Float ops (interpret bit patterns) ---- */
vmi_FADD:
    { float a,b; memcpy(&a,&R[VMI_SRC1(insn)],4); memcpy(&b,&R[VMI_SRC2(insn)],4);
      float r = a + b; memcpy(&R[VMI_DST(insn)],&r,4); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_FSUB:
    { float a,b; memcpy(&a,&R[VMI_SRC1(insn)],4); memcpy(&b,&R[VMI_SRC2(insn)],4);
      float r = a - b; memcpy(&R[VMI_DST(insn)],&r,4); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_FMUL:
    { float a,b; memcpy(&a,&R[VMI_SRC1(insn)],4); memcpy(&b,&R[VMI_SRC2(insn)],4);
      float r = a * b; memcpy(&R[VMI_DST(insn)],&r,4); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_FDIV:
    { float a,b; memcpy(&a,&R[VMI_SRC1(insn)],4); memcpy(&b,&R[VMI_SRC2(insn)],4);
      float r = a / b; memcpy(&R[VMI_DST(insn)],&r,4); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_DADD:
    { double a,b; memcpy(&a,&R[VMI_SRC1(insn)],8); memcpy(&b,&R[VMI_SRC2(insn)],8);
      double r = a + b; memcpy(&R[VMI_DST(insn)],&r,8); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_DSUB:
    { double a,b; memcpy(&a,&R[VMI_SRC1(insn)],8); memcpy(&b,&R[VMI_SRC2(insn)],8);
      double r = a - b; memcpy(&R[VMI_DST(insn)],&r,8); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_DMUL:
    { double a,b; memcpy(&a,&R[VMI_SRC1(insn)],8); memcpy(&b,&R[VMI_SRC2(insn)],8);
      double r = a * b; memcpy(&R[VMI_DST(insn)],&r,8); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_DDIV:
    { double a,b; memcpy(&a,&R[VMI_SRC1(insn)],8); memcpy(&b,&R[VMI_SRC2(insn)],8);
      double r = a / b; memcpy(&R[VMI_DST(insn)],&r,8); }
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

/* ---- VM enter/exit stubs ---- */
vmi_VM_ENTER:
    /* Save JVM call state into virtual registers */
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];

vmi_VM_EXIT:
    /* Restore JVM call state */
    insn = kbox_vm_fetch(vm);
    goto *base_dispatch[VMI_OP(insn)];
}

/* ===== JNI helper implementations ===== */

/*
 * Helper indices are assigned at obfuscation time.
 * Each helper performs one bounded JNI operation.
 */

/* Helper 0: Get static int field */
static void vm_h_getstatic_int(kbox_vm_t* vm) {
    /* R1 = object reference handle, R2 = field index */
    /* For simplicity, use direct JNI: GetStaticIntField */
    /* Full implementation would resolve handles */
}

/* ===== Public entry point ===== */

/*
 * kmp_vm_execute — main VMP entry point called from Java stubs.
 *
 * Parameters:
 *   env        JNI environment
 *   receiver   'this' object (NULL for static methods)
 *   code       encrypted VM instruction array
 *   code_len   number of 32-bit instructions
 *   key        per-method decryption key
 *   vstack     pre-allocated virtual stack (for locals + JNI args)
 *   vsize      virtual stack size in slots
 *   helpers    JNI helper function table (NULL-terminated array)
 *
 * Returns the VM's R[return_register] value.
 */
jint kbox_vm_execute(JNIEnv* env, jobject receiver,
                     uint32_t* code, uint32_t code_len, uint32_t key,
                     kbox_slot_t* vstack, uint32_t vsize,
                     void** helpers) {
    kbox_vm_t vm;
    memset(&vm, 0, sizeof(vm));

    vm.env         = env;
    vm.receiver    = receiver;
    vm.code        = code;
    vm.code_len    = code_len;
    vm.key         = key;
    vm.vstack      = vstack;
    vm.vstack_size = vsize;
    vm.vsp         = 0;
    vm.r[R0]       = 0;  /* R0 hardwired to 0 */

    /* Register helper table */
    if (helpers != NULL && !g_vm_helpers_init) {
        int i = 0;
        while (helpers[i] != NULL && i < 256) {
            g_vm_helpers[i] = (kbox_vm_jni_helper_t)helpers[i];
            i++;
        }
        g_vm_helpers_init = 1;
    }

    kbox_vm_run(&vm);
    return (jint)vm.retval;
}

/* ===== Stub: void return variant ===== */
void kbox_vm_execute_void(JNIEnv* env, jobject receiver,
                          uint32_t* code, uint32_t code_len, uint32_t key,
                          kbox_slot_t* vstack, uint32_t vsize,
                          void** helpers) {
    kbox_vm_execute(env, receiver, code, code_len, key, vstack, vsize, helpers);
}
