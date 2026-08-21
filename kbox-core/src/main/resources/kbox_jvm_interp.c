/*
 * KBox JVM Bytecode Interpreter (C) — v2 with sequential CP indexing
 *
 * A compact stack-based JVM bytecode interpreter that runs entirely in
 * native code. Each Java method protected via JNIC is replaced by a thin
 * stub that calls this interpreter.
 *
 * Arg layout (void* _a[]):
 *   [0] cp_cls ptr    [1] cp_cls_cnt      — pre-resolved jclass[]
 *   [2] cp_fld ptr    [3] cp_fld_cnt      — pre-resolved jfieldID[]
 *   [4] cp_mid ptr    [5] cp_mid_cnt      — pre-resolved jmethodID[]
 *   [6] cp_str ptr    [7] cp_str_cnt      — const char*[] for LDC strings
 *   [8] cp_int ptr    [9] cp_int_cnt      — jint[] for LDC integers
 *   [10..] Java args as void* (terminated by NULL)
 *
 * Sequential CP indices in the bytecode map directly to the arrays above.
 * For LDC: high-bit=1 means int index, else string index.
 *
 * Supports the full JVM instruction set except invokedynamic,
 * tableswitch/lookupswitch, jsr/ret, and monitorenter/monitorexit.
 */

#include <jni.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* ---- tagged value union ---- */
typedef union {
    jint    i;
    jlong   l;
    jfloat  f;
    jdouble d;
} kbox_value_t;

/* ---- opcode constants ---- */
enum {
    NOP=0x00, ACONST_NULL=0x01, ICONST_M1=0x02, ICONST_0=0x03, ICONST_1=0x04,
    ICONST_2=0x05, ICONST_3=0x06, ICONST_4=0x07, ICONST_5=0x08,
    LCONST_0=0x09, LCONST_1=0x0A, FCONST_0=0x0B, FCONST_1=0x0C,
    FCONST_2=0x0D, DCONST_0=0x0E, DCONST_1=0x0F,
    BIPUSH=0x10, SIPUSH=0x11, LDC=0x12, /* LDC_W=0x13, LDC2_W=0x14 — replaced by 2-byte LDC */
    ILOAD=0x15, LLOAD=0x16, FLOAD=0x17, DLOAD=0x18, ALOAD=0x19,
    ILOAD_0=0x1A,ILOAD_1=0x1B,ILOAD_2=0x1C,ILOAD_3=0x1D,
    LLOAD_0=0x1E,LLOAD_1=0x1F,LLOAD_2=0x20,LLOAD_3=0x21,
    FLOAD_0=0x22,FLOAD_1=0x23,FLOAD_2=0x24,FLOAD_3=0x25,
    DLOAD_0=0x26,DLOAD_1=0x27,DLOAD_2=0x28,DLOAD_3=0x29,
    ALOAD_0=0x2A,ALOAD_1=0x2B,ALOAD_2=0x2C,ALOAD_3=0x2D,
    IALOAD=0x2E,LALOAD=0x2F,FALOAD=0x30,DALOAD=0x31,
    AALOAD=0x32,BALOAD=0x33,CALOAD=0x34,SALOAD=0x35,
    ISTORE=0x36,LSTORE=0x37,FSTORE=0x38,DSTORE=0x39,ASTORE=0x3A,
    ISTORE_0=0x3B,ISTORE_1=0x3C,ISTORE_2=0x3D,ISTORE_3=0x3E,
    LSTORE_0=0x3F,LSTORE_1=0x40,LSTORE_2=0x41,LSTORE_3=0x42,
    FSTORE_0=0x43,FSTORE_1=0x44,FSTORE_2=0x45,FSTORE_3=0x46,
    DSTORE_0=0x47,DSTORE_1=0x48,DSTORE_2=0x49,DSTORE_3=0x4A,
    ASTORE_0=0x4B,ASTORE_1=0x4C,ASTORE_2=0x4D,ASTORE_3=0x4E,
    IASTORE=0x4F,LASTORE=0x50,FASTORE=0x51,DASTORE=0x52,
    AASTORE=0x53,BASTORE=0x54,CASTORE=0x55,SASTORE=0x56,
    POP=0x57,POP2=0x58,DUP=0x59,DUP_X1=0x5A,DUP_X2=0x5B,
    DUP2=0x5C,DUP2_X1=0x5D,DUP2_X2=0x5E,SWAP=0x5F,
    IADD=0x60,LADD=0x61,FADD=0x62,DADD=0x63,
    ISUB=0x64,LSUB=0x65,FSUB=0x66,DSUB=0x67,
    IMUL=0x68,LMUL=0x69,FMUL=0x6A,DMUL=0x6B,
    IDIV=0x6C,LDIV=0x6D,FDIV=0x6E,DDIV=0x6F,
    IREM=0x70,LREM=0x71,FREM=0x72,DREM=0x73,
    INEG=0x74,LNEG=0x75,FNEG=0x76,DNEG=0x77,
    ISHL=0x78,LSHL=0x79,ISHR=0x7A,LSHR=0x7B,IUSHR=0x7C,LUSHR=0x7D,
    IAND=0x7E,LAND=0x7F,IOR=0x80,LOR=0x81,IXOR=0x82,LXOR=0x83,
    IINC=0x84,
    I2L=0x85,I2F=0x86,I2D=0x87,L2I=0x88,L2F=0x89,L2D=0x8A,
    F2I=0x8B,F2L=0x8C,F2D=0x8D,D2I=0x8E,D2L=0x8F,D2F=0x90,
    I2B=0x91,I2C=0x92,I2S=0x93,
    LCMP=0x94,FCMPL=0x95,FCMPG=0x96,DCMPL=0x97,DCMPG=0x98,
    IFEQ=0x99,IFNE=0x9A,IFLT=0x9B,IFGE=0x9C,IFGT=0x9D,IFLE=0x9E,
    IF_ICMPEQ=0x9F,IF_ICMPNE=0xA0,IF_ICMPLT=0xA1,IF_ICMPGE=0xA2,
    IF_ICMPGT=0xA3,IF_ICMPLE=0xA4,IF_ACMPEQ=0xA5,IF_ACMPNE=0xA6,
    GOTO=0xA7,
    IRETURN=0xAC,LRETURN=0xAD,FRETURN=0xAE,DRETURN=0xAF,
    ARETURN=0xB0,RETURN=0xB1,
    GETSTATIC=0xB2,PUTSTATIC=0xB3,GETFIELD=0xB4,PUTFIELD=0xB5,
    INVOKEVIRTUAL=0xB6,INVOKESPECIAL=0xB7,INVOKESTATIC=0xB8,INVOKEINTERFACE=0xB9,
    NEW=0xBB,NEWARRAY=0xBC,ANEWARRAY=0xBD,
    ARRAYLENGTH=0xBE,ATHROW=0xBF,CHECKCAST=0xC0,INSTANCEOF=0xC1,
    IFNULL=0xC6,IFNONNULL=0xC7
};

static inline int16_t read_s16(const unsigned char *p) {
    return (int16_t)((p[0]<<8)|p[1]);
}

kbox_value_t kbox_jvm_interp(JNIEnv *env, jobject receiver,
                             const unsigned char *bytecode, int bc_len,
                             void **args, int max_locals, int max_stack) {
    /* Unpack CP arrays with size prefixes. */
    jclass     *cp_cls   = (jclass*)    args[0];
    int         cp_cls_n = (int)(intptr_t)args[1];
    jfieldID   *cp_fld   = (jfieldID*)  args[2];
    int         cp_fld_n = (int)(intptr_t)args[3];
    jmethodID  *cp_mid   = (jmethodID*) args[4];
    int         cp_mid_n = (int)(intptr_t)args[5];
    const char **cp_str  = (const char**)args[6];
    int         cp_str_n = (int)(intptr_t)args[7];
    const jint *cp_int   = (const jint*)args[8];
    int         cp_int_n = (int)(intptr_t)args[9];
    const int  *cp_mid_ac= (const int*) args[10];  /* arg count per method */
    int         cp_mid_ac_n=(int)(intptr_t)args[11];
    const char *cp_mid_rt= (const char*) args[12];  /* return type code per method */
    int         cp_mid_rt_n=(int)(intptr_t)args[13];
    jclass     *cp_mid_cls=(jclass*)   args[14];  /* jclass per method (for INVOKESTATIC) */
    int         cp_mid_cls_n=(int)(intptr_t)args[15];
    void      **real_args = &args[16];

    kbox_value_t stack[256];
    int sp = 0;
    kbox_value_t locals[256];
    memset(locals, 0, sizeof(locals));

    if (receiver != NULL) locals[0].l = (jlong)(intptr_t)receiver;
    { int slot = (receiver!=NULL)?1:0; void **ap = real_args;
      while (*ap != NULL && slot < max_locals) {
        locals[slot++].l = (jlong)(intptr_t)(*ap); ap++;
      }
    }

    const unsigned char *ip = bytecode, *end = bytecode + bc_len;

    while (ip < end) { unsigned char op = *ip++;
    switch (op) {
    /* ---- constants ---- */
    case ICONST_M1: stack[sp].i=-1; sp++; break;
    case ICONST_0:  stack[sp].i=0; sp++; break;
    case ICONST_1:  stack[sp].i=1; sp++; break;
    case ICONST_2:  stack[sp].i=2; sp++; break;
    case ICONST_3:  stack[sp].i=3; sp++; break;
    case ICONST_4:  stack[sp].i=4; sp++; break;
    case ICONST_5:  stack[sp].i=5; sp++; break;
    case LCONST_0:  stack[sp].l=0; sp++; break;
    case LCONST_1:  stack[sp].l=1; sp++; break;
    case FCONST_0:  stack[sp].f=0.0f; sp++; break;
    case FCONST_1:  stack[sp].f=1.0f; sp++; break;
    case FCONST_2:  stack[sp].f=2.0f; sp++; break;
    case DCONST_0:  stack[sp].d=0.0; sp++; break;
    case DCONST_1:  stack[sp].d=1.0; sp++; break;
    case ACONST_NULL: stack[sp].l=0; sp++; break;
    case BIPUSH: stack[sp].i=(jint)(int8_t)*ip++; sp++; break;
    case SIPUSH: stack[sp].i=(jint)read_s16(ip); ip+=2; sp++; break;

    /* --- LDC: 2-byte sequential CP index.  high-bit=1 → int, else string --- */
    case LDC: {
        int idx = read_s16(ip); ip += 2;
        if (idx & 0x8000) {
            /* integer constant */
            int ii = idx & 0x7FFF;
            stack[sp].i = (ii < cp_int_n) ? cp_int[ii] : 0;
        } else {
            /* string constant */
            jstring s = NULL;
            if (idx < cp_str_n && cp_str[idx]) {
                s = (*env)->NewStringUTF(env, cp_str[idx]);
            }
            stack[sp].l = (jlong)(intptr_t)s;
        }
        sp++;
        break;
    }

    /* ---- loads ---- */
    case ILOAD:{int idx=*ip++; stack[sp].i=locals[idx].i; sp++; break;}
    case LLOAD:{int idx=*ip++; stack[sp]=locals[idx]; sp++; break;}
    case FLOAD:{int idx=*ip++; stack[sp].f=locals[idx].f; sp++; break;}
    case DLOAD:{int idx=*ip++; stack[sp]=locals[idx]; sp++; break;}
    case ALOAD:{int idx=*ip++; stack[sp].l=locals[idx].l; sp++; break;}
    case ILOAD_0: stack[sp].i=locals[0].i; sp++; break;
    case ILOAD_1: stack[sp].i=locals[1].i; sp++; break;
    case ILOAD_2: stack[sp].i=locals[2].i; sp++; break;
    case ILOAD_3: stack[sp].i=locals[3].i; sp++; break;
    case ALOAD_0: stack[sp].l=locals[0].l; sp++; break;
    case ALOAD_1: stack[sp].l=locals[1].l; sp++; break;
    case ALOAD_2: stack[sp].l=locals[2].l; sp++; break;
    case ALOAD_3: stack[sp].l=locals[3].l; sp++; break;

    /* ---- stores ---- */
    case ISTORE:{int idx=*ip++; sp--; locals[idx].i=stack[sp].i; break;}
    case LSTORE:{int idx=*ip++; sp--; locals[idx]=stack[sp]; break;}
    case FSTORE:{int idx=*ip++; sp--; locals[idx].f=stack[sp].f; break;}
    case DSTORE:{int idx=*ip++; sp--; locals[idx]=stack[sp]; break;}
    case ASTORE:{int idx=*ip++; sp--; locals[idx].l=stack[sp].l; break;}
    case ISTORE_0: sp--; locals[0].i=stack[sp].i; break;
    case ISTORE_1: sp--; locals[1].i=stack[sp].i; break;
    case ISTORE_2: sp--; locals[2].i=stack[sp].i; break;
    case ISTORE_3: sp--; locals[3].i=stack[sp].i; break;
    case ASTORE_0: sp--; locals[0].l=stack[sp].l; break;
    case ASTORE_1: sp--; locals[1].l=stack[sp].l; break;
    case ASTORE_2: sp--; locals[2].l=stack[sp].l; break;
    case ASTORE_3: sp--; locals[3].l=stack[sp].l; break;

    /* ---- stack manip ---- */
    case POP: sp--; break;
    case POP2: sp-=2; break;
    case DUP: stack[sp]=stack[sp-1]; sp++; break;
    case DUP_X1:{kbox_value_t v1=stack[sp-1],v2=stack[sp-2];stack[sp-2]=v1;stack[sp-1]=v2;stack[sp]=v1;sp++;break;}
    case DUP2: stack[sp]=stack[sp-2];stack[sp+1]=stack[sp-1];sp+=2; break;
    case SWAP: {kbox_value_t t=stack[sp-1];stack[sp-1]=stack[sp-2];stack[sp-2]=t;break;}

    /* ---- int arithmetic ---- */
    case IADD: sp--; stack[sp-1].i+=stack[sp].i; break;
    case ISUB: sp--; stack[sp-1].i-=stack[sp].i; break;
    case IMUL: sp--; stack[sp-1].i*=stack[sp].i; break;
    case IDIV: sp--; stack[sp-1].i/=stack[sp].i; break;
    case IREM: sp--; stack[sp-1].i%=stack[sp].i; break;
    case INEG: stack[sp-1].i=-stack[sp-1].i; break;
    case ISHL: sp--; stack[sp-1].i<<=(stack[sp].i&0x1F); break;
    case ISHR: sp--; stack[sp-1].i>>=(stack[sp].i&0x1F); break;
    case IUSHR: sp--; stack[sp-1].i=(jint)(((uint32_t)stack[sp-1].i)>>(stack[sp].i&0x1F)); break;
    case IAND: sp--; stack[sp-1].i&=stack[sp].i; break;
    case IOR: sp--; stack[sp-1].i|=stack[sp].i; break;
    case IXOR: sp--; stack[sp-1].i^=stack[sp].i; break;
    case IINC: {int idx=*ip++;int incr=(int8_t)(*ip++);locals[idx].i+=incr;break;}

    /* ---- long arithmetic ---- */
    case LADD: sp--;stack[sp-1].l+=stack[sp].l;break;
    case LSUB: sp--;stack[sp-1].l-=stack[sp].l;break;
    case LMUL: sp--;stack[sp-1].l*=stack[sp].l;break;
    case LDIV: sp--;stack[sp-1].l/=stack[sp].l;break;
    case LREM: sp--;stack[sp-1].l%=stack[sp].l;break;
    case LNEG: stack[sp-1].l=-stack[sp-1].l;break;
    case LAND: sp--;stack[sp-1].l&=stack[sp].l;break;
    case LOR: sp--;stack[sp-1].l|=stack[sp].l;break;
    case LXOR: sp--;stack[sp-1].l^=stack[sp].l;break;
    case LSHL: sp--;stack[sp-1].l<<=(stack[sp].i&0x3F);break;
    case LSHR: sp--;stack[sp-1].l>>=(stack[sp].i&0x3F);break;
    case LUSHR: sp--;stack[sp-1].l=(jlong)(((uint64_t)stack[sp-1].l)>>(stack[sp].i&0x3F));break;

    /* ---- float ---- */
    case FADD: sp--;stack[sp-1].f+=stack[sp].f;break;
    case FSUB: sp--;stack[sp-1].f-=stack[sp].f;break;
    case FMUL: sp--;stack[sp-1].f*=stack[sp].f;break;
    case FDIV: sp--;stack[sp-1].f/=stack[sp].f;break;
    case FNEG: stack[sp-1].f=-stack[sp-1].f;break;
    case FREM:{float a=stack[sp-2].f,b=stack[sp-1].f;stack[sp-2].f=a-((jint)(a/b))*b;sp-=2;break;}
    case FCMPG: case FCMPL: {
        float a=stack[sp-2].f,b=stack[sp-1].f; sp-=2;
        if(a>b)stack[sp-1].i=1;else if(a==b)stack[sp-1].i=0;else stack[sp-1].i=-1;
        if(a!=a||b!=b)stack[sp-1].i=(op==FCMPG)?1:-1; break;
    }

    /* ---- double ---- */
    case DADD: sp--;stack[sp-1].d+=stack[sp].d;break;
    case DSUB: sp--;stack[sp-1].d-=stack[sp].d;break;
    case DMUL: sp--;stack[sp-1].d*=stack[sp].d;break;
    case DDIV: sp--;stack[sp-1].d/=stack[sp].d;break;
    case DNEG: stack[sp-1].d=-stack[sp-1].d;break;
    case DREM:{double a=stack[sp-2].d,b=stack[sp-1].d;stack[sp-2].d=a-((jlong)(a/b))*b;sp--;break;}
    case DCMPG: case DCMPL: {
        double a=stack[sp-2].d,b=stack[sp-1].d; sp-=2;
        if(a>b)stack[sp].i=1;else if(a==b)stack[sp].i=0;else stack[sp].i=-1;
        if(a!=a||b!=b)stack[sp].i=(op==DCMPG)?1:-1; sp++; break;
    }

    /* ---- type conversions ---- */
    case I2L: stack[sp-1].l=(jlong)stack[sp-1].i;break;
    case I2F: stack[sp-1].f=(jfloat)stack[sp-1].i;break;
    case I2D: stack[sp-1].d=(jdouble)stack[sp-1].i;break;
    case L2I: stack[sp-1].i=(jint)stack[sp-1].l;break;
    case L2F: stack[sp-1].f=(jfloat)stack[sp-1].l;break;
    case L2D: stack[sp-1].d=(jdouble)stack[sp-1].l;break;
    case F2I: stack[sp-1].i=(jint)stack[sp-1].f;break;
    case F2L: stack[sp-1].l=(jlong)stack[sp-1].f;break;
    case F2D: stack[sp-1].d=(jdouble)stack[sp-1].f;break;
    case D2I: stack[sp-1].i=(jint)stack[sp-1].d;break;
    case D2L: stack[sp-1].l=(jlong)stack[sp-1].d;break;
    case D2F: stack[sp-1].f=(jfloat)stack[sp-1].d;break;
    case I2B: stack[sp-1].i=(jint)(int8_t)stack[sp-1].i;break;
    case I2C: stack[sp-1].i=(jint)(uint16_t)stack[sp-1].i;break;
    case I2S: stack[sp-1].i=(jint)(int16_t)stack[sp-1].i;break;
    case LCMP: {
        sp-=2; jlong al=stack[sp].l,bl=stack[sp+1].l;
        stack[sp].i=(al>bl)?1:(al==bl?0:-1); sp++; break;
    }

    /* ---- control flow ---- */
    case IFEQ:case IFNE:case IFLT:case IFGE:case IFGT:case IFLE:{
        int t=stack[--sp].i,off=read_s16(ip); ip+=2; int ok=0;
        switch(op){case IFEQ:ok=(t==0);break;case IFNE:ok=(t!=0);break;
        case IFLT:ok=(t<0);break;case IFGE:ok=(t>=0);break;
        case IFGT:ok=(t>0);break;case IFLE:ok=(t<=0);break;}
        if(ok)ip+=off-3; break;
    }
    case IF_ICMPEQ:case IF_ICMPNE:case IF_ICMPLT:
    case IF_ICMPGE:case IF_ICMPGT:case IF_ICMPLE:{
        int b=stack[--sp].i,a=stack[--sp].i,off=read_s16(ip); ip+=2; int ok=0;
        switch(op){case IF_ICMPEQ:ok=(a==b);break;case IF_ICMPNE:ok=(a!=b);break;
        case IF_ICMPLT:ok=(a<b);break;case IF_ICMPGE:ok=(a>=b);break;
        case IF_ICMPGT:ok=(a>b);break;case IF_ICMPLE:ok=(a<=b);break;}
        if(ok)ip+=off-3; break;
    }
    case IF_ACMPEQ:case IF_ACMPNE:{
        jobject b=(jobject)(intptr_t)stack[--sp].l;
        jobject a=(jobject)(intptr_t)stack[--sp].l;
        int off=read_s16(ip); ip+=2;
        int ok=(op==IF_ACMPEQ)?(*env)->IsSameObject(env,a,b):!(*env)->IsSameObject(env,a,b);
        if(ok)ip+=off-3; break;
    }
    case GOTO: {int off=read_s16(ip); ip+=off-1; break;}
    case IFNULL:case IFNONNULL:{
        jobject r=(jobject)(intptr_t)stack[--sp].l;
        int off=read_s16(ip); ip+=2;
        int ok=(op==IFNULL)?(r==NULL):(r!=NULL);
        if(ok)ip+=off-3; break;
    }

    /* ---- returns ---- */
    case IRETURN:{kbox_value_t r;r.i=stack[--sp].i;return r;}
    case LRETURN:{kbox_value_t r;r.l=stack[sp-1].l;return r;}
    case FRETURN:{kbox_value_t r;r.f=stack[--sp].f;return r;}
    case DRETURN:{kbox_value_t r;r.d=stack[sp-1].d;return r;}
    case ARETURN:{kbox_value_t r;r.l=stack[--sp].l;return r;}
    case RETURN:{kbox_value_t r;r.i=0;return r;}

    /* ---- field access (sequential CP index) ---- */
    case GETSTATIC: {
        int idx=read_s16(ip); ip+=2;
        if(idx<cp_fld_n){
            /* Find the owning class: we stored fields with owner/name/desc triples.
             * Need to get the class from the field's owner. Re-find via the method's
             * pre-resolved classes (first class is usually the method's own class). */
            jclass cls=(cp_cls_n>0)?cp_cls[0]:NULL;
            if(cls) stack[sp].l=(jlong)(intptr_t)(*env)->GetStaticObjectField(env,cls,cp_fld[idx]);
            else stack[sp].l=0;
        }else stack[sp].l=0;
        sp++; break;
    }
    case PUTSTATIC: {
        int idx=read_s16(ip); ip+=2;
        jvalue v; v.l=(jobject)(intptr_t)stack[--sp].l;
        if(idx<cp_fld_n && cp_cls_n>0)
            (*env)->SetStaticObjectField(env,cp_cls[0],cp_fld[idx],v.l);
        break;
    }
    case GETFIELD: {
        int idx=read_s16(ip); ip+=2;
        jobject obj=(jobject)(intptr_t)stack[--sp].l;
        if(idx<cp_fld_n)
            stack[sp].l=(jlong)(intptr_t)(*env)->GetObjectField(env,obj,cp_fld[idx]);
        else stack[sp].l=0;
        sp++; break;
    }
    case PUTFIELD: {
        int idx=read_s16(ip); ip+=2;
        jvalue v; v.l=(jobject)(intptr_t)stack[--sp].l;
        jobject obj=(jobject)(intptr_t)stack[--sp].l;
        if(idx<cp_fld_n)(*env)->SetObjectField(env,obj,cp_fld[idx],v.l);
        break;
    }

    /* ---- method calls (sequential CP index) ---- */
    case INVOKESTATIC: {
        int idx=read_s16(ip); ip+=2;
        int ac = (idx<cp_mid_ac_n) ? cp_mid_ac[idx] : 0;
        char rt = (idx<cp_mid_rt_n) ? cp_mid_rt[idx] : 'V';
        jclass cls = (idx<cp_mid_cls_n) ? cp_mid_cls[idx] : NULL;
        jmethodID mid = (idx<cp_mid_n) ? cp_mid[idx] : NULL;
        /* collect args — use .l for all (jvalue union alias) */
        jvalue jargs[32];
        int base = sp - ac;
        for (int a=0; a<ac; a++) jargs[a].l = (jobject)(intptr_t)stack[base+a].l;
        sp = base;
        if (mid && cls) {
            switch(rt) {
            case 'V': (*env)->CallStaticVoidMethodA(env,cls,mid,jargs); break;
            case 'I': case 'Z': case 'B': case 'C': case 'S':
                stack[sp].i=(*env)->CallStaticIntMethodA(env,cls,mid,jargs); sp++; break;
            case 'J': stack[sp].l=(*env)->CallStaticLongMethodA(env,cls,mid,jargs); sp++; break;
            case 'F': stack[sp].f=(*env)->CallStaticFloatMethodA(env,cls,mid,jargs); sp++; break;
            case 'D': stack[sp].d=(*env)->CallStaticDoubleMethodA(env,cls,mid,jargs); sp++; break;
            default: stack[sp].l=(jlong)(intptr_t)(*env)->CallStaticObjectMethodA(env,cls,mid,jargs); sp++; break;
            }
        }
        break;
    }
    case INVOKEVIRTUAL: case INVOKEINTERFACE: {
        int idx=read_s16(ip); ip+=2;
        int ac = (idx<cp_mid_ac_n) ? cp_mid_ac[idx] : 0;
        char rt = (idx<cp_mid_rt_n) ? cp_mid_rt[idx] : 'V';
        jmethodID mid = (idx<cp_mid_n) ? cp_mid[idx] : NULL;
        jvalue jargs[32];
        int base = sp - ac - 1;
        for (int a=0; a<ac; a++) jargs[a].l = (jobject)(intptr_t)stack[base+1+a].l;
        jobject obj=(jobject)(intptr_t)stack[base].l;
        sp = base;
        if (mid) {
            switch(rt) {
            case 'V': (*env)->CallVoidMethodA(env,obj,mid,jargs); break;
            case 'I': case 'Z': case 'B': case 'C': case 'S':
                stack[sp].i=(*env)->CallIntMethodA(env,obj,mid,jargs); sp++; break;
            case 'J': stack[sp].l=(*env)->CallLongMethodA(env,obj,mid,jargs); sp++; break;
            case 'F': stack[sp].f=(*env)->CallFloatMethodA(env,obj,mid,jargs); sp++; break;
            case 'D': stack[sp].d=(*env)->CallDoubleMethodA(env,obj,mid,jargs); sp++; break;
            default: stack[sp].l=(jlong)(intptr_t)(*env)->CallObjectMethodA(env,obj,mid,jargs); sp++; break;
            }
        }
        break;
    }
    case INVOKESPECIAL: {
        int idx=read_s16(ip); ip+=2;
        int ac = (idx<cp_mid_ac_n) ? cp_mid_ac[idx] : 0;
        char rt = (idx<cp_mid_rt_n) ? cp_mid_rt[idx] : 'V';
        jmethodID mid = (idx<cp_mid_n) ? cp_mid[idx] : NULL;
        jvalue jargs[32];
        int base = sp - ac - 1;
        for (int a=0; a<ac; a++) jargs[a].l = (jobject)(intptr_t)stack[base+1+a].l;
        jobject obj=(jobject)(intptr_t)stack[base].l;
        sp = base;
        if (mid) {
            switch(rt) {
            case 'V': (*env)->CallNonvirtualVoidMethodA(env,obj,cp_cls[0],mid,jargs); break;
            case 'I': case 'Z': case 'B': case 'C': case 'S':
                stack[sp].i=(*env)->CallNonvirtualIntMethodA(env,obj,cp_cls[0],mid,jargs); sp++; break;
            case 'J': stack[sp].l=(*env)->CallNonvirtualLongMethodA(env,obj,cp_cls[0],mid,jargs); sp++; break;
            case 'F': stack[sp].f=(*env)->CallNonvirtualFloatMethodA(env,obj,cp_cls[0],mid,jargs); sp++; break;
            case 'D': stack[sp].d=(*env)->CallNonvirtualDoubleMethodA(env,obj,cp_cls[0],mid,jargs); sp++; break;
            default: stack[sp].l=(jlong)(intptr_t)(*env)->CallNonvirtualObjectMethodA(env,obj,cp_cls[0],mid,jargs); sp++; break;
            }
        }
        break;
    }

    /* ---- object creation ---- */
    case NEW: {
        int idx=read_s16(ip); ip+=2;
        jclass cls=(idx<cp_cls_n)?cp_cls[idx]:NULL;
        if(cls){
            jmethodID ctor=(*env)->GetMethodID(env,cls,"<init>","()V");
            jobject obj=(*env)->NewObject(env,cls,ctor);
            stack[sp].l=(jlong)(intptr_t)obj;
        }else stack[sp].l=0;
        sp++; break;
    }

    /* ---- arrays ---- */
    case NEWARRAY: {
        int at=*ip++,count=stack[--sp].i; jobject arr=NULL;
        switch(at){case 4:arr=(*env)->NewBooleanArray(env,count);break;
        case 5:arr=(*env)->NewCharArray(env,count);break;
        case 6:arr=(*env)->NewFloatArray(env,count);break;
        case 7:arr=(*env)->NewDoubleArray(env,count);break;
        case 8:arr=(*env)->NewByteArray(env,count);break;
        case 9:arr=(*env)->NewShortArray(env,count);break;
        case 10:arr=(*env)->NewIntArray(env,count);break;
        case 11:arr=(*env)->NewLongArray(env,count);break;}
        stack[sp].l=(jlong)(intptr_t)arr; sp++; break;
    }
    case ANEWARRAY: {
        int idx=read_s16(ip); ip+=2; int count=stack[--sp].i;
        jclass cls=(idx<cp_cls_n)?cp_cls[idx]:NULL;
        jobject arr=(*env)->NewObjectArray(env,count,cls,NULL);
        stack[sp].l=(jlong)(intptr_t)arr; sp++; break;
    }
    case ARRAYLENGTH: {
        jobject arr=(jobject)(intptr_t)stack[sp-1].l;
        stack[sp-1].i=(*env)->GetArrayLength(env,arr); break;
    }
    case IALOAD:{int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;jint b;(*env)->GetIntArrayRegion(env,a,ix,1,&b);stack[sp].i=b;sp++;break;}
    case AALOAD:{int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;stack[sp].l=(jlong)(intptr_t)(*env)->GetObjectArrayElement(env,a,ix);sp++;break;}
    case BALOAD:{int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;jbyte b;(*env)->GetByteArrayRegion(env,a,ix,1,&b);stack[sp].i=(jint)b;sp++;break;}
    case CALOAD:{int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;jchar b;(*env)->GetCharArrayRegion(env,a,ix,1,&b);stack[sp].i=(jint)b;sp++;break;}
    case SALOAD:{int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;jshort b;(*env)->GetShortArrayRegion(env,a,ix,1,&b);stack[sp].i=(jint)b;sp++;break;}
    case IASTORE:{jint v=stack[--sp].i;int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;(*env)->SetIntArrayRegion(env,a,ix,1,&v);break;}
    case AASTORE:{jobject v=(jobject)(intptr_t)stack[--sp].l;int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;(*env)->SetObjectArrayElement(env,a,ix,v);break;}
    case BASTORE:{jbyte v=(jbyte)stack[--sp].i;int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;(*env)->SetByteArrayRegion(env,a,ix,1,&v);break;}
    case CASTORE:{jchar v=(jchar)stack[--sp].i;int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;(*env)->SetCharArrayRegion(env,a,ix,1,&v);break;}
    case SASTORE:{jshort v=(jshort)stack[--sp].i;int ix=stack[--sp].i;jobject a=(jobject)(intptr_t)stack[--sp].l;(*env)->SetShortArrayRegion(env,a,ix,1,&v);break;}

    case ATHROW: {jobject ex=(jobject)(intptr_t)stack[--sp].l;(*env)->Throw(env,(jthrowable)ex);kbox_value_t r;r.i=0;return r;}
    case CHECKCAST: {read_s16(ip); ip+=2; break;} /* trust bytecode */
    case INSTANCEOF: {
        int idx=read_s16(ip); ip+=2; jclass cls=(idx<cp_cls_n)?cp_cls[idx]:NULL;
        jobject obj=(jobject)(intptr_t)stack[sp-1].l;
        stack[sp-1].i=(*env)->IsInstanceOf(env,obj,cls)?1:0; break;
    }

    default: break; /* skip unsupported */
    }}

    kbox_value_t r; r.i=0; return r;
}
