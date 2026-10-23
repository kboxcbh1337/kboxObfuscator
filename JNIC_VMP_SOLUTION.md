# KBox JNIC + VMP 完整命中方案：将解释层编译进 JAR

## 一、方案概述

本方案实现了两层高级代码保护，二者**共享同一个 C 解释器引擎**并一同嵌入 JAR：

| 保护层 | 原理 | 产物 | 运行时执行者 |
|--------|------|------|-------------|
| **JNIC** (Java→Native Interp C) | 将 JVM 字节码序列化，生成 C 桩函数 + C 解释器，MSVC 编译为 DLL | `kbox_native.dll` | C 解释器（原生机器码） |
| **VMP** (Virtual Machine Protection) | 将 JVM 字节码翻译为自定义栈机操作码，生成 `byte[]` 程序 | `$vmp_<n>` 字段 | Java 解释器 `VmpInterpreter` |

### 核心设计：解释层合一

JNIC 和 VMP 都依赖**解释执行**而非直接暴露原始逻辑：

```
                   ┌─────────────┐
                   │  原始 JVM    │
                   │  字节码      │
                   └──────┬──────┘
                          │
            ┌─────────────┴─────────────┐
            ▼                           ▼
    ┌───────────────┐          ┌───────────────┐
    │  JNIC 路径     │          │  VMP 路径      │
    │  序列化为       │          │  翻译为        │
    │  byte[] 数组   │          │  VmpOp 字节流  │
    └───────┬───────┘          └───────┬───────┘
            │                          │
            ▼                          ▼
    ┌───────────────┐          ┌───────────────┐
    │  C 桩函数       │          │  $vmp_N 字段   │
    │  _kfnN() {     │          │  byte[] code   │
    │    kbox_jvm_   │          │  Object[] cp   │
    │    interp(     │          └───────┬───────┘
    │      bc,       │                  │
    │      cparr[])} │                  ▼
    └───────┬───────┘          ┌───────────────┐
            │                  │  VmpInterp.    │
            ▼                  │  execute()     │
    ┌───────────────┐          │  (Java switch) │
    │  C 解释器       │          └───────────────┘
    │  kbox_jvm_    │
    │  interp()     │
    │  (MSVC→DLL)   │
    └───────────────┘
```

JNIC 的 C 解释器 (`kbox_jvm_interp.c` / `kbox_jnic_interp_v3.c`) 是一个**通用 JVM 字节码解释器**，在 C 层逐条执行 JVM 操作码。每个被保护的 Java 方法变成：

```c
// 自动生成的 C 桩（示例：matrixMultiply）
JNIEXPORT jobjectArray JNICALL _kfn0(JNIEnv *env, jclass cls,
                                      jobjectArray a, jobjectArray b) {
    // 字节码数组（序列化后的 JVM 字节码）
    static unsigned char bc[] = { 0x2a, 0xb4, ... };
    // 常量池辅助数组
    static const char *cpcls[] = { "[I", "[I", ... };
    static const char *cpmid[] = { ... };
    // 委托给 C 解释器
    return (jobjectArray) kbox_jvm_interp(env, cls, bc, sizeof(bc), cpcls, cpmid, ...);
}
```

---

## 二、目标方法如何被"命中"

### 2.1 JNIC 命中：三种方式

#### 方式一：`@Native` 注解（推荐）

```java
package com.kbox.annotations;

@Retention(RetentionPolicy.CLASS)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface Native {}
```

**使用示例**（类级注解 — 所有非静态方法全部翻译）：

```java
package com.example.crypto;

import com.kbox.annotations.Native;

@Native  // 整个类的非静态方法 → JNIC
public class CryptoCore {
    public byte[] aesEncrypt(byte[] data, byte[] key) { ... }
    public byte[] sha256(byte[] input) { ... }
}
```

**使用示例**（方法级注解 — 精准命中）：

```java
package com.example.license;

import com.kbox.annotations.Native;

public class LicenseValidator {
    @Native  // 仅此方法 → JNIC
    public static boolean verify(String key, String hwid) { ... }

    // 此方法不受影响
    public void log(String msg) { ... }
}
```

**`@Native` 排除注解**：

```java
@Native  // 类级：该类方法都翻译
public class Foo {
    public void secure() { ... }      // → JNIC

    @NotNative
    public void debug() { ... }      // → 不翻译，保持 Java
}
```

#### 方式二：配置文件显式指定

```ini
# demo-multi-max.conf
enableJnic = true
cc = D:/vs/VC/Tools/MSVC/14.52.36520/bin/Hostx64/x64/cl.exe
nativeMethod = com/example/CryptoCore#aesEncrypt([B[B)[B
nativeMethod = com/example/License#verify(Ljava/lang/String;Ljava/lang/String;)Z
```

**格式**：`类内部名#方法名#方法描述符`

#### 方式三：自动选择（无注解/无配置时）

当 `enableJnic=true` 但无任何已配置方法时，`AutoJnicVmpSelector` 自动生效：

- 选择条件：指令数 >= 10，非抽象/构造/clinit/桥接，无 `invokedynamic`
- 最多 50 个方法，按指令数降序（优先保护计算密集方法）

---

### 2.2 VMP 命中：两种方式

#### 方式一：配置文件显式指定（唯一推荐方式）

```ini
enableVmp = true
vmpMethod = com/kbox/demo/JnicVmpDemo.nextPrime (I)I
vmpMethod = com/kbox/demo/JnicVmpDemo.xorCipher ([BI)V
vmpMethod = com/kbox/demo/JnicVmpDemo.fibonacci (I)J
```

**格式**：`类内部名#方法名 描述符`（注意：类名/方法名之间是空格）

配置文件中的方法键会被 `ConfigLoader.addNormalizedMethod()` 自动标准化为内部格式 `com/kbox/demo/JnicVmpDemo#nextPrime#(I)I`。

#### 方式二：自动选择（无配置时）

当 `enableVmp=true` 但无配置方法时：

- 选择条件：指令数 5~50，排除已被 JNIC 选中的方法
- 最多 30 个方法
- 小方法（5~50 条指令）优先命中 VMP，避免对热点大方法产生性能影响

---

## 三、解释层详解

### 3.1 C 解释器（JNIC 运行时）

**源文件**：`kbox-core/src/main/resources/kbox_jnic_interp_v3.c`

核心函数签名：

```c
jvalue kbox_jvm_interp(
    JNIEnv   *env,        // JNI 环境
    jobject  receiver,    // this（静态方法时为 NULL）
    int      is_static,   // 是否为静态方法
    unsigned char *bc,    // JVM 字节码序列
    int      bc_len,      // 字节码长度
    // 常量池数组：
    const char **cpcls,   // 类引用
    const char **cpmid,   // 成员引用（owner#name#desc）
    const char **cpstr,   // 字符串常量
    int      *cpint,      // int 常量
    // 参数（变长，由桩函数负责压入）
    jvalue   *args,
    int      max_locals,
    int      max_stack
);
```

**关键能力**：

| 类别 | 支持的操作码 |
|------|------------|
| 栈操作 | `POP`, `DUP`, `SWAP` 等 |
| 算术 | `IADD`, `LADD`, `IMUL`, `LDIV`, `IREM` 等 |
| 类型转换 | `I2L`, `L2I`, `I2F`, `F2D` 等 |
| 比较 | `IF_ICMPEQ`, `IF_ICMPLT`, `IFNULL` 等 |
| 跳转 | `GOTO`, `TABLESWITCH`, `LOOKUPSWITCH` |
| 方法调用 | `INVOKESTATIC`, `INVOKEVIRTUAL`, `INVOKESPECIAL`, `INVOKEINTERFACE` |
| 字段 | `GETFIELD`, `PUTFIELD`, `GETSTATIC`, `PUTSTATIC` |
| 数组 | `NEWARRAY`, `ANEWARRAY`, `AALOAD`, `IASTORE` 等 |
| 对象 | `NEW`, `INSTANCEOF`, `CHECKCAST` |
| 异常 | `ATHROW` |

**不支持**：`invokedynamic`（会退回到 Java 字节码）

### 3.2 Java 解释器（VMP 运行时）

**源文件**：`kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java`

核心方法：

```java
public static Object execute(VmpMethod method, Object receiver, Object[] args);
```

**执行模型**：

```
VmpMethod {
    byte[]   code;     // VMP 操作码字节流
    Object[] cp;       // 常量池（惰性解析的 Class/Field/Method 引用）
    int      maxStack;
    int      maxLocals;
    int[][]  tryCatch; // 异常表 [startPc, endPc, handlerPc, catchTypeCpIdx]
}
```

栈机解释器维护：

- `Object[] stack` — 操作数栈（基本类型自动装箱/拆箱）
- `Object[] locals` — 本地变量（this + 参数 + 局部变量）
- `switch` 分发每条 `VmpOp` 指令

**VMP 操作码**（单字节）：

```java
ICONST, LCONST, FCONST, DCONST, ACONST_NULL, STRING_CONST,
ILOAD, LLOAD, FLOAD, DLOAD, ALOAD,
ISTORE, LSTORE, FSTORE, DSTORE, ASTORE,
IADD, LADD, FADD, DADD,
ISUB, LSUB, FSUB, DSUB,
IMUL, LMUL, FMUL, DMUL,
IDIV, LDIV, FDIV, DDIV,
IREM, LREM, FREM, DREM,
INEG, LNEG, FNEG, DNEG,
// ... 比较、跳转、方法调用、字段访问、数组操作等
RETURN, IRETURN, LRETURN, FRETURN, DRETURN, ARETURN,
ATHROW
```

---

## 四、DLL 嵌入 JAR 全流程

### 4.1 编译阶段：C 解释器 → DLL

```
kbox_jnic_interp_v3.c  ─────────┐
                                ├──→ MSVC cl.exe ──→ kbox_native.dll
自动生成的 C 桩函数(_kfn0..N) ──┘   (104 KB)
```

`NativeCompiler` 自动执行：

```java
// 1. 组装 C 源文件
String source = assembleInterpSource(fns);  // 包含所有桩函数 + JNI_OnLoad

// 2. 写入解释器源文件
writeInterpreterSource(cDir);  // 复制 kbox_jnic_interp_v3.c

// 3. MSVC 编译
compileMulti(sourceFiles, cDir, "kbox_native");
// 等价于: cl.exe /LD /O2 /I $JAVA_HOME/include /I $JAVA_HOME/include/win32 /I $SDK/include *.c
```

`JNI_OnLoad` 自动生成的注册代码：

```c
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_8);

    // 按类分组注册
    {   // 类: com/kbox/demo/JnicVmpDemo (重命名后)
        JNINativeMethod methods[] = {
            {"matrixMultiply", "([[I[[I)[[I", _kfn0},
            {"computeHash",    "([B)J",         _kfn1},
            {"bubbleSort",     "([I)V",         _kfn2},
        };
        jclass cls = (*env)->FindClass(env, "a/b/c/d");
        (*env)->RegisterNatives(env, cls, methods, 3);
    }
    return JNI_VERSION_1_8;
}
```

> **注意**：`FindClass` 使用**重命名后**的类名，因此 JNIC 在标识符重命名**之后**执行。

### 4.2 加密阶段：DLL → blob

```
kbox_native.dll (raw, ~130 KB)
    │
    ├── DEFLATE 压缩 (BEST_COMPRESSION)
    │    └── 压缩后 ~59 KB（约 46% 压缩比）
    │
    ├── ChaCha20 加密（随机 256-bit 密钥）
    │    └── 密文 ~59 KB
    │
    └── 打包头
         ┌──────────────────────────────────┐
         │  Magic "KBNL"           (4 bytes) │
         │  Key                     (32 bytes)│
         │  Nonce                   (12 bytes)│
         │  Counter                 (8 bytes) │
         │  Compressed Length       (4 bytes) │
         │  Raw Length              (4 bytes) │
         │  Ciphertext              (N bytes) │
         └──────────────────────────────────┘
         总计: 64 + N bytes (header + encrypted)
```

### 4.3 写入阶段：blob → JAR

```
Packager.write():
    ├── 创建输出 JAR
    ├── 写入 520 个 class 文件（重命名后的）
    ├── 写入资源文件（META-INF/services 等，引用已重写）
    ├── 注入运行时类：
    │   ├── NativeLoader.class     ← JNIC 启用时
    │   ├── ChaCha20.class         ← JNIC 启用时
    │   ├── VmpInterpreter.class   ← VMP 启用时
    │   ├── VmpOp.class            ← VMP 启用时
    │   └── ResourceGuardLauncher  ← 资源/类加密时
    ├── 写入 META-INF/kbox/native.bin  ← JNIC blob (59,979 bytes)
    └── 更新 MANIFEST.MF（Main-Class 替换等）
```

**输出 JAR 结构**：

```
KBox-Demo-Multi-protected.jar
├── META-INF/
│   ├── MANIFEST.MF
│   ├── kbox/
│   │   ├── native.bin          ← 加密压缩的 DLL blob
│   │   └── integrity.hash      ← JAR 完整性校验
│   └── services/...            ← 引用已重写的 SPI 文件
├── a/b/c/d.class               ← 重命名后的 JnicVmpDemo
│   └── 字段: $vmp_0, $vmpcp_0, $vmpm_0  ← VMP 程序数据
├── com/kbox/runtime/
│   ├── NativeLoader.class      ← 运行时 DLL 解密/加载
│   ├── ChaCha20.class          ← 流加密
│   ├── VmpInterpreter.class    ← VMP 运行时解释器
│   └── VmpOp.class             ← VMP 操作码定义
└── ...                          ← 其他重命名/加密的类
```

### 4.4 加载阶段：blob → DLL → 可用

```java
// NativeLoader.load() — 在第一个 <clinit> 中自动调用

// 1. 从 classpath 读取 blob
InputStream in = classLoader.getResourceAsStream("META-INF/kbox/native.bin");

// 2. 验证 magic "KBNL"
assert blob[0..3] == "KBNL";

// 3. 提取 key + nonce（自包含于 blob header）
byte[] key   = Arrays.copyOfRange(blob, 4, 36);
byte[] nonce = Arrays.copyOfRange(blob, 36, 48);

// 4. ChaCha20 解密
byte[] compressed = ChaCha20.process(key, nonce, 0L, ciphertext);

// 5. DEFLATE 解压
Inflater inflater = new Inflater(true);
byte[] dll = inflate(compressed, rawLen);

// 6. 写入临时文件
Path tmp = Files.createTempFile("kbox-native-", ".dll");
Files.write(tmp, dll);

// 7. 加载 DLL
System.load(tmp.toAbsolutePath().toString());
// → 触发 JNI_OnLoad → RegisterNatives → 所有 native 方法已绑定
```

---

## 五、完整端到端流程

### 5.1 用户侧：编写源代码

```java
// 文件: demo-multi/src/com/kbox/demo/JnicVmpDemo.java
package com.kbox.demo;

import com.kbox.annotations.Native;

public class JnicVmpDemo {

    // ════ @Native 方法 → JNIC (C解释器执行) ════

    @Native
    public static int[][] matrixMultiply(int[][] a, int[][] b) {
        int n = a.length;
        int[][] result = new int[n][n];
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++) {
                int sum = 0;
                for (int k = 0; k < n; k++)
                    sum += a[i][k] * b[k][j];
                result[i][j] = sum;
            }
        return result;
    }

    @Native
    public static long computeHash(byte[] data) { /* SHA-like hash */ }

    @Native
    public static void bubbleSort(int[] arr) { /* O(n^2) sort */ }

    // ════ VMP 方法 → VMP (Java解释器执行) ════

    public static int nextPrime(int n) { /* trial division */ }

    public static void xorCipher(byte[] data, int key) { /* XOR cipher */ }

    public static long fibonacci(int n) { /* iterative fibonacci */ }
}
```

### 5.2 用户侧：配置文件

```ini
# demo-multi-max.conf
enableJnic = true
enableVmp = true

# C 编译器路径（Windows MSVC）
cc = D:/vs/VC/Tools/MSVC/14.52.36520/bin/Hostx64/x64/cl.exe

# VMP 目标方法（config 显式指定）
vmpMethod = com/kbox/demo/JnicVmpDemo.nextPrime (I)I
vmpMethod = com/kbox/demo/JnicVmpDemo.xorCipher ([BI)V
vmpMethod = com/kbox/demo/JnicVmpDemo.fibonacci (I)J

# 其他保护（可选）
encryptStrings = true
obfuscateControlFlow = true
controlFlowStrength = 3
antiDecompilerLevel = 3
watermark = kboxstudio
```

### 5.3 保护器侧：流水线执行

```
java -jar kbox-protector-obfuscated.jar \
    --config demo-multi-max.conf \
    --input demo-multi/KBox-Demo-Multi.jar \
    --output KBox-Demo-Multi-protected.jar

流水线阶段:
  [分析]          → 解析所有 class，构建 ClassGraph
  [@Native 扫描]  → 发现 3 个 @Native 方法 → 加入 nativeMethods
  [Config 加载]   → 读取 3 个 vmpMethod 条目
  [标识符重命名]  → 所有类/方法/字段混淆（JNIC/VMP 目标方法也参与）
  [JNIC 翻译]     → JniBytecodeInterp.translate() × 3
                     → 生成 3 个 InterpFn（_kfn0, _kfn1, _kfn2）
                     → 每个 InterpFn 含 bytecode[] + cp arrays
  [JNIC 编译]     → NativeCompiler.assembleInterpSource(fns)
                     → 生成 C 文件（3 个桩函数 + JNI_OnLoad）
                     → kbox_jnic_interp_v3.c（解释器）写入工作目录
                     → MSVC cl.exe 编译 → kbox_native.dll
  [JNIC 打包]     → NativePacker.pack(dll) → encrypted blob
  [JNIC 标记]     → 3 个方法 access → ACC_NATIVE，清空 Code 属性
                     → 第一个类的 <clinit> 注入 NativeLoader.load()
  [VMP 翻译]      → VmpTranslator.translate() × 3
                     → 每个方法 → byte[] code + Object[] cpRaw
  [VMP 注入]      → VmpMethodInjector.rewrite()
                     → 每个类新增 $vmp_N / $vmpcp_N / $vmpm_N 字段
                     → <clinit> 中构造 VmpMethod 对象
                     → 方法体替换为 VmpInterpreter.execute() 桩
  [字符串加密]    → AES 加密 8 个字符串常量
  [控制流混淆]    → 强度 3 谓词注入 + 平坦化
  [反编译器对抗]  → 等级 3：巨型方法 + 非法 StackMapTable + 常量池炸弹
  [打包]          → Packager.write()
                     → 520 class + 运行时 class + native.bin + resources
                     → 输出: KBox-Demo-Multi-protected.jar
```

### 5.4 运行时：用户执行

```bash
java -jar KBox-Demo-Multi-protected.jar

# 运行时流程:
# 1. JVM 加载第一个类 → 触发 <clinit>
# 2. <clinit> 调用 NativeLoader.load()
#    → 从 META-INF/kbox/native.bin 读取 blob
#    → ChaCha20 解密 → Inflater 解压 → 写临时 .dll
#    → System.load() → JNI_OnLoad → RegisterNatives
# 3. 后续调用 matrixMultiply/computeHash/bubbleSort
#    → JVM 发现是 native 方法 → 路由到 DLL 中的 _kfnN
#    → _kfnN 将序列化字节码传给 C 解释器
#    → C 解释器逐条执行 JVM 操作码并返回结果
#
# 4. 调用 nextPrime/xorCipher/fibonacci
#    → 方法体已被替换为 VMP 桩代码
#    → 加载 $vmp_N 字节码 → 传给 VmpInterpreter.execute()
#    → Java 解释器逐条执行 VmpOp 指令并返回结果
```

---

## 六、关键约束与兼容性

### 6.1 JNIC 方法限制

| 条件 | 说明 |
|------|------|
| 非抽象方法 | 必须有具体方法体 |
| 非构造器 `<init>` | 对象初始化逻辑无法 native 化 |
| 非类初始化器 `<clinit>` | 类加载时序依赖 |
| 非桥接方法 (`ACC_BRIDGE`) | 泛型擦除生成的合成方法 |
| 无 `invokedynamic` | C 解释器不支持 `invokedynamic` |
| 指令数 >= 10 (自动选择时) | 太小的方法 native 化得不偿失 |

### 6.2 VMP 方法限制

| 条件 | 说明 |
|------|------|
| 指令数 5~50 (自动选择时) | 太小无意义，太大会导致 VMP 性能问题 |
| 排除已选 JNIC 方法 | 避免重复保护 |
| 不支持 `invokedynamic` | 翻译阶段抛出 `UnsupportedOpcodeException` 回退 |

### 6.4 Mixin 框架兼容

对 Mixin 项目，保留条件：

```ini
keepPrefix = leader.mixin., leader.init., org.spongepowered.
encryptClasses = false     # 破坏 MixinTweaker 字节码分析
obfuscateResources = false # 保护 mixins.leader.json 配置文件
exceptionJumpObf = false   # COMPUTE_FRAMES 冲突
```

---

## 七、扩展：新增目标方法

向现有 Demo 中添加新的 JNIC/VMP 目标：

### 添加 @Native 方法

```java
// 在 JnicVmpDemo.java 中添加
@Native
public static int binomialCoefficient(int n, int k) {
    if (k == 0 || k == n) return 1;
    return binomialCoefficient(n - 1, k - 1) + binomialCoefficient(n - 1, k);
}
```

无需修改配置 — `@Native` 自动扫描。

### 添加 VMP 方法

```java
// 在 JnicVmpDemo.java 中添加
public static boolean isPalindrome(String s) {
    int left = 0, right = s.length() - 1;
    while (left < right) {
        if (s.charAt(left) != s.charAt(right)) return false;
        left++; right--;
    }
    return true;
}
```

在配置中添加：

```ini
vmpMethod = com/kbox/demo/JnicVmpDemo.isPalindrome (Ljava/lang/String;)Z
```

---

## 八、故障排查

| 症状 | 原因 | 解决 |
|------|------|------|
| `UnsatisfiedLinkError: native blob not found` | `native.bin` 未写入 JAR | 检查 `enableJnic=true` 且 MSVC 编译成功 |
| `UnsatisfiedLinkError: bad magic` | blob 被篡改或写入异常 | 重新生成 JAR |
| `NoClassDefFoundError: com/kbox/runtime/NativeLoader` | 运行时类未注入 | 检查 `Packager` 是否正确注入 |
| `VerifyError` | StackMapTable 帧错误 | 检查 CF 变换类标记是否正确 |
| VMP 方法 `ArrayIndexOutOfBounds` | flatten pass 失败 | 自动 fallback 用原代码，不影响功能 |
| MSVC `stdio.h not found` | SDK 路径检测失败 | 检查 `cl.exe` 路径层级结构是否正确 |
| `Skipping unparseable class` | 分析阶段类描述符解析失败 | 不影响核心功能，仅工具类可能跳过 |
