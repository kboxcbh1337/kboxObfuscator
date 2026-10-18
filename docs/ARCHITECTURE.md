# 架构

## 1. 流水线

`ProtectionPipeline` 按阶段串行执行，逐类变换可以并行（`ParallelClassProcessor`）。
主要阶段：

```
载入 jar / 解析 ClassGraph
  ├─ 预扫描：反射、SPI、lambda、Mixin、框架注解
  ├─ 库分类：区分应用代码与第三方库
  ├─ BF 决策：可执行入口 / Mod 元数据 / TweakClass
  ├─ 我的世界适配：保留入口、Mixin、资源、元数据
  ├─ VMP / JNIC 方法自动选择（可 full coverage）
  ├─ 字符串加密（AES-256-CTR）
  ├─ 常量、MBA、类型混淆、控制流
  ├─ 重命名（类/方法/字段/包）
  ├─ Kotlin @Metadata 修复
  ├─ VMP 翻译 + 原生解释器编译
  ├─ 反分析：反调试、反反编译器、异常跳转、蜜罐
  ├─ kboxDedeobfShield：方法拆分、不透明状态机、哨兵交错
  ├─ BFVM / BrainfuckShield / K-OTP
  ├─ 资源混淆、原生库加壳
  └─ 打包：写 jar、注入运行时、写完整性哈希
```

任何单类序列化失败都会回滚到原始字节，**但名字仍按最终映射重写**，避免
“调用点保留旧名、声明已改名”的 `NoSuchMethodError`。

## 2. 运行时注入

| 类 | 作用 |
|---|---|
| `ResourceGuardClassLoader` / `ResourceGuardLauncher` | 类/资源解密引导，处理 `-jar` 与 `-cp` |
| `KBoxClassDecryptTweaker` | 类文件解密（AES + KBNL 密钥） |
| `KbnlKey` / `HardwareKeyRing` | 域分离密钥派生，构建期随机种子闭环 |
| `NativeLoader` / `NativeCrypto` | 原生库加载、原生字符串解密 |
| `VmpInterpreter` | VMP 字节码解释器（Java + 原生双路径） |
| `bfvm.VmCore` | BFVM / K-OTP 共用的 Brainfuck 方言解释器 |
| `KotpRuntime` | K-OTP 一次性程序：解密 → 执行 → 就地重随机 |
| `BfSecureLoader` | BF blob 引导与类定义 |
| `AntiDebug` / `IntegrityChecker` | 反调试金丝雀与产物完整性 |
| `ReflectionGateInjector` | `Class.forName` 白名单门 |

## 3. 密钥与字符串

```
key = SHA-256(hardwareFingerprint || buildSeed || domainTag || salt)
```

- 域分离：每个用途（字符串 / 类 / VMP / JNIC / OTP）独立 tag。
- 构建期随机 32B `seed.bin` 写入 `META-INF/kbox/`，保证 build ↔ run 一致。
- 字符串为 AES-256-CTR：`IV(16) || ciphertext`，密钥表经 KBNL 盲化，解密后擦除中间 `byte[]`。
- 所有格式魔数（KBNL/KBF2/KBFT…）在产物中以 XOR 遮蔽或分片形式存在。

## 4. 虚拟化

**VMP**：方法体 → 自定义栈式字节码 → `VmpInterpreter`。常量池按方法独立编码，
每次执行前按 key 解密；类解析使用声明类的 loader（与 JVM 语义一致）。

**BFVM**：方法体 → Brainfuck 方言。`VmCore` 解释执行，支持对象/数组/异常/反射。

**BrainfuckShield**：对 VMP 方法再做一层 ChaCha20 加密 + 方言解释，形成二次虚拟化。

**K-OTP**：`P = compile(method)`；`A = P XOR ks(seed, site, epoch, chain)`。
调用时还原 `P` 执行，随后用时间/线程/参数指纹重算 `A`，静态产物没有稳定方法体。

## 5. 原生层

- **JNIC**：把选中方法翻译为 C，编译为共享库，通过 `RegisterNatives` 绑定。
  类字面量解析失败不会中断整个方法：入口预解析失败置空，`LDC class` 真正执行时才抛
  `NoClassDefFoundError`，并优先使用声明类 loader。
- **kboXShield**：PE 壳（全节 ChaCha20、合成导入表、函数级虚拟化、指令变异、平坦化）。
- **protectNativeLibs**：扫描 jar 内 `.dll/.so/.dylib`，按魔数识别后加壳或加密，
  运行时解密落盘加载并立即擦除。

## 6. 兼容性设计

- JDK 8–25 字节码（major 52–69）。
- JDK 17+ 模块系统：`setAccessible` 失败降级；数组 `clone()` 自行浅拷贝。
- JDK 接口覆写方法一律保名（`List.iterator` 等），避免 `AbstractMethodError`。
- `InnerClasses` 始终保留（JVM 一致性校验 + `getSimpleName`/record `toString`）。
- 重命名后同步改写 `LDC` 字符串与注解字符串中的类名（`Class.forName`、`@SidedProxy` 等）。
- 反射门按重命名后的名字计算白名单，避免改名后误杀。
