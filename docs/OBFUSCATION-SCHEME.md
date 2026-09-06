# KBox Obfuscator — 保护方案说明文档

KBox 是一套可直接编译运行的 Java 应用保护系统，融合 ZKM 级字节码混淆、JNIC 本地化与 VMP 虚拟机解释器三大核心能力。本文档描述其架构、各保护阶段原理、配置参考与验证结果。

---

## 1. 系统架构

### 1.1 模块结构

```
kbox-obfuscator (parent pom)
├── kbox-core          保护引擎核心：分析、重命名、字符串加密、控制流、JNIC、VMP、打包
├── kbox-cli           命令行入口，打包为可执行 fat jar (kbox-protector.jar)
├── kbox-gui           Java Swing UI (ZKM 风格)
├── kbox-maven-plugin  Maven 插件封装，集成到构建生命周期
└── kbox-testapp       模拟 Spring Boot 应用，作为保护验证用例
```

### 1.2 保护管线执行顺序

```
analyze → reflection scan → JNIC (构建本地库) → control flow → string encrypt → VMP → rename → package
```

**顺序设计原理**：
- **JNIC 在重命名之前**：生成的 JNI 符号名 (`Java_pkg_Class_method`) 必须匹配原始类/方法名。
- **控制流在字符串加密之前**：使不透明谓词/平坦化分支无法通过检视字符串调用点被轻易剥离。
- **VMP 在控制流之后**：让分发器逻辑本身已是混淆态。
- **重命名最后执行**：所有前序 pass 可用原始名廉价解析。

### 1.3 核心类一览

| 职责 | 类 |
|------|----|
| 管线编排 | [ProtectionPipeline](../kbox-core/src/main/java/com/kbox/core/ProtectionPipeline.java) |
| 依赖分析 | [DependencyAnalyzer](../kbox-core/src/main/java/com/kbox/core/analysis/DependencyAnalyzer.java) |
| 反射扫描 | [ReflectionScanner](../kbox-core/src/main/java/com/kbox/core/analysis/ReflectionScanner.java) |
| 标识符重命名 | [NameObfuscator](../kbox-core/src/main/java/com/kbox/core/name/NameObfuscator.java) |
| 字符串加密 | [StringEncryptor](../kbox-core/src/main/java/com/kbox/core/stringenc/StringEncryptor.java) |
| 控制流混淆 | [ControlFlowObfuscator](../kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java) + [Flattener](../kbox-core/src/main/java/com/kbox/core/controlflow/Flattener.java) |
| JNIC 本地化 | [JnicOrchestrator](../kbox-core/src/main/java/com/kbox/core/jnic/JnicOrchestrator.java) + [JniCTranslator](../kbox-core/src/main/java/com/kbox/core/jnic/JniCTranslator.java) |
| VMP 引擎 | [VmpTranslator](../kbox-core/src/main/java/com/kbox/core/vmp/VmpTranslator.java) + [VmpMethodInjector](../kbox-core/src/main/java/com/kbox/core/vmp/VmpMethodInjector.java) |
| 运行时解密 | [KBoxRuntime](../kbox-core/src/main/java/com/kbox/runtime/KBoxRuntime.java) + [VmpInterpreter](../kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java) |
| 打包 | [Packager](../kbox-core/src/main/java/com/kbox/core/packaging/Packager.java) |

---

## 2. 保护技术详解

### 2.1 标识符重命名 (ZKM-level)

**原理**：重命名类（仅简单名，保留包名以兼容 Spring 组件扫描与资源路径查找）、方法、字段，同时尊重覆写等价性。

**算法**：
1. 对类层次做并查集 (union-find)，共享继承边的类归入同一连通分量。
2. 对每个 `(name, desc)` 对，收集所有声明者；同连通分量的成员形成一个**重命名组**。
3. 若组内**任一**成员被 keep，则整组保留原名（匹配 JVM 覆写语义）；否则分配同一新名。
4. 通过 `ClassRemapper` 应用映射，遍历超类链解析继承成员。

**保留决策** (RetentionDecision)：
- 入口点类 (`keepPrefix`) 整体保留
- 显式 `keepMember` 指定的成员保留
- 反射扫描 (`Class.forName`、`ServiceLoader`、注解) 发现的目标保留
- SPI/META-INF/services 引用的类保留

### 2.2 字符串常量加密

**原理**：将方法体内每个 `LDC "literal"` 替换为内联构造 `byte[]` + 调用 `KBoxRuntime.d()` (XOR, 强度1) 或 `KBoxRuntime.a()` (AES, 强度2)。明文 String 不再出现在常量池。

**强度1 — 滚动 XOR**：
- 布局：`4字节key + 密文`
- 密钥调度：`k = (key >>> shift) ^ (key << (32-shift) >>> 0)`，shift = `(i*7) % 32`
- 抵御简单 XOR 分析

**强度2 — AES/CBC**：
- 布局：`4字节key + 16字节IV + 密文`
- 密钥派生：SHA-256(int) 取前16字节 = AES-128 key
- 运行时通过 `javax.crypto.Cipher` 解密

**安全性**：
- 注解字符串值位于属性而非方法字节码，永不被触碰
- 反射目标字符串解密后经 `intern()` 保持 `==` 与 switch-on-String 语义
- `KBoxRuntime` 类在打包时原样注入（不重命名、不变换）

### 2.3 控制流混淆

两种互补技术，均在 `COMPUTE_FRAMES` 下安全：

**① 不透明谓词 (Opaque Predicates)**：
- 插入 `if (t*(t+1) % 2 != 0) goto bogus`，谓词恒假（两连续整数之积恒为偶）
- bogus 分支为死代码，执行合理算术以迷惑反编译器
- 对所有方法（含 `<init>`/`<clinit>`）安全

**② 控制流平坦化 (Flattening)**：
- 将方法体重写为 `switch(state)` 驱动的状态机，原始块顺序被破坏
- **准入条件**：
  - 无 try/catch handler
  - 每个分支目标操作数栈为空（经 ASM BasicVerifier 验证）
  - 至少2条分支
  - 无 TABLESWITCH/LOOKUPSWITCH
- 不满足时透明回退至仅不透明谓词，构建永不断裂
- strength≥2 时打乱 case id 顺序

### 2.4 JNIC 本地化

**原理**：将 Java 方法翻译为 C 代码，编译为本地库 (.dll/.so/.dylib)，原方法标记为 `native`。

**流程**：
1. `JniCTranslator` 将字节码翻译为 C 函数，按 JNI 命名规范生成符号
2. `NativeCompiler` 调用 GCC/Clang/MSVC 编译为共享库
3. 原方法体替换为 `native` 声明
4. 编译失败的方法静默回退至混淆管线

**配置**：
- `nativeMethods`：指定本地化的方法 (`owner#name#desc`)
- `cc`：C 编译器路径
- `failOnNativeError`：false（默认）时本地化失败回退至混淆

### 2.5 VMP 虚拟机解释器

**原理**：将 Java 方法翻译为自定义字节码 (`VmpOp`)，运行时由 `VmpInterpreter` 解释执行。

**虚拟指令集**：
- 单字节操作码，操作数以内联小端定宽字段存储
- 覆盖：常量/加载、算术、比较/分支、栈操作、字段访问、方法调用、类型/new、同步/异常、返回
- 不支持 `invokedynamic`（此类方法保留原字节码）

**注入机制**：
1. `VmpTranslator` 将方法翻译为 `byte[]` 程序 + 常量池规格
2. 程序存入 `static byte[] $vmp_<n>` 字段，常量池存入 `Object[] $vmpcp_<n>`
3. `<clinit>` 中构造 `VmpMethod` 对象并缓存
4. 原方法体替换为：加载 VmpMethod + 装箱参数 → 调用 `VmpInterpreter.execute()` → 拆箱返回

**解释器特性**：
- 操作数栈为 `Object[]`，基本类型自动装箱/拆箱（慢但正确）
- 常量池惰性解析并缓存 Class/Field/Method/String 引用
- 异常表处理 `ATHROW`/抛出异常
- 纯 Java 实现，兼容 JVM 8..21，不依赖 `sun.misc.Unsafe`

---

## 3. 运行时类注入

保护后的 jar 需要以下运行时类（由 `Packager` 从 kbox-core classpath 注入，原样不重命名）：

| 运行时类 | 触发条件 | 用途 |
|----------|----------|------|
| `com.kbox.runtime.KBoxRuntime` | `encryptStrings = true` | 字符串解密 (XOR/AES) |
| `com.kbox.runtime.VmpInterpreter` | `enableVmp = true` | VMP 解释器 |
| `com.kbox.runtime.VmpInterpreter$VmpMethod` | `enableVmp = true` | VMP 方法容器 |

注入逻辑位于 [Packager.injectRuntimeClasses()](../kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)，通过 `ClassLoader.getResourceAsStream()` 加载类文件字节，写入受保护 jar 的 `BOOT-INF/classes/`（Spring Boot）或根路径（普通 jar）。

---

## 4. 配置参考

### 4.1 配置文件格式 (kbox.conf)

```properties
# 混淆开关
renameIdentifiers = true
encryptStrings = true
obfuscateControlFlow = true
encryptClasses = false
enableVmp = false
enableJnic = false

# 强度 (1=light, 2=medium, 3=aggressive)
controlFlowStrength = 2
stringEncryptionStrength = 1     # 1=XOR, 2=AES

# 保留规则
keepPrefix = com.example.Main    # 保留入口类前缀
keepMember = com.example.Api#method(Ljava/lang/String;)V

# 本地化方法
nativeMethods = com.example.Secure#encrypt([B)[B
vmpMethods = com.example.Algo#compute(I)I

# 编译器
cc = C:/msys64/mingw64/bin/gcc.exe
failOnNativeError = false
```

### 4.2 命令行用法

```bash
java -jar kbox-protector.jar \
  --input app.jar \
  --output protected/app.jar \
  --config kbox.conf \
  [--verbose] [--gui]
```

### 4.3 Maven 插件用法

```xml
<plugin>
  <groupId>com.kbox</groupId>
  <artifactId>kbox-maven-plugin</artifactId>
  <version>1.0.0</version>
  <executions>
    <execution>
      <goals><goal>protect</goal></goals>
      <configuration>
        <input>${project.build.finalName}.jar</input>
        <output>${project.build.directory}/protected.jar</output>
        <config>kbox.conf</config>
      </configuration>
    </execution>
  </executions>
</plugin>
```

---

## 5. 验证结果

### 5.1 测试应用

测试应用 ([kbox-testapp](../kbox-testapp)) 覆盖：
- 普通 Java 对象创建与方法调用 (Greeter)
- 基本类型返回值方法 (License.check)
- ServiceLoader (强制 META-INF/services 保留)
- 字符串拼接 (验证字符串加密共存)

### 5.2 保护配置

```properties
renameIdentifiers = true
encryptStrings = true
obfuscateControlFlow = true
controlFlowStrength = 2
stringEncryptionStrength = 1
keepPrefix = com.kbox.testapp.Main
keepMember = com.kbox.testapp.Greeter#greet(Ljava/lang/String;)Ljava/lang/String;
```

### 5.3 保护输出

```
[INFO] analysis  - Loaded 3 classes, 3 resources
[INFO] reflect   - Keep-set size after reflection scan: 3
[INFO] controlflow - Inserted 8 opaque predicates, flattened 0 methods, skipped 4
[INFO] strings   - Encrypted 14 string literals (mode=XOR)
[INFO] names     - Renamed 2 classes, 3 methods, 0 fields
[INFO] package   - Injected 1 runtime classes
```

### 5.4 运行验证

| | 原始 jar | 受保护 jar |
|---|----------|------------|
| 输出 | `Hello, KBox!` / `License check: INVALID` / `Test app OK` | 完全一致 |
| 退出码 | 0 | 0 |

受保护 jar 内容：
```
com/kbox/testapp/Main.class          ← 保留 (入口点)
com/kbox/testapp/a.class             ← Greeter (重命名)
com/kbox/testapp/b.class             ← License (重命名)
com/kbox/runtime/KBoxRuntime.class   ← 注入运行时
META-INF/services/com.kbox.testapp.Main
META-INF/MANIFEST.MF
```

**结论**：受保护 jar 与原始 jar 功能等价，混淆（重命名 + 字符串加密 + 控制流）已正确应用且不破坏运行时语义。

---

## 6. Spring Boot Fat Jar 支持

Packager 自动检测 `BOOT-INF/classes` + `BOOT-INF/lib` 布局：
- 受保护类写入 `BOOT-INF/classes/`（重命名路径）
- `BOOT-INF/lib/*.jar` 依赖原样复制
- `org.springframework.boot.loader.*` 启动器类原样复制
- 运行时类注入到 `BOOT-INF/classes/com/kbox/runtime/`
- 资源引用 (spring.factories 等) 经 `ResourceReferenceUpdater` 更新类名

---

## 7. 安全性与回退保证

| 场景 | 行为 |
|------|------|
| 控制流平坦化不满足准入 | 回退至仅不透明谓词 |
| VMP 翻译不支持的操作码 | 保留原字节码，仅混淆 |
| JNIC 编译失败 | 回退至混淆管线 (`failOnNativeError=false`) |
| 任一类变换异常 | 该类保留原字节码，日志告警 |
| `COMPUTE_FRAMES` | 所有变换后由 ASM 重算栈帧，保证字节码合法 |
