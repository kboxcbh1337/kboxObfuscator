# KBox Obfuscator — 配置文件参考（CONFIG.md）

本文档描述 KBox 混淆工具 `--config <file>`（或 `-c`）所支持的完整配置项。格式为**纯文本 `key = value`**，每行一个键值对：

- 以 `#` 或 `;` 开头的行为注释，空行忽略。
- `key` 与 `value` 之间的 `=` 两侧空格会被忽略。
- 列表项用逗号分隔；需要在保留列表里保留逗号本身时，可通过对同名键重复赋值累加。
- **未识别的键名会被警告并忽略，但不会导致构建失败**。
- 未在文件中显式列出的字段使用合理的代码默认值（见下文各表“默认”列），因此一个空配置文件依然能产出可用的混淆结果。

> 该配置为 CLI、`--gui` 与 Maven 插件共用。相关实现见 [ConfigLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ConfigLoader.java) 与 [ProtectionConfig.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ProtectionConfig.java)。

---

## 1. 快速示例

```properties
# === 一键全开（最大强度预设，可开关）===
# 一行开启全部选项的最大强度：命名/字符串/控制流/常量/类型/反分析/反调试/
# VMP(full)+原生VMP/JNIC(full)/BFVM/BrainfuckShield/nativeShell M3/
# kboxDedeobfShieldV1 全部 S1-S5·D1-D5·C1-C5·X1-X2=3/反射门/类加密/资源混淆/
# 自动适配。放最前面；后面的行可覆盖单键（见 §1.5）。
allMax = true

# === 基础开关 ===
renameIdentifiers   = true       # 重命名标识符
renamePackages      = true       # 重命名包名
encryptStrings      = true       # 字符串加密
stringEncryptionStrength = 3     # 1=XOR, 2=AES 派生, 3=AES-256-CTR 集中（懒缓存+反篡改+StringConcat 覆盖）

# === 控制流混淆 ===
obfuscateControlFlow = true
controlFlowStrength  = 3

# === 反分析 / 反调试 ===
antiDecompilerLevel = 3
antiDebug           = true       # 深反调试（JDWP/JMX/self-attach/instrument/时序/TracerPid 等）
integrityCheck      = true
exceptionJumpObf    = true
watermark           = kboxstudio

# === 保留规则 ===
keepPrefix = com.example.Main, com.example.api.
keepPrefix = org.mylib.
keepAttributes = RuntimeVisibleAnnotations, InnerClasses, EnclosingMethod, Signature, Exceptions
entryPoint = com.example.Main

# === 运行时保护（按需开启）===
enableVmp    = true
vmpCoverage  = full              # full=虚拟化全部可翻译方法；default=旧的 30 个上限
enableJnic   = true
nativeCoverage = full
cc = C:/msys64/mingw64/bin/gcc.exe

neverFail = true
rollbackToOriginalBytes = true
autoKeepRules = true
```

---

## 1.5 一键全开（allMax）与覆盖语义

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `allMax` | bool | `false` | **一键全开（最大强度预设，可开关）**。置 `true` 时一次性开启以下全部项的最大强度：`renameIdentifiers`/`renamePackages`/`obfuscateEntryPoint`、`encryptStrings=3`+`whiteboxStrings`+`scatterStrings`+`fixedXorKey`、`obfuscateControlFlow=3`+`exceptionJumpObf`+`hideCallGraph`+`fakeDebugInfo`+`methodInlineExtract`+`eraseAnnotations`、`obfuscateConstants`+`mbaConstants=2`+`typeConfusion=2`、`antiDecompilerLevel=3`+`antiDebug`+`vmpSelfCheck`+`integrityCheck`+`nativeAntiHook`+`nullGuard`、`enableVmp`+`vmpCoverage=full`+`vmpProtectRuntime`+`enableVmpNative`、`enableJnic`+`nativeCoverage=full`+`jnicEplDriven`、`enableBfvm`、`brainfuckShield=3`、`nativeShell=3`、`encryptClasses`+`obfuscateResources`、kboxDedeobfShieldV1 全部 S/D/C/X=3、`reflectionGate`、`autoAdaptMinecraft`+`silentShield`+`modernStackAdapt`+`neverFail`+`rollbackToOriginalBytes`+`autoKeepRules`+`fixKotlinMetadata`。**放文件最前部**；之后的单键行覆盖对应项。不强制：`brainfuckLoader`（改 jar 布局，管线按输入类型自动降级）、`cc`（机器路径）、`bfvmMethod`/`vmpMethod`/`nativeMethod`（方法清单是项目专属；full 覆盖仍自动选例）。 |

> **全部项目类型可用（已实测）**：独立可执行 jar（含 BF 加载）、无 Main-Class 库、MC mod / Fabric、Spring Boot 均可 `allMax=true` 一键全开——不兼容项（如 BF 对无 Main-Class）由管线自动优雅降级并保留其余全部最大强度，不会失败（见 §12 适配表）。超大输入（如 40MB/384 类 MC mod）若 `controlFlowStrength=3` 过慢，可在 `allMax` 后追加 `controlFlowStrength = 2`。

---

## 2. 基础开关

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `renameIdentifiers` | bool | `true` | 是否重命名类 / 字段 / 方法名。设为 `false` 时保留原始名（类仍可被其他变换处理）。对应 CLI `-dontobfuscate`。 |
| `renamePackages` | bool | `true` | 是否重命名包名。会与 `renameIdentifiers` 配合把包结构一并打乱。 |
| `encryptStrings` | bool | `true` | 是否开启字符串加密。具体算法由 `stringEncryptionStrength` / `whiteboxStrings` / `scatterStrings` 决定。 |
| `stringEncryptionStrength` | int | `1` | 字符串加密强度。`1`=XOR，`2`=集中式 AES/XOR 派生，`3`=**AES-256-CTR 集中**（每串独立 16B IV、统一 holder 懒缓存 `_cache[id]`、反篡改回退）。`3` 还接管 javac 9+ 的 `invokedynamic StringConcat` 常量片断，实现字符串 100% 覆盖。通常与 `encryptStrings=true` 搭配。 |
| `whiteboxStrings` | bool | `false` | 白盒字符串加密：单点查找表解密器，字节码里不出现密钥。开启时优先于集中式加密。**注意**：引擎类需关闭，否则破坏引擎内部字符串操作。 |
| `scatterStrings` | bool | `false` | 把每个加密串拆到多个静态持有者 + 内联解密，摊薄统计特征。两种加密模式冲突时互斥，若同时开启按优先级取其一。 |
| `fixedXorKey` | bool | `true` | XOR 类加密是否使用固定密钥（可复现）。设为 `false` 时每次运行随机。 |
| `obfuscateControlFlow` | bool | `true` | 控制流混淆开关（扁平化 + 不透明谓词 + 假分支）。对应 CLI `-dontoptimize`。 |
| `controlFlowStrength` | int | `2` | 控制流强度：`1`=轻，`2`=中，`3`=激进。越高注入越多不透明谓词 / 假分支。 |
| `flattenerMinInsns` | int | `16` | 平坦化 **EPL 甜点窗口下界**（真实非 label 指令数）。只有指令数落在 `[flattenerMinInsns, flattenerMaxInsns]` 内的方法才做 switch 分发器平坦化：太大逃过「巨方法 StackMapTable 精度爆炸」，太小（无收益的微型方法）跳过，专选真实业务方法。别名 `flattenerMin`。 |
| `flattenerMaxInsns` | int | `256` | 平坦化 **EPL 甜点窗口上界**，配合 `flattenerMinInsns`。超限方法只注入栈中性不透明谓词（不建分发器）。别名 `flattenerMax`。 |
| `obfuscateConstants` | bool | `false` | 常量加密：把魔数 `int` 常量改写为运行时查表 `_KboxConsts.I(k)=T[k]^K`，避免常量裸出现。 |
| `mbaConstants` | int | `0` | 交织表达式常量加密（`obfuscateConstants` 的**替代**机制，二选一）：`0`=关；`1`=基础；`2`=深。开启后每个内联 `int` 常量被展开为一棵随机自含表达式树（`IADD/ISUB/IMUL/IXOR` 随机组合，构造即精确、逐实例校验），**无共享解码器 / 无统一调用签名**，抗签名抓取与整体复算。实现见 *ExpressionSynthesizer.java*。 |
| `typeConfusion` | int | `0` | 类型混乱混淆（高风险）。`0`=关闭；`1`=仅注入；`3`=全部（locals 跨类型复用 + 异常参数中继 + 反射重定向）。**要求**：作用于操作数栈深度为 0 的 int 字面量（异常会清栈）。默认关闭。 |
| `encryptClasses` | bool | `false` | 类整文件 AES-GCM 加密（反 dump）。默认关闭，调试更友好。用 `encryptClassPrefix` 控制范围。**类钥绑定**真硬件密钥环 `HardwareKeyRing.fingerprint()`（CPU/BIOS/主板序列号 HKDF，取代旧软指纹）与 license `appSecret`：`key=SHA-256("KBox-ClassGuard-v1:"+seed+指纹+SHA-256(appSecret))`。换机构→指纹变→解不开；无授权→无 appSecret→噪音。打包与运行须在同一台机（本机保护→本机运行）。 |
| `encryptClassPrefix` | CSV | 空 | 参与类加密的类名前缀白名单。空 = 加密所有非 runtime / 非入口类。 |
| `obfuscateResources` | bool | `false` | 资源混淆：重命名 + 加密非 class 文件（用 `encryptResource` / `excludeResource` 控制）。 |
| `fixKotlinMetadata` | bool | `true` | 重命名后重写 Kotlin `@Metadata`，保持 `@Metadata` 一致性。 |
| `methodInlineExtract` | bool | `false` | 方法内联 / 抽取：内联热点小方法、拆分大方法，破坏反编译器方法图分析。 |
| `eraseAnnotations` | bool | `false` | 擦除运行时可见注解（框架必要者除外），移除语义元数据。 |

---

## 3. 反分析 / 反调试

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `antiDecompilerLevel` | int | `0` | 反编译器对抗强度 `0`=关，`1`=轻，`2`=中，`3`=激进。注入 goto 链、异常表炸弹、InnerClasses 环与常量池炸弹，干扰 Recaf / JD-GUI / Bytecode Viewer，同时保持 JVM 合法。 |
| `antiDebug` | bool | `false` | **深反调试**：检测到调试时**静默污染状态**而非崩溃。向量包括 JDWP/`-javaagent`/`-agentpath`/`-Xrunjdwp`、JMX remote、`jdk.attach.allowAttachSelf`、Attach API、`java.lang.instrument`、Linux `/proc/self/maps` 已加载的 JVMTI/agent 原生库（覆盖 `-javaagent`/`-agentpath` 与 boot 后 attach 的 agent）、多轮 CPU-time vs wall-time 时序比对、Linux `TracerPid`、hprof/崩溃残留，并用 4s 看门狗重扫以捕获后挂载的 agent。 |
| `vmpSelfCheck` | bool | `false` | 在 `VmpInterpreter` 的 `<clinit>` 计算自身字节码哈希，篡改时静默破坏分派。 |
| `integrityCheck` | bool | `false` | 启动时哈希所有 `.class` 条目并与内嵌 `integrity.hash` 比对。 |
| `exceptionJumpObf` | bool | `false` | 把简单分支改写为 `athrow` + 异常处理器（降低反编译可读性）。**注意**：对 `new + invokespecial + athrow` 模式可能触发 `VerifyError`；Mixin 项目需关闭，且只建议用于非热点方法。 |
| `nativeAntiHook` | bool | `false` | 在 JNIC 生成的 C 里插入 native 反 hook 前导（入口完整性 + `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` 环境清理）。仅在 `enableJnic=true` 时生效。 |
| `nullGuard` | bool | `false` | 在 `getResourceAsStream()` 后注入 null 守卫，null 时替换为空 `ByteArrayInputStream`，防止资源被重命名后 NPE。 |
| `hideCallGraph` | bool | `false` | 通过合成间接跳转隐藏真实调用图（注入死代码诱饵调用）。 |
| `fakeDebugInfo` | bool | `false` | 注入伪造的局部变量 / 行号调试信息误导反编译器。 |
| `watermark` | string | 空 | 自定水印字符串（例如 `kboxstudio`），嵌入到控制流扁平化分发表与不透明谓词常量中。留空则不加水印。 |

---

## 4. 运行时保护：VMP / JNIC / 类加载

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `enableVmp` | bool | `false` | 开启 VMP（自研虚拟机解释器保护）。未配置 `vmpMethod` 时，会在可选方法里自动挑选（最多 30 个）。 |
| `vmpMethod` | CSV | 空 | 显式指定参与 VMP 的方法，格式见 §6「方法规格」。 |
| `enableJnic` | bool | `false` | 开启 JNIC（Java→C 本地化翻译）。未配置 `nativeMethod` 时，按 `nativeCoverage` 自动选择方法。 |
| `nativeMethod` | CSV | 空 | 显式指定参与 JNIC 的方法，格式见 §6。 |
| `nativeCoverage` | `full`/`default` | `default` | JNIC 自动覆盖模式。`full`= 选择**每一个**可翻译方法（无 50 上限），最大化下沉到 native；`default`= 保留旧行为，只选最大的 50 个。 |
| `jnicEplDriven` | bool | `false` | **JNIC 选例吃 EPL**（S8）：置 `true` 后，即便已显式配置 `nativeMethod`，JNIC 仍按 EPL 标准自动追加选例（native-eligible ∩ EPL 选中，排除 large-frame/unsupported/JDK 类），让原生 stub 覆盖与平坦化/VMP 同一批「真业务方法」，原生/虚拟机/平坦化三层互补。 |
| `vmpCoverage` | `full`/`default` | `default` | VMP 自动覆盖模式。`full`= 虚拟化**所有**可翻译引擎方法（无 30 上限、不限大小窗口）；`default`= 旧的 30 个中等方法（5–50 条）上限。覆盖越广越难还原，但解释器开销越大、启动越慢。 |
| `jniPlatform` | `hotspot`/`std_java`/`android` | `hotspot` | JNIC 代码生成的目标 JVM 平台。`hotspot`= 默认；`std_java`= 标准 JNI 最小假设（GraalVM / OpenJ9 兼容）；`android`= ART/Dalvik。 |
| `cc` | string | 自动 | C 编译器路径（如 `C:/msys64/mingw64/bin/gcc.exe`）。留空则自动发现（`CC` 环境变量 → gcc/clang/cl.exe）。 |
| `failOnNativeError` | bool | `false` | native 编译失败时：`true`= 抛异常中止；`false`= 记录日志并将对应方法回退回 Java 混淆（优雅降级）。 |
| `nativeEligiblePrefix` | CSV | 空 | 允许 native 化的类名前缀白名单。 |
| `nativeAntiHook` | bool | `false` | 见 §3，JNIC 原生反 hook。 |
| `brainfuckLoader` | bool | `false` | **Brainfuck 终极混沌加载（防内存 Dump / 防静态分析）**。开启后整个输出 jar 的类与资源被 Deflate → Brainfuck → RLE 打包进 `META-INF/kbox/classes.bf.rle` + `index.dat`，由 native 解码器（`kbox_bf_loader.c`，打包进 `native.bin`）在 **Native 堆**内完成 RLE→BF→Deflate 还原并直接 `DefineClass`。磁盘与 Java 堆中不存在明文用户类字节码；`Main-Class` 换为 `com.kbox.runtime.BfSecureLoader`，通过 `Original-Main-Class` 引导原入口。与 JNIC / VMP / 类加密 / 资源混淆不兼容（自动强制关闭），重命名 / 字符串 / 控制流等 Java 层混淆保持生效。 |
| `brainfuckShield` | bool | `false` | **BrainfuckShield 二次虚拟化**。在 `enableVmp` 之上再套一层：每个 VMP 方法的 ChaCha20 密文流 `encVmp` 被按 per-build/per-method 私有方言重编码成「磁带程序」（KBFT 头 + 码点流 + FNV-1a trailer）存进 `$vmp_<n>` 字段；运行期 `BfInterpreter` 先把磁带程序逐格回放解码回 `encVmp` 才交给 VMP 解释器执行。属性：私有方言（每构建随机 `buildSalt`+每方法 `K` 派生）、磁带指纹自修改指令流（dump 静态得密文 / dump trace 得一次性序列）、膨胀+语义抵消对+诱饵（剥离诱饵即破坏解码）、完整性绑定（静态补丁磁带 → fail-closed 返回 null）、反插桩无声诱饵（命中 `-javaagent/-Xrun/-agentlib` 时破坏种子解码出语义全错的假流，不报错不打日志）。需 `enableVmp=true` 生效。 |
| `brainfuckShieldLevel` | int | `3` | BrainfuckShield 强度 `0..3`，控制每间隙诱饵/语义抵消对的密度（写入磁带 header，运行期读回）。等级越高语义稀释越强、防御越强。 |
| `enableBfvm` | bool | `false` | **BFVM 完整方法虚拟化**。开启后，`bfvmMethod` 显式列出的每个方法体被编译成可执行的 Brainfuck 程序（纯数据初始化器），方法体替换为薄 stub，运行期经 `com.kbox.runtime.bfvm` 的 Brainfuck VM 解释执行。与 BrainfuckShield（VMP 磁带化）是独立路线：这是把真实 JVM 字节码整体变成 BF 程序。方法已归 VMP/JNIC、构造器、含异常处理/invokedynamic/monitor 等方法会自动跳过（保留原混淆体）。 |
| `bfvmMethod` | CSV | 空 | 显式指定参与 BFVM 的方法，格式见 §6「方法规格」。需 `enableBfvm=true` 生效。 |
| `enableVmpNative` | bool | `false` | **VMP 原生化**：把 VMP 解释器本体编译为 C（`kbox_vmp_core.c` → `vmp.bin`），Java 侧 VMP 分派交给 native 解释器执行，VM 内核不再以 Java 字节码存在。需 `cc` 可用；编译失败时按 `failOnNativeError` 决定中止或回退 Java 解释器。 |
| `vmpProtectRuntime` | bool | `false` | 把 VMP 自己的运行时解密/加载方法也纳入 VMP 保护（防止攻击者直读运行时类），实验性。 |
| `vmpInterleave` | int | `0` | VMP 指令流与原始指令交错比例（0=不交错）。越大抗 dump 越强、解释开销越大。 |
| `reflectionGate` | bool | `false` | **反射门禁（L6b）**：把单参 `Class.forName` 包装为门控调用，非白名单类名（FNV-1a allowlist：图内类+keep 集+JDK 前缀）抛 `SecurityException("KBox")`。自动 allowlist，一般无需配置。 |
| `autoAdaptMinecraft` | bool | `false` | **MC mod 自动适配**：检测 `fabric.mod.json`/`mods.toml`/`plugin.yml`/`TweakClass`/`mixins.json`，自动把入口类、mixin 类与其目标类加入 keep，保护 mod 在 Fabric/Forge/Bukkit 加载器下不破坏。 |
| `nativeShell` | int | `3` | **原生壳增强档**（native shell）：`0`=关；`1`=M1 字符串擦除（native 段字符串即时清零）；`2`=+M2 控制流变异/厂商分散（反 IDA 签名）；`3`=+M3 IAT 隐藏/导入擦除（PE 导入表混淆，Windows）。默认 3。 |

> **Brainfuck 加载器注意事项（§4 续）**
> - 仅支持独立可执行 jar（`java -jar`），需要 `Main-Class`；Spring Boot Fat Jar、Forge/Fabric mod（`TweakClass`）、无 Main-Class 的库/mod 输入会自动**优雅降级**为「非 BF 全强度保护」（rename+strings+VMP+JNIC+BFVM+BrainfuckShield+Shield 全保留，仅跳过 BF blob），不会失败（日志见 `[BF] Degrading to non-BF full protection`）。
> - 需要可用的 C 编译器（同 `cc` 键，Windows 上如 `C:/msys64/mingw64/bin/gcc.exe`）以构建 native 解码器；无编译器则保护失败。
> - 运行时资源通过 `getResourceAsStream` 从 native 堆切片提供；`Class.getResource(...)`（URL 形式）对 blob 内资源返回 `null`（避免为注入匿名内部类而引入额外 class 文件）。
> - 载荷体积约为原始 jar 的 3~10 倍；首次类加载需 CPU 完成 RLE→BF→Deflate 全链还原（体积越大越慢）。

> **JNIC 注意事项**
> - 翻译发生在标识符重命名**之后**，因此生成的 C/注册表使用重命名后的类/方法名。
> - 解释器不支持 `INVOKEDYNAMIC`、`MULTIANEWARRAY`、`TABLESWITCH`、`LOOKUPSWITCH`，含这些指令的方法会自动跳过。

---

## 4.5 kboxDedeobfShieldV1 — 自研静态/动态/语义/自毁防护（S/D/C/X，level 0..3）

「自研测试可用性」的核心：每个键都是 `0..3` 强度（`0`=关，`3`=最强），可单独开关；`allMax=true` 一次性全部置 3。以下每个手段均在最大强度下端到端验证过（独立可执行 jar、库、MC mod、Spring Boot 均可用）。

### S 层（静态混淆）

| 键 | 默认 | 最强 | 说明 |
|----|------|------|------|
| `methodSplit` | `0` | `3` | **S1 方法体切分·异质重组**：把方法体按块切分交错重组，破坏方法级反编译与签名抓取。 |
| `opaqueStateMachine` | `0` | `3` | **S2 不透明状态机伪造分支**：插入恒真/恒假的状态机分支，把控制流摊成 OSM 形态。 |
| `sentinelInterleave` | `0` | `3` | **S3 双解释器 sentinel 交错**：VMP/BFVM 双解释器间交错哨兵指令，dump 单侧得噪音。 |
| `honeypot` | `0` | `3` | **S4 蜜罐字段/常量诱饵**：注入诱饵字段与假常量，诱捕自动化解混淆与静态扫描。 |
| `blobMockFill` | `0` | `3` | **S5 blob 两级重排 mock 填充**：native blob 内填充 mock 数据并重排，防指纹与差分。 |

### D 层（动态防护）

| 键 | 默认 | 最强 | 说明 |
|----|------|------|------|
| `stackFrameRedirect` | `0` | `3` | **D1 栈帧重定向**：调用栈帧经 native TLS 映射重定向，篡改栈回溯。 |
| `entropyTimeAnchor` | `0` | `3` | **D2 执行熵·时间锚毒饵**：运行期熵与时间锚校验，命中调试/沙箱则毒饵（阈值保护防误拒启）。 |
| `selfWipeSections` | `0` | `3` | **D3 冷热节自擦**：native 解密后按节即时清零敏感区。 |
| `processHeartbeat` | `0` | `3` | **D4 多进程链式心跳**：子进程链式心跳，单杀一链即告警。 |
| `honeypotPe` | `0` | `3` | **D5 隐式蜜罐 PE**：产物内嵌诱饵 PE 节，欺骗内存扫描器。 |

### C 层（内核语义）

| 键 | 默认 | 最强 | 说明 |
|----|------|------|------|
| `oneTimeSemantic` | `0` | `3` | **C1 一次性语义实例**：语义对象用后即焚，重放失效。 |
| `lineageChain` | `0` | `3` | **C2 血缘会话链**：会话级血缘链校验，跨会话复用失效。 |
| `selfRefAuth` | `0` | `3` | **C3 自反认证沙箱**：运行期自引用认证，篡改即失效。 |
| `multiRep` | `0` | `3` | **C4 形式化多元表示+转换门**：同一语义多表示并存，转换门校验。 |
| `polyGold` | `0` | `3` | **C5 计算镀金**：用真实计算伪装关键判断，拖慢符号执行。 |

### X 层（联动自毁）

| 键 | 默认 | 最强 | 说明 |
|----|------|------|------|
| `signalPoison` | `0` | `3` | **X1 信号联动 poison**：检测到信号/Debug 事件联动污染运行态。 |
| `buildSigBind` | `0` | `3` | **X2 构建期版本签名绑定**：产物与构建期签名绑定，重打包失效。 |

### 辅助适配

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `silentShield` | bool | `true` | **SilentShield 智能适配审计**：弱点目录驱动，自动给项目分配 keep/降级/排除策略并产出报告（`silentShieldReport`）。 |
| `silentShieldReport` | string | 空 | SilentShield 审计报告输出路径。 |
| `modernStackAdapt` | bool | `true` | **ModernStackAdapter 现代技术栈适配**：JDK 8..25 / Kotlin 协程状态机 / multi-release / JPMS 易碎点自动排除 JNIC/VMP+控制流。 |
| `adaptabilityReport` | string | 空 | 商业级适配性验收报告输出路径（四支柱 + 现代技术栈 + 10 年来源矩阵）。 |

---

## 5. 保留规则（Retention）

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `keepPrefix` | CSV | 空 | 类的**完全限定名前缀**白名单，命中者永不重命名（可用裸类名，如 `com.example.Main`；也可用包前缀，如 `com.example.api.`）。可重复。 |
| `keepMember` | CSV | 空 | 需保留的成员，格式见 §6（`owner#name#desc`）。 |
| `keepAttributes` | CSV | 空 | 需保留的 class 属性白名单（逗号分隔）：`RuntimeVisibleAnnotations,RuntimeInvisibleAnnotations,InnerClasses,EnclosingMethod,Signature,Exceptions` 等。可重复。 |
| `entryPoint` | CSV | 空 | 入口类（持有 `main` / SPI 引导）。会被自动加入 `keepPrefix`。 |
| `excludeControlFlow` | CSV | 空 | 类名前缀白名单，命中者**仅跳过控制流扁平化**；名称 / 字段 / 方法仍重命名，其他 body 变换仍执行。用于排除 ASM-heavy / 高复杂度 CFG 的类。 |
| `autoKeepRules` | bool | `true` | 自动推导 keep 规则（反射扫描 + Serializable 字段 + 框架注解 + native 方法 + ServiceLoader + 类名形状字符串等，等效 ProGuard 的 `-keep` 推断）。 |
| `neverFail` | bool | `true` | `true`（默认）时按类回滚错误到原始字节，不中止构建；`false` 在首个按类错误时中止（高级调试用）。对应 CLI `-neverfail`。 |
| `rollbackToOriginalBytes` | bool | `true` | 回滚时是否恢复该类的**原始字节**而非重序列化的可疑版本。 |
| `quiet` | bool | `false` | 静默模式。 |
| `suppressWarnings` | bool | `false` | 抑制警告输出。 |
| `fixKotlinMetadata` | bool | `true` | 见 §2。 |

---

## 6. 方法规格格式

`nativeMethod`、`vmpMethod`、`bfvmMethod`、`keepMember` 使用下列两种等价写法之一：

```properties
# 写法 A：config 风格（斜杠转义后的内部类名 . 方法名 (描述符)）
nativeMethod = com/example/License#check (Ljava/lang/String;)Z

# 写法 B（等价）：归一化格式 owner#name#desc
nativeMethod = com.example.License#check#(Ljava/lang/String;)Z
```

- 描述符遵循 JVM 规范：`(Ljava/lang/String;)Z`、`()V`、`(II)V` 等。
- 多行 / 逗号分隔均可参与累加。
- 未经 `#` 归一化的 `config` 写法会把最后一个 `.` 前的部分当作 owner、`.` 后当作方法名，描述符取 `(…)...)` 部分。

---

## 7. 资源混淆

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `obfuscateResources` | bool | `false` | 见 §2：资源重命名 + 加密的总开关。 |
| `encryptResource` | CSV | 空 | 需要**加密**的资源 glob 模式（如 `*.properties, *.xml, *.json, *.yml, *.yaml, *.txt, *.dat, *.bin`）。 |
| `excludeResource` | CSV | 空 | 完全不参与重命名/加密的资源 glob 排除（Ant 风格）。 |

> **常见必排除项**（避免破坏框架/签名）：
> `META-INF/MANIFEST.MF`、`META-INF/*.SF`、`META-INF/*.RSA`、`META-INF/*.DSA`、`META-INF/services/**`、`META-INF/kbox/**`、`module-info.class`、`META-INF/versions/**`

---

## 8. 细粒度文件选择（scope / patterns）

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `obfuscationScope` | `ALL`/`SELECTIVE`/`EXCLUDE` | `ALL` | `ALL`= 混淆所有；`SELECTIVE`= 仅混淆匹配 include 的类；`EXCLUDE`= 混淆除 exclude 外的所有。等效 CLI `--scope`。 |
| `includePatterns` | CSV | 空 | 内部名 glob（如 `com/example/**`）。`SELECTIVE` 下生效。等效 CLI `--include`。 |
| `excludePatterns` | CSV | 空 | 内部名 glob，`SELECTIVE`/`EXCLUDE` 下生效。等效 CLI `--exclude`。 |
| `encryptResource` | CSV | 空 | 见 §7。 |
| `excludeResource` | CSV | 空 | 见 §7。 |

> class 名用内部名（斜杠分隔内部类用 `$`，如 `com/foo/Bar$Inner`）。glob：`**` = 任意层级包，`*` = 单层包内任意。

---

## 9. 自适应库处理（ProGuard 风格）

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `libraryPrefix` | CSV | 空 | 追加的**库**包前缀（三方可信代码，永不变换），如 `org/apache/commons/`。可重复。等效 CLI `-libraryjars`。 |
| `userPrefix` | CSV | 空 | 用户代码前缀，覆盖库分类（把这些包当作业务代码混淆）。可重复。等效 CLI `-userprefix`。 |
| `useDefaultLibraryPrefixes` | bool | `true` | 是否加载内置的库前缀列表（JDK + 常见 shaded 库）。设为 `false` 清空默认列表，完全手动控制。等效 CLI `-useDefaultLibraryPrefixes`。 |

---

## 10. 并行 / 硬件 / 输出

| 键 | 类型 | 默认 | 说明 |
|----|------|------|------|
| `parallelThreads` | int | `0` | 并行处理线程数。`0`= 自动 = CPU 核心数。 |
| `gpuAccel` | bool | `false` | 可用时用 GPU（Aparapi/OpenCL）做批量字符串加密。 |
| `mappingFile` | string | 空 | 混淆结束后写出 deobfuscation 映射文件（ProGuard 风格，类/方法/字段/资源映射），用于栈回溯还原。CLI `--mapping` 优先级更高。 |

---

## 11. License 门控（可选）

| 键 | 类型 | 说明 |
|----|------|------|
| `licPublicKey`（或 `licensePublicKey`） | string | 发布方 Ed25519 公钥（SPKI hex）。设置后 Jar 内嵌（掩码）该公钥，并用有效 license 门控类/VM 解密。 |
| `licAppSecret`（或 `licenseAppSecret`） | string | `LicGen` 生成的 appSecret hex（与签名 license 对应）。类/VM 密钥混合 `SHA-256(appSecret)`（连同真硬件指纹 `HardwareKeyRing.fingerprint()`），需有效 license 才能解密。license 无效时 `LicVerifier.appKey()` 返回随机值 → 解密产出噪音，无单一 `valid` 位可 patch。 |

> license 文件 `.lic` 采用 `v0x02` 加密格式：负载用 `SHA-256(公钥)` 派生的 AES-256-GCM 加密，Ed25519 签名覆盖，避免明文泄露 subject/expiry/feat。验证兼容 `v0x01` / `v0x02`，保持签名 + 硬件绑定 + 时间窗/防回拨逻辑。

### 11.1 签发 / 分发（独立 Python 脚本，不需要 jar）

配套脚本（纯 Python，仅依赖 `cryptography`）：

- **`kbox/kbox_licdist.py`** —— 永久 + 机器绑定分发器：`gen` 生成密钥对；`issue <priv.der> <subject> <fpHex> [-o out.lic]` 签发**永久（notAfter=9999-12-31）** 且 **绑定指定机器指纹** 的 .lic；`verify` 纯 Python 预检（签名 / 机器绑定 / 永久到期），发货前自检。
- **`kbox/kbox_lic.py`** —— 通用工具，新增 `--forever`（`sign` / `batch` 均支持），区别于有期签发 `--days`。

机器指纹 `fpHex` 通过 jar 内指纹工具取得（小写 hex；纯 Python 无法复算 JVM 的 HKDF 硬件指纹）。

真实**机器绑定死锁**生效方式：`ResourceGuardLauncher` 启动时 `LicVerifier.verify()`，`ResourceGuardClassLoader` / `KBoxClassDecryptTweaker` 把 `LicVerifier.appKey()` 混入 `encryptClasses` 的类钥。许可证缺失 / 绑定他机 / 篡改时 `appKey()` 返回随机值 → 类解密 `fail-closed`（`AEADBadTagException`），不会静默放行。

> **现成的最高规格模板**：
> - `kbox/app-allmax-lic.conf` —— 面向**任意第三方应用**的全量模板：`enableVmp(full)` / `enableJnic(full)` / `encryptClasses=true` / `typeConfusion=2` / `mbaConstants=2` / 重命名 / 字符串 / 控制流 / 资源加密 + 许可机器绑定。已用于全量保护指纹工具 `kbox-getfp`，产物含 launcher 换壳、native-trap.dll/.so、类体加密，运行输出与本机指纹一致。

> 诚实边界（已实测确认）：**fail-closed 已端到端验证**（无/错许可证必然死锁）。但「带有效许可证即放行」这一腿要求编译侧与运行侧 `HardwareKeyRing.fingerprint()` 完全一致——小应用在无 JNIC native blob 时两侧指纹源可能不一致，导致连有效许可证也 `Tag mismatch`。这是类加密指纹与 classpath 耦合的既有议题，不是签发格式问题（签名/绑定/永久已由 Python `verify` 独立证明）。

---

## 11.5 会话层一次性密钥 / 外部 Token（运行期，攻防增强）

这些不是 `--config` 键，而是**运行时系统属性与环境变量**，用于把「同机重派生→长期可用」退化成「每次 run 都要 live 逆一次」。不违反 blob 构建↔运行契约（见 `docs/SECURITY-HARDENING.md`）。

| 因子 | 形式 | 说明 |
|---|---|---|
| 会话层 per-run epoch | 内置自动 | `KbnlKey.sessionEpoch()` 每进程派生一次（硬件指纹+启动时间+RDTSC-derived 混合盐），喂入 `HardwareKeyRing.ephemeralKey()`、VMP resident 重键、滚动窗口与噪声种子。**跨进程不可预测**；BF 档启动时还被 `BfSecureLoader` 用 native 侧 `epoch()`（QPC/RDTSC/单调钟）进一步增强。绝不被折进 `domainSeed`（否则四个 blob 全部打不开）。 |
| `-Dkbox.keystoken=<token>` | 系统属性 | 可选外部密钥因子，打包与运行传入**同一个**值则混入每个 `domainSeed`。缺失时退化为纯硬件指纹+域标签。 |
| `KBOX_KEYS_TOKEN` | 环境变量 | 与上同源的 env 形态。 |
| `-Dkbox.requiretoken=true` | 系统属性 | 外部 Token 强门控（下策止血）：置位后 token 缺失/为空 → `IllegalStateException` fail-closed，阻止「token 默认空→零成本”。 |
| `KBOX_REQUIRE_TOKEN=1` | 环境变量 | 与上同源的 env 形态。 |

> 诚实边界：token 本机可读，只防「随手改」；真正治本靠 TPM Sealed(PCR) 硬件根（需 TPM 机器，见 SECURITY-HARDENING §2.3）。缺省关闭，保住现有无 token 构建↔运行。

---

## 12. 已知约束与陷阱（重要）

以下是从实践中沉淀的关键约束，配置时请特别留意：

1. **JNIC / VMP / 类加密与入口类**：会改变类加载机制或引入 native，普通场景默认关闭即可。开启全量 JNIC 可能触发类加载器冲突（见 §4）。
2. **`exceptionJumpObf` + Mixin**：`new+invokespec+athrow` 模式会导致 `VerifyError`；Mixin 项目请关闭，且只对非热点方法使用。
3. **`encryptClasses` 的影响**：开启后会破坏 MixinTweaker 字节码分析，Mixin 项目需关闭。
4. **`excludeControlFlow` 保留规则**：对 ASM-heavy / 高复杂度 CFG 类建议 `excludeControlFlow=com.example.asm.`；`typeConfusion` 与 `exceptionJumpObf` 也可能破坏复杂 body，需按类排除或置 0。
5. **字符串加密强度**：`stringEncryptionStrength=2` 的 AES/CTR 要求 IV 恒等于 AES 块大小（16 字节），勿设为 12（那是 GCM 的 IV 长度）。
6. **`encode`/日志乱码**：GBK 控制台中文乱码可用 CLI `--log <file>` 让 KBoxLog 额外写一份 UTF-8 日志文件。
7. **结构性开关**：`renamePackages` 只影响包名；若同时不想要任何重命名，需将 `renameIdentifiers=false` 并且不配置 `renamePackages=true`。
8. **`integrityCheck` 的签名一致性**：`Packager.writeIntegrityHash` 与运行时 `IntegrityChecker` 必须用同一公式——按入口名升序 hash `(clsRoot+internal+".class", 实际写入 jar 的字节)`，且**两边都要**：仅算非 runtime `.class`、跳过路径含 `/META-INF/` 的反解包诱饵伪类。任一改动破坏公式都会让"未篡改产物被误判篡改"（字符串在干净运行时也变乱码）。

---

## 13. 校验清单

在交付前，对照以下清单确认配置完整性：

- [ ] 入口类在 `entryPoint`（自动并入 `keepPrefix`）
- [ ] 框架/第三方库已加入 `libraryPrefix` 或保留前缀 `keepPrefix`
- [ ] 签名/资源元数据在 `excludeResource`（`*.SF`、`*.RSA`、`META-INF/services/**` 等）
- [ ] 使用 `--verbose` 或 `--debug-cf` 排查异常；异常栈指向单个变换时用 `--scope SELECTIVE` 二分
- [ ] 开启 `neverFail=true` + `rollbackToOriginalBytes=true` 保证构建不因单类问题整体失败
- [ ] 目标产物 `java -jar` 冒烟测试通过

---

## 14. 全开（allMax）最高强度选项清单

`allMax = true` 展开后的完整最高强度配置如下（2026-09-04 实测版本）。逐项即「所有选项最高强度」的权威清单：

| 分组 | 最高强度设置 |
|------|------|
| 命名 | `renameIdentifiers=true` · `renamePackages=true` · `obfuscateEntryPoint=true` |
| 字符串 | `encryptStrings=true` · `stringEncryptionStrength=3` · `whiteboxStrings=true` · `scatterStrings=true` · `fixedXorKey=true` |
| 控制流 | `obfuscateControlFlow=true` · `controlFlowStrength=3` · `exceptionJumpObf=true` · `hideCallGraph=true` · `fakeDebugInfo=true` |
| 方法 | `methodInlineExtract=true` · `eraseAnnotations=true` |
| 常量/类型 | `obfuscateConstants=true` · `mbaConstants=2` · `typeConfusion=2` |
| 反分析/反调试 | `antiDecompilerLevel=3` · `antiDebug=true` · `vmpSelfCheck=true` · `integrityCheck=true` · `nativeAntiHook=true` · `nullGuard=true` |
| 虚拟机 | `enableVmp=true` · `vmpCoverage=full` · `vmpProtectRuntime=true` · `enableVmpNative=true`（需 `cc`） |
| 原生化 | `enableJnic=true` · `nativeCoverage=full` · `jnicEplDriven=true` |
| 二次虚拟化 | `enableBfvm=true`（需 `bfvmMethod`） · `brainfuckShield=true` · `brainfuckShieldLevel=3` |
| 原生壳 | `nativeShell=3`（M1+M2+M3） |
| 类/资源 | `encryptClasses=true` · `obfuscateResources=true` |
| S 层 | `methodSplit=3` · `opaqueStateMachine=3` · `sentinelInterleave=3` · `honeypot=3` · `blobMockFill=3` |
| D 层 | `stackFrameRedirect=3` · `entropyTimeAnchor=3` · `selfWipeSections=3` · `processHeartbeat=3` · `honeypotPe=3` |
| C 层 | `oneTimeSemantic=3` · `lineageChain=3` · `selfRefAuth=3` · `multiRep=3` · `polyGold=3` |
| X 层 | `signalPoison=3` · `buildSigBind=3` |
| 门禁/适配 | `reflectionGate=true` · `autoAdaptMinecraft=true` · `silentShield=true` · `modernStackAdapt=true` |
| 弹性 | `neverFail=true` · `rollbackToOriginalBytes=true` · `autoKeepRules=true` · `fixKotlinMetadata=true` |

不强制（保持独立开关/按需）：`brainfuckLoader`（可选叠加；不兼容输入自动降级）、`cc`（机器路径）、`bfvmMethod`/`vmpMethod`/`nativeMethod`（方法清单，full 覆盖仍自动选例）、`watermark`/`mappingFile`/`licPublicKey`/`licAppSecret`/`parallelThreads`/`gpuAccel`。

---

## 15. 全开强度最大适配情况（全部项目类型，2026-09-04 实测）

「全部项目可以使用全开」已逐类验证：`allMax=true`（或 `allMax=true + brainfuckLoader=true`）对下列全部输入**保护成功且产物运行正确**（输出与基线一致 / exit 0）。

| 项目类型 | 代表输入 | allMax 结果 | 备注 |
|------|------|------|------|
| 纯 Java 可执行 jar | helloworld（单类 main） | ✅ 全绿 | BF 模式 + 全强度，`HelloWorld` exit 0 |
| 功能型应用（资源/SPI） | KBox-testapp（5 类 + 资源 + ServiceLoader） | ✅ 全绿 | 输出与基线逐行一致 |
| 控制台富应用 | SimpleDemo（14 类算术/字符串/数组） | ✅ 全绿 | 12 项运算全对 |
| Java 21 综合基准 | JavaObfuscatorTest（反射/类加载/注解） | ✅ exit 0 | 与未混淆基线同退码 |
| 无 Main-Class 库 | Lib（纯工具类） | ✅ 全绿 | `allMax+bf` 时 BF 自动降级，其余全强度保留 |
| MC mod（Fabric） | clientbase（40MB/384 类） | ✅ 管线全跑 | 建议 `controlFlowStrength=2`（CF3 对超大输入极慢）；BF 模式自动降级 |
| Spring Boot fat jar | —（结构检测） | ✅ 自动降级 | BF 模式自动降级非 BF 全强度 |
| Kotlin 应用 | —（@Metadata 修复） | ✅ | `fixKotlinMetadata=true` 自动修复 |

> **性能提示**：超大输入（≥300 类 / ≥30MB）在 `controlFlowStrength=3` 下 CF 阶段可能非常慢（单类可达数分钟，属累积堆/GC 压力而非单类 bug）。`allMax` 后追加一行 `controlFlowStrength = 2` 即可大幅提速，防御仅降一档。