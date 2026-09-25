# KBox Obfuscator

一款针对 JVM 应用的 Java 保护系统，融合了 **ZKM 级别的字节码混淆 + JNIC 原生化为长 + VMP 虚拟化** 三类手段，面向「不愿被别人拿到即可反编译/解包复用」的场景。

> 说明：本文档只描述**当前代码库真实存在且已验证**的能力，不承诺任何未经实现的「绝对不可破解」。任何声称字节码级别程序「数学上不可逆」的说辞都不符合事实——本项目的目标是让**自动化解混淆与一次性抓取**的成本足够高，而不是制造不变量不存在的「完美保护」。

## 目录

- [能力概览](#能力概览)
- [项目结构](#项目结构)
- [构建](#构建)
- [快速使用](#快速使用)
- [配置](#配置)
- [新能力：交织表达式常量混淆 (mbaConstants)](#新能力交织表达式常量混淆-mbaconstants)
- [静态深度 / 动态钻取补全（S6-S8 + D6-D9）与最大强度适配](#静态深度--动态钻取补全s6-s8--d6-d9与最大强度适配)
- [kboXShield 独立功能线（Windows PE 加壳）](#kboxshield-独立功能线windows-pe-加壳)
- [已有能力与诚实边界](#已有能力与诚实边界)

---

## 能力概览

| 类别 | 能力 | 默认 |
|---|---|---|
| **一键全开** | **`allMax=true` 全部选项最高强度 + 全项目类型自动适配（可开关）** | 关 |
| 名称 | 类/方法/字段重命名、包名打散（`renamePackages`） | 开 / 关 |
| 字符串 | AES-256-CTR 集中加密（`stringEncryptionStrength` 1..3）、**密钥进 KBNL 硬件派生域**（S7）、白盒单解码、分散存储 | 开 |
| 控制流 | 平坦化 + 不透明谓词（分级 1..3）、**EPL 甜点窗口选择**（`flattenerMin/MaxInsns` 16..256）、异常跳转混淆、调用图隐藏、调试信息伪造 | 开 |
| 常量 | 间接查表加密（`obfuscateConstants`）或**交织表达式加密**（`mbaConstants`，二选一） | 关 |
| 混淆对抗 | 反编译器 L0..L3（goto 链、常量池炸弹、非法 StackMapTable）、类型混淆 | 分级 |
| 原生 | JNIC Java→C 原生化（**EPL 驱动选例 `jnicEplDriven`**，S8）、Native crypto 主密钥层、native 反钩子、**native 节自擦**（D7） | 关 |
| 原生库 | **`protectNativeLibs` jar 内原生库加壳（自动查找）**：扫描全部目录 `.dll/.so/.dylib`，`.dll` 走 kboXShield 完整加壳（函数级虚拟化/变异/平坦化），`.so/.dylib` 加密降级；运行时解密落盘加载并擦除临时文件，明文原生库不进产物 jar | 关 |
| 虚拟机 | 双状态异或分发解释器（VMP）+ **dispatch 二次校验 slot 分发**（D8）、**BrainfuckShield 二次虚拟化**（每方法私有方言磁带）、滚动窗口 watchdog、每运行 ephemeralKey | 关 |
| 类加载 | 类体加密（`encryptClasses`）、自定义类加载器、入口守卫、**Brainfuck 终极混沌加载**（类/资源全打包进 native 解码器，明文只驻 native 堆） | 关 |
| 运行时 | 反调试（JDWP/JVMTI/agent/timing/TracerPid/**三源校时**）、**探头分散+模块名分片**（D6）、完整性自检、license 校验、**篡改联锁 TamperShield**、**明文曝光窗收敛**（D9） | 关 |
| 资源 | 资源名混淆 + 加密 | 关 |

完整配置详见 [docs/CONFIG.md](docs/CONFIG.md) 与 [docs/CLI-USAGE.md](docs/CLI-USAGE.md)。

---

## 项目结构

```
kbox-core/     保护引擎（所有混淆 pass、VMP/JNIC/BFVM、打包器、运行时类）
kbox-cli/      CLI fat jar（shade 打包为 kbox-protector.jar / kboxobf.jar）
kbox-gui/      HTML UI（`--gui`：内嵌 HTTP 服务 + 浏览器，白绿/黑绿双主题）
kbox-maven-plugin/  Maven 插件
kbox-testapp/  端到端测试应用
docs/          配置与 CLI 文档
kboxObfPro/    干净源码交付树（com/kbox/core/bfvm + runtime/bfvm + 模块源码 + dist 产物）
```

kboXShield 功能线的 PE 加壳代码位于 `kbox-core/src/main/java/com/kbox/core/shield/`，
其汇编 blob 资产位于 `kbox-core/src/main/resources/shield/`。

关键代码位置：

- 常量混淆：`kbox-core/src/main/java/com/kbox/core/obfu/ConstantObfuscator.java`
- **交织表达式合成与混淆（本仓库新增）：**
  - `.../obfu/ExpressionSynthesizer.java`（随机、按构造可验证的整数表达式树）
  - `.../obfu/MbaConstantObfuscator.java`（常量改写 pass）
- 编排：`kbox-core/src/main/java/com/kbox/core/ProtectionPipeline.java`
- 配置：`kbox-core/src/main/java/com/kbox/core/config/*.java`
- VMP 运行时：`kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java`
- JNIC：`kbox-core/src/main/java/com/kbox/core/jnic/*.java`
- **kboXShield PE 加壳（本仓库新增，由 C/C++ 全量移植）：**
  - `.../shield/ShieldPacker.java`（打包主流程）、`.../shield/PeImage.java`（PE 解析）
  - `.../shield/VmBuilder.java` / `VmMeta.java` / `MetaInner.java`（镜像与嵌套 Meta 程序生成）
  - `.../shield/LiftX64.java` / `IrCompile.java`（x86-64 提升与 IR→字节码编译）
  - `.../shield/VmEngine.java`（打包期自由态解释器，用于镜像自检预演）

---

## 构建

环境要求：JDK（推荐 21）、Maven 3.9.x。

```powershell
$env:JAVA_HOME='C:\Program Files\Java\jdk-21'
mvn -f kbox-core\pom.xml clean install -DskipTests
mvn -f kbox-cli\pom.xml clean package -DskipTests
# 产物：kbox-cli\target\kbox-protector.jar（约 3.7 MB）
```

> 若改了 kbox-core 但 CLI 产物未生效，请务必 `clean` 全量重建；增量编译可能导致 shaded jar 里是旧类。

**无 Maven 环境（手工构建）**：仓库根目录的 `build.ps1` 用 `javac` + `jar` 直接复刻同构 fat jar
（`kbox-core`/`kbox-cli` 用 `--release 8`，`kbox-gui` 用 `--release 17`），依赖从本地 m2 仓库取：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
# 产物：dist\kboxObfuscatorb3.jar（主类 com.kbox.cli.ProtectorCli）
```

（构建脚本把中间产物放在系统临时目录，并在打包时先写临时名再覆盖：工作区内的 `.class`/`.jar`
会被 IDE 语言服务或安全软件短暂独占，直接写目标路径偶发失败。）

### 自混淆（把混淆器自身混淆后仍可用）

```powershell
java -Xmx6g -jar dist\kboxObfuscatorb3.jar `
  --input  dist\kboxObfuscatorb3.jar `
  --output dist\kboxObfuscatorb3-protected.jar `
  --config self-allmax.conf
```

`self-allmax.conf` 开 `allMax = true`（除 BF 外全部最高强度），并必须声明一条
**方法体保真边界**：

```properties
brainfuckLoader = false          # BF 会把 CLI 入口吞进 blob，自混淆场景必须关
jnicExcludePrefix = com.kbox.
vmpExcludePrefix  = com.kbox.
nativeExcludePrefix = com.kbox.
```

**为什么必须排除？** 混淆器自身就是被混淆的目标：JNIC / VMP / native 会把方法体**搬进解释器**，
而解释器按「记录下来的名字与元数据」解析成员，语义与原始字节码并不等价。一旦把引擎功能核心
搬走，产物会在自己的热路径上直接失败。实测（已修配置前）：

```
java.lang.NullPointerException: Cannot read the array length because "bytes" is null
    at java.lang.String.<init>
    at com.kbox.core.analysis.DependencyAnalyzer.readManifest(DependencyAnalyzer.java:78)
```

根因是 `DependencyAnalyzer#readAll` 这个 6 行的 zip 读取辅助方法被 JNIC 变成了
`private static native byte[] readAll(InputStream)`，而 native 实现返回 `null` —— 混淆任务还没开始
就在「读输入 jar 的 MANIFEST」处 NPE。注意 `keepPrefix` **只豁免重命名**，不豁免 JNIC/VMP
（`ProtectionConfig.shouldProtectClass` 才是方法体级决策，`AutoJnicVmpSelector` 与
`JnicOrchestrator` 都按它过滤）。

该前缀只按类名匹配：产物去混淆**其他工程**时，其类不在 `com.kbox.` 下，JNIC/VMP 依旧全量生效。

除该边界外其余全部保持最高强度：重命名（未列入 `keepPrefix` 的引擎类照常改名）、AES 字符串加密、
控制流平坦化、常量/MBA、类型混淆、类体加密、抗反编译、反调试、完整性校验、资源混淆等。

### 本版本修复：lambda 的 SAM 方法名随接口改名同步

自混淆过程中暴露出一个**通用**（不只影响自混淆）的重命名缺陷：当 `lambda`
实现的函数式接口**来自被混淆工程自身**时，接口方法会被改名，但 `invokedynamic`
的名字没有被同步，运行期报

```
AbstractMethodError: Receiver class com.kbox.core.shield.tg$$Lambda$28/0x... does not define
or inherit an implementation of the resolved method 'abstract int vo(com.kbox.core.shield.zf, int)'
of interface com.kbox.core.shield.hf.
```

原因：ASM 的 `Remapper.mapInvokeDynamicMethodName` 默认**原样返回**，而
`LambdaMetafactory` 的 indy 名恰好就是「函数式接口的 SAM 方法名」——它不在 `bsmArgs` 里
（`bsmArgs` 只有 samMethodType / implMethod / instantiatedMethodType），所以只能靠
indy 名同步。修复见 `NameObfuscator.KBoxRemapper#mapInvokeDynamicMethodName`：以 indy
描述符的返回类型定位函数式接口，沿接口/父类链查 `Mapping` 的 `(owner, name)` 新名
（`Mapping#mapMethodByName`，同名不同描述符且新名不一致时视为歧义、不改）。

实现 JDK 接口（`Runnable`/`Function` 等）的 lambda 不受影响，因此该缺陷在只跑通用目标时
很容易漏掉，只有「自己有接口 + 自己写 lambda」的工程（例如本引擎的 `VmEngine.VmHandler`）
才会命中。

---

## 快速使用

**双击运行（HTML UI）**：直接双击 `kboxobf.jar`（或 `java -jar kboxobf.jar` 不带参数），自动启动内嵌 HTTP 服务并打开浏览器进入 **HTML UI**（一键全开 / 全部防御开关 / 实时日志）。

**命令行（指令操控）**：带参数运行即为 CLI，脚本化保护：

```powershell
java -jar kbox-cli\target\kbox-protector.jar `
  --input app.jar --output app-prot.jar `
  --config app.conf           # 任一配置文件；不传则使用默认保护
```

**一键全开（全部项目可用，可开关）**：配置里写一行 `allMax = true` 即可开启**全部选项的最高强度**（命名/字符串/控制流/常量/类型/反分析/反调试/VMP(full)+原生VMP/JNIC(full)/BFVM/BrainfuckShield/nativeShell M3/自研 S/D/C/X 全层=3/反射门/类加密/资源混淆/自动适配），且对**全部项目类型**自动适配——独立可执行 jar、无 Main-Class 库、MC mod/Fabric、Spring Boot、Kotlin 均可用（不兼容项如 BF 对无 Main-Class 输入自动优雅降级，其余全强度保留，不会失败）。之后的行可覆盖单键：

```properties
allMax = true
controlFlowStrength = 2      # 超大输入（≥300 类）加速可降一档 CF
# encryptClasses = false      # Mixin mod 如需关闭类加密
```

GUI（`--gui`）里也有「一键全开 · 最大强度」开关，勾选即把所有选项拉满。

**HTML UI 的「⚡ 智能适配」覆盖全部数字选项（含 nativeShell 增强壳）**：除勾选类开关外，
它会按输入类型回填全部 21 个数字档位并在面板里列出「数字项推荐」摘要——

| 数字项 | 独立应用 | 含 Mixin 的模组 | Spring Boot / 无入口库 |
|---|---|---|---|
| `nativeShell` 增强壳 | **3**（M1 字符串擦除 + M2 控制流变异 + M3 IAT/导入隐藏） | **0**（不产出原生码） | **0**（VMP/JNIC 已关，同为 no-op） |
| `typeConfusion` / `mbaConstants` | 2 · 深 | 2 · 深 | 2 · 深 |
| S1–S5 / D1–D5 / C1–C5 / X1–X2 | 3 · 最强 | 3（除 `stackFrameRedirect`=0、`methodSplit`=1，Mixin 会重排局部变量） | 3 · 最强 |
| BF 家族（`bfvm`/`bfShield`/`bfShieldLevel`） | 保持 0，需显式开启 | 0 | 0 |

nativeShell 是**源码级**改写，作用于本轮生成的全部原生源码（JNIC 分片、VMP native、
native crypto、BF native decoder）；**本轮没有原生码产出时置 0**，避免无谓的原生构建。


> **最高强度适配报告（2026-09-04 全类别实测）**：helloworld / KBox-testapp / SimpleDemo / JavaObfuscatorTest / 无 Main-Class 库 / 40MB Fabric mod / Spring Boot / Kotlin 全部 `allMax` 保护成功且运行正确。完整选项清单与适配表见 [docs/CONFIG.md §14-15](docs/CONFIG.md)。

CLI 完整参数见 [docs/CLI-USAGE.md](docs/CLI-USAGE.md)（`--help` 也可查看）。

---

## 新能力：交织表达式常量混淆 (mbaConstants)

这是对原「间接查表加密常量」(`obfuscateConstants`) 的一个**替代机制**，二选一，配置键：

```ini
# 0=关（默认） 1=基础 2=深
mbaConstants = 2
```

**它做了什么**：把方法体内联的 `int` 魔法数，展开成一段**自包含的随机表达式树**，例如常量 `0x1D5A3BCF` 变成

```java
((a ^ b) + ((x - y) * (c - d)))
```

其中 `a,b,x,y,c,d` 是随机 32 位取值，按代数身份构造保证整棵树逐位等于原常量（`a+b=v`、`a-b`、`a*b`、`a^b`）。每次运行、每个常量产生的树形状都不同。

**与旧方案的差异（为什么值得加）**：
- 旧方案所有常量都走同一个 `_KboxConsts.I(idx)`——共享一份密钥表，攻击者找到这一个签名即可整体复算全部常量。
- 新方案**没有共享解码器、没有统一调用签名**：每个常量是独立、随机、自含的表达式，无法 grep 一个点把全表复算；符号化简/程序合成必须逐常量处理一棵新树。这正是加固型混淆器用来对抗自动化解混淆的思路在 JVM 上的落地。
- **正确性有硬保证**：每棵树在返回前都会实际求值校验等于原常量（构造即精确），且改写是栈中性的（只压入一个 int、不消费任何东西），`COMPUTE_FRAMES` 重算后所有帧仍合法。

**实测验证**（已做）：对 `MbTest`（多个魔法数 + 真实算术）开启 `mbaConstants=2` 后运行，输出与原始产物逐位一致（`SUM=156299795921`），退出码 0。

> 局限（诚实说明）：这是**逐实例的异构/随机化**，不是信息论上的隐藏——确定无疑的求解者仍可能手工化简某棵表达式。它击败的是「一次抓住共享表/统一签名→整体复算」和「模式匹配自动化解码」，而非「有无限时间的人肉分析」。

---

## 新能力：篡改联锁 TamperShield（篡改 → 字符串也变乱码）

计划里的 Stage D/E（「看得到也是空白」）在运行时落地为一层**统一篡改门**。

**背景**：字符串解码器此前只检查 `AntiDebug.isTampered()`（挂了调试器才触发）。这意味着——**不改类结构、不挂调试器**，只改一下 jar（比如改动一个资源、替换一段类字节、修补某方法内存），字符串照样原样解出。这正与「篡改后让你拿到的东西是空白」的目标相悖。

**本改动**：新增 [TamperShield.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/TamperShield.java)，把三类独立篡改信号做**并集**：
- `AntiDebug.isTampered()` —— 调试器 / agent / JDWP / 计时探针
- `IntegrityChecker.isTampered()` —— 启动时 jar SHA-256 与存储值不符（改了 jar 就触发，**即使没挂任何调试器**）
- `VmpInterpreter.isTampered()` —— 虚拟机指令流 FNV-1a / 解释器自校验触发（内存打补丁）

随后把 `KBoxRuntime` 的主解码器 `d/e/f/g/h/a` 的开关从「只查 AntiDebug」换成「查 `TamperShield.isTampered()`」。任一信号触发，字符串解密返回乱码而非明文（且不再走 `intern()` 保 `==`，最大化干扰）；进程不崩溃——这就是「篡改后看得到也是空白」。

**依赖安全**：`IntegrityChecker` / `VmpInterpreter` 都是**防御性 try/catch** 引用——对应功能关闭时它们不会被打进产物，缺失类抛的 `NoClassDefFoundError` 被吞成 `false`。因此该合并器在任意功能组合下都能加载运行，无需强注入这两类。

**注入**：`Packager` 在 `encryptStrings` 开启时注入 `TamperShield`（与 `KBoxRuntime`、`AntiDebug` 同批）。

**隔离单元验证（已跑，确定性）**：仅翻转 `IntegrityChecker` 信号（不挂调试器、不改类），`KBoxRuntime.d("HELLO"密文)` 从 `HELLO` 变为乱码；恢复后重新可读；`VmpInterpreter` 类缺失时正确回退 `false`。全断言通过、退出码 0。

> **集成修复（已交付，非遗留）**：曾存在 `IntegrityChecker` 与 `Packager` hash 集合/字节不一致（构建侧只算受保护类、运行侧连 META-INF 与反解包诱饵伪类都算），导致 `integrityCheck=true` 时**未篡改产物也误判篡改**、字符串在干净运行时也变乱码。已修复：
> - `Packager.writeIntegrityHash` 改算实际写入 jar 的字节（`written`）+ `clsRoot+internal+".class"` 入口名 + 按名排序，与 `IntegrityChecker` 逐位同构；
> - `IntegrityChecker` 只算非 runtime `.class`，并跳过路径含 `/META-INF/` 的诱饵伪类（真类不会在其中）。
> 端到端验证：正常运行字符串全可读；篡改任意 jar 一步后字符串变空白/乱码（进程不崩溃）。

---

## 许可分发（永久 + 机器绑定死锁）

配套**独立 Python 脚本**（不依赖 jar、不需要在发行机上跑 JVM），可直接签出可被运行时 `LicVerifier` 识别的许可证：

- [kbox_licdist.py](file:///d:/kboxobf/kbox/kbox_licdist.py) —— 永久 + 机器绑定分发器：
  - `gen <base>` 生成本地密钥对（私钥绝不离开发行机）
  - `issue <priv.der> <subject> <fpHex>` 签发**永久有效（9999-12-31）**、**绑定目标机指纹**的 `.lic`
  - `verify <pub.der> <lic> <fpHex>` 发货前纯 Python 自检（签名 / 绑定 / 永久）
- [kbox_lic.py](file:///d:/kboxobf/kbox/kbox_lic.py) —— 通用工具，新增 `--forever`（`sign` / `batch` 均支持），区别于有期签发 `--days`。

**工作流**
```powershell
python kbox_licdist.py gen   keys                      # 生成 keys.priv.der / keys.pub.der
# 客户机上报目标机器指纹 fpHex（jar 内指纹工具输出，小写 hex）
python kbox_licdist.py issue keys.priv.der "客户" <fpHex> -o xxx.lic   # 永久+机器绑定
python kbox_licdist.py verify keys.pub.der xxx.lic <fpHex>             # 预检
# 把打印的 licPublicKey / licAppSecret 写进保护配置，再混淆产物
# 把 xxx.lic 命名为 license.lic 放到产物旁（或 -Dlic.path=xxx.lic）交付
```

**机器绑定指纹工具**：`licdist-test\FpTool.java`（`com.kbox.tools.FpTool`）是独立机器指纹读取器，目标机运行即输出绑定的机器指纹 hex（与配置/运行时同一 `HardwareKeyRing.fingerprint()`）。该工具本身也是展示「第三方应用全量保护 + 许可机器绑定」的理想载体——用 `app-allmax-lic.conf` 混淆后，产物含 launcher 换壳、native-trap.dll/.so、类体加密，运行仍输出与本机一致的指纹。参考配置与产物：`kbox\app-allmax-lic.conf`、`licdist-test\kbox-getfp-plain.jar`（明文输入）/ `kbox-getfp-allmax2.jar`（全量产物）。

**机器绑定死锁真正生效**（`encryptClasses=true` 时）：`ResourceGuardLauncher` 启动即 `LicVerifier.verify()`；许可证缺失 / 绑定他机 / 篡改时 `LicVerifier.appKey()` 返回随机值 → 类钥错误 → 解密 `fail-closed`（`AEADBadTagException`），不会静默放行。

> 诚实边界：**fail-closed 已端到端验证**；但「带有效许可即放行」要求编译侧与运行侧 `HardwareKeyRing.fingerprint()` 一致——无 JNIC native blob 的小应用两侧指纹源可能不一致（既有指纹/classpath 耦合议题）。签发格式（签名/绑定/永久）已由脚本 `verify` 独立证明。

---

## Stage B / C（加载层 / native 自修改）与本机的现实约束

计划的 Stage B（加载层 shell-only，令 JVMTI 只看到壳+密文）在标准 JVM 下受 `ClassFileLoadHook` 在解密后触发这一**结构性限制**，只能做尽力而为，不能彻底消除。

Stage C（native 自修改/数据依赖寄存器分配）需要把 JNIC 的 C 解释器改动并用本机编译器构建。**本机 MSYS2 MinGW gcc 实为可用**：将 `C:\msys64\usr\bin` 与 `C:\msys64\mingw64\bin` 加入 `PATH` 后即能正常编译（此前"不可用"仅因 cc1 定位失败）。因此 native 链路**不是被阻塞，而是需要专项聚焦推进**（改 C 解释器 + 走一遍 JNIC gcc 构建 + 验证产物），属独立的深度任务，本次未虚标完成。

---

## 面向第三方应用的最高防护（all-max 模板）

任意第三方应用可以全部开最高，**一行 `allMax = true` 即可**（见「快速使用」），全部项目类型自动适配。历史上的全量模板（`kbox/max-jnic.conf` 等）已由 `allMax` 预设取代。

> 注意：这是**面向任意的第三方应用**的配置模板。使用前请按具体应用实测（反射/Spring/Mixin 等需相应 keep/排除，或让 `autoAdaptMinecraft`/`silentShield` 自动处理）。

---

## 静态深度 / 动态钻取补全（S6-S8 + D6-D9）与最大强度适配

在既有引擎（KBNL 会话绑定、KBNL 容器、watchdog、native 解释器、EPL）之上补齐的两条短板，**已在最大强度下全量验证**：

| 编号 | 手段 | 落点 |
|---|---|---|
| **S6** | 平坦化 **EPL 甜点窗口**（16..256 指令）——只扁平化真业务方法，既躲开巨方法 StackMapTable 精度爆炸，又保证分发器有实际收益 | `ControlFlowObfuscator.inFlattenWindow()`；VMP 目标/构造器自动跳过只补栈中性不透明谓词 |
| **S7** | 字符串密钥进 **KBNL 硬件派生域**——置换表 T 被 `KbnlKey.derive(域标签,盐)` 盲化，密钥永不以静态形式出现 | `AesStringEncryptor`（`strDomainTag`/`strSalt`，构建↔运行确定性一致） |
| **S8** | JNIC 选例**吃 EPL**——即便显式配置了 `nativeMethod`，仍按 EPL 标准自动追加选例（`jnicEplDriven=true`），原生/虚拟机/平坦化三层互补 | `AutoJnicVmpSelector.autoSelectJnic()` |
| **D6** | 探头分散 + 模块名**分片**——反调试模块名按平台用 `kbox_xdec` 还原、即时擦除，RDTSC/QPC/单调钟**三源校时**；IDA 搜不到模块名字符串 | `kbox_probeAgentModules()`（`KBOX_BF_ENCRYPTED` 分支） |
| **D7** | native **节自擦**——解密后用不可省略的 volatile 逐字节清零敏感区（`.data`/`.kboxexp`）再释放 | `kbox_bf_selfWipeNative()` + `kbox_secmem_clear()` |
| **D8** | VM dispatch **二次校验**——slot 分发（`composite[twin^raw]` + invPerm 置换）完全镜像 Java 侧，`VMP_MAX_STEPS` 防 tampered 跑飞 | `kbox_vmp_core.c` |
| **D9** | **明文曝光窗收敛**——exbox 释放先 `kbox_secmem_clear` 再 unmap，常量池驻留、窗口逐段擦除 | `kbox_exboxFree()` |

**最大强度适配核验（全部实测通过）**：C 四原生单元（bf_loader/vmp/jnic/crypto）GCC 编译全绿 → `mvn install` 全量成功 → `ns-full.conf`（BF + JNIC + VMP-native + S/D/C/X 全 level=3 + `brainfuckShieldLevel=3`）重保护 `app.jar` → `bftest.Main` 端到端全绿（`ENCODING_ROUNDTRIP_EQUAL=true`、exit 0）→ 产物 jar 内 KBNL/KBF2/KBFT/KBCE/KBOX/KEPD/KMII/instrument 魔数 grep 命中 **0**。同配置对 `helloworld.jar` 全开最高强度，产物 `_bftest/out-hello-nsfull.jar` 正常输出且注入拦截仍生效。完整施工单见 [docs/STATIC-DYNAMIC-LIFT-PLAN.md](docs/STATIC-DYNAMIC-LIFT-PLAN.md)。

> 构建提示：本机 `PATH` 上的 `mvn` 是指向源码树的 wrapper（会报 `-classpath requires class path specification`），请直接用 `D:\apache-maven-3.9.6\bin\mvn.cmd`。

---

## MCMOD 兼容与运行时可靠性工程（2026-09）

针对 1.8.9 Forge + Mixin 类 mod（LiquidBounce 系）全量实测，固化了一整套「混淆器 × Mixin / 启动器 / Java 8 老运行时」兼容层。任何一个缺失都会在启动期以不同方式崩溃（`NoSuchMethodError` / `AbstractMethodError` / `ClassFormatError` / `VerifyError` / Mixin NPE）：

- **Java 8 链接正确性**：所有注入到产物的代码改用 `--release 8` 编译——仅写 `source/target=8` 只改字节码版本号、不锁 API，javac 仍会把 Java 9+ 符号（如 `ByteBuffer.rewind()` 的协变返回）链接进去，老 JVM 加载即 `NoSuchMethodError`。
- **外部接口覆写永不改名**：继承/实现 jar 外类型（如 LaunchWrapper `IClassTransformer`）的方法保持原名，避免 `AbstractMethodError`。
- **Mixin 三层保护（`autoAdaptMinecraft` 自动完成）**：mixin 类与其目标类自动加入 ① `keepPrefixes`（防改名）② `bodyExcludePrefixes`（方法体不改写——Mixin 注入处理器合并进目标类时会重排局部槽并外包 try/catch，任何改写帧/局部/异常表的 pass 都会破坏它）③ VMP/JNIC 排除（`@Shadow` 字段在 mixin 类里根本不存在，下沉进解释器必然解析失败）。
- **mixin 直接引用的类排除 JNIC**：处理器合并进目标类后仍会调用其原引用类（如 `ClientUtils.getLOGGER()`），这些类也被排除 JNIC 原生下沉——原生解释器对静态字段访问器返回 null 的问题已在多个类复现。
- **`@Shadow` 等 Mixin 注解按包前缀整体保留**：注解擦除对 `Lorg/spongepowered/asm/mixin/` 前缀整体豁免（逐条列举曾因包路径写错而误删 `@Shadow`，导致 Mixin 应用期 NPE）。
- **Cheat Engine / 内存扫描对抗（native 层）**：新增 `\\.\DBK` 内核驱动设备探测、进程内 `cheatengine-*.dll` 模块探测、CE 窗口/进程扫描；任一命中即 `epochBump` 内存自毁。配合既有 Dr7 硬件断点、调试端口、JVMTI agent 能力探测。
- **可靠性基线（safe-base）**：`typeConfusion` / `mbaConstants` / `stackFrameRedirect(D1)` / `exceptionJumpObf` 这类「载体异常重写」pass 与自带 try/catch 的复杂解析类冲突（FlatLaf `UIDefaultsLoader` 曾把 `"0.5"` 路由进 `Integer.parseInt` 直接崩）；已内置「跳过自带 try/catch 方法」守卫。大型 mod 建议先用安全基线（关闭这 4 项，其余全开）拿可用产物，再按需逐个加回。

**VMP / JNIC 排除类**（新配置键，GUI 同步支持）：
```ini
# 点分/斜杠均可，支持 .* 通配（自动归一化）；每行一个
vmpExcludePrefix  = com.example.ui, com/example/netty.NettyHandler
jnicExcludePrefix = com.example.io
bodyExcludePrefix = com.example.parse      # 方法体整体豁免（框架解析类）
nativeExcludePrefix = com.example.legacy   # VMP+JNIC 共用硬排除
```
GUI 中「VMP 排除类」「JNIC 排除类」文本框仅在勾选 VMP / JNIC 时显示与可选。

---

## kboXShield 独立功能线（Windows PE 加壳）

kboXShield 是原独立的 C++ PE 加固工程（`include/` + `packer/` + `stub/`），现已**全量移植为 Java**
并作为独立功能线并入本混淆器：`--shield <in.exe> <out.exe>`，或直接调用
`com.kbox.core.shield.ShieldPacker.run(String[])` / `pack(String, String, StringBuilder)`。

### 使用入口

| 入口 | 用法 |
|---|---|
| CLI | `java -jar kboxObfuscatorb3.jar --shield app.exe app-protected.exe`（默认档） |
| HTML UI | `--gui` 打开页面内的 **「kboXShield · PE 加壳」** 独立面板（含 ⚡ 智能适配 + 结构自检回显） |
| 编程 | `ShieldPacker.pack(in, out, ShieldOptions, log)` / `ShieldVerify.verify(out, opts)` |

`ShieldOptions` 可控制：架构偏好（自动 / 仅 x64 / 仅 x86）、`def_flags`（18 项运行期检测位掩码）、
`def_policy`（bit0 延迟 / bit1 诱饵 / bit2 终止）、延迟循环、时序阈值、是否虚拟化 `.textvm*` 标记节。
默认值与原始 C++ `packer/main.cpp` 一致。

**HTML UI 面板**：输入/输出 PE、架构、虚拟化开关、响应策略三项、延迟/时序阈值、
**18 项检测位分组开关**（L1 / L2 / L3 / 反VM / 反hook / 完整性 / 反注入，附「全开 / 全关 / 仅 L1」快捷档
与实时掩码显示）、以及打包后的 **PE 自检结论**。面板的「智能适配」(`/api/shield/analyze`) 会解析输入 PE
（架构 / 节表 / TLS 回调 / 资源目录 / `.textvm` 标记节 / 是否 DLL）并回填推荐档 + 给出理由——
例如 DLL 场景自动把响应策略降为「延迟 + 诱饵」（不终止宿主进程）。

**产物自检**（`ShieldVerify`，CLI 与 UI 都会跑）：PE 解析、节表几何与对齐、入口点可执行性、
合成导入表、8 个必须清零的目录、资源目录保留、以及 **KboxConfig 可解密性**
（用 stub 的 LCG 算法解出配置区，校验 magic/version/`stub_rva` 与入口节一致/`oep_rva`/`payload_rva`/`vm_count`，
并回显 `def_flags`/`def_policy` 与本次选项比对）。这样「能写出但 Windows 直接拒载」这类问题
在打包阶段就能暴露，而不是等到实机运行。

### jar 内原生库加壳（`protectNativeLibs`）

混淆时自动扫描输入 jar 的**全部目录**，识别原生库并做完整保护，明文原生库从不进入产物 jar。

**识别规则**（与文件名无关）：扩展名 `.dll/.so/.dylib` 优先；扩展名不匹配时按**内容魔数**识别共享库——
PE 需带 `IMAGE_FILE_DLL` 标志、ELF 需 `e_type == ET_DYN`、Mach-O 需 `MH_DYLIB`/`MH_BUNDLE`。
因此以 **`.bin`/`.dat`** 等任意名字打包在 jar 里的原生库同样会被加壳，而 jar 内附带的 `.exe` 或普通数据不会被误判。

| 支持矩阵 | `.dll` / PE（任意文件名） | `.so` / ELF | `.dylib` / Mach-O |
|---|---|---|---|
| 加壳方式 | **完整加壳**：全节 ChaCha20 加密 + 合成导入表 + 函数级虚拟化（.pdata 逐函数，入口 E9 改写）+ 指令变异 + 控制流平坦化（双族 VM） | 压缩 + ChaCha20 加密存储（解密落盘加载） | 压缩 + ChaCha20 加密存储（解密落盘加载） |
| 运行时 | `System.load` 前解密落盘，加载后立即擦除临时文件（nuke + delete） | 同左 | 同左 |

- **开关**：`protectNativeLibs = true`（`allMax=true` 自动开启；GUI「高级选项」勾选「原生库加壳」）。
- **产物布局**：每个库打包为 `META-INF/kbox/natlib/N.bin`（KBNL 格式：压缩 + ChaCha20，密钥经硬件域派生），
  清单 `META-INF/kbox/natlibs.list` 记录 `逻辑路径|blob路径|格式`（格式为 dll/so/dylib，按内容判定）。
- **运行时加载**：引导类（`ResourceGuardLauncher`）在应用 `main` 之前自动按当前 OS 匹配格式
  调用 `NativeLoader.loadNativeLibs()`；也可在业务代码中显式
  `NativeLoader.loadNativeLib(String)` 按逻辑路径按需加载（如 `native/lib/mylib.bin`）。
- **JNI 符号可见性**：声明 `native` 方法的业务类会自动加入 `parent-delegate.list`，由系统加载器定义
  （原生库也在系统加载器命名空间下 `System.load`）；否则守卫加载器会自定义这些类，
  导致 `UnsatisfiedLinkError`。同时 `AutoKeepDeriver` 本来就保留这类类名与方法名（JNI 符号要求）。
- **与资源混淆协作**：开启后原生库条目自动豁免资源重命名（按内容识别，`.bin` 命名同样生效），
  保留原始逻辑路径，应用按原名加载不受影响。
- **注意事项**：DLL 间依赖顺序由清单顺序（jar 条目顺序）决定，存在依赖的库建议用
  `loadNativeLib(String)` 显式控制顺序；运行时防御位（`defFlags`）在进程内加载时置 0，
  避免 JVM 宿主内误判与杀软实时防护冲突——虚拟化/变异/平坦化不受影响。
- **自测样例**：`_nattest/`（`mylib.dll` 导出 `Java_Main_nativeCheck` → 加壳后符号保留，输出 `NAT_OK v=42`）；
  `_nattest2/`（同一 DLL 改名为 `native/lib/mylib.bin`，验证内容魔数识别 + 资源混淆共存 → 同样 `NAT_OK v=42`）。

### 打壳模型（原地变换，与 Themida/UPX 同思路）

1. 保留原 PE 全部节（代码/数据/资源节，载荷数据被加密）；
2. 末尾追加两个随机命名节：**代码节**（`blob[0, iat_off)`，RX）与**数据节**（RWX）；
   节内顺序为 `[KboxConfig | stub 代码][trampoline][加密 payload][合成导入表][VM 镜像组][运行期汇编引擎][VmRecs][防御报告][TLS 回调表]`；
3. `AddressOfEntryPoint → stub 入口`；Import Directory → 合成导入表（仅 `LoadLibraryA/GetProcAddress/VirtualProtect`）；
4. `Security/BaseReloc/TLS/LoadConfig/BoundImport/IAT/DelayImport/CLR` 目录清零（防 loader 读密文）；
5. 运行期 stub：取基址 → 解密配置区 → 还原字符串池 → 运行期防御 → **VM 自检** →
   解密 payload → 逐节解密 → 重建 IAT → 重定位 → 恢复节权限 → 代跑 TLS 回调 → 跳 OEP。

### 关键设计

- **配置区加密**：`KboxConfig`（`[0,0x100)`）以每构建随机 LCG 流密钥异或，种子写入代码节
  `kbox_cfg_root` 槽；stub 入口先自解密。
- **完整性 CRC32**：覆盖 `stub[0x100, iat_off)`，按「运行期视图」（字符串池已还原）计算。
- **逐节独立 ChaCha20**：每节独立 12 字节 nonce（4B 节 ID + 8B 随机）+ 起始块计数。
- **嵌套虚拟化**：内层 VM 解释器本身不再以明文 native 存在，而是编译为**外层 Meta VM 字节码**
  （`MetaInner.vmBuildInnerMeta`，定长 8 字节指令、就地解密/回加密、opcode_map 随机重排 +
  handler 偏移表）。运行期唯一明文 native 循环是 `kbox_meta_run`（blob 内，位置无关）。
- **汇编 blob**：4 个资产由 `stub/*.S` 汇编后平铺为裸二进制，入口位于 blob 偏移 0：
  `blob_{x64,x86}.bin`（stub，各 24576B）、`engine_{x64,x86}.bin`（运行期引擎，2848/3816B）。
  重新生成见下节。

### 重新生成汇编 blob

```powershell
# 需要 MSYS2 mingw-w64 binutils（as/ld/objcopy/objdump/nm）
python build_blobs.py     # 见交付说明：对 stub/*.S 剥离 ELF 专有指示符后汇编，输出到 resources/shield/
```

### 移植中修复的上游跨文件契约漂移

原 C++ 快照存在几处「改造只做了一半」的不一致；移植以**随包发布的运行期汇编引擎为准**统一，
否则产物在运行期必然失败：

| 漂移 | 现象 | 处理 |
|---|---|---|
| `vm_inner_state.h` 的 `IS_SIZE/IS_FRAME`（1248/732）与 `vm_engine_*.S`（1208/696）不一致 | 引导程序与 Meta 程序对 GPR 帧的偏移错位 40/36 字节 | 修正 `.S` 为 1248/732 并重建 engine blob |
| 「方案B：魔数由密钥派生」只改了 `vm_builder.cpp`/`vm_engine.cpp`，汇编引擎与 `meta_inner.cpp` 仍按固定魔数校验 | 运行期 `kbox_vm_run` 以 `BAD_MAGIC` 停机 | 统一使用固定 `VM_IMAGE_MAGIC=0x4D56424B` |
| 「方案B：ks1^ks2 双 keystream」只改了 builder/预览引擎，汇编引擎与 `meta_inner.cpp` 只有单 ks1 | 运行期反查表解密错位 → `BAD_OPCODE` | 映射区统一只叠加 ks1 |
| 资源节（`.rsrc`）被整体加密，但 `RESOURCE` 目录未清零 | `CreateProcess` 解析清单失败 → **ERROR_BAD_EXE_FORMAT(193)**，打壳后的程序根本无法启动 | 资源节标记 `PAYLOAD_FLAG_SKIP_DECRYPT` 并保持明文（stub 已支持该标记，原先从未接线） |

### 已验证的契约（离线逐字节核对）

- `KboxConfig` 以 stub 的 LCG 算法解密后，`magic/version/stub_rva/oep_rva/image_base/payload/key/nonce/VM 元数据/防御配置/TLS` 全部正确；
- `payload` 以 `key+nonce+counter=0` 解密后 `magic=KPAY`、18 条节记录、2 个 DLL、50 条导入、reloc 0x74 全部正确；
- 18 个被加密节逐节 ChaCha20 解密后与原始 PE 的对应节数据**完全一致**；
- 完整性 CRC32 与配置中的期望值 **MATCH**；
- 内层镜像头 `0x4D56424B / ver2 / familyA / dispatch0 / stack_words32`、`reserved[0]=0x110 → Meta 镜像 0x4D56424D / ver1` 全部正确；
- 合成导入表（OFT/hint/name/FirstThunk）结构合法，pefile 解析通过。

### 当前边界（诚实说明）

- 打壳产物**可正常加载并执行到 stub**（PE 头、导入表、重定位目录处理均正确），但
  **运行期 VM 自检路径仍会崩溃**：禁用 VM 自检（`vm_flags=0`）后不再出现访问违例，
  说明故障位于 native stub/引擎的运行期执行链，而非 Java 侧打包逻辑（打包契约已全部离线验证正确）。
  该链路的进一步定位需要在目标机上以原生调试器（WinDbg/cdb）跟踪，属后续加固项。
- 反调试开启时附加调试器会改变 stub 走向（`.Ldead` 为死循环），因此定位需先关闭 `def_flags`。

---

## 已有能力与诚实边界

**默认关闭、需显式开启的高风险项**（原因：字节码重写风险，关闭可保产物稳定）：
`enableVmp`、`enableJnic`、`encryptClasses`、`typeConfusion>0`、`mbaConstants>0`。
`typeConfusion` / `mbaConstants` / `stackFrameRedirect(D1)` / `exceptionJumpObf` 已内置「跳过自带 try/catch 方法」守卫，但复杂解析类仍建议用 `bodyExcludePrefix` 整类豁免。

**诚实的边界**——请勿相信任何「绝对不可破解」营销话术：
- 只要程序能在攻击者控制的机器上运行，就存在被逆向的语义信息（动态度量、JIT、仿真必然泄漏）。
- 本项目不接受「数学上不可逆」的承诺，只追求：顺手的自动化工具有效性显著下降 + 一次性抓取（单密钥/单签名）失效 + 人工分析成本上升。
- 成品保护强度 = 配置里各项之和；对核心敏感逻辑建议开启 JNIC/VMP/类加密的组合，并权衡性能与体积。

---

## License

仅作为产品级防护工具本人使用与研究，具体授权约定见 `docs/` 与发行说明。

---

## 📜 许可证 / License

**重要：使用/分发本项目即表示你已阅读并接受 [LICENSE](LICENSE)。**
**By using, copying, or distributing this project you agree to the [LICENSE](LICENSE).**

**一句话条款（以 LICENSE 英文原文为准）：**

- ✅ 任意修改、复制、分发，允许商用。

- ⚠️ 必须**原样保留** 代码内水印 `kboxcbh1337` 与 `kboxStudio`。

- ⚠️ 在官网/开源站点必须标明项目**共同开发人**（见下方致谢 Credits）。

- 💰 **任何直接或间接营利性使用**（含销售集成本项目的软件、依托本项目盈利的产品/游戏等）都必须通过**微信或支付宝**向开发者 **kboxcbh1337** 支付**不少于 500 美元**的商业许可费。

该许可证属于「源码可用 + 付费商用」的自定义许可，并非 OSI 批准的开源许可证。

**Payment & Contact（商业许可支付 / 联系）：** 获取微信/支付宝收款二维码与账号、或咨询商业许可事宜，请通过项目官网或联系 **kboxcbh1337**（GitHub Issues / 项目主页）。

## 🙏 致谢 / 共同开发人 / Credits

本项目由以下共同开发者共同开发，**任何分发与展示都必须保留此署名**：

| 角色 | 署名 |
|---|---|
| 开发者（License 持有方） | **kboxcbh1337** |
| 项目 / 团队（水印持有方） | **kboxStudio** |
| 共同开发人 | **kboxhh** |

注意：`kboxcbh1337` 与 `kboxStudio` 同时作为代码内水印必须随代码保留，不得移除。

## ⚠️ 免责声明

本项目仅用于合法的软件保护与安全研究目的。使用本项目时请遵守所在司法辖区的法律法规。作者对因使用本项目产生的任何直接或间接损失不承担责任（详见 LICENSE 第 6 条）。

*KBox Obfuscator v2.0 — kboxcbh1337 & kboxStudio*