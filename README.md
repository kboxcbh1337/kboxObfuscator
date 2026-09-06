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

关键代码位置：

- 常量混淆：`kbox-core/src/main/java/com/kbox/core/obfu/ConstantObfuscator.java`
- **交织表达式合成与混淆（本仓库新增）：**
  - `.../obfu/ExpressionSynthesizer.java`（随机、按构造可验证的整数表达式树）
  - `.../obfu/MbaConstantObfuscator.java`（常量改写 pass）
- 编排：`kbox-core/src/main/java/com/kbox/core/ProtectionPipeline.java`
- 配置：`kbox-core/src/main/java/com/kbox/core/config/*.java`
- VMP 运行时：`kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java`
- JNIC：`kbox-core/src/main/java/com/kbox/core/jnic/*.java`

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

## 已有能力与诚实边界

**默认关闭、需显式开启的高风险项**（原因：字节码重写风险，关闭可保产物稳定）：
`enableVmp`、`enableJnic`、`encryptClasses`、`typeConfusion>0`、`mbaConstants>0`。

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