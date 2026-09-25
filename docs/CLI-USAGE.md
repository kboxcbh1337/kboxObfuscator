# KBox Obfuscator — Command-Line Usage

KBox 提供一个独立的命令行入口 `kbox-protector.jar`，支持 ZKM 级混淆、JNIC（Java→C 本地化）、VMP（虚拟机解释器）以及完整的反分析 / 反调试 / 反编译器对抗能力。同时内置 **HTML UI**（`--gui`，内嵌 HTTP 服务 + 自动打开浏览器，白绿/黑绿双主题），无需单独打包。

---

## 1. 快速开始

```bash
# 最简保护（使用全部默认值：重命名 + 字符串加密 + 控制流混淆 + 资源混淆）
java -jar kbox-protector.jar --input app.jar --output protected/app.jar

# 最高强度保护 + 自定义水印 + 详细日志
java -jar kbox-protector.jar -i app.jar -o protected/app.jar \
    --config kbox.conf \
    --verbose

# 启动 HTML UI（内置 HTTP 服务，自动打开浏览器；白绿/黑绿双主题）
java -jar kbox-protector.jar --gui
```

---

## 2. 命令行参数总览

| 参数 | 简写 | 取值 | 说明 |
|------|------|------|------|
| `--input`  | `-i` | `PATH`  | 输入 jar（普通 jar 或 Spring Boot Fat Jar） |
| `--output` | `-o` | `PATH`  | 输出 jar 路径 |
| `--config` | `-c` | `PATH`  | KBox 配置文件（可选，缺省使用安全默认值） |
| `--gui`    | —    | flag   | 启动内置 HTML UI（内嵌 HTTP 服务 + 浏览器，不再运行 headless 流程） |
| `--verbose`| `-v` | flag   | 启用 DEBUG 日志（完整进度 + 异常栈） |
| `--debug-cf` | —  | flag   | 把每个类 / 方法的控制流处理日志直接打印到 stdout（始终可见，与 `--verbose` 独立） |
| `--mc-preset` | —  | `NAME` | 应用 Minecraft Mod 加载器预设：`NEOFORGE` / `FORGE` / `FABRIC` / `BUKKIT` / `MIXIN` |
| `--scope`  | —    | `MODE` | 文件混淆范围：`ALL`（默认）/ `SELECTIVE` / `EXCLUDE` |
| `--include`| —    | `PATTERN` | 类包含模式（可重复）。仅 `SELECTIVE` 模式下生效 |
| `--exclude`| —    | `PATTERN` | 类排除模式（可重复）。`SELECTIVE` 与 `EXCLUDE` 模式下生效 |
| `--list-presets` | — | flag | 列出所有可用的 Minecraft Mod 预设 |
| `--shield` | — | `IN.exe OUT.exe` | **kboXShield 独立功能线**：对 Windows PE 加壳（不读 `--input/--output`，详见第 11 节） |
| `--help`   | `-h` | flag   | 显示帮助 |

> 字符串模式使用 Glob 语法：`**` = 任意多级包路径，`*` = 单层包内通配。
> 内部类用 `$` 分隔，例如 `com/foo/Bar$Inner`。

---

## 3. 文件级选择（细粒度混淆）

KBox 提供三种作用域，由 `--scope` 控制：

| 模式 | 行为 |
|------|------|
| `ALL` | 混淆所有类与资源（受 keep 规则保护） |
| `SELECTIVE` | 仅混淆匹配任一 `--include` 模式的类；其余保持原样 |
| `EXCLUDE` | 混淆所有类，但跳过匹配任一 `--exclude` 模式的类 |

### 模式语法（Glob → 内部名）

- 输入使用斜杠分隔的内部名：`com/myapp/**`
- `**` 匹配任意层级的包（含 0 层）
- `*` 匹配单层包内的任意字符
- 示例：
  - `com/example/**` — 整个 `com.example` 树
  - `com/foo/Bar` — 仅 `com.foo.Bar` 一个类
  - `com/foo/*` — `com.foo` 包下的所有类（不含子包）

### 典型用例

```bash
# 仅混淆业务包，跳过 API 与 DTO
java -jar kbox-protector.jar -i app.jar -o out.jar \
    --scope SELECTIVE \
    --include com/mycompany/service/** \
    --include com/mycompany/core/** \
    --exclude com/mycompany/service/api/**

# 混淆整个 jar，但跳过 JPA 实体与外部 SPI
java -jar kbox-protector.jar -i app.jar -o out.jar \
    --scope EXCLUDE \
    --exclude com/mycompany/entity/** \
    --exclude com/mycompany/spi/**
```

---

## 4. Minecraft Mod 预设

针对 Minecraft 模组生态，KBox 内置了加载器专属的 keep 规则与资源排除规则：

| 预设 | 适用加载器 | 关键行为 |
|------|-----------|----------|
| `NEOFORGE` | NeoForge 1.20+ | 保留 `net/neoforged/`、`net/minecraft/`；排除 `META-INF/neoforge.mods.toml`；控制流强度上限 2 |
| `FORGE`    | Minecraft Forge | 保留 `net/minecraftforge/`、`net/minecraft/`；排除 `META-INF/mods.toml`、`mcmod.info` |
| `FABRIC`   | Fabric Loader | 保留 `net/fabricmc/`；排除 `fabric.mod.json`、`META-INF/jarjar/` |
| `BUKKIT`   | Spigot / Paper 插件 | 保留 `org/bukkit/`、`org/spigotmc/`、`org/yaml/snakeyaml/`；保留 `plugin.yml` |
| `MIXIN`    | SpongePowered Mixin | 保留 `org/spongepowered/asm/`、所有 `*.mixins.json`；关闭会破坏 mixin transform 的手段 |

### 使用方式

```bash
# NeoForge 模组
java -jar kbox-protector.jar -i mymod.jar -o mymod-protected.jar \
    --mc-preset NEOFORGE \
    --scope EXCLUDE --exclude com/myorg/mixin/**

# Fabric 模组（保留 fabric.mod.json）
java -jar kbox-protector.jar -i fabricmod.jar -o out.jar \
    --mc-preset FABRIC
```

预设可与 `--scope` / `--include` / `--exclude` 组合使用，预设的 keep 规则与用户传入的模式合并生效。

---

## 5. 配置文件（`--config`）

配置文件是 YAML 风格的纯文本文件，可被 CLI、GUI 与 Maven 插件共用。未在文件中显式列出的字段使用代码默认值。常用字段：

```properties
# 基础开关
renameIdentifiers   = true
encryptStrings      = true
obfuscateControlFlow = true
controlFlowStrength = 2
stringEncryptionStrength = 1

# 高级能力（默认关闭，按需开启）
enableVmp           = false
enableJnic           = false
encryptClasses      = false
obfuscateResources  = true
fixKotlinMetadata   = true

# 反分析
antiDecompilerLevel = 0
antiDebug           = false
vmpSelfCheck        = false
integrityCheck      = false
exceptionJumpObf    = false
nativeAntiHook      = false
watermark           = kboxstudio

# 保留规则（每行一个前缀）
keepPrefixes = [
  com/myapp/Main,
  com/myapp/spi/
]

# 细粒度选择
obfuscationScope = ALL
includePatterns  = []
excludePatterns  = []
```

> 完整字段定义见 [ProtectionConfig.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ProtectionConfig.java)。

---

## 6. 控制流调试（`--debug-cf`）

当控制流混淆结果不符合预期时，加上 `--debug-cf` 可让 [ControlFlowObfuscator](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java) 把每个类、每个方法的处理日志直接打印到 stdout（即使整体日志级别不是 DEBUG）：

```bash
java -jar kbox-protector.jar -i app.jar -o out.jar --debug-cf 2>cf.log
```

输出包含：
- 进入 / 跳过的类与方法名
- 跳过原因（例如：存在异常表、栈非空、含 native 抽象方法）
- 每个方法实际应用的变换与耗时

---

## 7. 进度与日志

- **默认模式**：stderr 输出 ANSI 进度条（`[Stage x/y] name … [n%] detail`），stdout 输出 INFO 级日志。
- **`--verbose`**：禁用进度条，输出 DEBUG 级日志，包含完整异常栈。
- **`--debug-cf`**：仅控制流阶段输出 DEBUG 级内容到 stdout，与 `--verbose` 互补。

进度阶段由 [ProtectionPipeline](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/ProtectionPipeline.java) 通过 `KBoxLog.ProgressListener` 回调，CLI 与 GUI 都基于此机制。

---

## 8. 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 保护成功，输出 jar 已生成 |
| 1 | 保护流程中抛出异常（见日志详情） |
| 2 | 命令行参数错误（缺值、未知参数等） |

---

## 9. 与 Maven / Gradle 集成

KBox 也提供 Maven 插件与可被 Gradle 调用的命令行接口：

- **Maven**：使用 `kbox-maven-plugin`，绑定到 `package` 阶段，参见 [ProtectMojo.java](file:///d:/kboxobf/kbox-maven-plugin/src/main/java/com/kbox/maven/ProtectMojo.java)。
- **Gradle**：在 `build.gradle` 中以 `JavaExec` 任务调用 `kbox-protector.jar`，参数与本文件一致。

---

## 10. 常见问题

**Q：为什么默认不开 VMP / JNIC / 类加密？**
A：这三项会改变类加载机制或引入 native 库，在跨平台 / 嵌入式场景需要额外配置。普通用户开启重命名 + 字符串加密 + 控制流混淆已经能挡住绝大多数静态分析。

**Q：混淆后 `java -jar` 跑不起来，怎么办？**
A：先用 `--verbose` 看完整异常栈；再用 `--debug-cf` 定位是否是控制流变换导致；最后用 `--scope SELECTIVE --include <出问题的包>` 二分定位。

**Q：可以混淆 Spring Boot Fat Jar 吗？**
A：可以。KBox 会保留 `BOOT-INF/` 结构与 `Main-Class`，仅混淆 `BOOT-INF/classes/` 下的业务类。

**Q：Minecraft 模组用哪个预设？**
A：NeoForge / Forge 选对应预设；Fabric 选 `FABRIC`；含 Mixin 的模组额外用 `--scope EXCLUDE --exclude <mixin 包路径>` 保护 mixin 类。

---

## 11. kboXShield PE 加壳（`--shield` / HTML UI）

独立功能线：对 **Windows PE（PE32 / PE32+）** 加壳，输出仍可被 Windows 加载的可执行文件。
与 jar 混淆完全独立，不读取 `--input/--output/--config`。

**两种入口**：

```powershell
# 1) CLI（默认档：def_flags=0x0003FFFF、def_policy=7、跟随输入架构）
java -jar kboxObfuscatorb3.jar --shield app.exe app-protected.exe

# 2) HTML UI：页面内「kboXShield · PE 加壳」独立面板
java -jar kboxObfuscatorb3.jar --gui
```

**编程入口**（可传选项）：

```java
ShieldOptions o = new ShieldOptions()
        .arch(ShieldOptions.ARCH_AUTO)   // AUTO / ARCH_X64 / ARCH_X86（仅“限架构”，不支持跨架构）
        .defFlags(0x0003FFFF)            // 18 项运行期检测位掩码，0 = 全关
        .defPolicy(7)                    // bit0 延迟 / bit1 诱饵 / bit2 终止
        .defDelayLoops(20000000)
        .defTimingTicks(100000)
        .virtualizeMarkedSections(true); // 虚拟化 .textvm* 标记节（x64 专用）
boolean ok = ShieldPacker.pack("app.exe", "app-protected.exe", o, log);

// 产物自检（只读，不执行）
ShieldVerify.Report rep = ShieldVerify.verify("app-protected.exe", o);
System.out.println(rep.toText());
```

### HTML UI 加壳面板

- 输入 PE（`.exe/.dll/.sys`，支持拖拽）/ 输出 PE（留空自动推导 `*-protected.exe`）；
- **⚡ 智能适配**（`/api/shield/analyze`）：解析 PE 后回填推荐档——
  架构、`def_flags`、响应策略、延迟/时序阈值、是否虚拟化，并给出理由；
- 架构（自动 / 仅 x64 / 仅 x86）、虚拟化 `.textvm*`、响应策略三项、延迟循环、时序阈值；
- **18 项运行期检测位**按功能分组（L1/L2/L3/反VM/反hook/完整性/反注入）逐个开关，
  并提供「全开 / 全关 / 仅 L1」快捷档，实时显示 `def_flags` 掩码；
- 打包后自动跑 **PE 结构自检**（`/api/shield` 返回 `verify`），日志与结论一并显示在面板内。

### 行为

- 输入 PE 的原有节全部保留（代码/数据/资源节数据被逐节 ChaCha20 加密，每节独立 nonce）；
- 追加两个随机命名节：RX 代码节（KboxConfig + stub）与 RWX 数据节（payload/导入表/VM 镜像组/引擎/VmRecs/防御报告/TLS 回调表）；
- 入口点改写为 stub；`Import Directory` 指向合成导入表（仅 `LoadLibraryA` / `GetProcAddress` / `VirtualProtect`）；
- `Security/BaseReloc/TLS/LoadConfig/BoundImport/IAT/DelayImport/CLR` 目录清零；
- **资源节（含 manifest）保持明文**并标记 `PAYLOAD_FLAG_SKIP_DECRYPT`——否则 `CreateProcess`
  在进程创建阶段解析清单会失败并返回 `ERROR_BAD_EXE_FORMAT (193)`。

### 产物自检项（`ShieldVerify`）

产物大小、PE 解析（arch/节数/SizeOfImage/SizeOfHeaders）、节表几何（raw 区越界、对齐、虚拟区间）、
入口点是否落在可执行节、合成导入表、必须清零的 8 个目录、资源目录是否保留、
**KboxConfig 可解密性**（用 stub 的 LCG 算法解 `[0,0x100)`，校验 magic/version/`stub_rva`
与入口节一致/`oep_rva`/`payload_rva`/`vm_count`，并回显 `def_flags`/`def_policy` 与本次选项比对）。

### 退出码

| 码 | 含义 |
|---|---|
| `0` | 加壳成功 |
| `1` | 打包失败（PE 解析失败 / VM 自检失败 / 架构约束不满足 / 无法读写文件） |
| `2` | 参数错误（未给出 `<in.exe> <out.exe>`） |

### 注意

- 运行期 stub 的 VM 自检链路仍有已知崩溃（见 README「kboXShield 独立功能线」的“当前边界”），
  请先在测试样本上验证再加壳；自检只覆盖**静态**结构，不能替代实机运行验证；
- 反调试启用时不要附加调试器运行产物（stub 会走 `.Ldead` 死循环）；
- DLL 场景建议把响应策略降为「延迟 + 诱饵」（`def_policy=3`，不终止宿主进程）——UI 的智能适配已自动这样推荐。
