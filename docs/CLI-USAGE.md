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
