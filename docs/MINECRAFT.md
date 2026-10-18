# 我的世界 Mod 适配

`autoAdaptMinecraft = true`（默认）时，KBox 会读取 jar 元数据识别加载器并调整保护策略，
目标是在“尽可能强”和“能被宿主加载器接受”之间取平衡。

## 1. 识别

| 元数据 | 加载器 |
|---|---|
| `fabric.mod.json` | Fabric |
| `META-INF/mods.toml` | Forge 1.13+ |
| `META-INF/neoforge.mods.toml` | NeoForge |
| `mcmod.info` | Forge 1.8.9 / 1.12.2 |
| `plugin.yml` / `paper-plugin.yml` | Bukkit / Paper |
| Manifest `TweakClass` / `FMLCorePlugin` | 旧版 Forge / Mixin |

入口类来源：`fabric.mod.json` 的 `entrypoints`、`@Mod(modid=...)`、`@Mod("...")`、
`mcmod.info` + 所有带 `@Mod` 的类。

## 2. 自动保留

- 入口类、`@Mod` 类、Fabric entrypoint 类；
- Mixin 类与目标类（类名、成员名、方法体都不混淆）；
- `mixins.*.json`、`fabric.mod.json`、`mods.toml`、`neoforge.mods.toml`、`mcmod.info`；
- `*.accesswidener`、`*.accesstransformer.cfg`、`META-INF/jars/`（Fabric 嵌套 Mod）；
- 框架注解：`Lorg/spongepowered/`、`Lnet/fabricmc/`、`Lcpw/mods/`、
  `Lnet/minecraftforge/`、`Lnet/neoforged/`。

## 3. 自动降级（避免加载器拒绝）

| 功能 | 原因 |
|---|---|
| 类加密 | Forge/NeoForge 在定义类之前 ASM 扫描每个 `.class` 找 `@Mod`；密文条目会让整个 jar 被判 corrupt |
| 资源混淆 | 加载器与 Mod 按原路径读取 `assets/**`、`data/**`、`ResourceBundle` |
| 反反编译器畸形属性 | 同上，任何不可解析的 class 条目都会中断全量扫描 |
| BF blob 加载器 | 宿主加载器自己定义 Mod 类，blob 内引擎类不可见 → `NoClassDefFoundError` |
| VMP | 解释器侧类解析与 Mod 模块层的 `Class` 身份语义冲突（可 `mcForceVmp=true` 强制） |

仍然生效：重命名、字符串加密、控制流、常量/类型混淆、JNIC、BFVM、
BrainfuckShield、K-OTP、方法拆分/不透明状态机、原生库加壳。

## 4. 已完成的真实环境验证

| 环境 | 版本 | 测试 Mod | 结果 |
|---|---|---|---|
| Forge | 1.8.9 / 11.15.1.2318 | JEI 2.28.18.187 | 服务端启动，Mod 加载 |
| Forge | 1.12.2 / 14.23.5.2860 | AppleSkin 1.0.14 | 服务端启动，Mod 加载 |
| Forge | 1.16.5 / 36.2.42 | AppleSkin 2.5.1 | 服务端启动，Mod 加载 |
| Forge | 26.3 / 66.0.13 | NoChatReports 2.21.0 | 服务端启动，Mod 加载 |
| Fabric | 1.16.5 / loader 0.19.5 | LuckPerms 5.3.9 + Fabric API 0.42.0 | 服务端启动，LuckPerms v5.3.9 |
| Fabric | 26.3 / loader 0.19.5 | NoChatReports 2.21.0 + Fabric API 0.163.0 | 服务端启动，Mod 加载 |
| NeoForge | 26.3 / 26.3.0.90 | NoChatReports 2.21.0 | 服务端启动，Mod 加载 |

Java：1.8.9/1.12.2/1.16.5 使用 JDK 8，26.3 使用 JDK 25。

## 5. 建议配置

```ini
allMax = true
autoAdaptMinecraft = true
mbaRewrite = 3
cc = C:/msys64/mingw64/bin/gcc.exe
```

- 需要 VMP 时显式加 `mcForceVmp = true`，并自行验证目标 Mod。
- 重度 Mixin Mod 建议先用 `bodyExcludePrefix` 扩大排除范围。
- 客户端 Mod（如 LiquidBounce）通常没有可独立运行的入口，产物应放回
  `.minecraft/mods` 由 Forge/Fabric 加载。

## 6. 已知边界

- 重度 Mixin + 复杂 handler 的 Mod 仍可能有兼容性问题（实测 Lithium 0.6.6/1.16.5
  存在 handler 内 NPE；同环境 LuckPerms 的简单 Mixin 正常）。
- 26.3 的 Forge/NeoForge 仍处于快速迭代期，升级加载器后建议重新验证。
