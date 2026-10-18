# KBox Obfuscator 3.0.2

KBox 是一套面向 Java 字节码与原生二进制的多层保护工具。它把**标识符重命名、字符串加密、
控制流变换、常量/MBA 混淆、类型混淆、VMP 虚拟机化、JNIC 原生化、BFVM / BrainfuckShield
二次虚拟化、K-OTP 一次性程序、kboXShield 原生壳**组合在同一条流水线里，并提供桌面 GUI 与
命令行两种入口。

> 本仓库是 3.0.2 的干净源码树。构建产物不随源码提交。

## 保护层

| 层 | 作用 | 开关 |
|---|---|---|
| 重命名 | 类 / 方法 / 字段 / 包名混淆，保留框架与反射契约 | `renameIdentifiers` |
| 字符串加密 | AES-256-CTR + KBNL 盲化表 + 弱引用缓存 + 用后即擦 | `encryptStrings`, `stringEncryptionStrength` |
| 控制流 | 不透明谓词、块平坦化、异常跳转、调用图隐藏 | `obfuscateControlFlow`, `controlFlowStrength` |
| 常量 / MBA | 交织常量表达式、运行时算术恒等式重写 | `obfuscateConstants`, `mbaConstants`, `mbaRewrite` |
| 类型混淆 | 引用/整数经中继载体传递，打断静态类型推断 | `typeConfusion` |
| VMP | 方法体编译为自定义 VM 字节码，解释执行 | `enableVmp`, `vmpCoverage=full` |
| JNIC | 方法体翻译为 C，编译为原生库，`native` 绑定 | `enableJnic`, `nativeCoverage=full` |
| BFVM | 方法体编译为 Brainfuck 方言，由 VM 解释 | `enableBfvm` |
| BrainfuckShield | 对 VMP 方法做**第二层**虚拟化（ChaCha20 密文 + 方言解释） | `brainfuckShield`, `brainfuckShieldLevel` |
| K-OTP | 原生种子驱动的一次性程序，每次调用后重随机 | `enableOtp` |
| kboXShield | PE 壳：全节加密、合成导入表、函数级虚拟化、指令变异 | `nativeShell`, `protectNativeLibs` |
| 反分析 | 反调试、完整性校验、反射门、反反编译器、蜜罐 | `antiDebug`, `integrityCheck`, `reflectionGate`, `antiDecompilerLevel` |
| 元数据 | 擦除 SourceFile / 行号 / 局部变量表 / 泛型签名 | `eraseDebugInfo`, `eraseSignatures` |
| 我的世界适配 | 自动识别 Forge / Fabric / NeoForge / Bukkit 并降级冲突项 | `autoAdaptMinecraft` |

## 环境要求

- **构建**：JDK 8+（`build.ps1` 用 `javac` 直接编译，`kbox-gui` 需要 JDK 17+）。
- **运行**：Java 8+；已在 Java 8 / 17 / 21 / 25 上验证。
- **JNIC / 原生壳（可选）**：MinGW-w64 `gcc`，通过配置 `cc = C:/msys64/mingw64/bin/gcc.exe` 指定。
- Windows PowerShell 5.1+。

## 快速开始

```powershell
# 1. 构建（输出 dist/kboxObfuscatorb3.jar）
powershell -ExecutionPolicy Bypass -File .\build.ps1

# 2. 一键最高强度
java -jar dist\kboxObfuscatorb3.jar `
     -i app.jar -o app-protected.jar `
     -c max.conf --log protect.log

# 3. 桌面界面（无参数启动）
java -jar dist\kboxObfuscatorb3.jar
```

`max.conf` 示例：

```ini
allMax = true                 # 最大强度预设
eraseAnnotations = true
mbaRewrite = 5
encryptClasses = true
obfuscateResources = true
cc = C:/msys64/mingw64/bin/gcc.exe
```

> 对超大 jar（数万类）建议关闭 `mbaRewrite`/`mbaConstants`，或降低 `parallelThreads`，
> 否则堆内存与产物体积会急剧上升。VMP/JNIC/BF 覆盖不受影响。

## 我的世界 Mod

`autoAdaptMinecraft` 默认开启。检测到 `fabric.mod.json`、`META-INF/mods.toml`、
`META-INF/neoforge.mods.toml` 或 `mcmod.info` 时，会：

- 保留入口类、`@Mod`、Mixin 类与目标类、mixins 配置、`accesswidener` / `accesstransformer`；
- 关闭与该加载器冲突的项：类加密、资源混淆、反反编译器畸形属性、BF blob；
- 默认关闭 VMP（`mcForceVmp=true` 可强制开启）；
- 关闭 Mixin 类/目标类的方法体级混淆。

已在 Forge 1.8.9 / 1.12.2 / 1.16.5 / 26.3、Fabric 1.16.5 / 26.3、NeoForge 26.3 上
完成真实服务端加载验证。详见 [docs/MINECRAFT.md](docs/MINECRAFT.md)。

## 文档

- [构建说明](BUILD.md)
- [更新日志](CHANGELOG.md)
- [命令行](docs/CLI.md)
- [配置参考](docs/CONFIGURATION.md)
- [流水线与运行时架构](docs/ARCHITECTURE.md)
- [我的世界适配](docs/MINECRAFT.md)
- [JNIC / VMP 设计](docs/JNIC-VMP-SOLUTION.md)
- [开发日志](docs/devlog/)

## 目录结构

```
kbox-core/          保护流水线、混淆/虚拟化/原生编译器、运行时注入类
kbox-cli/           命令行入口与 GUI 启动器
kbox-gui/           Swing 桌面界面
kbox-maven-plugin/  Maven 集成
kbox-shield/        kboXShield PE 壳（C/汇编 stub 与 VM ISA）
mobile-monitor/     可选的移动端监控客户端
docs/               文档与开发日志
build.ps1           无 Maven 构建脚本
```

## 许可证

见 [LICENSE](LICENSE)。
