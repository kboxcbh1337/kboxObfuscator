# 命令行

```text
java -jar kboxObfuscatorb3.jar --input app.jar --output out.jar [options]
```

不带参数启动会打开桌面 GUI。带任意参数进入命令行模式。

## 基本参数

| 参数 | 说明 |
|---|---|
| `-i`, `--input <path>` | 输入 jar（普通 jar / Spring Boot fat jar / MC Mod） |
| `-o`, `--output <path>` | 输出 jar |
| `-c`, `--config <path>` | 配置文件（见 [CONFIGURATION.md](CONFIGURATION.md)） |
| `--log`, `--log-file <path>` | 额外写一份 UTF-8 日志（避免 Windows 控制台乱码） |
| `--gui` | 启动 GUI，并预填输入/输出/配置 |
| `-v`, `--verbose` | DEBUG 级别日志 + 完整异常栈 |
| `--debug-cf` | 控制流分析逐文件输出 |
| `--main-class <class>` | 输入没有 `Main-Class` 时指定入口 |
| `--shield-native-output <bool>` | 是否给原生产物再套一层壳 |
| `--shield <in.exe> <out.exe>` | 独立 PE 加壳模式（kboXShield） |
| `--list-presets` | 列出内置预设 |
| `-h`, `--help` | 帮助 |

## 我的世界

| 参数 | 说明 |
|---|---|
| `--auto-mc` | 强制开启 Mod 自动识别（默认配置已开启） |
| `--mc-preset <forge\|fabric\|neoforge\|bukkit>` | 应用指定加载器的保留规则 |

## ProGuard 兼容参数

| 参数 | 说明 |
|---|---|
| `-keep <class/package>` | 等价于 `keepPrefix` |
| `-keepclassmembers <owner#name#desc>` | 等价于 `keepMember` |
| `-keepattributes <A,B>` | 等价于 `keepAttributes` |
| `-libraryjars <prefix,...>` | 追加库包前缀 |
| `-userprefix <prefix,...>` | 用户代码前缀（优先于库分类） |
| `-dontwarn` | 抑制警告 |
| `-dontnote` | 静默 |
| `-dontobfuscate` | 关闭重命名 |
| `-dontoptimize` | 关闭控制流混淆 |
| `-neverfail <bool>` | 单类失败是否继续（默认 true） |
| `-useDefaultLibraryPrefixes <bool>` | 是否使用内置库前缀表 |

## 文件选择

| 参数 | 说明 |
|---|---|
| `--include <glob>` | 只处理匹配的类 |
| `--exclude <glob>` | 跳过匹配的类 |
| `--scope <all\|app\|custom>` | 处理范围 |

## 示例

```powershell
# 最高强度 + 完整日志
java -jar dist\kboxObfuscatorb3.jar `
  -i app.jar -o app-protected.jar -c max.conf --log protect.log -v

# 只混淆应用包，保留第三方库
java -jar dist\kboxObfuscatorb3.jar `
  -i app.jar -o app-protected.jar `
  --scope custom --include "com/example/**" --exclude "com/example/api/**"

# PE 加壳
java -jar dist\kboxObfuscatorb3.jar --shield in.exe out.exe
```

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 保护失败（异常） |
| 2 | 参数错误 |
