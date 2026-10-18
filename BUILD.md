# 构建说明

## 依赖

| 组件 | 版本 | 说明 |
|---|---|---|
| JDK | 8+（GUI 需要 17+） | `build.ps1` 用 `javac` 直接编译，不依赖 Maven |
| PowerShell | 5.1+ | Windows 自带 |
| MinGW-w64 gcc | 可选 | 仅 JNIC / 原生壳 / VMP 原生化需要 |

`build.ps1` 会自动寻找可用的 JDK；也可以用 `JAVA_HOME` 指定。

## 一键构建

```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```

产物：

```
dist/kboxObfuscatorb3.jar      # fat jar（CLI + GUI + core + 依赖）
```

编译目标：

- `kbox-core` / `kbox-cli`：`--release 8`
- `kbox-gui`：`--release 17`

## 仅编译某个模块

```powershell
javac --release 8 -d out\classes `
  -cp "lib\asm-9.7.1.jar;lib\asm-tree-9.7.1.jar" `
  (Get-ChildItem kbox-core\src\main\java -Recurse -Filter *.java)
```

## 原生链（可选）

安装 MinGW-w64 后，在配置中指定：

```ini
cc = C:/msys64/mingw64/bin/gcc.exe
```

只有以下功能需要 `cc`：

- `enableJnic = true` / `nativeCoverage = full`
- `enableVmpNative = true`（VM 解释器原生化）
- `nativeShell > 0`、`protectNativeLibs = true`、`shieldNativeOutput = true`

找不到 `cc` 时，JNIC 会回退到纯 Java 混淆（`failOnNativeError=false` 时）。

## 常见问题

**编译期找不到 ASM**：确认 `lib/` 下的 ASM / kotlinx-metadata / kotlin-stdlib 未被清理；
`build.ps1` 的 `$DepCp` 列出了全部依赖。

**构建后 GUI 无法启动**：GUI 使用 Java 17+ 编译，请用 JDK 17 或更高版本运行 fat jar。

**超大 jar OOM**：降低 `parallelThreads`（如 2–4），关闭 `mbaRewrite` / `mbaConstants`，
或提高 `-Xmx`。VMP/JNIC 覆盖数量与堆内存直接相关。
