# 配置参考

配置文件是逐行 `key = value` 文本，`#` / `;` 开头为注释。未知键会告警但不失败。
`allMax = true` 会先应用最大强度预设，后续行可单独覆盖任意键。

```ini
allMax = true
mbaRewrite = 5
cc = C:/msys64/mingw64/bin/gcc.exe
```

---

## 1. 总开关与重命名

| 键 | 默认 | 说明 |
|---|---|---|
| `allMax` | false | 应用最大强度预设（不包含 `eraseAnnotations` / `nullGuard`） |
| `renameIdentifiers` | true | 类/方法/字段重命名 |
| `renamePackages` | true | 包名重命名（按原包做确定性映射） |
| `obfuscateEntryPoint` | true | 入口类也参与重命名（会写回 Manifest） |
| `mainClass` | — | 覆盖 Manifest 的 `Main-Class` |
| `useMapping` / `mappingFile` | — | 复用已有的类名映射 |
| `fixedXorKey` | false | 使用固定 XOR 密钥（默认每次构建随机） |
| `parallelThreads` | 0（自动） | 并行处理线程数；大 jar 建议 2–4 |

## 2. 字符串

| 键 | 默认 | 说明 |
|---|---|---|
| `encryptStrings` | true | 字符串加密 |
| `stringEncryptionStrength` | 1 | 1=XOR，2=AES-256-CTR + KBNL |
| `whiteboxStrings` | false | 白盒字符串变换 |
| `scatterStrings` | false | 字符串分片散列 |
| `plaintextAudit` | — | 产物明文审计（true 时输出命中列表） |

## 3. 控制流 / 常量 / 类型

| 键 | 默认 | 说明 |
|---|---|---|
| `obfuscateControlFlow` | true | 控制流混淆总开关 |
| `controlFlowStrength` | 2 | 1–3 |
| `flattenerMinInsns` | 16 | 平坦化最小指令数 |
| `flattenerMaxInsns` | 256 | 平坦化最大指令数 |
| `exceptionJumpObf` | false | 用异常分派隐藏跳转 |
| `hideCallGraph` | false | 调用图隐藏 |
| `methodInlineExtract` | false | 方法内联/抽取 |
| `obfuscateConstants` | false | 常量混淆 |
| `mbaConstants` | 0 | 交织常量表达式深度（0–2+） |
| `mbaRewrite` | 0 | 运行时 MBA 重写深度；对超大 jar 很吃内存 |
| `typeConfusion` | 0 | 类型混淆强度（0–3） |

## 4. VMP

| 键 | 默认 | 说明 |
|---|---|---|
| `enableVmp` | false | 开启 VMP |
| `vmpCoverage` | — | `full` = 不设方法数上限 |
| `vmpInterleave` | 0 | 与 JNIC 的交错层数 |
| `enableVmpNative` | false | 把 VM 解释器编译为原生库 |
| `vmpSelfCheck` | false | VM 自检 |
| `vmpMethod` | — | 显式方法列表 `owner#name#desc` |
| `vmpExcludePrefix` | — | 排除包/类前缀 |
| `mcForceVmp` | false | Mod 场景下强制保留 VMP |

## 5. JNIC

| 键 | 默认 | 说明 |
|---|---|---|
| `enableJnic` | false | 开启 JNIC |
| `nativeCoverage` | — | `full` = 不设方法数上限 |
| `jnicEplDriven` | false | 由 EPL 窗口驱动密钥还化 |
| `failOnNativeError` | false | 原生编译失败时是否终止 |
| `cc` | 自动 | C 编译器路径 |
| `nativeMethod` | — | 显式方法列表 |
| `nativeEligiblePrefix` / `nativeExcludePrefix` | — | 参与/排除前缀 |
| `jnicExcludePrefix` | — | 排除前缀 |
| `jniPlatform` | 自动 | 目标平台 |

## 6. BFVM / BrainfuckShield / K-OTP

| 键 | 默认 | 说明 |
|---|---|---|
| `enableBfvm` | false | 方法体编译为 Brainfuck 方言并由 VM 解释 |
| `bfvmMethod` | — | 显式方法列表；为空时自动选择 |
| `brainfuckShield` | false | 二次虚拟化（VMP 方法再套一层） |
| `brainfuckShieldLevel` | 3 | 0–3 |
| `brainfuckLoader` | false | 整 jar 打包为 BF blob 并由自带 loader 引导 |
| `brainfuckMcHybrid` | false | MC 混合模式（宿主加载器 + blob） |
| `enableOtp` | false | K-OTP 一次性程序（依赖 JNIC 原生种子） |

## 7. 类加密 / 资源

| 键 | 默认 | 说明 |
|---|---|---|
| `encryptClasses` | false | 类文件加密（由 guard loader 解密） |
| `encryptClassPrefix` | — | 只加密指定前缀 |
| `obfuscateResources` | false | 资源重命名 + 加密 |
| `encryptResource` / `excludeResource` | — | 资源包含/排除规则 |

> 类加密与资源混淆**不适用于 Minecraft Mod**：加载器会直接 ASM 扫描原始 class，
> 资源也按原路径读取。检测到 Mod 时会自动关闭。

## 8. 反分析 / 元数据

| 键 | 默认 | 说明 |
|---|---|---|
| `antiDecompilerLevel` | 0 | 0–3；2/3 会写入畸形属性 |
| `antiDebug` | false | 反调试金丝雀 |
| `integrityCheck` | false | 产物完整性校验 |
| `reflectionGate` | false | `Class.forName` 白名单门 |
| `nullGuard` | false | `getResourceAsStream` 空流保护（会改变语义） |
| `eraseDebugInfo` | true | 擦除 SourceFile/行号/LVT/MethodParameters |
| `eraseSignatures` | false | 擦除 Signature/EnclosingMethod（InnerClasses 始终保留） |
| `eraseAnnotations` | false | 擦除运行期注解（会改变反射可见性） |
| `fixKotlinMetadata` | true | 重命名后修复 Kotlin `@Metadata` |
| `fakeDebugInfo` | false | 伪造调试信息 |
| `watermark` | — | 写入水印 |

## 9. 原生壳 / 原生库

| 键 | 默认 | 说明 |
|---|---|---|
| `nativeShell` | 3 | kboXShield 强度（0 关闭） |
| `protectNativeLibs` | false | 对 jar 内 `.dll/.so/.dylib` 完整加壳/加密 |
| `shieldNativeOutput` | true | 对 JNIC/VMP 原生产物再套壳 |
| `nativeAntiHook` | false | 原生反 Hook |

## 10. 保留规则 / 适配

| 键 | 默认 | 说明 |
|---|---|---|
| `keepPrefix` | — | 保留类/包（可多次） |
| `keepMember` | — | 保留成员 `owner#name#desc` |
| `keepAttributes` | — | 保留属性名 |
| `bodyExcludePrefix` | — | 排除方法体混淆 |
| `excludeControlFlow` | — | 排除控制流 |
| `libraryPrefix` / `userPrefix` | — | 库/用户代码分类 |
| `autoAdaptMinecraft` | true | 自动识别并适配 MC Mod 加载器 |
| `autoKeepRules` | true | 自动保留反射/框架引用 |
| `neverFail` | true | 单类失败后继续 |
| `rollbackToOriginalBytes` | true | 序列化失败时回滚原始字节（仍会重映射名字） |
| `silentShield` / `silentShieldReport` | true / — | 静默适配审计与报告 |
| `modernStackAdapt` | true | 高版本字节码栈适配 |
| `adaptabilityReport` | — | 输出适配性报告路径 |
| `gpuAccel` | false | GPU 加速（实验性） |

## 11. 许可证（可选）

| 键 | 说明 |
|---|---|
| `licPublicKey` / `licensePublicKey` | 许可证公钥 |
| `licAppSecret` / `licenseAppSecret` | 应用密钥 |
| `lic` | 启用许可证校验 |

---

## 预设建议

**可执行 jar（最高强度）**

```ini
allMax = true
eraseAnnotations = true
mbaRewrite = 5
encryptClasses = true
obfuscateResources = true
brainfuckLoader = true
cc = C:/msys64/mingw64/bin/gcc.exe
```

**超大 jar（>5000 类）**

```ini
allMax = true
mbaRewrite = 0
mbaConstants = 0
parallelThreads = 4
enableVmp = true
enableBfvm = true
brainfuckShield = true
brainfuckShieldLevel = 3
cc = C:/msys64/mingw64/bin/gcc.exe
```

**Minecraft Mod**

```ini
allMax = true
autoAdaptMinecraft = true
mbaRewrite = 3
cc = C:/msys64/mingw64/bin/gcc.exe
# 可选：强制 VMP（默认 Mod 场景关闭）
# mcForceVmp = true
```
