# kboXShield 兼容性矩阵

> 适用版本：3.0.5 ｜ 生成方式：`--shield-matrix` 实测 + 人工标注未覆盖项 ｜ 更新：2026-10-24

**规则：只有实测通过的行才能写 PASS。没有样本或没有执行的项目写"未测试"，不得写成"支持"。**

---

## 1. 实测矩阵（由工具自动生成）

运行：

```bash
java -jar kboxObfuscator.jar --shield-matrix samples\shield\ --shield-out shield-out\ \
     --shield-report shield-out\matrix.json
```

输出文件：

- `matrix.json`：逐样本 `ok`、`error`、`exportsPreserved`、`missingExports`、前后 SHA-256；
- `matrix.md`：下表的人工可读版本（工具直接生成，不手填）。

| 样本（加壳产物） | 类型 | 架构 | 具名导出数 | 导出保留 | 结构校验 | 运行时验证 |
|---|---|---|---|---|---|---|
| `test-x64-packed.dll` | DLL | x64 | 1 | 是 | PASS | **PASS**（LoadLibrary + GetProcAddress + 调用） |
| `tls-x64-packed.dll` | DLL（TLS 回调） | x64 | 1 | 是 | PASS | **PASS**（TLS 回调 + 导出调用） |
| `seh-x64-packed.dll` | DLL（C++ 异常） | x64 | 2 | 是 | PASS | **PASS**（`catch(...)` + `catch(int)`） |
| `test-x86-packed.dll` | DLL | x86 | 1 | 是 | PASS | **PASS**（LoadLibrary + 导出调用） |
| `tls-x86-packed.dll` | DLL（TLS 回调） | x86 | 1 | 是 | PASS | **PASS**（TLS 回调 + 导出调用） |
| `seh-x86-packed.dll` | DLL（C++ 异常） | x86 | 2 | 是 | PASS | **PASS**（`catch(...)` + `catch(int)`） |
| `host.exe` / `host-x86.exe` | EXE（宿主） | x64/x86 | 0 | — | PASS | 未单独执行 |

> 结论（3.0.5）：x86 (PE32) 与 x64 的具名导出、TLS 回调、C++ 异常展开（含类型匹配
> `catch(int)`）全部实测通过。逐样本判定标准、命令与回归基线见
> `docs/reports/shield-matrix.md`。
> 新增样本后请重新运行矩阵并提交 `shield-matrix.json`，不要手工编辑结果。

---

## 2. 覆盖矩阵（按能力维度）

| 维度 | 用例 | 状态 | 证据 / 备注 |
|---|---|---|---|
| 架构 | x64 (PE32+) | 已测 | 见上表 |
| 架构 | x86 (PE32) | 已测 | 见上表（3.0.5 修复） |
| 编译器 | MSVC | **未测试** | 需 VS 构建样本 |
| 编译器 | mingw-w64 (GCC) | 已测 | 见上表 |
| 编译器 | Clang/LLVM | **未测试** | — |
| 导出 | 具名导出 | 已测 | 重建 `.kbxed` 明文节，EAT 指向移位 RVA |
| 导出 | 序号导出（无名） | **部分** | 仅条目数量保留 |
| 导出 | `__stdcall` 名字修饰 | **未测试** | 需 C++ 样本 |
| 加载 | 静态导入（宿主 EXE） | **未测试** | 需真实宿主 |
| 加载 | `LoadLibrary` + `GetProcAddress` | 已测 | x86/x64 宿主均 PASS |
| 加载 | 延迟导入 (delay-load) | **未测试** | — |
| 运行时 | TLS 回调 | 已测 | x86/x64 样本 PASS |
| 运行时 | SEH / C++ 异常展开 | 已测 | x86/x64 PASS（含 `catch(int)` 类型匹配） |
| 运行时 | chained unwind (`UNW_FLAG_CHAININFO`) | **未测试** | 打包器未平移链式 RUNTIME_FUNCTION |
| 运行时 | 多线程并发调用导出 | **未测试** | — |
| 运行时 | 反病毒/EDR 共存 | **未测试（已知风险）** | 默认 `defFlags` 已改为 `0`；需要防御时显式开启并自测 |
| 打包形态 | 独立 DLL 加壳 | 已测 | `--shield-dll` |
| 打包形态 | JAR 内 `.dll` 原生库加壳 | 已测 | 混淆配置 `protectNativeLibs=true`（不同能力，勿混用） |

---

## 3. 已知失败与限制

1. **AV 活动期加载失败（已缓解）**：默认 `defFlags` 已从 `0x3FFFF` 改为 `0`，发布默认优先保证可加载；
   需要主动防御时用 `--shield-def-flags 0x3FFFF` 显式开启，并在目标 AV 环境自测。
2. **chained unwind 未处理**：`UNW_FLAG_CHAININFO` 的链式 `RUNTIME_FUNCTION` 未随节平移，
   该形态不得标注为支持。
3. **序号导出**：只比较条目数量，未验证序号连续性。
4. **导出表校验是静态的**：不覆盖"导出存在但调用即崩溃"的情形；这类问题必须在运行时矩阵中暴露。

---

## 4. 如何补一条用例

1. 把样本放入 `samples\shield\`（不进发布包，避免体积与授权问题）。
2. 运行矩阵命令；确认 `matrix.json` 中出现该样本。
3. 若为运行时用例（如 TLS / 延迟导入），额外记录宿主程序、输入、期望输出与实际输出。
4. 把"未测试"改为"已测"前，必须有可复现的实验记录。
