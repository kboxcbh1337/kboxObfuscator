# kboXShield 独立 PE 保护产品（DLL / EXE）

> 适用版本：3.0.4 ｜ 模块：`kbox-core`（`com.kbox.core.shield`） ｜ 更新：2026-10-23

本文档定义 kboXShield 作为**独立产品**的边界、输入输出契约、错误码与导出接口保留规则。
它不描述 Java/JAR 混淆流水线，也不把两者混称为同一项能力。

---

## 1. 定位与分离原则

kboXShield 只做一件事：**一个 PE 文件进，一个 PE 文件出**。

| 项 | 说明 |
|---|---|
| 输入 | PE32 / PE32+（`MZ` + `PE\0\0`），EXE 或 DLL |
| 输出 | 与输入同架构的 PE；失败时不留下半成品文件 |
| 状态 | 不读取、不修改任何 JAR / class / 资源文件 |
| 进程 | 与 `ProtectionPipeline` 无共享状态，可被独立脚本/CI 调用 |
| 依赖 | 纯 Java 实现，无外部 DLL/命令行工具依赖 |

命令行入口（与 JAR 混淆完全分离）：

```bash
# 单文件
java -jar kboxObfuscator.jar --shield-dll in.dll --shield-out out.dll \
     --shield-report out-report.json [--shield-arch auto|x86|x64]

# 兼容性矩阵（目录或单文件）
java -jar kboxObfuscator.jar --shield-matrix samples\ --shield-out shield-out\ \
     --shield-report shield-out\matrix.json
```

旧入口 `--shield <in.exe> <out.exe>` 仍然保留，等价于最小参数调用。

---

## 2. 输入输出契约

| 契约项 | 规则 |
|---|---|
| 输入校验 | 读取 `e_lfanew` → `PE\0\0`；非法输入直接拒绝（退出码 3），不尝试"修复" |
| 架构 | 默认按输入 COFF `Machine` 自动选择；`--shield-arch` 可显式指定，冲突时以输入为准并记录 |
| 输出写入 | 先打包到目标路径；任何失败都会删除输出，避免部署半个镜像 |
| 可重复性 | `--shield-seed` 固定后，同输入同参数的结构选择可复现（SROX 报告可对照） |
| 报告 | `--shield-report` 输出 JSON：输入/输出 SHA-256、架构、DLL 标志、导出表前后对比、选项串、`ok`/`error` |
| 日志 | 失败原因写入 `error` 字段；不会只打印 "failed" |

### 错误码

| 退出码 | 含义 | 典型原因 |
|---|---|---|
| 0 | 成功 | 打包完成且导出表逐项保留 |
| 2 | 参数错误 | 缺少 `--shield-out`、未知参数、矩阵目录为空 |
| 3 | 输入不支持 | 不是 PE、文件不存在、非 DLL/EXE |
| 4 | 打包失败 | 壳生成失败、输出非法 PE、**导出表未保留** |

> 退出码 4 的"导出表未保留"是硬失败：宁可拒绝打包，也不产出会让宿主 `LoadLibrary`/`GetProcAddress` 失败的 DLL。

---

## 3. 导出接口保留规则

1. 打包前后都解析 PE 导出目录（`DataDirectory[0]`）。
2. 输入中每一个**具名导出**必须在输出中仍然存在，且具名导出总数不得减少。
3. 任一项缺失 → `exportsPreserved=false`，运行失败（退出码 4），输出文件被删除。
4. 序号导出（仅有 ordinal、无名字）目前**只保证条目数量不减少**，名字级对比不适用；这一项在兼容性矩阵中标注为未充分验证。
5. 导出名顺序、RVA 值允许变化（重定位/节布局会变），比较的是**符号集合**，不是字节位置。

> 运行时验证（真实宿主 `LoadLibrary` + `GetProcAddress`）不在本检查范围内，属于兼容性矩阵的实验项。

---

## 4. 四种能力必须分开描述（04）

| 能力 | 入口 | 运行时暴露 | 平台 |
|---|---|---|---|
| **独立 DLL / EXE 加壳** | `--shield-dll` | 壳在加载时解密节并执行；磁盘上是加密镜像 | Windows PE |
| **JAR 内原生库磁盘保护** | 混淆配置 `protectNativeLibs=true` | 解包到临时文件 → `System.load` → 尝试删除；临时文件在加载窗口内**可被观察到** | 依赖平台 |
| **资源封装** | 混淆流水线（资源加密/重命名） | 运行期解密为内存字节，不落盘（除框架自身缓存） | JVM |
| **内存加载** | 不在 3.0.4 范围内 | — | — |

> 结论：`protectNativeLibs` 是"磁盘临时文件 + 加载后删除"，**不等于**内存加载，也不等于 kboXShield 的 PE 加壳。
> 三者不能互相替代，文档与 UI 中不得混写。

---

## 5. 支持范围（诚实版本）

| 项 | 状态 |
|---|---|
| 独立 DLL 入口 + 契约 + 导出表校验 | ✅ 已实现 |
| DLL 导出表重建（打包后仍可 `GetProcAddress`） | ✅ 已实现：新增明文 `.kbxed` 节承载导出目录，EAT 指向移位后的函数 RVA |
| x64 DLL 运行时加载 + 导出调用 | ✅ 实测 PASS（LoadLibrary + GetProcAddress + 调用返回值正确） |
| TLS 回调 | ✅ x86/x64 实测 PASS（回调在 OEP 前由 stub 触发） |
| x64 EXE | 🟡 可打包，样本有限 |
| C++ 异常展开（SEH / `.pdata`+`.xdata`） | ✅ x86/x64 实测 PASS，含 `catch(...)` 与类型匹配 `catch(int)`（3.0.5 修复） |
| x86 (PE32) | ✅ 实测 PASS（3.0.5 修复后：普通导出 / TLS / C++ 异常三样本） |
| chained unwind（`UNW_FLAG_CHAININFO`） | 🟡 未平移链式 `RUNTIME_FUNCTION`，未实测 |
| 延迟导入 | 🟡 未实测 |
| 序号导出（无名） | 🟡 部分：条目数量保留，未做名字级验证 |
| 反病毒共存 | 默认 `defFlags` 已改为 `0`（AV 安全）；需要主动防御时显式 `--shield-def-flags 0x3FFFF` |

> **3.0.5 实测结论**（`docs/reports/shield-matrix.md` + 宿主运行时验证）：
> x86 与 x64 的普通导出 DLL、TLS 回调 DLL、C++ 异常展开 DLL 全部 PASS
> （`checks` 断言通过且退出码 0）。chained unwind、延迟导入等未覆盖项仍按“未验证”处理。

未列出的组合一律视为**未验证**，不得在发布说明中写成“支持”。

---

## 6. 验证方式

1. 构建期：导出表集合对比（自动，失败即拒绝）。
2. 发布期：`--shield-matrix` 在固定样本集上跑一遍，产出 `matrix.json` / `matrix.md`。
3. 外部复测：见 `docs/KBOXSHEID-BENCHMARK.md`（冻结版本、固定参数、邀请未参与开发者复测）。

> 任何"强度提升"的说法都必须附带对应的矩阵结果与失败案例；没有数据就写"未验证"。
