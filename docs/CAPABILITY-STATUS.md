# 能力状态清单（Capability Status）

> 适用版本：3.0.4 ｜ 更新：2026-10-23
>
> 目的：把"已实现并测试 / 已实现未充分验证 / 设计中 / 暂不支持"分开标注，避免把计划当成能力。
> 任何对外宣传只能引用本表的状态，不得越级。

## 状态定义

| 标记 | 含义 |
|---|---|
| ✅ 已实现并测试 | 有自动化或人工实测记录，可复现 |
| 🟡 已实现未充分验证 | 代码存在、能跑，但样本少或缺少边界测试 |
| 🔵 设计中 | 有设计文档，未实现 |
| ⛔ 暂不支持 | 明确不支持，遇到应降级或拒绝 |

---

## 一、kboXShield（PE）

| 能力 | 状态 | 模块 | 证据 |
|---|---|---|---|
| 独立 DLL 加壳入口（`--shield-dll`） | ✅ | `shield/ShieldCli` | CLI + 契约文档 |
| 输入输出契约 / 退出码 / JSON 报告 | ✅ | `shield/ShieldCli` | `docs/KBOXSHEID.md` |
| 导出表保留**校验**（静态，失败即拒绝） | ✅ | `shield/ShieldCli.PeInfo` | 缺失即退出码 4 |
| DLL **导出表重建/保留**（打包后可用） | ⛔ | `shield/ShieldPacker` | 3.0.4 实测 FAIL（`docs/reports/shield-matrix.md`） |
| x64 DLL 加壳（可被宿主加载） | ⛔ | `shield/ShieldPacker` | 依赖上一项，当前不可用 |
| x64 EXE 加壳 | 🟡 | 同上 | 样本有限 |
| x86 (PE32) | 🟡 | 同上 | 未实测 |
| TLS 回调 / 延迟导入 / SEH | 🟡 | 同上 | 未验证 |
| 序号导出 | 🟡 | 同上 | 仅数量校验 |
| 函数级虚拟化 | 🟡 | `shield/VmEngine` | 有实现，无第三方分析报告 |
| VM 跨构建差异化度量 | 🟡 | `shield/Srox*` | `docs/KBOXSHEID-DIFFERENTIATION.md` |
| 内存加载（不落盘） | ⛔ | — | 不在 3.0.4 范围 |
| 与商业壳的强度对比 | 🔵 | — | 需按 `docs/KBOXSHEID-BENCHMARK.md` 实测 |

## 二、JAR / JVM 保护

| 能力 | 状态 | 模块 | 证据 |
|---|---|---|---|
| 标识符重命名 | ✅ | `name/NameObfuscator` | 编译 + 回归样本 |
| 字符串加密（AES-256-CTR + KBNL） | ✅ | `stringenc/AesStringEncryptor` | 构建/运行验证 |
| 控制流（平坦化 / 不透明谓词） | ✅ | `controlflow/*` | 构建 + 样本运行 |
| 常量 / 交织表达式 | ✅ | `obfu/ConstantObfuscator`、`MbaConstantObfuscator` | 构建验证 |
| 运行期 MBA 重写 | ✅ | `obfu/MbaRewriteObfuscator` | 构建验证 |
| 类型混淆 | 🟡 | `obfu/TypeConfusionObfuscator` | 覆盖面依赖配置 |
| VMP（Java 解释器） | ✅ | `runtime/VmpInterpreter` | 回归样本 |
| JNIC 原生化 | 🟡 | `jnic/*` | 依赖本机编译器与样本 |
| 语义证据扩散（SED-VX） | 🟡 | `sedvx/*` | 3.0.4 首个受限实现：仅 int/long 证据位点，逐方法验证后提交 |
| 原生库磁盘保护（`protectNativeLibs`） | 🟡 | `packaging/NativeLibPacker` | 临时文件落盘，非内存加载 |
| 类体加密 | 🟡 | `packaging/*` | 与框架兼容性相关，按项目开启 |

## 三、密钥与硬件绑定

| 能力 | 状态 | 说明 |
|---|---|---|
| 每构建随机种子（per-build seed） | ✅ | 产物带 `META-INF/kbox/seed.bin`，跨构建不复用 |
| 硬件绑定 / TPM 密封 | 🔵 | 2026-09-05 移除，未重新引入 |
| "硬件派生密钥"宣传 | ⛔ | 已从文档撤回；当前为便携种子派生 |

> 密钥根没有产物外因子（license 服务端/TPM）之前，**不能**声称客户端密钥保密。

---

## 四、维护与发布

| 项 | 状态 |
|---|---|
| 可复现构建（固定 seed） | ✅ 支持 |
| 版本迁移说明 | ✅ `docs/MIGRATION.md` |
| 安全漏洞报告流程 | ✅ `SECURITY.md` |
| 第三方安全审计 | ⛔ 无 |
| 社区问题追踪 | 🟡 GitHub Issues |
