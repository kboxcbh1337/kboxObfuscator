# 变更日志 / Changelog

格式：Keep a Changelog ｜ 版本：语义化版本

---

## 3.0.4 — 2026-10-23

### 新增

- **kboXShield 独立产品入口**：`--shield-dll/--shield-in`、`--shield-out`、`--shield-report`、
  `--shield-matrix`，与 JAR 保护流水线完全分离（`com.kbox.core.shield.ShieldCli`）。
- **导出表保留校验**：打包前后解析 PE 导出目录，缺失任具名导出即失败（退出码 4）并删除输出。
- **兼容性矩阵工具**：一次跑完目录内 DLL/EXE，生成 `matrix.json` / `matrix.md`，未覆盖项明确列为"未测试"。
- **SED-VX 语义证据扩散（受限首版）**：语义地图 → 关键切片 → 等价实现池 → 构建种子编排 → 逐方法验证，
  配置键 `sedVx` / `sedVxMaxSlices` / `sedVxBudget`，报告 `kbox-work/sedvx-report.json|.md`。
- **kboXShield DLL 导出表重建**：打包后新增明文 `.kbxed` 节重建导出目录，EAT 指向移位后的函数 RVA；
  同时重建 x64 `.pdata` 与 `.xdata` 副本并翻译 RVA。宿主实测 `LoadLibrary` + `GetProcAddress` 通过。
- **kboXShield 默认安全化**：`defFlags` 默认从 `0x3FFFF` 改为 `0`（AV 活动期可加载）；
  需要主动防御时显式 `--shield-def-flags 0x3FFFF`。
- **HTML UI 产品切换**：右上角新增 `kboxObf` / `kboXShield` 切换，kboXShield 页真实接入
  `/api/shield`（架构、defFlags、IR、SROX、种子、CFG/虚拟化开关）并输出实时日志。
- **长期 MBA**：交织表达式常量支持 `long`；新增变量绑定恒等式（`v == ((v^k)+2*(v&k))-k`）。
- **确定性构建随机源**（`DetRandom`）：CF / 常量 / SED-VX 的形态选择改为按
  (buildSeed, pass, class) 派生，构建可复现且不随线程数变化。
- **文档**：`docs/KBOXSHEID.md`、`docs/KBOXSHEID-COMPATIBILITY.md`、
  `docs/KBOXSHEID-DIFFERENTIATION.md`、`docs/KBOXSHEID-BENCHMARK.md`、
  `docs/CAPABILITY-STATUS.md`、`docs/MIGRATION.md`、`SECURITY.md`。

### 修复

- **平坦化块重排导致指令链成环**：重排后遍历死循环（CF 阶段 100% CPU 卡死），改为经
  `InsnList.remove/add` 重挂。
- **TABLESWITCH 键空间用 int 计算溢出**：`min=Integer.MIN_VALUE` 时误走小表分支，
  逐键循环接近 2^32 次（构建挂起），改用 long 并加上限。
- **VMP 分发表常量索引**：`(st1^st2)` 恒等于 twin 的恒等式已移除；改为 32 位 twin 与
  每运行临时流混合、每次执行重建分发表。
- **字符串解密锚点**：新增 `(Ljava/lang/Object;I)` 变体，拆除"单描述符即可枚举全部解密点"的入口。
- **不透明谓词死支可被 DCE**：新增双分支活代码（两支执行等价更新），死边不可再被直接删除。

### 变更

- GUI 恢复为 v2 的单页 HTML 控制台（仅"保护目标 / 混淆选项 / 高级选项 / 执行"），
  所有开关真实接入当前 `ProtectionConfig`；移除独立的 SED-VX 分析页面，
  SED-VX 改为高级选项中的一个等级（0/1/2）。
- README 恢复为 v2.0 版本内容。

### 已知问题

- **C++ 异常展开（SEH）仍不通过**：已重建 `.pdata`/`.xdata`，抛异常时仍报 “has no image-section”；
  x64 具名导出与 TLS 用例已通过（见 `docs/reports/shield-matrix.md` 与兼容性文档）；
- x86 / 延迟导入未实测；序号导出只校验数量；
- 默认 `defFlags` 已改为 `0`（AV 活动期可加载）；如需主动防御请显式开启并自测。
- 客户端密钥仍无产物外因子，不构成"密钥保密"。

---

## 3.0.3 — 2026-10-2x

- 控制流 / 字符串 / 引用 / VMP / native 加固；Java 8–27 支持。

## 3.0.2 / 3.0.1 / 3.0.0 / 2.x

- 历史版本，见 Git 标签。
