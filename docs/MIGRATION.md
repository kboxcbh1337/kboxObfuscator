# 版本迁移指南

## 3.0.3 → 3.0.4

### 兼容性

| 项 | 影响 |
|---|---|
| 配置文件 | 向后兼容。新增键均为可选：`sedVx`、`sedVxMaxSlices`、`sedVxBudget` |
| CLI | 全部旧参数不变；新增 `--sedvx`、`--sedvx-level`、`--shield-dll`、`--shield-out`、`--shield-report`、`--shield-matrix` 等 |
| GUI | 恢复为 v2 单页 HTML 控制台；`--gui` 仍可用。若脚本依赖 3.0.3 的 SED-VX 独立页面，请改用 `--sedvx` 或配置文件 |
| 产物格式 | 不加密格式无变化；class/resource 魔数保持 3.0.3 语义 |
| 构建可复现 | 3.0.4 起同一 build seed 可字节级复现；不同线程数不再影响产物 |

### 迁移步骤

1. 保留旧配置，先原样构建一次，确认产物可启动。
2. 需要语义证据扩散时，添加：

   ```properties
   sedVx=1
   sedVxMaxSlices=200
   sedVxBudget=6
   ```

   构建后检查 `<输出目录>/kbox-work/sedvx-report.json` 中的 `sitesDiffused` 与 `verifyFailures`。
3. 使用独立 PE 保护时，改用新入口（不再与 JAR 混淆混用）：

   ```bash
   java -jar kboxObfuscator.jar --shield-dll in.dll --shield-out out.dll --shield-report r.json
   ```
4. CI 中若解析日志：3.0.4 新增 SED-VX / shield 相关行，旧正则仍匹配，但请更新覆盖率统计口径。

### 回滚

- 回滚到 3.0.3 时，删除上述新键即可；产物不会互相污染。
- 若已用 3.0.4 的 seed 生成产物，回到 3.0.3 需要重新构建（种子合同不同）。

---

## 2.x → 3.x 摘要

- 硬件绑定移除，改为 per-build 便携种子（`META-INF/kbox/seed.bin`）；
- 新增 VMP/JNIC/BFVM/PE 壳等模块；
- 配置键大量新增，旧键保留；
- `docs/CAPABILITY-STATUS.md` 是判断某项能力真实状态的第一来源。
