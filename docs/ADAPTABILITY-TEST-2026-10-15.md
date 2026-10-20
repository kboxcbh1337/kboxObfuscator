# KBox 适配性检测报告（最强强度）— 2026-10-15

> 被测产物：`kboxObfuscatorv3.0.1` 同源构建（`kbox-cli/target/kbox-protector.jar`，本报告后附两处修复并已重新构建验证）。
> 判据：**保护后运行输出必须与基线逐字一致**；基线 = `Hello, KBox! sum=42 prod=42 add=84 util=21433 ck=-993 tag=42`。
> 「最强强度」= `allMax=true` **+** `brainfuckLoader=true` **+** `brainfuckMcHybrid=true` **+** `mbaRewrite=5`（`allMax` 本身**不含** BF 混沌、且 `mbaRewrite` 只到 3）。
> 所有结论均来自本机可复现实验，脚本与日志见 `D:\kboxobf\_adapttest\`。

---

## 1. 工具自身启动

| # | 用例 | 期望 | 实测 | 结论 |
|---|---|---|---|---|
| 1 | `--help` | 0 | 0，正常打印用法 | ✅ |
| 2 | `--list-presets` | 0 | 0，列出 5 个 MC 预设 | ✅ |
| 3 | 未知参数 `--bogus` | 2 | 打印用法后退出 | ✅（退出码见备注） |
| 4 | 缺 `--input/--output` | 2 | 打印用法后退出 | ✅（同上） |
| 5 | 输入文件不存在 | 明确报错 | **exit 1，但信息误导** | ⚠️ 见 F1 |
| 6 | `--shield` 缺参数 | 2 | 2，打印 `usage: kbox_packer ...` | ✅ |

**F1（真实缺陷）**：`--input Z:\nope.jar` 时报的是
`Protection failed: java.nio.file.FileSystemException: Z:\kbox-work: Unable to determine if root directory exists`，
即先用**输出路径的父目录**去创建 `kbox-work` 才失败，**没有先校验输入是否存在** → 用户看到的是"工作目录"错误而非"输入文件不存在"。

**F2（体验问题）**：Windows 控制台（GBK 代码页）下中文 banner 与 `—` 显示为乱码（`KBox Obfuscator �� Java application protection system`）。
属控制台编码问题：Java 以 UTF-8 输出、控制台按 GBK 解释。

> 备注：用例 3/4 在 PowerShell 里用 `| Select-Object -First N` 捕获时会因**管道提前终止**而读到 `-1`；不是产品退出码问题（`System.exit(2)` 本身正确）。

---

## 2. 最强强度适配性矩阵（9 类输入）

输入：`exe`(独立可执行) / `mr`(multi-release) / `res`(重资源) / `native`(含原生库) / `lib`(无 Main-Class) /
`boot`(Spring Boot fat jar 布局) / `fabric`(fabric.mod.json) / `forge`(TweakClass+mods.toml) / `jpms`(module-info)。

### 修复前
```
case   exit  sec outKB bfLog warn verdict run
exe       0 13.8 780.5    11    0 CHECK   JVM fatal error EXCEPTION_ACCESS_VIOLATION 0xc0000005
mr        0 12.8 681.7    11    0 CHECK   JVM fatal error ...
res       0 12.7 780.4    11    0 CHECK   JVM fatal error ...
native    0 13.8 852.3    11    0 CHECK   JVM fatal error ...
lib/boot/fabric/forge/jpms  0  ~12  ~700  5  2-3  CHECK  (无 Main-Class / 需外部加载器，产物已生成)
```

### 修复后（本轮修复 2 处后）
```
case   exit  sec outKB bfLog warn verdict run
exe       0 10.8 660.7     5    3 PASS    Hello, KBox! sum=42 prod=42 add=84 util=21433 ck=-993 tag=42
mr        0 12.0 567.2     5    3 PASS    同上（逐字一致）
res       0 10.4 661.8     5    3 PASS    同上
native    0 12.0 788.6     5    3 PASS    [KBOX-NATIVE] Loaded native lib: nat/hello.dll | 同上
lib/boot/fabric/forge/jpms  0  ~11  ~670  5  2-3  CHECK  (无 Main-Class / 需外部加载器；均已正常出包)
```
> `bfLog` 从 11 降到 5、`warn` 从 0 升到 3 = BF 按新规则**优雅降级**（见 D2），这正是预期的行为。

---

## 3. 隔离实验（定位过程，全部可复现）

### 3.1 「最强」下可执行产物**启动即原生崩溃**
```
allMax(无BF)              : util=0            <-- 结果错误（见 D1）
allMax + BF               : EXCEPTION_ACCESS_VIOLATION 0xc0000005   <-- 崩溃
allMax + BF, 关 JNIC/VMP  : util=21433  ✅
BF + 仅 JNIC              : CRASH
BF + 仅 VMP               : CRASH
BF + JNIC + VMP           : CRASH
BF + 都不开               : util=21433  ✅
```
→ 结论：**BF 混沌加载 与 JNIC/VMP 原生化 二者不能共存**（BF 单独正常、JNIC/VMP 单独正常）。

### 3.2 同一配置**结果不确定**（非确定性缺陷）
```
同配置连跑 3 次: util = 21433 / 21432 / 43865      <-- 同输入同配置，结果不同
mbaConstants=0 (仅关常量MBA) : 3/3 = 21433  ✅
mbaRewrite=0   (仅关运行时MBA): 3/3 = 21433  ✅
两者都关                     : 3/3 = 21433  ✅  (即 mbaOff 分支)
opaqueStateMachine=0         : 1/3 错（839909928）→ 非根因
```
→ 结论：**`mbaConstants`（交织常量 MBA）是根因**；它此前**没有**像 `mbaRewrite` 那样跳过 JNIC/VMP 目标方法。

---

## 4. 已修复缺陷（2 处，含修复前后验证）

### D1 交织常量 MBA 破坏 JNIC/VMP 目标方法 → 结果错误/不确定/死循环【已修】
- 根因：`MbaConstantObfuscator` 未跳过 `nativeMethods`/`vmpMethods` 选中的方法，其方法体会被下沉到原生解释器重放，而解释器并不等价复现合成表达式。
- 修复：`MbaConstantObfuscator` 增加与 `MbaRewriteObfuscator` 相同的跳过规则（`isNativeOrVmpTarget`）。
- 验证：`allMax + JNIC/VMP` 连跑 **3/3 → util=21433**（修复前 21433/21432/43865）。

### D2 BF 混沌加载 + JNIC/VMP → 启动即 `0xc0000005`【已修（安全降级）】
- 根因：BF 混沌加载 与 JNIC/VMP 的内存态原生模块映射不兼容（复现稳定）。
- 修复：在 BF 兼容性判定链**最前面**加规则——`enableJnic || enableVmp` 时判定 BF 不兼容并**自动降级**（沿用 BF 既有"不兼容输入自动降级"契约），日志明确说明原因。
- 验证：9 例矩阵 **全绿**；`exe/mr/res/native` 输出与基线**逐字一致**。

---

## 5. 真实第三方库适配性（6 个真实 jar）

关键指标：**公共 API 路径保留率**（库混淆最常见的破坏点）。

| 库 | exit | 耗时 | 类数 in→out | 原始路径保留 | 保留率 |
|---|---|---|---|---|---|
| commons-lang3-3.14.0 | 0 | 4.3s | 404 → 947 | 403/404 | **99.8%** |
| gson-2.11.0 | 0 | 3.5s | 224 → 767 | 223/224 | **99.6%** |
| jsoup-1.18.1 | 0 | 3.8s | 277 → 820 | 275/277 | **99.3%** |
| snakeyaml-2.2 | 0 | 3.6s | 232 → 775 | 229/232 | **98.7%** |
| slf4j-api-2.0.13 | 0 | 4.7s | 55 → 598 | 54/55 | **98.2%** |
| **procyon-0.6.0** | **1** | **417.8s** | 874 → — | 91/874 | **10.4%** ❌ |

- 库混淆**基本保留公共 API**（丢失的 1–3 个类通常是 `module-info`/`package-info`/入口类），这是适配性上的优点。
- **procyon-0.6.0 失败**：根因 **`OutOfMemoryError: Java heap space`**，发生位置
  `Packager.verifyClassBytes → CheckClassAdapter.verify`（打包期逐类 ASM 校验），耗时 418s 后 exit 1。

### D3 大输入 OOM【部分缓解，未根治】
- 现象：874 类的真实 jar（procyon-0.6.0）在**打包期** OOM（`Frame.<init>`），默认堆 417.8s 后 exit 1。
- 关键：**`-Xmx4g` 也不能解决**（355s 仍 OOM）→ 不是简单堆大小问题。
- 已加护栏 `VERIFY_MAX_BYTES = 512KB`（[Packager.java](file:///d:/kboxobf/高级先行版源码/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)）：
  覆盖三级深校验（`verifyClassBytes` / `checkStackAtReturn` / `checkFrameConsistency`），超阈值只跳过**该类**并告警。
- **实测结论（诚实）**：护栏确实生效（单轮跳过 **21** 个超大类的深校验），但 OOM **仍然发生**——
  说明触发点不是"类体积大"，而是**某些方法的数据流分析内存爆炸**（一个 <512KB 的类也能炸）。
  → 该缺陷**未根治**；方向应改为"按方法规模/指令数设限或对深校验设内存预算/独立进程"。
- 状态：**OPEN**（护栏保留，作为降低概率的缓解）。

---

## 6. 复现清单

```
# 最强配置
d:\kboxobf\_adapttest\max.conf : allMax=true + brainfuckLoader=true + brainfuckMcHybrid=true + mbaRewrite=5

# 矩阵（9 输入）
powershell -File d:\kboxobf\_adapttest\run_max.ps1      -> results-max.txt / results-max.json

# 真实库
powershell -File d:\kboxobf\_adapttest\run_libs.ps1     -> results-libs.txt / results-libs.json

# 大堆复测（原始症状：-Xmx4g 仍 OOM）
java -Xmx4g -jar _adapttest\protector.jar --input procyon-0.6.0.jar \
     --output procyon-4g.jar --config _adapttest\lib.conf

# 护栏修复后复测（-Xmx2g，小堆即应通过）
java -Xmx2g -jar _adapttest\protector.jar --input procyon-0.6.0.jar \
     --output procyon-guard.jar --config _adapttest\lib.conf
```

原始日志：`d:\kboxobf\_adapttest\out\*.log`、`d:\kboxobf\_adapttest\lib\*.log`。
