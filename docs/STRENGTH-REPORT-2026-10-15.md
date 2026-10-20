# KBox 强度实测报告 — 2026-10-15

> 工作树：`D:\kboxobf\高级先行版源码`（JDK 21 + Maven 3.9.6）
> 原则：**本文所有数字均为本机实测原始数据**（可复现命令与产物见文末）。所有结论均以本仓库实测为准，
> 不引用未在本机验证的第三方数字，也不做无证据支撑的强弱排名。凡未经实测的推断均明确标注。

---

## 0. 一句话结论（不含营销话术）

KBox 的强度由**多层可独立开关的机制**叠加而成；本轮实测确认：
- 每个强度旋钮都有**单调、可测**的效果（见 §2），且**不改变程序语义**（输出与基线逐字一致）；
- 原生层已做到“**PE 走壳+函数级虚拟化，ELF/Mach-O 走真实加密**”，并产出**可审计的二进制覆盖报告**（见 §3）；
- 本仓库**不具备**声称“行业第一”的证据条件（缺同机基线、缺第三方独立评测），故**不声称**。§5 给出后续强度量化实验的设计。

---

## 1. 测试样本与方法

| 项 | 说明 |
|---|---|
| 样本 | `_verify/demo.jar`：`demo.Hello`（入口，保留）+ `demo.Util`（`addA(int,int)` / `compute(int)` / `checksum(int)` 含密集 `+ - & \| ^ << >>>`） |
| 判据（正确性） | 保护后运行输出必须与基线**逐字一致**：`Hello, KBox! sum=42 prod=42 add=84 util=21433 ck=-993 tag=42`，exit 0 |
| 判据（强度） | 类文件字节数增长、被改写/注入点计数、反编译可读性、产物熵/字节 |
| 反编译对照 | CFR 0.152（`_autotest/samples/cfr-0.152.jar`） |
| 编译基线 | `mvn -f 高级先行版源码/pom.xml clean install -DskipTests`（全绿，5 个 jar） |

---

## 2. 强度旋钮的**实测**效果

### 2.1 运行时 MBA 重写（`mbaRewrite`，本轮新增并扩展 0..5）

把**运行时两个活值之间**的 `IADD/ISUB/IAND/IOR/IXOR` 替换为代数等价位运算恒等树（`a+b → (a^b)+((a&b)<<1)` 等），
按层递归再展开。实测（同一 `demo.Util`，其余开关关闭以隔离变量）：

| `mbaRewrite` | 内部 depth | `demo/Util.class` 字节 | 相对基线 | 改写点数 | 运行结果 |
|---|---|---|---|---|---|
| 0（关） | — | **814** | — | 0 | 基线 |
| 1 | 1 | **1044** | +28% | 18 | 与基线一致 ✅ |
| 2 | 2 | **1200** | +47% | 18 | 与基线一致 ✅ |
| 3 | 3 | **1528** | +88% | 18 | 与基线一致 ✅ |
| 4 | 4 | **2162** | +166% | 18 | 与基线一致 ✅ |
| 5 | 4（上限） | 2162 | +166% | 18 | 与基线一致 ✅ |

> 复现：`_verify/mba{0..4}.conf` + `_verify/mba-l{0..4}.jar`（`Util.class` 已解出到 `_verify/ext-l{0..4}/`）。
> **语义安全**：全部恒等式对 32 位补码成立（模 2^32，溢出无关），改写栈中性；5 个档位输出完全一致。

**反编译对照（CFR 0.152，`mbaRewrite=3`）**：
```java
// 原始：public static int addA(int a,int b){ return a + b; }
// 保护后（方法被重命名，体）：
return (n4 | n3) - (n4 & n3) + ((n4 | n3) - (n4 ^ n3))
     + ((n4 ^ n3) + (n4 & n3) - ((n4 | n3) - (n4 & n3)));
```

### 2.2 JNIC / VMP 原生产物加壳（`shieldNativeOutput`）
| 产物 | 加壳前 | 加壳后（再进 KBNL） | 标记 |
|---|---|---|---|
| `native.bin`（JNIC 库） | 91 648 B | 160 256 B | `[inner PE shell + VM]` |
| `vmp.bin`（VMP 解释器） | 68 608 B | 136 704 B | `[inner PE shell + VM]` |
| `native-crypto.bin` | 21 504 B | 72 192 B | `[inner PE shell + VM]` |

实测运行（JNIC+VMP+加壳全开）输出与基线一致，exit 0。

### 2.3 其他既有强度项的定性说明（本轮未逐项量化，**不虚标数字**）
字符串 AES-256-CTR + KBNL 硬件派生域、控制流平坦化+不透明谓词（分级 1..3）、反编译器 L0..L3、
类型混淆、异常跳转、调用图隐藏、调试信息伪造、类体加密、BF 系列、S/D/C/X 各层——均存在且可开，
但**本轮未做逐项 A/B 量化**（这属于 §5 的“待补实验矩阵”）。

---

## 3. 二进制覆盖矩阵（W2，本轮实测）

样本 `_verify/natdemo.jar` = `demo/*.class` + 一个**真实 PE x64 DLL**（93696 B）+ 合成 ELF x64 `ET_DYN` + 合成 Mach-O x64 `MH_DYLIB`。
配置 `protectNativeLibs=true`，产物内 `META-INF/kbox/native-coverage.txt` 实录：

```
nat/libx.so     | so    | x64 | encrypt-only | raw=256B    | blob=85B
nat/hello.dll   | dll   | x64 | shield+vm    | raw=93696B  | blob=128803B
nat/liby.dylib  | dylib | x64 | encrypt-only | raw=256B    | blob=85B
```

| 格式 | 架构识别 | 处置 | 是否明文残留 |
|---|---|---|---|
| **PE (.dll/.exe)** | x64 / x86 / arm64（machine 字段） | **kboXShield 壳**：全节 ChaCha20 + 合成导入表 + 函数级虚拟化（x64）+ 指令变异 + 平坦化 | 否 |
| **ELF (.so)** | x64 / x86 / arm64（`e_machine`） | **KBNL**：DEFLATE + ChaCha20，运行时解密落盘 `System.load` 后擦除 | 否 |
| **Mach-O (.dylib)** | x64 / x86 / arm64（`cputype`） | 同 ELF | 否 |

> **诚实边界**：ELF/Mach-O 目前是 **encrypt-only**——即“产物里的原生码是密文、运行期解密加载”，
> **没有**等价于 PE 的“壳内函数级虚拟化”；原因是 shell/engine 资产（`blob_*.bin` / `engine_*.bin`）是
> **PE 专用的手写汇编 blob**，且本机无 Linux/macOS 环境做端到端验证。这一限制**已写进产物内的报告文件**，不隐藏。

---

## 4. 本轮顺带修复的真实缺陷（非新增，属既有）

| # | 缺陷 | 影响（实测） | 修复后 |
|---|---|---|---|
| 1 | `Flattener` 引用不存在的 ASM 常量 | **整个工程无法编译** | 全量构建通过 |
| 2 | JNIC 解释器自检 `if (!kbox_self_check())` 取反 | **所有 JNIC 方法恒返回 0**（`add=0 util=0`） | `add=84 util=21433`（与基线一致） |
| 3 | `VmpRuntimeProtector` 运行时引用闭包不完整 | **VMP 无法出包**（拒绝写坏产物） | 闭包收敛通过，VMP 产物可运行 |
| 4 | MBA 展开后 JNIC 解释器语义不一致 | `ck=-993 → -997` | 按既有规则让 MBA 跳过 JNIC/VMP 目标方法 → 一致 |

---

## 5. 后续强度量化实验设计（未完成，明确列出）

1. **同机基线**：对同一组 PE 样本（含开源程序），在不同保护配置下分别处理，作为强度对照。
2. **指标**：
   - 静态：节熵、IAT 合成度、被虚拟化函数占比（`.pdata` 覆盖率）、字符串可恢复率、符号可恢复率；
   - 动态：首个被 dump 到“可反编译形态”的时间（人工+自动化各一组）、内存 dump 语义完整率；
   - 自动化：CFR/jadx/Procyon/IDA/Ghidra 各自的成功率与人工修正量。
3. **样本量**：≥30 个真实程序（桌面 + MC mod + 服务端），每项 ≥3 次重复，报中位数与离散度。
4. **可复现**：脚本 + 原始日志 + 产物哈希全部归档（本仓库 `_verify/` 已是雏形）。

在上述数据产出前，**任何“超过 X”的表述都不成立**——本文不写。

---

## 6. 复现清单

```
# 构建
$env:JAVA_HOME='C:\Program Files\Java\jdk-21'
D:\apache-maven-3.9.6\bin\mvn.cmd -f 高级先行版源码\pom.xml clean install -DskipTests

# MBA 强度阶梯（§2.1）
高级先行版源码\_verify\mba{0..4}.conf  →  mba-l{0..4}.jar  →  ext-l{0..4}/demo/Util.class

# 二进制覆盖（§3）
高级先行版源码\_verify\nat.conf + natdemo.jar  →  natdemo-prot.jar
  解出 META-INF/kbox/native-coverage.txt 查看逐文件处置
```

**原始数据位置**：`D:\kboxobf\高级先行版源码\_verify\`（`*.conf` / `*.jar` / `*.log` / `ext-l*/` / `covout/`）。
