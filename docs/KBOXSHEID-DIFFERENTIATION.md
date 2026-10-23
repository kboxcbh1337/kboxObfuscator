# kboXShield 虚拟机差异化：度量方法与证据

> 适用版本：3.0.4 ｜ 更新：2026-10-23 ｜ 相关模块：`shield/Srox*`、`shield/VmEngine`

本文回答一个问题：**"使用自定义 VM" 本身不是强度证明**——必须能说明不同构建之间到底变了什么、变了多少、以及覆盖率如何计算。

---

## 1. 每次构建会变化的结构

| 结构 | 3.0.4 行为 | 可度量的表现 |
|---|---|---|
| 构建种子 | `--shield-seed` 固定则完全可复现；不固定则每构建唯一 | 同输入不同 seed 的产物 SHA-256 必然不同 |
| 处理函数表布局 | 处理函数槽位按 per-build 排列 | 反汇编中 handler 索引/顺序不同 |
| 操作码映射 | 每条虚拟指令的操作码经置换 | 同一函数的 VM 字节流字节序列不同 |
| 分发表 | 运行期重建（旋转/掩码/间接表） | dump 到的表逐次运行都不同 |
| IR 变异 | `--shield-ir` 控制层级 | 同一语义的指令序列长度/形态不同 |
| CFG 平坦化 | `--shield-no-cfg` 可关闭对照 | 基本块顺序与派发器数量不同 |
| SROX 轮数 | `--shield-srox-rounds` | 每轮变换后的中间结构摘要 |

**注意**：以上差异只有在"归一化后仍然不同"时才算真实差异化。若只是常量池/节排序不同，属于表面差异，不作为证据。

## 2. 覆盖率怎么计算（诚实口径）

工具报告使用三个数，必须同时给出：

- `configured`：配置要求保护的函数数；
- `translated`：实际完成虚拟化/变异的函数数；
- `skipped(reason)`：跳过数与原因（过小、含不支持指令、入口函数、重叠函数、不可提升）。

覆盖率 = `translated / configured`，并附 skip 直方图。**不得只报 translated 的绝对值。**

## 3. 复现实验

```bash
# 同一输入，两个不同种子
java -jar kboxObfuscator.jar --shield-dll test.dll --shield-out a.dll \
     --shield-seed 0x1111 --shield-srox-report report-a.json
java -jar kboxObfuscator.jar --shield-dll test.dll --shield-out b.dll \
     --shield-seed 0x2222 --shield-srox-report report-b.json
```

验收：

1. `a.dll` 与 `b.dll` 的 SHA-256 不同；
2. 两份 `srox-report` 的 handler 布局 / 操作码映射 / 结构摘要不同；
3. 相同 seed 重复构建两次，产物**字节一致**（可复现性）；
4. 两个产物在同一宿主上行为一致（正确性优先于差异化）。

## 4. 跨构建迁移率（对抗性指标）

对同一函数的分析成果（例如手工标注的 handler 语义表）在另一个构建上直接复用的比例：

```
transfer = 可直接沿用的标注数 / 上一构建的标注总数
```

- 只比较"归一化后的图与语义映射"，不比较文件哈希；
- 迁移率越低，差异化越有效；但必须同时满足第 3 节的正确性与可复现性约束。

## 5. 当前证据状态

- 已有：per-build seed、运行期分发表重建、SROX 多轮变换与报告落盘；
- 尚无公开的第三方分析报告；
- 因此**不能**声称"虚拟机强度超过 Themida/VMProtect"。本文只提供可执行的度量协议与工具入口。
