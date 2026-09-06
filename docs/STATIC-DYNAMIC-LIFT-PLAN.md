# KBox 静态混淆 + 动态钻取防护提升施工单

> 基线：静态 5.4 / 动态 6.2 → 目标 7+ / 8+
> 配套：已实证架构（KbnlKey 会话绑定、KBNL 容器、watchdog、native 解释器、EPL）
> 原则：分批回归，每批编译验证 + 端到端跑测 + 同机实破复测

## 0. 现状校准（spec 勘误）

先纠正 spec 与代码的偏差，避免做"已存在的工作"：

| spec 项 | spec 主张 | 代码实证 | 真实缺口 |
|---------|----------|---------|---------|
| S6 平坦化 | "KBox 缺它" | ✅ 已存在：`Flattener.flatten` 在 [ControlFlowObfuscator.java:237](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java#L237) 被调用，跳过 ctor 与 VMP 目标，带 COMPUTE_FRAMES 校验+回滚 | EPL 选择性 + 指令数上限 |
| S7 字符串进 KBNL | "字符串仍明文/简单变形" | ⚠️ 部分错：`AesStringEncryptor` 已做 AES-256-CTR，但**密钥 T 落 synthetic holder 类**，静态可恢复 | 把 T 路由到 `KbnlKey.sessionBoundKey` |
| S8 stub 分层 | "只铺 EPL 选中" | ⚠️ 反过来：现状按 `nativeMethod` 配置选，**未与 EPL 联动** | 让 JNIC 选例吃 EPL 输出 |
| D6 探头分散 | "watchdog 独立线程+定时扫描" | ✅ 准确：`kbox_watchdog`+`kbox_probeDebugger/Hooks/AgentModules` 都是命名函数 | 内联化 + 模块名分片 |
| D7 节自擦 | "D3 落地" | ❌ `KBoxDedeobfGuard.selfWipeCold` 仅 `Arrays.fill(scratch,0)`，**无 native .data 擦除** | 真正的 native 节擦除 |
| D8 二次校验 | "把 native.bin 的 GetThreadContext 用起来" | ⚠️ 已用于 watchdog（[kbox_bf_loader.c:2097](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c#L2097) 查 Dr7） | 把同校验搬到 VM dispatch |
| D9 流式 decode | "改流式" | ❌ `kbox_defineClassImpl` 仍 decode→define 批处理（已有 `FlushInstructionCache` 后置） | 真流式交替 |

---

## 一、静态混淆提升（5.4 → 7+）

### S7 字符串密钥进 KBNL 会话层（批1，最高优先）

**问题**：[AesStringEncryptor.java:191-234](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/stringenc/AesStringEncryptor.java#L191-L234) 的 `encryptClass` 把构建期随机 AES 密钥 `T` 落进 synthetic holder 的常量池——反编译者拿到 holder 即可静态解全部字符串。

**改动**：
1. `AesStringEncryptor.apply()` 末尾：不再把 `T` 写入 holder 的 `static final byte[]`，改为把 `T` 经 `KbnlKey.sessionBoundKey(domStr, blobSalt)` 包一层后存 holder（domStr 用 `MethodEpdManifest` 的 domain tag）。
2. holder 的 `dec` 方法：先 `KbnlKey.sessionBoundKey(domStr, blobSalt)` 还原 `T`，再 AES 解密。运行期外攻击者拿到的 holder 常量已是会话包装密文，跨会话不同。
3. 防破：保留 `_MCT` 缓存不动；解密后 `Arrays.fill(pt,0)` 已落地（project memory 中 Phase2-L6a 约束）。

**落点文件**：
- [AesStringEncryptor.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/stringenc/AesStringEncryptor.java) — `apply()` 与 `encryptClass()` 改写
- [KbnlKey.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/KbnlKey.java) — `sessionBoundKey` 已存在，新增 `domStr` 重载（吃字符串而非 byte[] salt）

**回归**：
- 字符串解码全绿（`bftest.EncodingTest` 多语言 roundtrip）
- 静态 javap holder 看不到 `T` 明文
- 跨进程跑两次，holder 常量不同

---

### S6 平坦化 EPL 选择 + 指令上限（批2，最大静态收益）

**问题**：[ControlFlowObfuscator.java:236-243](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java#L236-L243) 当前对所有非 ctor/非 VMP 目标方法都跑 `Flattener.flatten`，**无 EPL 选择、无指令数上限**——大方法被平坦化后 switch 巨大，精度暴破风险高。

**改动**：
1. `obfuscateClass` 在 `if (!isCtor && !isVmpTarget)` 分支前加 EPL 白名单过滤：吃 `MethodEpdManifest` 的 selected 列表（已在 Stage8 之前生成）。
2. 加 `insnCount <= MAX_FLATTEN_INSNS`（默认 256）上限；超限方法只跑 opaque predicate，不跑 flatten。
3. EPL 选择策略：**只挑 instruction count ∈ [16, 256] 且非 ctor/non-VMP 的方法**——这是"精度不暴破"与"覆盖率高"的甜点区。
4. 配置项：`flattenerMaxInsns` 默认 256，`flattenerEplOnly=true` 默认开。

**落点文件**：
- [ControlFlowObfuscator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java) — `obfuscateClass` 加 EPL 过滤+上限
- [ProtectionConfig.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ProtectionConfig.java) — 新增 `flattenerMaxInsns`/`flattenerEplOnly`
- [ConfigLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ConfigLoader.java) — 解析新键

**回归**：
- 平坦化方法行为一致（`bftest.PerfTest#arith` 数值结果不变）
- 类仍能 COMPUTE_FRAMES 通过（既有回滚机制保留）
- `--stats` 输出 `methodsFlattened` 数下降但不为 0

---

### S8 JNIC 选例吃 EPL 输出（批3，需 native 回归）

**问题**：[JnicOrchestrator.java:75-208](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/JnicOrchestrator.java#L75-L208) 现状按 `nativeMethod` 配置项选方法（`bftest.PerfTest#arith#(J)J` 一条），未与 EPL 联动，**没"全量铺开"**。

**改动**：
1. 新增配置 `jnicEplDriven=true`：开启后 JNIC 选例 = EPL 选中 ∩ native-eligible（排除 large-frame/unsupported/JDK 类）。
2. `JnicOrchestrator.run()` 在 `nativeMethod` 解析后追加 EPL 驱动分支：从 `MethodEpdManifest` 取 selected 集合，过滤后翻译。
3. 防过载：硬上限 `jnicMaxMethods=32`（避免 native blob 爆炸）。
4. 与 VMP 的关系：**JNIC 与 VMP 都从 EPL 选，但互斥**——EPL selected 内 `jnicEligible` 优先 JNIC，其余走 VMP。这是 spec 里"stub 分层 vs VMP"的统一调度。

**落点文件**：
- [JnicOrchestrator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/JnicOrchestrator.java) — `run()` 加 EPL 驱动分支
- [MethodEpdManifest.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/) — 暴露 `selectedFor(String layer)` 给 JNIC
- [ProtectionConfig.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ProtectionConfig.java) — `jnicEplDriven`/`jnicMaxMethods`

**回归**：
- native blob 不超过 `jnicMaxMethods * 8KB`
- `bftest.PerfTest#arith` native 调用仍返回正确值
- `META-INF/kbox/jnic.bin` 头是 KBNL 新格式（68B 头+随机 domainTag）

---

## 二、动态防护提升（6.2 → 8+）

### D7 native 节自擦（批1，堵 dump 抄家）

**问题**：[KBoxDedeobfGuard.java:127-132](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/KBoxDedeobfGuard.java#L127-L132) 的 `selfWipeCold` 只擦 Java `byte[]`，**native .data/.kboxexp 里的派生表/密钥页 procdump 直接可读**。

**改动**：
1. 新增 native export `kbox_selfWipeNative(int sectionMask)`：按 mask 擦 `.kboxexp` 派生表 + `.data` 密钥页（不擦 `.text`，避免执行中崩）。
2. 擦后 `FlushInstructionCache(GetCurrentProcess(), addr, len)`（[kbox_bf_loader.c:1502](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c#L1502) 已有同款调用）。
3. Java 侧 `KBoxDedeobfGuard.selfWipeCold` 改为：先 `Arrays.fill(scratch,0)`，再 JNI 调 `kbox_selfWipeNative(0x3)`。
4. 触发点：`JNI_OnLoad` 完成解码后立即调一次；`BfSecureLoader` shutdown hook 也调。

**落点文件**：
- [kbox_bf_loader.c](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c) — 新增 `kbox_selfWipeNative` + 注册到 `kbox_bf_methods`
- [KBoxDedeobfGuard.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/KBoxDedeobfGuard.java) — `selfWipeCold` 加 native 调用
- [BfSecureLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/BfSecureLoader.java) — shutdown hook 调 `selfWipeCold(null)`

**回归**：
- procdump 镜像里 `.kboxexp`/`.data` 关键页是 0
- 合法运行仍通过（`ENCODING_ROUNDTRIP_EQUAL=true`）
- shutdown 后 `kbox_selfWipeNative` 退出码 0

---

### D9 明文窗口收敛（批2，堵窗口抓明）

**问题**：[kbox_bf_loader.c:1434-1479](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c#L1434-L1479) 的 `kbox_defineClassImpl` 是 decode-whole-then-define 批处理——明文类字节在 native 堆整驻一瞬，**`_probe 动态抓 epoch` 窗口存在**。

**改动**：
1. 改 `kbox_defineClassImpl` 为流式：按方法/字段为单位从 KBF2 索引流式解，每段定义后立即 `secureFree`+`FlushInstructionCache`。
2. ClassFile 结构本身是顺序的（常量池→字段→方法→属性），按区段流式解码可行。
3. 失败回退：流式失败回退到现有批处理路径（保兼容）。

**落点文件**：
- [kbox_bf_loader.c](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c) — `kbox_defineClassImpl` 重写为流式
- 保留 `kbox_defineClassImpl_batch` 作为 fallback

**回归**：
- 类加载仍正确（`bftest.Main` 可加载）
- 内存窗口扫描器（既有的 `_bf-vfdump-*` 工具）抓不到完整 CAFEBABE 头
- 流式失败回退路径仍工作

---

### D6 探头分散 + 模块名分片（批3，堵 patch）

**问题**：`kbox_probeDebugger`/`kbox_probeHooks`/`kbox_probeAgentModules`（[kbox_bf_loader.c:2048-2695](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c) 范围内）都是**命名函数 + 独立 watchdog 线程**，攻击者 IDA 找到函数名 patch 掉即可。模块名 `"kernel32.dll!IsDebuggerPresent"`（[L2299](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c#L2299)）是**静态字符串**。

**改动**：
1. `kbox_probeAgentModules` 的固定模块名表改为分片存储（XOR 异或 + 运行时拼回），消除静态字符串。
2. 把 `kbox_probeDebugger` 的强信号分支（`IsDebuggerPresent`/`Dr7`）**内联进 `JNI_OnLoad` 主路径**，不再抽独立函数。
3. watchdog 线程保留弱信号（timing/INT3），强信号下沉到主路径，让攻击者 patch watchdog 不再够。
4. 探测点之间插 `__rdtsc()` 散布，无固定时序点。

**落点文件**：
- [kbox_bf_loader.c](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c) — `kbox_probeAgentModules` 模块名分片、`kbox_probeDebugger` 部分内联

**回归**：
- 反调试零误伤（合法运行不被误判）
- IDA 静态搜不到 `kernel32.dll!IsDebuggerPresent` 完整字符串
- `-agentlib:jdwp` 仍被挡死

---

### D8 VM dispatch 二次校验（批3，堵单步）

**问题**：[kbox_bf_loader.c:2097](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_bf_loader.c#L2097) 的 `GetThreadContext` 只在 watchdog 里查 `Dr7`，**VM dispatch 主路径不查**——攻击者单步跑 VMP 不被发。

**改动**：
1. `kbox_vmp_core.c` 的 `executeNative` 主 dispatch 首段加 `GetThreadContext` 自校验：查 `Dr0-Dr3`/`Dr7` 硬件断点 + `EFlags.TF` 单步标志。
2. 命中即 `kbox_selfDie()`（既有的 fail-closed 路径）。
3. 节流：每 N 条指令查一次（默认 N=256），避免性能塌。

**落点文件**：
- [kbox_vmp_core.c](file:///d:/kboxobf/kbox-core/src/main/resources/kbox_vmp_core.c) — `executeNative` 加 dispatch 校验
- `kbox_vmp_core.c` 的 dispatch 循环里加 `if ((++ipc & 0xFF) == 0) kbox_dispatchCheck();`

**回归**：
- VMP 解释性能下降 < 20%（5M 次 fib 基准）
- 硬件断点设上即崩（WinDbg bp 验证）
- 合法运行无影响

---

## 三、落地排期（分批回归）

| 批 | 动作 | 落点层 | 回归重点 | 验收门槛 |
|---|------|-------|---------|---------|
| **批1** | S7 字符串进 KBNL + D7 native 节自擦 | S/D | 字符串全绿; procdump 后等效性 | `ENCODING_ROUNDTRIP_EQUAL=true` + procdump `.kboxexp` 全 0 |
| **批2** | S6 平坦化 EPL 选择 + 指令上限 + D9 流式 decode | S/D | 平坦化方法行为一致; 明文窗口收紧 | `PerfTest#arith` 数值不变 + `_bf-vfdump-*` 抓不到 CAFEBABE |
| **批3** | S8 stub 分层(EPL 驱动) + D6 探头分散 + D8 dispatch 校验 | S/D | native∩EPL; 反调试零误伤 | `jnic.bin` KBNL 新格式 + IDA 搜不到模块名字符串 + 硬件断点崩 |

每批完成后：
1. `mvn -pl kbox-core,kbox-cli install -DskipTests`
2. 重保护 `app.jar` → `out-nsfull.jar`（用 [ns-full.conf](file:///d:/kboxobf/_bftest/ns-full.conf)）
3. 跑 `bftest.Main` 端到端
4. 复跑 ATK6/ATK7 确认无回归
5. 更新 [project_memory.md](file:///c:/Users/cbh12/.trae-cn/memory/projects/-d-kboxobf--p2-74faa1454f12b537965a/project_memory.md)

---

## 四、诚实边界

- **S7 字符串进 KBNL**：会话密钥仍依赖硬件指纹（KbnlKey 既有约束），同机攻击者持有硬件仍可派生。这是 KBox 的硬上限，不是 S7 的缺陷。
- **D7 native 节自擦**：只擦表层 .data/.kboxexp，不擦 .text（执行中擦 = 自爆）。属于"提高 dump 攻击成本"，非"绝对防 dump"。
- **D9 流式 decode**：ClassFile 顺序约束使流式可行，但属性区段可能引用前序常量池，需保留常量池驻留。这是"明文窗口从整类缩到常量池+当前段"，非"零明文"。
- **D6 探头分散**：内联化让 patch 难度上升，但 determined attacker 仍可 patch 内联点。这是"抬高门槛"，非"不可破"。
- **D8 dispatch 校验**：硬件断点检测在用户态可被 PatchGuard 之外的 hook 绕过。属于"逼攻击者上内核态"。
