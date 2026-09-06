# kboxDedeobfShieldV1 — 「同机重派生 / 内存无明文」攻坚施工单

> 目标：把「同机攻击者解一次用一辈子」退化成「每次 run 都要 live 逆一次」。
> 钥匙只有一条：**密钥每会话独有 + 只在一次性原生页驻留 + 数据根用 TPM/PCR 锁在本机**。
> 本文档是可落地施工单，逐条给文件/函数锚点、改动内容、成本、验证。

---

## 0. 先立住的一条架构红线（决定 ② 怎么做才不漏）

**Blob 密钥来自构建期，不是运行期。**
- 打包侧 `NativePacker.pack()` 用 `KbnlKey.derive(domain, blobSalt)` 加密 `native.bin/jnic.bin/vmp.bin/native-crypto.bin`（见 `NativePacker.java:94-101`）。
- 运行侧 `NativeLoader/NativeCrypto` 用**同一个** `KbnlKey.domainSeed(domain)` 派生同一把密钥去解。
- `domainSeed = SHA-256( fingerprint() || externalToken() || domainTag )`，其中 `fingerprint()` 在本机确定可重现。

**推论：`perRunEpoch` 不能混进 `domainSeed`（会把打包密钥和运行密钥打散，四个 blob 全部无法打开）。**
「一次性会话」只能做在两类东西上：
1. 运行期才产生的**会话层**（`HardwareKeyRing.ephemeralKey()` / VMP resident 重键 / `VmpInterpreter.ksEph`）——它们已经是 per-run，把熵源换成原生 epoch 即可；
2. 让派生密钥的**根**在硬件上一次性——这是 `TPM2 Sealed + PCR` 的活，也就是「中策」。

所以 ② 的「上策=perRunEpoch」在工程上要修正为：**上策=TPM Sealed（硬件根）+ 会话层原生 epoch + 密钥原生受保护页驻留**。谁要在这里假装「perRunEpoch 进 domainSeed」就违反了红线，行为是「构建即自爆」。

---

## 1. 分档定义（什么是「真无明文」）

| 档位 | 手段 | 明文暴露 | 落地位置 | 本轮 |
|---|---|---|---|---|
| L1 止血 | 锁 token、流式解码、栈上覆盖、会话 epoch | 短 | Java + native | ✅ 本轮做 Java 侧；native 侧给施工图 |
| L2 治本 | TPM Sealed(PCR) + 原生受保护页 + 块级 scrambler + 净代码归原生 | 瞬态 + 不可重放 | native 为主 | ⏳ 施工图 + 前置项 |
| L3 硬件 | TPM2 Sealed Object + PCR 绑定 | 只本机一次性 | native (tss2-esapi) | ⏳ 需 TPM 机器 |
| L4 物理 | Intel SGX / AMD SEV enclave | 外部真无明文 | enclave | ✖ 平台受限，超出范围 |

诚实边界：任何要取指的字节在 CPU 寄存器层就是明文（L4 才能挡）；任何要 stdout/加载的字符串注定出现明文。工程极值 = L2 + L3。

---

## 2. 破口②（决定性）——同机密钥重派生

### 2.1 诊断（已锚定）
- `KbnlKey.fingerprint()` 在本机确定 ⇒ 同机攻手重现一次 = 长期有效，跨会话重放。
- `HardwareKeyRing.ephemeralKey()`/`VmpInterpreter` resident 重键已是 per-run，但熵源是纯 Java `System.nanoTime()`，可预测性高，且密钥驻留 Java 堆。

### 2.2 上策（治本，本轮可做会话层）+ 修正
**A. 会话层原生 epoch（低风险、不破红线）**
- 新增 `KbnlKey.sessionEpoch()`：`SHA-256( MachineFeed || GetSystemTimeAsFileTime-派生x || RDTSC-派生y || 一次性随机 )`，进程内缓存。**只喂会话层**（`ephemeralKey` / resident 重键），绝不进 `domainSeed`。
- 改 `HardwareKeyRing.ephemeralKey()` 把 `sessionEpoch()` 混入 salt，替换纯 `nanosSalt()`。验证：同一进程两次调用一致、跨进程不同。
- native 侧 `kbox_bf_loader.c` 的 `kbox_epochInit`（L197-），把 `GetSystemTimeAsFileTime + RDTSC` 写入 `kbox_epoch_t`；`SecureLoader` 通过新增 JNI 导出 `kbox_sessionEpoch()` 取回混入 Java 会话层。

**B. 派生密钥原生受保护页驻留（治本）**
- 在 `kbox_bf_loader.c` 定义 `kboxKeyStore`: `VirtualAlloc(PAGE_READONLY)` → init 填派生密钥 → `VirtualProtect(PAGE_NOACCESS)` → 退出整页 wipe + VirtualFree。Java 侧 `NativeLoader` 取密钥走 native handle，不留 Java 堆明文。
- 锚点：仿 `kbox_exboxMake/Free`（L607-），沿用现有 guard-page 手法。

### 2.3 中策（L3，硬件，需 TPM 机器 + 平台回退）
- `tss2-esapi` 的 `Esys_Unseal`，PCR 绑定（SecureBoot/BitLocker）；PCR 不匹配 → Unseal 失败 → 密钥拿不到，跨机「连拿都拿不到」。
- 非 Windows / 无 TPM 回退：Linux `/sys/devices/platform/tpm*/tpm*/npmx` 或降级回 2.2-A。
- **前置项**：先落地 2.2-B 的 `kboxKeyStore`，Sealed 只是把「进页的密钥」换成「Unseal 出来的密钥」，改动面收敛。

### 2.4 下策（止血，先做，5 分钟）externalToken 强门控
- `KbnlKey.externalToken()` 现默认空 → 攻击者零成本。
- 加门控：`-Dkbox.requiretoken=true`（或 env `KBOX_REQUIRE_TOKEN`）时，token 为空 → `IllegalStateException` fail-closed。
- 真 token 由打包侧随机生成写入 `META-INF/kbox/method.token` + 清单 attr；运行侧读同一处校验。构建↔运行必须一致，故走 KbnlKey 双端同源（不破红线）。
- 局限：token 本机可读，只防「随手改」，不防「有意逆向」；明确标注。

---

## 3. 破口③——解码明文窗口（流式收敛）

**目标**：把「全段解码 → DefineClass」改成「解一页 → DefineClass → Unmap 该页」，明文驻留压到单页指令级。

**现状锚点**：`kbox_bf_loader.c` 的 `decodeEntryInto`（L1251）/ `kbox_bf_defineClassFromBF`（L1299）。整段解进 `rleDecode→bfRun→inflateInto` 缓冲后 `DefineClass`。

**改动（native，施工图）**：
1. 新增 `deflateStream`：`inflateInto` 改为带回调，每产出 `roundPage` 字节回调一次 `JVM_DefineClass`（分包：内存内定义仍可分段，`nameToClassPath` 需对齐——实测 JVM 支持增量定义，否则退化为「按段 Rolling」）。
2. 每段回调完成后立即对段页 `VirtualProtect(PAGE_NOACCESS)`，全部完成后统一 `wipe + VirtualFree`（现有 `0x3ba0 memset(0) + 0x3b40 VirtualFree` 保留兜底）。
3. 回归：跑 BF 档 jar，确认类能正常定义、`bfshield-run` 全绿。

**风险**：中（重排解码主循环）。建议在独立 `kbox-decrypt-stream` 分支施工，合回前先跑 `ns-full-fast.conf` 半档回归。

---

## 4. 破口④——内存镜像脱壳（冷热节自擦）

**目标**：`JNI_OnLoad` 初始化完成后，擦除「静态分析可利用」的 `.kboxexp/.data` 表层，而非执行用的 `.text`。

**现状锚点**：`kbox_bf_loader.c` `JNI_OnLoad` 完成初始化（RegisterNatives 之后）。

**改动（native，施工图）**：
1. `JNI_OnLoad` 末尾对含派生表/反调试元数据/导出表哈希的节就地覆写（随机 XOR）→ `FlushInstructionCache(GetCurrentProcess(), base, size)`。
2. 目录表/导出表若也被擦则解析会断 —— 只擦「信任校验表」，不擦加载器自身仍需的 PE 表；或保留一个「执行用影子表」并让访问全部走它。
3. 回归：`procdump -ma` 后 `dumpbin /exports` 应扫不到敏感名（M3 已把名字改成 per-build XOR，此项是纵深）。

---

## 5. 破口⑤——时序竞态（X1 毒化 + D4 链式心跳）

**目标**：主 `GetModuleHandleA` 扫描之外，加周期性二次哈希校验 + 双 peer 链式心跳。

**现状锚点**：`kbox_bf_loader.c` `startWatchdog`（L1156）+ `kbox_epoch*`（L184-260）已有互卫 sentinel tick（`h bW1/hbW2`）、`kbox_selfDie`、`kbox_gateCheck`（逐类反 agent）。

**改动（native，施工图）**：
1. watchdog 降 Sleep(100ms) → 加深为「周期哈希再校验」（对非可写节重算 FNV-1a vs 启动时快照）。
2. 双 peer：进程 A 持 half-state，进程 B 持另一半（IPC 共享内存 `named SharedMemory`），任一方失速/成 key 不一致即 `kbox_selfDie` 全链路 poison（字符串毒、VM noise、类残余 wipe、拒启）。
3. 复用 `kbox_epochArmed()` 判定「disarm 安全期」，避免初始化窗口误杀。

---

## 6. 破口①——输出截获（D2 时间锚毒饵）

**目标**：测试串/业务输出守不住，只做反假阳性兜底。
- 采 `HardwareKeyRing`/门控器已有的时间锚，加**阈值保护**（μs 级容差 + 二分窗），避免正常机器误拒启。
- 放最后，非优先。

---

## 7. 本轮已落地（Java 侧，不破红线，已编译回归）

- `KbnlKey.sessionEpoch()`：per-run 原生/混合会话盐，喂会话层（不碰 domainSeed）。
- `KbnlKey.attachEpochRoot(byte[] root)`：把原生侧 per-run epoch 根混入会话 epoch 头（`BfSecureLoader` 启动时喂入），使 per-run 因子不再纯 Java `System.nanoTime()`。仍只停会话层，绝不进 domainSeed。
- `HardwareKeyRing.ephemeralKey()`：混入 `sessionEpoch()`，跨进程不可预测（原纯 `nanosSalt`）。
- `KbnlKey.externalToken()` 门控：`-Dkbox.requiretoken=true` | env `KBOX_REQUIRE_TOKEN` → 空 token fail-closed（下策止血，缺省关闭以保住现有无 token 构建↔运行）。
- `BfSecureLoader` 静态初始化：`NativeLoader.load()` 后调 native `epoch()`（`kbox_bf_sessionEpoch`，load 时 QPC/RDTSC/单调钟派生 32B）→ `KbnlKey.attachEpochRoot()`。构成 2.2-A 全回路：native epoch → Java 会话层 → `ephemeralKey()`。原生不可用则静默回退纯 Java 会话 epoch。

**本轮已回归验证**：kbox-core/kbox-cli 重建（jdk-21 + maven 3.9.6）、`out-nsfull.jar` 用 `ns-full.conf` 全开（BF + JNIC + VMP-native + nativeShell=3 + brainfuckShield=3 + S/D/C/X 全 3）重保护，运行 `bftest.Main` 全绿：`RESOURCE_MATCH=true`、`ENCODING_ROUNDTRIP_EQUAL=true`、exit 0。

**待 native 专档回归（施工图上方已给锚点）**：2.2-B 受保护页密钥驻留（`kboxKeyStore`: VirtualAlloc(READONLY)→init→VirtualProtect(NOACCESS)→退出整页 wipe+Free）、③ 流式解码、④ 节自擦、⑤ 双心跳、TPM Sealed（L3，需 TPM 机器）。

---

## 8. 落地优先级（建议）

| 序 | 修复 | 成本 | 性质 | 状态 |
|---|---|---|---|---|
| 1 | externalToken 强门控（下策） | 低 | 止血 | ✅ 本轮 Java 完成 + 回归 |
| 2 | 会话层原生 epoch + 受保护页驻留（上策核心） | 中 | 治本 | ✅ Java 会话 epoch 接线完成 + native epoch 导出回路回归通过；native 页驻留已给施工图 |
| 3 | 解码窗口流式收敛（③） | 中 | 治本 | ⏳ 施工图，待 native 档 |
| 4 | TPM2 Sealed（中策） | 高 | 治本 | ⏳ 需 TPM 机器 + 平台回退 |
| 5 | 冷热节自擦 + 链式心跳（④⑤） | 中 | 兜底 | ⏳ 施工图，待 native 档 |
| 6 | 时间锚毒饵（①） | 中 | 兜底 | ⏳ 放最后 |

一句话：真的修复是「**TPM Sealed 硬件根 + 会话层原生 epoch + 原生受保护页驻留**」，而「perRunEpoch 进 domainSeed」在 blob 构建↔运行契约下是伪修复，会自我引爆。