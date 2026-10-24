# kboXShield 兼容性矩阵（实测）

## 判定标准

一行记 **PASS** 必须同时满足：

1. `LoadLibrary` 成功（加壳产物，非原始样本）；
2. `GetProcAddress` 取到的每个导出可调用且断言通过；
3. 进程退出码为 0。

宿主与断言：

- `_shieldtest\host.exe` / `host-x86.exe`：`kbox_add(1,2)==3`、`kbox_div(10,2)==5`、
  `kbox_div(10,0)==-1`、`kbox_thrower(3)==30`、`kbox_tls_value()==42`
  （按样本实际导出集合取子集）。
- 未调用导出、仅“装载成功”的样本不计 PASS（此前的矩阵曾把未加壳原始 DLL 误记为
  PASS，已更正）。

## 实测结果（2026-10-24，`dist\kboxObfuscatorb3.jar` 全默认选项）

| 样本（加壳产物） | 架构 | 导出 | checks | 结果 | 备注 |
|---|---|---|---|---|---|
| `out2\test-x86-packed.dll` | x86 | kbox_add | 1 | **PASS** | `kbox_add=3` |
| `out2\seh-x86-packed.dll` | x86 | kbox_div, kbox_thrower | 3 | **PASS** | 含异常路径 `kbox_thrower(3)=30` |
| `out2\tls-x86-packed.dll` | x86 | kbox_tls_value | 1 | **PASS** | TLS 回调代跑正常，返回 42 |
| `out2\test-x64-packed.dll` | x64 | kbox_add | 1 | **PASS** | `kbox_add=3` |
| `out2\tls-x64-packed.dll` | x64 | kbox_tls_value | 1 | **PASS** | 返回 42 |
| `out2\seh-x64-packed.dll` | x64 | kbox_div, kbox_thrower | 1/3 | **FAIL** | 见「已知缺陷 1」 |

加壳命令（x86 / x64 通用）：

```
java -cp dist/kboxObfuscatorb3.jar com.kbox.cli.ProtectorCli \
     --shield-dll <in.dll> -o <out.dll> --shield-report <report.json>
```

## 已知缺陷

### 1. x64 C++ 异常展开（`seh-x64`）

- **现象**：`LoadLibrary` 成功；`kbox_div` 两个断言通过（其中 `kbox_div(10,0)`
  走 `throw 7` + `catch(...)`，说明**无类型匹配的异常路径正常**）；
  `kbox_thrower`（`throw x` + `catch(int e)`，需类型匹配）触发 `0xC0000005`。
- **崩溃现场**（`dbgrun64.exe` 采样）：`RIP=镜像+0x281E7`（原 RVA `0x161E7`），
  指令为 `mov rax,[rbx] / call [rax+0x20]`（type_info 虚函数调用形态），
  `rbx=0x045b0103d002b104`（野值），`rbp=0`，异常读写地址
  `0xFFFFFFFFFFFFFFFF`；此前已有 2 次 `0x20474343`（GCC EH magic）首机会异常，
  说明异常本身已抛出并进入人格例程。
- **已排除**（逐项实测，均非根因）：
  - reloc 未应用：清除 `DYNAMIC_BASE`/`HIGH_ENTROPY_VA` 使 `delta=0` 后仍崩；
  - 函数虚拟化：`--shield-no-virtualize` 仍崩；
  - 控制流平坦化 / IR 变异 / SROX：`--shield-no-cfg`、`--shield-ir 0`、
    `--shield-no-srox` 组合仍崩；
  - 原始节解密错误：运行时镜像与原始 PE 逐节比对，`.xdata` 差异 0、
    `.text` 仅 2 处各 5 字节（预期的函数级 `jmp` 桥），`.pdata` 为预期的
    `+0x12000` 平移；
  - 异常目录位置：把 `DD[EXCEPT]` 从 `.kbxed` 副本改指真实 `.pdata` 节仍崩；
  - `.kbxed` 内 pdata/xdata 副本：`RUNTIME_FUNCTION.BeginAddress` 已平移、
    `UnwindData` 指向副本、`ExceptionHandler RVA` 已 `0x18350 → 0x2a350` 平移。
- **结论**：失败点已收敛到**类型匹配阶段**（`catch(...)` 通过、`catch(int)` 失败，
  取 type_info 时对象指针为野值），属该阶段指针解析缺陷，尚未定位到具体字段；
  当前不作为支持项宣称。x86 同类异常路径（含 `catch(int e)`）已 PASS。

## 未测试（不标注为支持）

- 延迟导入 (delay-load)
- 序号导出（无名字）
- 插件式 LoadLibrary 热加载（同一进程反复 load/unload）
- 反病毒交互（本机 AV 活动期曾观测到加载失败，需在 AV 关闭环境复测）

> 只有本表中 PASS 的行代表实测通过；未列出的组合一律视为未验证。

## 本次缺陷修复（回归基线）

| 缺陷 | 根因 | 修复 | 回归 |
|---|---|---|---|
| x86 加壳后 `LoadLibrary` 返回 1114 | `kbox_chacha` 尾字节循环用 `%al` 承载数据字节，覆写 `%eax`（buf 指针）低 8 位，导致明文字节散写到“低字节=数据值”的伪地址，截断 `KERNEL32.dll` / `msvcrt.dll` | 改用 `%cl` 承载 | `test/seh/tls` x86 三样本 PASS |
| x86 加壳后 1114（第二根因） | stub 把 `ebx/esi/edi` 当通用寄存器，跳 OEP 前未还原；`ntdll!LdrpCallInitRoutine` 依赖 `esi` 保存的栈快照，返回时 `mov esp,esi` 破坏栈指针 | 入口保存、两处跳 OEP 前恢复 | 同上 |
| x86 stub 偏移失步 | `BlobLayout.X86` 为手抄常量，stub 指令增删后符号整体漂移（本次 `+32`），配置解密种子读错 → `.Ldead` 静默死循环 | 同步常量，并在 `build_blobs.py` 增加 `BlobLayout.java` 一致性构建闸门 | `python build_blobs.py` 两端校验通过 |
