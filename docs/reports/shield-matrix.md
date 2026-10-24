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
| `out2\seh-x86-packed.dll` | x86 | kbox_div, kbox_thrower | 3 | **PASS** | 含 `catch(...)` 与 `catch(int e)` |
| `out2\tls-x86-packed.dll` | x86 | kbox_tls_value | 1 | **PASS** | TLS 回调代跑正常，返回 42 |
| `out2\test-x64-packed.dll` | x64 | kbox_add | 1 | **PASS** | `kbox_add=3` |
| `out2\seh-x64-packed.dll` | x64 | kbox_div, kbox_thrower | 3 | **PASS** | 含 `catch(...)` 与 `catch(int e)` |
| `out2\tls-x64-packed.dll` | x64 | kbox_tls_value | 1 | **PASS** | 返回 42 |

加壳命令（x86 / x64 通用）：

```
java -cp dist/kboxObfuscatorb3.jar com.kbox.cli.ProtectorCli \
     --shield-dll <in.dll> -o <out.dll> --shield-report <report.json>
```

## 未测试（不标注为支持）

- 延迟导入 (delay-load)
- 序号导出（无名字）
- 插件式 LoadLibrary 热加载（同一进程反复 load/unload）
- chained unwind（`UNW_FLAG_CHAININFO`）——打包器未平移其链式 RUNTIME_FUNCTION
- 反病毒交互（本机 AV 活动期曾观测到加载失败，需在 AV 关闭环境复测）

> 只有本表中 PASS 的行代表实测通过；未列出的组合一律视为未验证。

## 缺陷修复与回归基线

### 3.0.5 — x64 C++ 类型匹配 catch 崩溃

**现象**：`catch(...)` 通过，`catch(int e)` 在 `0xC0000005` 崩溃。
**根因**（两处并存，缺一不可）：

1. `PeExports` 把输入 `.xdata` **整体复制**到新增 `.kbxed` 节。GCC 的 LSDA
   **内联**在 `UNWIND_INFO` 之后（handler data 不是 RVA 指针），其 type table
   条目用 `pcrel`（相对条目自身）编码；副本整体位移后，`type_info` 计算值偏出
   `.rdata`/`.data` → `catch_type` 为野指针 → 崩在 libstdc++
   `get_adjusted_ptr` 的 `mov rax,[rbx]`。
2. `ShieldPacker.shiftImageInternals` 平移了 `RUNTIME_FUNCTION` 的
   Begin/End/UnwindData，但**漏平移 `.xdata` 中 `UNWIND_INFO` 的
   `ExceptionHandler RVA`**。仅修第 1 项后，人格例程仍按旧 RVA 被调用，落点是
   平移后 `.text` 的中段乱码（实测 `RIP = 镜像+0x18350`，正确应为 `+0x2a350`）。

**修复**：

- `ShieldPacker.shiftImageInternals` 新增 `patchUnwindInfoHandler()`：按
  `RUNTIME_FUNCTION` 去重后逐个平移 `UNW_FLAG_EHANDLER` 的 handler RVA；
  LSDA 内容不动（与代码同量平移，pcrel 自洽）。
- `PeExports`：`.pdata` 副本的 `UnwindData` 改为指回**原 `.xdata` 节的新 VA**
  （不再复制 `.xdata`），从根上保证 LSDA 与 `type_info` 相对位置不变。

**回归**：`seh-x64-packed.dll` → `checks=3 fails=0`，退出码 0；x86 三样本与
x64 test/tls 同时复测 PASS。

### 3.0.5 — x86 (PE32) 加壳后 `LoadLibrary` 返回 1114

| 缺陷 | 根因 | 修复 |
|---|---|---|
| 导入名被截断 | `kbox_chacha` 尾字节循环用 `%al` 承载数据字节，覆写 `%eax`（buf 指针）低 8 位，末块明文散写到「低字节=数据值」的伪地址，截断 `KERNEL32.dll` / `msvcrt.dll` → 两个 `LoadLibraryA` 失败 → IAT 未绑定 | 改用 `%cl` 承载 |
| 跳 OEP 破坏栈 | stub 把 `ebx/esi/edi` 当通用寄存器且未还原；`ntdll!LdrpCallInitRoutine` 依赖 `esi` 保存的栈快照，返回时 `mov esp,esi` 破坏栈指针 | 入口保存、两处跳 OEP 前恢复 |
| stub 偏移失步 | `BlobLayout.X86` 为手抄常量，stub 指令增删后符号整体漂移（本次 `+32`），配置解密种子读错 → `.Ldead` 静默死循环 | 同步常量，并在 `build_blobs.py` 增加 `BlobLayout.java` 一致性构建闸门 |
