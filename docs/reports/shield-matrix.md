# kboXShield 兼容性矩阵（实测）

| 样本 | 类型 | 架构 | 导出数 | 导出保留 | 结果 | 备注 |
|---|---|---|---|---|---|---|
| `d:\kboxobf\_shieldtest\kbox-shield-test-x64.dll` | DLL | x64 | 2 | 否 | FAIL | 导出表未保留（缺失 2 项） |

## 未测试（不标注为支持）

- x86 (PE32) 样本
- TLS 回调
- 延迟导入 (delay-load)
- SEH / C++ 异常展开
- 序号导出（无名字）
- 插件式 LoadLibrary 热加载
- 反病毒交互

> 只有本表中 PASS 的行代表实测通过；未列出的组合一律视为未验证。
