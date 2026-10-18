# 更新日志

## 3.0.2

### 适配性

- **字符串解密误报修复**：反调试崩溃日志扫描只认当前进程 PID；计时金丝雀阈值放宽到
  50ms/轮、wall/cpu 250ms；`antiDebug=false` 的产物不再生成 tamper 噪声分支。
- **反射字符串随类名重写**：`Class.forName` / `loadClass` / `getResourceAsStream`
  以及注解值中的类名（`@Mod` 的 `clientSide`、`@SidedProxy`）在重命名后同步更新。
- **JDK 接口覆写保名**：所有 `java/*` 接口的实现方法不再改名，修复
  `AbstractMethodError`（如 `List.iterator`）。
- **InnerClasses 保留**：修复嵌套 record `toString` 与 `getSimpleName()` 退化，
  同时避免 JVM `IncompatibleClassChangeError`。
- **回滚类名字映射**：回滚字节码按最终映射重写，并在父类链查找时归一化原名/新名，
  修复 `NoSuchMethodError`。
- **BFVM**：虚拟化后保留方法注解（Mixin `@Overwrite/@Inject`）；类/字段查找覆盖
  父类接口（Guava `Collection.stream` 等）。
- **JNIC**：类解析改为惰性 + 声明类 loader 兜底；专用服务器上缺失的客户端类不再
  让未执行分支的方法整体失败。
- **VMP**：注入 `bindOwner`，解释器按声明类 loader 解析类型。

### 我的世界

- 识别 Forge 1.8.9/1.12.2 的 `mcmod.info`；`@Mod` 同时读取 `modid`/`value`。
- 修复 `fabric.mod.json` 解析器把 `"environment": "server"` 的值当作 entrypoints 键。
- Mod 场景自动降级：类加密、资源混淆、反反编译器畸形属性、BF blob、VMP
  （新增 `mcForceVmp` 可强制保留 VMP）。
- 在 Forge 1.8.9/1.12.2/1.16.5/26.3、Fabric 1.16.5/26.3、NeoForge 26.3 上完成
  真实服务端加载验证。

### 其他

- 版本号统一为 3.0.2。
- 新增 `mcForceVmp` 配置键。
- 文档重写（README / BUILD / CLI / CONFIGURATION / ARCHITECTURE / MINECRAFT）。

## 3.0.1

- VMP / JNIC / BF 三条保护线的稳定性与覆盖率改进。
- Minecraft Mod 自动适配、资源/类加密降级、Fabric/Forge/NeoForge 元数据保留。
- kboXShield 原生壳、K-OTP 一次性程序、BrainfuckShield 二次虚拟化。

## 3.0

- 首个 3.x 公开版本：重命名、字符串、控制流、VMP、JNIC、BFVM、原生壳。
