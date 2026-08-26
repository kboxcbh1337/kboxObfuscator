#注意，该仓库目前停止更新暂停所有维护，如果要继续使用请购买kboxobfuscator高级版（19美元/每月）
# KBox Obfuscator

> 一个 ZKM 级、带 **JNIC 原生化** + **VMP 虚拟机** + **原生主密钥派生** 的 Java 字节码防护器。
> A ZKM-level Java bytecode protector with **JNIC native compilation**, **VMP virtual machine**, and **pure-native master-key derivation**.



---

## 📜 许可证 / License

**重要：使用/分发本项目即表示你已阅读并接受 [LICENSE](LICENSE)。**
**By using, copying, or distributing this project you agree to the [LICENSE](LICENSE).**

**一句话条款（以 LICENSE 英文原文为准）：**

- ✅ 任意修改、复制、分发，允许商用。
- ⚠️ 必须**原样保留**代码内水印 `kboxcbh1337` 与 `kboxStudio`。
- ⚠️ 在官网/开源站点必须标明项目**共同开发人**（见下方 [致谢 Credits](#-致谢--共同开发人--credits)）。
- 💰 **任何直接或间接营利性使用**（含销售集成本项目的软件、依托本项目盈利的产品/游戏等）都必须通过**微信或支付宝**向开发者 **kboxcbh1337** 支付**不少于 500 美元**的商业许可费。

> 该许可证属于「源码可用 + 付费商用」的自定义许可，**并非** OSI 批准的开源许可证。

> **Payment & Contact（商业许可支付 / 联系）：** 获取微信/支付宝收款二维码与账号、或咨询商业许可事宜，请通过项目官网或联系 **kboxcbh1337**（GitHub Issues / 项目主页）。

---

## ✨ 特性

| 类别 | 能力 |
|------|------|
| **命名与结构** | 标识符全重命名、包名打散、Kotlin @Metadata 修复、跨包访问修复 |
| **字符串** | AES-256-CTR 集中式加密（16B IV + 惰性缓存）、whitebox / 分散存储 |
| **控制流** | 控制流平坦化、不透明谓词（分级强度）、L3 类型混淆、异常跳转 |
| **JNIC 原生化** | 将方法编译为原生 C，原生库 LZ77+ChaCha20 打包含密，运行时即解即载 |
| **VMP 虚拟机** | 双状态异或分发、惰性解密、滚动窗口 watchdog、篡改静默置噪声 |
| **类加密** | AES-256-GCM 类体加密，密钥绑定真硬件指纹（HKDF 派生） |
| **原生主密钥** | 主密钥在 **native 层**（HKDF-SHA256）派生，不进 Java 堆，每运行换钥 |
| **反分析** | 反编译器对抗 L3、调用图隐藏、调试信息伪造、常量池密钥化 |
| **反调试/反破解** | JDWP/javaagent/attach 检测、完整性校验（SHA-256 防二次打包）、反解包诱饵 |
| **授权/水印** | 256 bit 数字水印、入口守卫混淆、许可证设备绑定 |

---

## 🚀 快速开始

### 构建

```bash
# 需要 JDK 21 + Maven 3.9.x
mvn -DskipTests package -pl kbox-cli -am
# 产物: kbox-cli/target/kbox-protector.jar
```

### CLI 用法

```bash
java -jar kbox-protector.jar --input app.jar --output protected/app.jar
                             [--config kbox.conf] [--gui] [--verbose]
```

全部参数见 `kbox-cli` 的 `ProtectorCli`（`--help`）。

### 配置示例

```ini
renameIdentifiers = true
renamePackages   = true

encryptStrings         = true
stringEncryptionStrength = 3   # AES-256-CTR
obfuscateControlFlow   = true
controlFlowStrength    = 3
enableVmp              = true
vmpCoverage            = full
enableJnic             = true
nativeCoverage         = full
encryptClasses         = true
obfuscateResources     = true
antiDecompilerLevel    = 3
antiDebug              = true
integrityCheck         = true
cc = C:/msys64/mingw64/bin/gcc.exe   # JNIC + native crypto 需要的 C 编译器
```

---

## 🧩 项目结构

```
kbox-core/   # 混淆核心（分析、加密、CF、VMP、JNIC、打包、native crypto）
kbox-cli/    # 命令行入口（ProtectorCli）+ GUI
kbox-work/   # 构建/原生编译的临时工作目录（可忽略）
```

---

## 🙏 致谢 / 共同开发人 / Credits

本项目由以下共同开发者共同开发，**任何分发与展示都必须保留此署名**：

| 角色 | 署名 |
|------|------|
| 开发者（License 持有方） | **kboxcbh1337** |
| 项目 / 团队（水印持有方） | **kboxStudio** |
| 共同开发人 | **kboxhh** |

> 注意：`kboxcbh1337` 与 `kboxStudio` 同时作为代码内水印必须随代码保留，不得移除。

---

---

## ⚠️ 免责声明

本项目仅用于合法的软件保护与安全研究目的。使用本项目时请遵守所在司法辖区的法律法规。作者对因使用本项目产生的任何直接或间接损失不承担责任（详见 LICENSE 第 6 条）。

*KBox Obfuscator — kboxcbh1337 & kboxStudio*