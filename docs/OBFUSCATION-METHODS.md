# KBox 混淆器 — 完整混淆手段报告

本文档按编号列出 KBox 混淆器当前已实现的**全部混淆手段**，每条均包含：实现位置、核心代码片段、字节码/资源变换说明。所有代码均为真实实现节选。

---

## 1. 标识符重命名（ZKM 风格类/方法/字段重命名）

- **实现位置**：[NameObfuscator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/name/NameObfuscator.java) + [Mapping.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/name/Mapping.java) + [RetentionDecision.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/name/RetentionDecision.java)
- **是否有代码示例**：是（下方节选）

核心算法：对类层次做并查集 (union-find)，共享继承边的类归入同一连通分量；每个 `(name, desc)` 组在分量内共享新名；任一成员被 keep 则整组保留原名（匹配 JVM 覆写语义）。

```java
// NameObfuscator.renameMethodGroup：override 等价组的整体保留语义
private void renameMethodGroup(List<String> owners, String name, String desc) {
    for (String o : owners) {
        ClassNode cn = graph.getClasses().get(o);
        if (cn != null && decision.keepMethod(cn, name, desc)) {
            return; // keep original name for everyone
        }
    }
    String newName = mapping.newName();
    for (String o : owners) {
        mapping.mapMethod(o, name, desc, newName);
    }
}
```

```java
// Mapping.newName：base-26 生成 a,b,...,z,aa,ab,... 的混淆短名
public String newName() {
    int n = nextSeq();
    StringBuilder sb = new StringBuilder();
    int v = n;
    do {
        sb.append((char) ('a' + (v % 26)));
        v /= 26;
    } while (v > 0);
    return sb.toString();
}
```

- **变换**：类只改 simple name（保留包名以兼容 Spring 组件扫描）；构造器 `<init>`/`<clinit>` 不改名；通过 ASM `ClassRemapper` + 自定义 `KBoxRemapper` 应用映射，沿 super 链查找真实声明者。
- **保留决策**：`RetentionDecision.keepMethod` 自动保留 `main`、Object 继承方法（`wait/notify/clone/finalize/equals/hashCode/toString`）、Serializable 钩子（`readObject/writeObject/readResolve`）、枚举 `values/valueOf`、`serialVersionUID`、用户配置 keep、反射种子、用户声明的 native 等。

---

## 2. 字符串常量加密（XOR / AES）

- **实现位置**：[StringEncryptor.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/stringenc/StringEncryptor.java) + 运行时 [KBoxRuntime.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/KBoxRuntime.java)
- **是否有代码示例**：是

将方法体内每条 `LDC "literal"` 替换为「内联构造 `byte[]` + 调用 `KBoxRuntime.d()`/`a()` 解密」，明文不再出现在常量池。

```java
// StringEncryptor.buildReplacement：LDC String -> 字节数组构造 + 解密调用
private InsnList buildReplacement(String s) {
    byte[] utf8 = s.getBytes(StandardCharsets.UTF_8);
    int key = rng.nextInt();
    byte[] blob = cfg.getStringEncryptionStrength() == 2
            ? AesHelper.encrypt(utf8, key)
            : XorHelper.encrypt(utf8, key);
    String method = cfg.getStringEncryptionStrength() == 2 ? AES_DEC : XOR_DEC;
    InsnList l = new InsnList();
    pushInt(l, blob.length);
    l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_BYTE));
    for (int i = 0; i < blob.length; i++) {
        l.add(new InsnNode(Opcodes.DUP));
        pushInt(l, i); pushByte(l, blob[i]);
        l.add(new InsnNode(Opcodes.BASTORE));
    }
    l.add(new MethodInsnNode(Opcodes.INVOKESTATIC, RUNTIME_OWNER, method, DEC_DESC, false));
    return l;
}
```

**两种加密强度**：

```java
// 强度1：滚动 XOR（XorHelper.encrypt）—— 前4字节key + 移位混合密钥流
for (int i = 0; i < data.length; i++) {
    int shift = (i * 7) % 32;
    int k = (key >>> shift) ^ (key << (32 - shift) >>> 0);
    out[i + 4] = (byte) (data[i] ^ (k & 0xFF));
}
```

```java
// 强度2：AES/CBC + PKCS5（AesHelper.encrypt）—— [4字节key][16字节IV][密文]
SecretKeySpec k = deriveKey(key);                  // SHA-256(int) 取前16字节
Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
byte[] iv = new byte[16]; new SecureRandom().nextBytes(iv);
c.init(Cipher.ENCRYPT_MODE, k, new IvParameterSpec(iv));
```

- **变换**：`LDC String` → `NEWARRAY byte + 多条 BASTORE + INVOKESTATIC KBoxRuntime.d/a([B)Ljava/lang/String;`；运行时返回 intern 字符串，使 `==`、`switch-on-String` 仍正确。注解字符串在 attribute 里不被改。

---

## 3. 不透明谓词（Opaque Predicates）

- **实现位置**：[ControlFlowObfuscator.java#buildOpaquePredicate](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ControlFlowObfuscator.java)
- **是否有代码示例**：是

插入恒假条件 `if (t*(t+1) % 2 != 0) goto bogus`（两连续整数之积恒为偶），bogus 块为引用 tmp 的死代码，迷惑反编译器。

```java
// buildOpaquePredicate：插入永假分支与死代码块
l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
l.add(new VarInsnNode(Opcodes.ILOAD, tmp));
l.add(new InsnNode(Opcodes.ICONST_1));
l.add(new InsnNode(Opcodes.IADD));
l.add(new InsnNode(Opcodes.IMUL));
l.add(new InsnNode(Opcodes.ICONST_2));
l.add(new InsnNode(Opcodes.IREM));
LabelNode bogus = new LabelNode();
LabelNode end = new LabelNode();
l.add(new JumpInsnNode(Opcodes.IFNE, bogus));     // never taken
l.add(new JumpInsnNode(Opcodes.GOTO, end));
l.add(bogus);
// dead junk: ILOAD tmp; ICONST_3; IMUL; POP  (让 tmp 看似活跃)
```

- **变换**：在方法体中段随机插入不透明分支；强度由 `cfg.getControlFlowStrength()` 控制插入数量；`<init>/<clinit>` 仅插 1 个。

---

## 4. 控制流平坦化（Control Flow Flattening）

- **实现位置**：[Flattener.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/Flattener.java)
- **是否有代码示例**：是

将方法体重写为 `switch(state)` 派发的状态机，原始块顺序被破坏，可见 CFG 塌缩为单一分发循环。

```java
// Flattener.doFlatten：前置 LOOKUPSWITCH 分发器
InsnList head = new InsnList();
int entryId = ids.get(0);
if (entryId >= 0 && entryId <= 5) head.add(new InsnNode(Opcodes.ICONST_0 + entryId));
else head.add(new IntInsnNode(Opcodes.SIPUSH, entryId));
head.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
head.add(dispatch);
// 构建 id -> block label 的映射表
Map<Integer, LabelNode> idToLeader = new LinkedHashMap<>();
for (int i = 0; i < leadersRaw.size(); i++) {
    idToLeader.put(ids.get(i), (LabelNode) leadersRaw.get(i));
}
head.add(new VarInsnNode(Opcodes.ILOAD, stateLocal));
head.add(new LookupSwitchInsnNode(def, keys, lbls));   // switch(state){...}
head.add(def);
head.add(new InsnNode(Opcodes.ATHROW));                // 防御性死代码
mn.instructions.insertBefore(mn.instructions.getFirst(), head);
```

```java
// 块终结跳转改写：GOTO L -> s = id(L); goto dispatch
private static InsnList exitStub(int stateLocal, LabelNode dispatch, int id) {
    InsnList l = new InsnList();
    if (id >= 0 && id <= 5) l.add(new InsnNode(Opcodes.ICONST_0 + id));
    else if (id >= Byte.MIN_VALUE && id <= Byte.MAX_VALUE)
        l.add(new IntInsnNode(Opcodes.BIPUSH, id));
    else l.add(new IntInsnNode(Opcodes.SIPUSH, id));
    l.add(new VarInsnNode(Opcodes.ISTORE, stateLocal));
    l.add(new JumpInsnNode(Opcodes.GOTO, dispatch));
    return l;
}
```

- **变换**：方法体拆为基本块并加入 int 状态变量 `s`；块终结跳转改为 `ISTORE s; GOTO dispatch`；前置 `LOOKUPSWITCH` 派发；strength≥2 时打乱 id 顺序。**准入条件**保守：无 try/catch、无 TABLESWITCH/LOOKUPSWITCH、无 ATHROW、分支≥2，并用 ASM `BasicInterpreter` 验证每个分支目标栈为空。不满足则回退至仅不透明谓词。

---

## 5. VMP 虚拟机保护 — 自定义指令集

- **实现位置**：[VmpOp.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/vmp/VmpOp.java)
- **是否有代码示例**：是

定义单字节操作码 + 内联定宽操作数，覆盖常量/加载、算术、分支、栈操作、字段、方法调用、类型、同步、返回。

```java
public static final byte ICONST        = 0x02; // 1 int operand: value
public static final byte STRING        = 0x06; // 1 int operand: cp index (String)
public static final byte ILOAD         = 0x10;
public static final byte GOTO          = 0x3E; // 1 int operand: target pc
public static final byte INVOKEVIRTUAL   = 0x60;
public static final byte INVOKESTATIC    = 0x62;
public static final byte MONITORENTER  = (byte) 0x80;
public static final byte ATHROW         = (byte) 0x82;
public static final byte IRETURN       = (byte) 0x90;
public static final byte END           = (byte) 0xFF;
```

- **变换**：将 JVM 字节码翻译为自定义字节码，使反编译只能看到 `VmpInterpreter.execute` 调用而非原始逻辑。

---

## 6. VMP 虚拟机保护 — JVM→VMP 字节码翻译

- **实现位置**：[VmpTranslator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/vmp/VmpTranslator.java)
- **是否有代码示例**：是

两遍扫描：Pass 1 计算每条 Label 的 pc 偏移；Pass 2 逐条 emit JVM 指令为 VMP 字节码，建立常量池，并把 try-catch 表翻译成整数数组。

```java
// 方法指令翻译为常量池引用 + VMP 操作码
if (n instanceof MethodInsnNode) {
    MethodInsnNode m = (MethodInsnNode) n;
    int idx = cp.memberRef(m.owner, m.name, m.desc);  // 常量池去重
    switch (op) {
        case Opcodes.INVOKEVIRTUAL: writeOp(out, VmpOp.INVOKEVIRTUAL, idx); return;
        case Opcodes.INVOKESTATIC:  writeOp(out, VmpOp.INVOKESTATIC, idx); return;
        case Opcodes.INVOKESPECIAL: writeOp(out, VmpOp.INVOKESPECIAL, idx); return;
        case Opcodes.INVOKEINTERFACE: writeOp(out, VmpOp.INVOKEINTERFACE, idx); return;
    }
}
```

```java
// 异常表翻译：try-catch -> [start, end, handler, catchTypeCp]
int catchCp = tcb.type == null ? -1 : cp.classRef(tcb.type);
ex[i] = new int[]{start, end, handler, catchCp};
```

- **变换**：`MethodNode.instructions` → `byte[]` 程序 + `Object[] cpRaw`（成员形如 `owner#name#desc`）+ 异常表。不支持的操作码抛 `UnsupportedOpcodeException`，调用方回退到普通混淆。

---

## 7. VMP 虚拟机保护 — 方法体替换为解释器调用桩

- **实现位置**：[VmpMethodInjector.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/vmp/VmpMethodInjector.java)
- **是否有代码示例**：是

新增 3 个 static 字段（`$vmp_<n>` 程序字节、`$vmpcp_<n>` 常量池、`$vmpm_<n>` 缓存的 `VmpMethod`）；`<clinit>` 中构造 `VmpMethod` 并缓存；原方法体清空替换为「装箱参数 + 调用 `VmpInterpreter.execute` + 拆箱返回」的桩。

```java
// 原方法体替换为薄壳
mn.visitFieldInsn(Opcodes.GETSTATIC, cn.name, methodFieldName, "L" + INTERPRETER_METHOD + ";");
if (isStatic) mn.visitInsn(Opcodes.ACONST_NULL);
else mn.visitVarInsn(Opcodes.ALOAD, 0);
pushInt(mn, argTypes.length);
mn.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
for (int i = 0; i < argTypes.length; i++) {
    mn.visitInsn(Opcodes.DUP);
    pushInt(mn, i);
    loadAndBox(mn, argTypes[i], localIdx);   // Integer.valueOf 等
    localIdx += argTypes[i].getSize();
    mn.visitInsn(Opcodes.AASTORE);
}
mn.visitMethodInsn(Opcodes.INVOKESTATIC, INTERPRETER, "execute",
        "(L" + INTERPRETER_METHOD + ";Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
unboxReturn(mn, retType);  // CHECKCAST + intValue() 等
```

- **变换**：`<clinit>` 内联 byte[] 字面量初始化、构造 `VmpMethod`、`PUTSTATIC` 缓存；原方法只剩参数装箱/拆箱的薄壳。

---

## 8. VMP 虚拟机保护 — 运行时解释器

- **实现位置**：[VmpInterpreter.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java)
- **是否有代码示例**：是

单 `switch` 派发循环，`Object[]` 栈 + `Object[]` locals，原语自动装箱/拆箱；常量池懒解析（Class/Field/Method/Constructor 通过反射 `setAccessible(true)` 缓存）；异常表匹配时清栈压异常并跳 handler。

```java
case 0x62: { // INVOKESTATIC
    int idx = readInt(code, pc); pc += 4;
    Method me = resolveMethod(m, cp, idx, true);
    Object[] args2 = popArgs(me.getParameterTypes(), stack, sp);
    sp -= args2.length;
    Object r = me.invoke(null, args2);
    if (me.getReturnType() != void.class) stack[sp++] = r;
    break;
}
```

```java
// 异常表匹配
} catch (Throwable t) {
    if (m.exceptions != null) {
        for (int[] row : m.exceptions) {
            if (ppc >= row[0] && ppc < row[1]) {
                Class<?> catchType = row[3] >= 0 ? resolveClass(m, cp, row[3]) : Throwable.class;
                if (catchType.isInstance(t)) { sp = 0; stack[sp++] = t; pc = row[2]; continue; }
            }
        }
    }
    throw t;
}
```

- **变换**：把 Java 字节码执行转成自定义字节码 + Java 反射调用；纯 Java 实现，兼容 JVM 8..21，不依赖 `sun.misc.Unsafe`。

---

## 8b. BFVM 完整方法虚拟化 — JVM 字节码 → Brainfuck 程序

- **实现位置**（构建侧）：[BfMethodCompiler.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/bfvm/compile/BfMethodCompiler.java)、[BfProgramWriter.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/bfvm/compile/BfProgramWriter.java)、[BfvmMethodInjector.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/bfvm/BfvmMethodInjector.java)
- **实现位置**（运行侧）：[BfInterpreter.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/bfvm/BfInterpreter.java)、[VmCore.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/bfvm/VmCore.java)、[BfRuntime.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/bfvm/BfRuntime.java)
- **是否有代码示例**：是

与 BrainfuckShield（VMP 密文磁带化）不同的独立虚拟化路线：把**真实的 JVM 字节码方法体**整体编译成一段**可执行的 Brainfuck 程序**（纯 `+ - > < [ ] . ,` 数据初始化器），方法体替换为薄 stub 调用 `com.kbox.runtime.bfvm.BfRuntime.call`。运行期先用真正的 BF 解释器把程序逐格回放还原成 BFVM 指令流（进程内缓存），再经 `VmCore`（Object[] 栈机 + 反射调用，语义对齐 JVM）解释执行。

```java
// 构建侧：JVM 指令 -> BFVM 流 -> BF 程序（纯数据初始化）
byte[] stream = BfMethodCompiler.compile(mn, cn.name);
String bf = BfProgramWriter.write(stream);          // cell0/1=长度, 2..=流字节
// 方法体替换为：BfRuntime.call(bf, ownerClass, self, args)
```

```java
// 运行侧：BF 程序 -> 还原流 -> 执行
byte[] stream = BfInterpreter.executeToData(source); // 真正的 BF 解释器
return VmCore.execute(stream, owner, self, args, loader); // Object[] 栈机
```

- **选例**：配置 `enableBfvm=true` + `bfvmMethod = owner#name#desc`（格式同 `vmpMethod`）。已归 VMP/JNIC、构造器、native/abstract、含异常处理/invokedynamic/monitor 等方法自动跳过（保留原混淆体）。
- **运行期边界**：反射返回的 `char/boolean/byte/short` 统一按 JVM int 类表示（`Character`→`Integer` 等）入栈，出参按声明类型回装箱，保证 `charAt(i)` 参与算术等场景语义一致。
- **变换**：真实 JVM 字节码在产物中不再以可读指令存在，而是以 BF 程序字符串 + 解释器形式存在；反编译只能看到 stub 调用。

---

## 9. JNIC 本地化 — 字节码→C/JNI 翻译

- **实现位置**：[JniCTranslator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/JniCTranslator.java)
- **是否有代码示例**：是

生成 `JNIEXPORT <ret> JNICALL Java_<class>_<method>(JNIEnv*, jobject/jclass, ...)`，本地用 `kbox_value_t _stk[64]` 栈机模拟，每条 JVM 指令翻译成几行 C 调用 JNI。

```java
sb.append("  kbox_value_t _stk[64]; int _sp = 0;\n");
sb.append("  kbox_value_t _locals[64];\n");
// INVOKESTATIC -> FindClass + GetStaticMethodID + CallStatic<Type>Method
sb.append("  { jclass _c = (*_env)->FindClass(_env, \"").append(m.owner)
        .append("\"); jmethodID _mid = (*_env)->GetStaticMethodID(_env, _c, \"").append(m.name)
        .append("\", \"").append(sig).append("\"); ");
sb.append("_stk[_sp++].").append(retSuffix).append(" = (*_env)->CallStatic")
        .append(callType(retType)).append("Method(_env, _c, _mid").append(argList).append("); }\n");
```

```java
case Opcodes.ATHROW:
    sb.append("  (*_env)->Throw(_env, (jthrowable)_stk[--_sp].l); return 0;\n");
```

- **变换**：方法体转为 C 源码；不支持的操作码抛 `UnsupportedException` 让调用方回退。

---

## 10. JNIC 本地化 — 编排与 loadLibrary 注入

- **实现位置**：[JnicOrchestrator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/JnicOrchestrator.java)
- **是否有代码示例**：是

对配置中每个 `nativeMethod` 调用 `JniCTranslator.translate`，成功的全部编译；编译成功后把方法 `access |= ACC_NATIVE`、清空 instructions 与 tryCatchBlocks，并在首个类的 `<clinit>` 头部插入 `System.loadLibrary("kbox_native")`。

```java
// 标记方法为 native
for (JniCTranslator.CFunction fn : fns) {
    MethodNode mn = toMark.get(fn.name);
    mn.access |= Opcodes.ACC_NATIVE;
    mn.instructions.clear();
    if (mn.tryCatchBlocks != null) mn.tryCatchBlocks.clear();
    mn.localVariables = null;
}
```

```java
// <clinit> 头部注入 loadLibrary
InsnList head = new InsnList();
head.add(new LdcInsnNode(LIB_NAME));                          // "kbox_native"
head.add(new MethodInsnNode(Opcodes.INVOKESTATIC, "java/lang/System", "loadLibrary",
        "(Ljava/lang/String;)V", false));
clinit.instructions.insert(head);
```

- **变换**：JVM 方法变为 native 桩，原始 Java 字节码消失；JNI 符号名沿用原类/方法名，所以必须在重命名之前执行（`ProtectionPipeline` 已保证）。失败的方法不动，继续走混淆管线。

---

## 11. JNIC 本地化 — 跨平台原生库编译

- **实现位置**：[NativeCompiler.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/NativeCompiler.java)
- **是否有代码示例**：是

编译器优先级 `userCc > $CC > 自动发现(cl.exe/gcc/clang)`；自动拼接 `JAVA_HOME/include` 与平台子目录（win32/linux/darwin）；区分 gcc/clang 与 MSVC 命令行。

```java
cmd.add("-shared");
cmd.add("-fPIC");
cmd.add("-O2");
cmd.add("-I"); cmd.add(javaHome.resolve("include").toString());
String plat = platformInclude();   // win32 / linux / darwin
if (plat != null) {
    Path p = javaHome.resolve("include").resolve(plat);
    cmd.add("-I"); cmd.add(p.toString());
}
cmd.add("-o"); cmd.add(outputDir.resolve(libName + "." + ext).toString());
cmd.add(cSourceFile.toString());
```

- **变换**：产物 `kbox_native.dll` / `libkbox_native.so` / `libkbox_native.dylib`，由 `Packager` 拷贝到输出 jar 同级目录。

---

## 12. 类图与依赖分析

- **实现位置**：[ClassGraph.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/analysis/ClassGraph.java) + [DependencyAnalyzer.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/analysis/DependencyAnalyzer.java)
- **是否有代码示例**：是（非混淆变换本身，但为所有混淆提供 IR）

```java
// ClassGraph.reachableFrom：BFS 闭包
public Set<String> reachableFrom(String root) {
    Set<String> seen = new LinkedHashSet<>();
    ArrayDeque<String> q = new ArrayDeque<>();
    q.add(root);
    while (!q.isEmpty()) {
        String c = q.poll();
        if (!seen.add(c)) continue;
        Set<String> next = references.get(c);
        if (next != null) q.addAll(next);
    }
    return seen;
}
```

```java
// DependencyAnalyzer：兼容普通 jar / Spring Boot executable / Uber jar
if (springBoot) KBoxLog.info(TAG, "Detected Spring Boot executable jar layout");
// 遍历每条指令收集跨类引用
if (ins instanceof MethodInsnNode) {
    MethodInsnNode mi = (MethodInsnNode) ins;
    if (!mi.owner.startsWith("java/") && !mi.owner.startsWith("[")) {
        graph.addReference(owner, mi.owner);
    }
}
```

- **变换**：构建 ClassGraph；Spring Boot 嵌套 jar 也会被解析以保持重命名一致性。

---

## 13. 反射安全扫描（自动 keep）

- **实现位置**：[ReflectionScanner.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/analysis/ReflectionScanner.java)
- **是否有代码示例**：是

自动检测 `Class.forName(String)`、`getDeclaredMethod/Field`、`Proxy.newProxyInstance`、`ServiceLoader.load`、lambda/method-handle bootstrap args，把对应类/成员塞入 `keepSet`；并用 ASM `Analyzer`+`BasicInterpreter` 做 `Class.forName` 字符串常量传播。

```java
if (owner.equals("java/lang/Class") && m.equals(CLASS_FOR_NAME)) {
    String cls = readPrevLdcString(mi);   // 常量传播
    if (cls != null) graph.keep(MemberRef.ofClass(cls.replace('.', '/')));
}
// lambda bootstrap args 中的 Handle
for (Object o : id.bsmArgs) {
    if (o instanceof Handle) {
        Handle h = (Handle) o;
        if (!h.getOwner().startsWith("java/")) {
            graph.keep(new MemberRef(h.getOwner(), h.getName(), h.getDesc()));
        }
    }
}
```

- **变换**：让即使用户忘了 `@Keep`，反射目标仍能被自动保留，做到 safe-by-default。

---

## 14. 资源引用更新（META-INF/services、Spring factories）

- **实现位置**：[ResourceReferenceUpdater.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/ResourceReferenceUpdater.java)
- **是否有代码示例**：是

重写 `META-INF/services/<service-class>` 的文件名与每行实现类、`spring.factories` / `AutoConfiguration.imports` 中逗号/换行分隔的 FQCN，未匹配的类名原样保留。

```java
if (path.startsWith("META-INF/services/")) {
    newText = rewriteLines(text);          // 每行一个 FQCN
} else if (path.endsWith("spring.factories") || path.endsWith("AutoConfiguration.imports")) {
    newText = rewriteFqcns(text);          // 逗号/换行分隔 FQCN
}
return newPath + "\u0000" + newText;       // 用 NUL 分隔路径与内容
```

- **变换**：资源文件路径和内容里的类名随重命名同步更新，使 ServiceLoader、Spring Boot 自动配置等仍能找到重命名后的实现类。

---

## 15. Manifest 更新

- **实现位置**：[ManifestUpdater.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/ManifestUpdater.java)
- **是否有代码示例**：是

刻意避开 `java.util.jar.Manifest`（避免行折叠/规范化破坏下游工具），改用最小文本编辑：找到 `Main-Class:` 行整行替换为映射后类名，并保证以 CRLF+空行结尾。

```java
int i = s.indexOf("Main-Class:");
if (i >= 0) {
    int end = s.indexOf('\n', i);
    if (end < 0) end = s.length();
    s = s.substring(0, i) + "Main-Class: " + newMain + "\r\n" + s.substring(end);
}
if (!s.endsWith("\r\n\r\n")) s = s + "\r\n";
```

- **变换**：MANIFEST.MF 中的 `Main-Class` 跟随重命名更新。

---

## 16. 运行时类注入

- **实现位置**：[Packager.java#injectRuntimeClasses](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)
- **是否有代码示例**：是

按配置从 kbox-core classpath 加载运行时类字节，原样写入受保护 jar（不重命名、不变换），使生成的桩能解析。

```java
if (cfg.isEncryptStrings()) {
    byte[] bytes = loadClasspathResource("com/kbox/runtime/KBoxRuntime.class");
    if (bytes != null) putEntry(out, clsRoot + "com/kbox/runtime/KBoxRuntime.class", bytes);
}
if (cfg.isEnableVmp()) {
    byte[] interp = loadClasspathResource("com/kbox/runtime/VmpInterpreter.class");
    if (interp != null) putEntry(out, clsRoot + "com/kbox/runtime/VmpInterpreter.class", interp);
    byte[] method = loadClasspathResource("com/kbox/runtime/VmpInterpreter$VmpMethod.class");
    if (method != null) putEntry(out, clsRoot + "com/kbox/runtime/VmpInterpreter$VmpMethod.class", method);
}
```

- **变换**：注入 `KBoxRuntime`（字符串解密）和 `VmpInterpreter`+`VmpMethod`（VMP）到 `BOOT-INF/classes/`（Spring Boot）或根路径。

---

## 17. Spring Boot Fat Jar 支持

- **实现位置**：[Packager.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)
- **是否有代码示例**：是

自动检测 `BOOT-INF/classes` + `BOOT-INF/lib` 布局：受保护类写入 `BOOT-INF/classes/`（重命名路径）；`BOOT-INF/lib/*.jar` 依赖原样复制；`org.springframework.boot.loader.*` 启动器类原样复制。

```java
if (springBoot) {
    Enumeration<? extends ZipEntry> en = in.entries();
    while (en.hasMoreElements()) {
        ZipEntry ze = en.nextElement();
        if (ze.isDirectory() || !ze.getName().startsWith("BOOT-INF/lib/")) continue;
        if (!ze.getName().endsWith(".jar")) continue;
        putEntry(out, ze.getName(), readAll(in.getInputStream(ze)));
    }
    // 复制 Spring Boot 启动器
    Enumeration<? extends ZipEntry> en2 = in.entries();
    while (en2.hasMoreElements()) {
        ZipEntry ze = en2.nextElement();
        String n = ze.getName();
        if (n.startsWith("org/springframework/boot/loader/") && n.endsWith(".class")) {
            putEntry(out, n, readAll(in.getInputStream(ze)));
        }
    }
}
```

- **变换**：保护后仍为合法 Spring Boot fat jar，`java -jar` 正常工作。

---

## 18. 非类文件名混淆（资源名随机化）

- **实现位置**：[ResourceNameObfuscator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/resource/ResourceNameObfuscator.java) + [ResourceMapping.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/resource/ResourceMapping.java)
- **是否有代码示例**：是

遍历 jar 中所有非 `.class` 文件，用 `SecureRandom` 生成 16 位十六进制随机名，统一放入扁平 `res/` 目录以隐藏原始目录结构。保留文件扩展名（按扩展名分发的加载器仍能工作），无扩展名则用 `.dat`。Ant 风格 glob 匹配排除/加密名单。

```java
// ResourceNameObfuscator.randomName：扁平 res/ 目录 + 16-hex 随机名 + 保留扩展名
private String randomName(String original) {
    byte[] buf = new byte[8];
    rng.nextBytes(buf);
    StringBuilder sb = new StringBuilder(RES_PREFIX.length() + 24);
    sb.append(RES_PREFIX);                       // "res/"
    for (byte b : buf) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16));
        sb.append(Character.forDigit(b & 0xF, 16));
    }
    String ext = extension(original);
    if (ext != null) sb.append(ext);
    else sb.append(".dat");
    return sb.toString();
}
```

- **安全跳过规则**：`META-INF/MANIFEST.MF`、`META-INF/services/*`（由 #14 处理）、`META-INF/kbox/*`（KBox 内部）、`org/springframework/boot/loader/*`、`spring.factories`、`AutoConfiguration.imports`、`.class` 文件绝不重命名。
- **变换**：原始路径映射表 `originalPath → {newPath, encrypted}` 写入 `ResourceMapping`，供加密器与运行时加载器使用。

---

## 19. 资源内容加密（AES-256-GCM）

- **实现位置**：[ResourceEncryptor.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/resource/ResourceEncryptor.java)
- **是否有代码示例**：是

对匹配 `encryptResourcePatterns` 的资源做 AES-256-GCM 全文件加密。密文布局：`[1-byte magic 'K'][12-byte IV][密文 + 16-byte GCM tag]`。AES 密钥由每个 jar 唯一的 32 字种 `SHA-256` 派生；种子存入 `META-INF/kbox/resource-guard.bin`，运行时由启动器读取。

```java
// ResourceEncryptor.encrypt：每文件随机 IV + AES-GCM
private byte[] encrypt(byte[] data) throws Exception {
    byte[] iv = new byte[IV_LEN];
    rng.nextBytes(iv);
    SecretKeySpec key = deriveKey();                 // SHA-256(seed) 取前 32 字节
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
    byte[] ct = c.doFinal(data);
    ByteBuffer out = ByteBuffer.allocate(1 + IV_LEN + ct.length);
    out.put(MAGIC);                                 // 0x4B 'K'
    out.put(iv);
    out.put(ct);
    return out.array();
}
```

```java
// 密钥派生：种子 -> SHA-256 -> AES-256 key
private static SecretKeySpec deriveKey(byte[] seed) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(seed);
    return new SecretKeySpec(hash, 0, 32, "AES");
}
```

- **变换**：加密后的字节写回 `graph.resources` 的新路径下；非加密资源仅改名。映射表 `resources.map` 本身也用同一 AES-GCM 方案加密后写入 jar，防止枚举原名↔新名对应关系。
- **保守回退**：单个文件加密失败只记录 warning，改以明文存于新名下，不中断构建。

---

## 20. Kotlin 元数据修复（@Metadata 重写）

- **实现位置**：[KotlinMetadataFixer.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/kotlin/KotlinMetadataFixer.java)
- **是否有代码示例**：是

Kotlin 编译的每个类携带 `@kotlin.Metadata` 注解，其 `d1`/`d2` 字段是 ProtoBuf 编码的 `KotlinClassHeader`，内含类名引用。类名重命名后这些引用仍指向旧名，会导致 `KClass.forName`、`::class.memberProperties`、数据类反序列化等失效。本修复器扫描 `d1`/`d2` 的 UTF-8 内容，把旧内部名（`/` 或 `.` 分隔）替换为新名；同时扫描 `.kotlin_module` 文件内容。

```java
// KotlinMetadataFixer.fixClassMetadata：重写 @Metadata 的 d1/d2 字符串数组
for (AnnotationNode an : (List<AnnotationNode>) cn.visibleAnnotations) {
    if (!METADATA_DESC.equals(an.desc)) continue;     // "Lkotlin/Metadata;"
    for (int i = 0; i < an.values.size() - 1; i += 2) {
        String key = (String) an.values.get(i);
        if (!"d1".equals(key) && !"d2".equals(key)) continue;
        String[] arr = (String[]) an.values.get(i + 1);
        for (int j = 0; j < arr.length; j++) {
            String rewritten = rewriteString(arr[j], mapping);
            if (rewritten != null && !rewritten.equals(arr[j])) arr[j] = rewritten;
        }
    }
}
```

```java
// 字节长度保持的替换（避免破坏 ProtoBuf 长度前缀）
if (oldInternal.getBytes(UTF_8).length == newInternal.getBytes(UTF_8).length) {
    result = result.replace(oldInternal, newInternal);
}
```

- **设计权衡**：不引入 `kotlinx-metadata-jvm` 依赖（保持单 jar 分发），改用字节长度保持的字符串替换。长度不一致时跳过该条目（类仍可加载运行，仅该类的 Kotlin 反射降级）。`.kotlin_module` 文件做自由文本替换。
- **变换**：`@Metadata` 注解的 `d1`/`d2` 数组与 `.kotlin_module` 内容中的类引用同步更新为混淆后类名。

---

## 21. 资源守护启动器（Main-Class 替换 + 引导）

- **实现位置**：[ResourceGuardLauncher.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/ResourceGuardLauncher.java) + [ManifestUpdater.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/ManifestUpdater.java)
- **是否有代码示例**：是

启用资源混淆时，`MANIFEST.MF` 的 `Main-Class` 被替换为 `com.kbox.runtime.ResourceGuardLauncher`，原主类名存入自定义属性 `Original-Main-Class`。启动时：①读取 `resource-guard.bin` 种子；②构造 `ResourceGuardClassLoader` 并解密 `resources.map` 载入映射；③设为线程上下文类加载器（Spring/Jackson 等框架据此加载资源）；④反射调用原 `main()`。

```java
// ResourceGuardLauncher.main：五步引导
byte[] seed = readResource(sys, SEED_PATH);             // META-INF/kbox/resource-guard.bin
ResourceGuardClassLoader guard = new ResourceGuardClassLoader(sys, seed);
byte[] map = readResource(sys, MAP_PATH);              // META-INF/kbox/resources.map
map = decryptMap(map, seed);                           // AES-GCM 解密映射表
if (map != null) guard.loadMapping(map);
Thread.currentThread().setContextClassLoader(guard);   // 框架透明接入
launchOriginal(guard, args, guard);                    // 反射调用原 main
```

```java
// ManifestUpdater：Main-Class 替换 + Original-Main-Class 暂存
String replacement = "Main-Class: " + launcherClass + "\r\n"
        + "Original-Main-Class: " + newMain + "\r\n";
s = s.substring(0, i) + replacement + s.substring(end);
```

- **变换**：保护后 jar 启动时先执行 KBox 引导，安装资源解析器后再进入应用主类，应用代码完全无感。未启用资源混淆时此步骤跳过，Main-Class 仅做重命名同步。

---

## 22. 资源守护类加载器（运行时透明资源解析）

- **实现位置**：[ResourceGuardClassLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/ResourceGuardClassLoader.java)
- **是否有代码示例**：是

覆盖 `getResource` / `getResourceAsStream` / `getResources`：应用以原名请求资源时，查映射表找到新路径，经父加载器读取字节，若标记为加密则 AES-GCM 解密，返回原始字节。结果内存缓存避免重复解密。**不覆盖 `loadClass`**——类加载仍走 JVM 默认链，避免分裂类加载器的风险。

```java
// ResourceGuardClassLoader.resolve：原名 -> 新路径 -> 解密 -> 缓存
private byte[] resolve(String name) {
    if (cache.containsKey(name)) return cache.get(name);
    Entry e = map.get(name);                          // 查映射表
    if (e == null) { cache.put(name, null); return null; }
    InputStream in = delegate.getResourceAsStream(e.newPath);
    byte[] raw = readAll(in);
    if (e.encrypted) raw = decrypt(raw);               // AES-GCM 解密
    cache.put(name, raw);
    return raw;
}
```

```java
// getResourceAsStream 透明委派
@Override
public InputStream getResourceAsStream(String name) {
    byte[] data = resolve(name);
    if (data != null) return new ByteArrayInputStream(data);
    return super.getResourceAsStream(name);           // 未映射资源走默认
}
```

- **变换**：应用代码与框架（Spring `ClassPathResource`、Jackson、ServiceLoader）调用 `ClassLoader.getResource(...)` 时自动得到解密后的原始资源字节，完全无感。类加载（`loadClass`）不受影响，与类名映射体系严格分离。

---

## 23. 运行时元数据注入（加密映射表 + 种子 + 守护类）

- **实现位置**：[Packager.java#injectResourceGuardClasses](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java) + [Packager.java#writeResourceGuardMetadata](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)
- **是否有代码示例**：是

向受保护 jar 注入三类运行时资产：①`META-INF/kbox/resources.map`（AES-GCM 加密的映射表）；②`META-INF/kbox/resource-guard.bin`（32 字节 AES 种子）；③所有 `ResourceGuard*` 运行时类（启动器 + 加载器 + 内部类）。守护类通过自动发现 classpath 上 `com/kbox/runtime/ResourceGuard*.class`（jar 枚举或目录列举）注入，避免漏掉匿名内部类（如 `$1`、`$Entry`）。

```java
// Packager.discoverGuardClasses：自动发现所有 ResourceGuard* 类（含内部类）
if ("jar".equals(url.getProtocol())) {
    ZipFile zf = new ZipFile(new File(((JarURLConnection) url.openConnection())
            .getJarFileURL().toURI()));
    Enumeration<? extends ZipEntry> en = zf.entries();
    while (en.hasMoreElements()) {
        String n = en.nextElement().getName();
        if (n.startsWith("com/kbox/runtime/ResourceGuard") && n.endsWith(".class"))
            out.add(n.substring(0, n.length() - ".class".length()));
    }
}
```

```java
// writeResourceGuardMetadata：加密映射表 + 写种子
byte[] mapBytes = mapping.serialize();
encryptedMap = encryptMap(mapBytes, seed);             // AES-GCM
putEntry(out, "META-INF/kbox/resources.map", encryptedMap);
putEntry(out, "META-INF/kbox/resource-guard.bin", seed);
```

- **变换**：受保护 jar 自包含全部解密所需资产，标准 JVM `java -jar` 即可运行，无需额外参数或 agent。

---

## 24. 反反编译器对抗（Anti-Decompiler）

- **实现位置**：[AntiDecompiler.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/AntiDecompiler.java)
- **是否有代码示例**：是

向受保护 jar 注入一个合成类 `com/kbox/runtime/_KboxAntiDec`，承载四种针对反编译器/分析器解析缺陷的字节码模式。强度由 `antiDecompilerLevel` 控制（0=off, 1=light, 2=medium, 3=aggressive）。所有变换均产生 JVM 合法字节码——`java -jar` 完全正常——但会让 Recaf/JD-GUI/Bytecode Viewer 卡死、OOM 或解析失败。

```java
// AntiDecompiler.apply：分强度注入四种"工具对抗"模式
public void apply() {
    int level = cfg.getAntiDecompilerLevel();
    if (level <= 0) return;
    ClassNode sink = ensureSinkClass();
    int labels = level >= 3 ? 30000 : (level >= 2 ? 12000 : 5000);
    injectGotoChain(sink, labels);            // 1.1 巨型方法 + 深度嵌套循环标签
    if (level >= 2) {
        injectExceptionBomb(sink);            // 1.2 异常处理表泛滥
        injectSelfReferencingInnerClasses(sink); // 1.3 无限递归类继承关系
    }
    if (level >= 3) {
        injectConstantPoolBomb(sink);         // 1.4 常量池炸弹（65535 字节 CONSTANT_Utf8）
    }
}
```

```java
// 1.1 goto 链：L0: nop; goto L1; L1: nop; goto L2; ...
//    JVM 线性执行无开销；JD-GUI 路径枚举堆栈溢出，Recaf UI 假死
for (int i = 0; i < labelCount; i++) {
    l.add(labels[i]);
    l.add(new InsnNode(Opcodes.NOP));
    if (i + 1 < labelCount) {
        l.add(new JumpInsnNode(Opcodes.GOTO, labels[i + 1]));
    } else {
        l.add(new InsnNode(Opcodes.RETURN));
    }
}
```

```java
// 1.2 异常表炸弹：500 个 try/catch 条目指向同一死分支 handler
//    合法但反编译器异常流分析可能指数爆炸
for (int i = 0; i < 500; i++) {
    mn.tryCatchBlocks.add(new TryCatchBlockNode(
            start, end, handler, "java/lang/Throwable"));
}
```

```java
// 1.3 自引用 InnerClasses：inner == outer == 自身，类图构建器死循环
cn.innerClasses.add(new InnerClassNode(
        SYNTH_CLASS, SYNTH_CLASS, "_KboxAntiDec",
        Opcodes.ACC_STATIC | Opcodes.ACC_PUBLIC));
```

```java
// 1.4 常量池炸弹：65535 字节 CONSTANT_Utf8，工具分配/显示时 OOM
char[] chars = new char[65535];
Arrays.fill(chars, 'x');
l.add(new LdcInsnNode(new String(chars)));
```

- **配置项**：`antiDecompilerLevel = 1|2|3`
- **变换**：合成 `_KboxAntiDec` 类被注入 graph 后随主混淆流一同重命名打包，不污染用户类。
- **回退**：整个 pass 用 try/catch 包裹，失败只记录 warning。

---

## 25. 反调试措施（Anti-Debug）

- **实现位置**：[AntiDebug.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/AntiDebug.java)
- **是否有代码示例**：是

运行时静默反调试。一旦任一检测命中，`tampered` 标志置位，由字符串解密器/VMP 派发表查询以**返回错误结果而非崩溃**，使攻击者看到的是垃圾数据却无法定位反调试代码。

```java
// AntiDebug.check：三种检测向量
public static void check() {
    checkJvmArgs();     // -agentlib:jdwp / -Xrunjdwp / -agentpath / -javaagent
    checkAttachApi();   // com.sun.tools.attach.VirtualMachine 可加载性
    checkTiming();      // 5000 次循环 > 5ms => 单步跟踪
}
```

```java
// checkJvmArgs：扫描 JVM 启动参数中的调试/agent 标志
for (String a : args) {
    if (a.startsWith("-agentlib:jdwp") || a.startsWith("-Xrunjdwp")
            || a.contains("-agentpath") || a.contains("-javaagent")) {
        tampered = true;
        return;
    }
}
```

```java
// checkTiming：5000 次循环可计算（< 1ms），单步执行 > 5ms
long start = System.nanoTime();
int acc = 0;
for (int i = 0; i < 5000; i++) {
    acc ^= i;
    acc = (acc << 1) | (acc >>> 31);
}
if (acc == 0xDEADBEEF) tampered = true;   // 防 JIT 消除
long elapsed = System.nanoTime() - start;
if (elapsed > 5_000_000L) tampered = true;
```

- **设计原则**：永不抛异常。所有检测用 try/catch 包裹，失败保持 `tampered=false`（保守不破坏）。
- **字符串隐匿**：本类内的字符串字面量在 protector 自身混淆时由 StringEncryptor 加密，避免被关键词搜索定位。
- **配置项**：`antiDebug = true|false`

---

## 26. VMP 解释器自检（VmpSelfCheck）

- **实现位置**：[VmpInterpreter.java#verifySelf](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java) 的 `<clinit>`
- **是否有代码示例**：是（部分实现）

VmpInterpreter 类的 `<clinit>` 在加载时验证自身字节码资源可读且尺寸合理；若失败，`selfTampered` 标志置位，`execute()` 派发表会污染执行结果。

```java
// VmpInterpreter.verifySelf：检查类资源完整可读
private static void verifySelf() {
    try {
        InputStream in = VmpInterpreter.class.getClassLoader()
                .getResourceAsStream("com/kbox/runtime/VmpInterpreter.class");
        if (in == null) { selfTampered = true; return; }
        long total = 0; byte[] buf = new byte[8192]; int r;
        while ((r = in.read(buf)) > 0) total += r;
        in.close();
        if (total < 1024) selfTampered = true;  // 尺寸过小 => 可疑
    } catch (Throwable t) {
        selfTampered = true;
    }
}

static { verifySelf(); }
```

- **设计权衡**：完整 SHA-256 字节比对存在"鸡生蛋"问题——把哈希常量嵌入类会改变被哈希的字节本身。当前实现只做尺寸/可读性校验，完整哈希校验委托给 [IntegrityChecker](#29-jar-完整性校验integrity-check--anti-repackaging) 在引导阶段对全 jar 进行（参见方法 29）。
- **进阶选项**：`vmpSelfCheck = true` 启用本检查。解释器方法体内联克隆/派发表篡改破坏等重型方案为路线图项。
- **配置项**：`vmpSelfCheck = true|false`

---

## 27. Native 反 Hook（Native Anti-Hook）

- **实现位置**：[NativeCompiler.java#assembleSource](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/jnic/NativeCompiler.java) 在 `antiHook=true` 时注入
- **是否有代码示例**：是

针对 JNIC 生成的 `.so/.dll`，防御 Frida/Xposed/LD_PRELOAD 等 JNI 钩子。在生成的 C 源码前部插入两类防护：①构造器属性函数（`__attribute__((constructor))`）在库加载时立即清理 `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`/`LD_DEBUG`；②每个 JNI 函数入口处检查首 4 字节是否仍为 x86_64 标准序言（`55 48 89 e5` = `push rbp; mov rsp,rbp`），inline hook 会覆写此序言。

```c
/* __constructor__：库加载时尽早清空环境变量 */
__attribute__((constructor)) static void _kbox_env_scrub(void) {
    unsetenv("LD_PRELOAD");
    unsetenv("DYLD_INSERT_LIBRARIES");
    unsetenv("LD_DEBUG");
}

/* 序言完整性检查：检测 inline hook */
static int _kbox_check_prologue(void* fn) {
#if defined(__x86_64__)
    unsigned char* p = (unsigned char*)fn;
    if (p[0]==0x55 && p[1]==0x48 && p[2]==0x89 && p[3]==0xe5) return 1;
    return 0;
#else
    return 1; /* 未知架构跳过 */
#endif
}

#define KBOX_ANTI_HOOK() \
    if (!_kbox_check_prologue((void*)__func__)) { \
        /* 已被 hook：返回合理默认，不崩溃 */ \
    }
```

- **配置项**：`nativeAntiHook = true|false`（仅在 `enableJnic = true` 时生效）
- **变换**：仅影响 JNIC 生成 C 源码的预lude，不修改 Java 字节码。
- **平台适配**：x86_64 实现序言检查；其他架构（arm64、x86）跳过序言检查但仍执行环境变量清理。
- **回退**：序言检查命中 hook 时不崩溃，只返回合理默认值（"欺骗分析者"策略）。

---

## 28. 数字水印嵌入（Watermarking）

- **实现位置**：[Watermarker.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/Watermarker.java)
- **是否有代码示例**：是

将用户自定义水印字符串（如客户 ID、授权码）编码为 256 位比特数组，存入合成类 `com/kbox/runtime/_KboxWm` 的 `static final long[] _wm` 字段，并由 `<clinit>` 用 `LDC` 常量逐位初始化——这些常量同时进入常量池，使水印可被授权方通过提取字段初始化器恢复。同时附加可见注解 `@KBoxWatermark(hash=...)`，值为水印经 `KBox-WM-v1:` 盐化后的 SHA-256 十六进制（不存原值）。

```java
// Watermarker.encode：水印 -> SHA-256 -> 256-bit 数组
byte[] hash = md.digest(wm.getBytes(UTF_8));
byte[] bits = new byte[hash.length * 8];
for (int i = 0; i < hash.length; i++) {
    for (int b = 7; b >= 0; b--) {
        bits[i * 8 + (7 - b)] = (byte) ((hash[i] >> b) & 1);
    }
}
```

```java
// installClinit：long[] 字段逐位 LDC 初始化（比特位进入常量池）
l.add(new IntInsnNode(Opcodes.NEWARRAY, Opcodes.T_LONG));
for (int i = 0; i < bits.length; i++) {
    l.add(new InsnNode(Opcodes.DUP));
    pushInt(l, i);
    l.add(new LdcInsnNode((long) bits[i]));      // 比特 -> 常量池
    l.add(new InsnNode(Opcodes.LASTORE));
}
l.add(new FieldInsnNode(Opcodes.PUTSTATIC, HOLDER, "_wm", "[J"));
```

```java
// installMarkerAttribute：附加可见注解（盐化哈希，不含原水印）
md.update("KBox-WM-v1:".getBytes(UTF_8));
byte[] hash = md.digest(wm.getBytes(UTF_8));
AnnotationNode an = new AnnotationNode("Lcom/kbox/runtime/KBoxWatermark;");
an.values = Arrays.asList("hash", toHex(hash));
cn.visibleAnnotations.add(an);
```

- **抗清除**：水印类是合成的，不在用户代码 reachable 集合内，重命名 pass 会重命名它但不会移除；控制流平坦化不作用于合成类。要清除水印需识别并删除整个 `_KboxWm` 类。
- **配置项**：`watermark = <任意字符串>`
- **变换**：合成 `_KboxWm` 类被注入 graph 后随主混淆流重命名打包。

---

## 29. Jar 完整性校验（Integrity Check / Anti-Repackaging）

- **实现位置**：[Packager.java#writeIntegrityHash](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)（构建期）+ [IntegrityChecker.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/IntegrityChecker.java)（运行期）
- **是否有代码示例**：是

防二次打包：构建期对受保护 jar 中所有非运行时 `.class` 条目按字典序排序后做 SHA-256，写入 `META-INF/kbox/integrity.hash`。运行期由 `IntegrityChecker.check()` 在引导阶段重新计算并与存储值比对；不一致则置 `tampered` 标志，由下游字符串解密/VMP 派发静默污染（**不崩溃，让攻击者看到垃圾输出**）。

```java
// Packager.writeIntegrityHash：构建期写入哈希
TreeSet<String> names = new TreeSet<>();
for (String n : graph.getClasses().keySet()) {
    if (n.startsWith("com/kbox/runtime/")) continue;  // 排除 KBox 运行时
    names.add(n);
}
for (String n : names) {
    md.update(n.getBytes(UTF_8));
    md.update(serialize(graph.getClasses().get(n), graph));
}
putEntry(out, "META-INF/kbox/integrity.hash", hex(md.digest()));
```

```java
// IntegrityChecker.check：运行期校验
File jar = locateJar();          // 通过 ProtectionDomain.getCodeSource()
byte[] expected = readResource("META-INF/kbox/integrity.hash");
String actualHex = hashJar(jar); // 同样排除 com/kbox/runtime/*
if (!expectedHex.equals(actualHex)) {
    tampered = true;             // 下游污染，不抛
}
```

- **配置项**：`integrityCheck = true|false`
- **设计权衡**：哈希文件本身不加密（哈希不是秘密）；安全来自任何类修改都会改变摘要。把哈希常量嵌入启动器类常量池的进阶方案为路线图项。
- **回退**：找不到 jar 或哈希文件时静默跳过；读取异常时置 `tampered=true`（保守破坏）。

---

## 30. 异常跳转混淆（Exception-Jump Obfuscation）

- **实现位置**：[ExceptionJumpObfuscator.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/controlflow/ExceptionJumpObfuscator.java)
- **是否有代码示例**：是

将符合条件的 `()I` 方法（无参、返回 int、单 `IRETURN`、无既有 try/catch）的返回值改造为通过抛出+捕获合成异常 `com/kbox/runtime/_KboxIntCarrier` 传递。JVM 语义完全保持（返回值不变），但 JD-GUI/CFR 会把整个方法体渲染成冗长的 try/catch 而无法还原为简单 return，可读性大幅下降。

```java
// rewriteReturn：IRETURN -> new Carrier(value); athrow + handler 捕获返回
patch.add(new TypeInsnNode(Opcodes.NEW, CARRIER));
patch.add(new InsnNode(Opcodes.DUP_X1));
patch.add(new MethodInsnNode(Opcodes.INVOKESPECIAL, CARRIER, "<init>", "(I)V", false));
patch.add(new InsnNode(Opcodes.ATHROW));
patch.add(handler);
patch.add(new MethodInsnNode(Opcodes.INVOKEVIRTUAL, CARRIER, "getValue", "()I", false));
patch.add(new InsnNode(Opcodes.IRETURN));
mn.instructions.insert(iret, patch);
mn.instructions.remove(iret);
mn.tryCatchBlocks.add(new TryCatchBlockNode(
        (LabelNode) mn.instructions.getFirst(), handler, handler, CARRIER));
```

- **配置项**：`exceptionJumpObf = true|false`
- **性能权衡**：每次返回都抛异常（~100x 慢于普通 return），**默认关闭**，仅用于非热点方法。合成载体类 `_KboxIntCarrier extends RuntimeException`，由 `ensureCarrier()` 自动注入 graph。
- **回退**：单方法变换失败只记录 debug 日志，跳过该方法。
- **限制**：当前只处理 `()I` 签名；扩展到其他返回类型为路线图项。

---

## 32. 类方法体动态解密防 Dump（Anti-Dump）

- **状态**：**已实现**。受保护 jar 中的 `.class` 文件以 AES-256-GCM 加密存储，运行时由 `ResourceGuardClassLoader` 在 `defineClass` 前透明解密。
- **原理**：
  - 打包阶段，`Packager.encryptClassBody()` 对每个 eligible 类的序列化字节进行 AES-GCM 加密，前置 4 字节魔数 `KBCE` + 12 字节 IV + 密文 + 16 字节 GCM tag。
  - 密钥派生：`SHA-256("KBox-ClassGuard-v1:" + classSeed)` 取前 32 字节，`classSeed` 为 32 字节随机种子，存入 `META-INF/kbox/class-seed.bin`。
  - 加密类名列表存入 `META-INF/kbox/class-list.bin`（内部名，换行分隔）。
  - 运行时 `ResourceGuardClassLoader.loadClass()` 拦截加密类：读取原始加密字节 → 检测 `KBCE` 魔数 → 解密 → `defineClass`。非加密类正常委派给父加载器。
  - 对 Spring Boot Fat Jar 兼容：自动尝试 `BOOT-INF/classes/` 前缀路径。
- **eligible 规则**：跳过 `com.kbox.runtime.*` 运行时类和 manifest 入口类，仅加密应用业务类。
- **配置项**：`encryptClasses = true|false`（默认 false）
- **实现文件**：[Packager.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)（加密）+ [ResourceGuardClassLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/ResourceGuardClassLoader.java)（解密）
- **测试**：kbox-testapp 以 `encryptClasses = true` 保护后，`java -jar` 输出与原始 jar 完全一致，dump 出的 .class 文件为密文无法反编译。

---

## 33. 字符串引用打散与动态拼接（String Scattering）

- **状态**：**已实现**。`StringScatterer` 作为 `StringEncryptor` 的强化替代方案，在 `scatterStrings = true && encryptStrings = true` 时启用。
- **原理**：
  - 每个非空字符串字面量被拆成 3 段（UTF-8 字节均匀分割）。
  - 每段以独立 4 字节 rolling key XOR 加密，存入 8 个合成 holder 类（`com/kbox/runtime/_KboxS0` ~ `_KboxS7`）之一的 `static byte[]` 字段（每 holder 最多 256 字段）。
  - 使用点生成**完全内联**的解密+拼接代码：
    ```
    StringBuilder sb = new StringBuilder();
    byte[] a = HolderX.fY;
    for (int i=0; i<a.length; i++) a[i] ^= (key >>> (i%4)*8) & 0xFF;
    sb.append(new String(a, UTF_8));
    // ... 重复段 2、3 ...
    String result = sb.toString().intern();
    ```
  - **不调用** `KBoxRuntime.d()`，解密逻辑完全内联，使基于方法断点的自动化脱壳脚本失效。
  - Holder 类在重命名 pass 之前注入 graph，会与业务类一同被重命名，增加静态分析难度。
- **关键修复**：IUSHR 指令操作数顺序必须为 `key, shift`（value1=value, value2=shift），否则解密结果错误。
- **配置项**：`scatterStrings = true|false`（默认 false，需同时启用 `encryptStrings`）
- **实现文件**：[StringScatterer.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/stringenc/StringScatterer.java)
- **测试**：kbox-testapp 以 `scatterStrings = true` 保护后，30 个字符串分散到 8 个 holder（80 个字段），`java -jar` 输出与原始 jar 完全一致。

---

## 34. BrainfuckShield — 二次虚拟化（磁带机私有方言 + 自修改指令流 + 无声诱饵）

- **实现位置**：[BfDialect.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/brainfuckshield/BfDialect.java)（构建期方言/磁带核心）+ [BfMethodInjector.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/brainfuckshield/BfMethodInjector.java)（per-method 注入器）+ 运行时 [BfInterpreter.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/BfInterpreter.java) + 集成点 [VmpMethodInjector.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/vmp/VmpMethodInjector.java) / [VmpInterpreter.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/VmpInterpreter.java) / [ProtectionPipeline.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/ProtectionPipeline.java) / [Packager.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java)
- **是否有代码示例**：是
- **设计哲学**：针对「AI 读不懂 → AI 写不出破解工具」。Barak 已证 black-box 混淆不存在，因此不追求不可逆，而是攻击破解的**经济结构**——让「写一个通用 BF→VMP 转译器」这件事不存在，把攻击成本从一次性的 O(1) 抬到每次构建 O(n)。

### 34.1 位置：在 VMP 之上再加一层

现有 VMP 已把 Java 方法翻译成 VMP 微码流（per-method 随机密钥 `K` + 逐方法 opcode 置换 + ChaCha20 静态加密，见方法 5-8）。BrainfuckShield 在 VMP 之后再套一层：把 VMP 的静态密文流 `encVmp` 按 per-build/per-method 随机**私有方言**重编码成「磁带程序」存进 `$vmp_<n>` 字段。运行期 `BfInterpreter` 先把磁带程序逐格回放解码回 `encVmp`，才交给 `VmpInterpreter` 执行。

```java
// VmpMethodInjector.encrypt：VMP 加密完成后，若 bfLevel>0 再磁带化
if (bfLevel > 0) {
    byte[] rawEnc = encCode;
    encCode = com.kbox.core.brainfuckshield.BfMethodInjector.shield(
            rawEnc, K, bfBuildSalt, bfLevel);   // encVmp -> 磁带程序
    if (System.getProperty("kbox.bf.verify") != null) {
        if (!com.kbox.core.brainfuckshield.BfMethodInjector.verifyRoundTrip(
                rawEnc, K, bfBuildSalt, bfLevel)) {
            throw new KBoxException("BrainfuckShield round-trip verify failed");
        }
    }
}
```

```java
// VmpInterpreter$VmpMethod.<init>：运行期构造时解磁带
byte[] decryptedCode = com.kbox.runtime.BfInterpreter.decodeIfTape(tape, K);
```

### 34.2 关键组件① 私有方言生成（对抗「写通用转译器」）

`BfDialect.vmpToCode` 由 `K + buildSalt` 派生的 256 置换。每次构建新建随机 `buildSalt`（`BfMethodInjector.newBuildSalt()`），与每方法 `K` 共同派生方言，故**方法间方言各异、构建间方言全异**。攻击者写一个「通用 BF→VMP 转译器」不成立。

```java
// ProtectionPipeline.injectVmp：每构建随机 buildSalt（写进磁带 header，运行期读回）
int bfLevel = cfg.isBrainfuckShield() ? Math.max(1, cfg.getBrainfuckShieldLevel()) : 0;
int bfBuildSalt = bfLevel > 0
        ? com.kbox.core.brainfuckshield.BfMethodInjector.newBuildSalt() : 0;
VmpMethodInjector injector = new VmpMethodInjector(bfLevel, bfBuildSalt);
```

```java
// BfDialect.vmpToCode：确定性 splitmix 播种(K,"kbox.bf.dialect."+buildSalt) 洗牌 256 置换
BfRng rng = new BfRng(K, "kbox.bf.dialect." + buildSalt);
int[] m = new int[256];
for (int i = 0; i < 256; i++) m[i] = i;
for (int i = 255; i > 0; i--) { int j = rng.nextInt(i + 1); int t = m[i]; m[i]=m[j]; m[j]=t; }
```

### 34.3 关键组件② 磁带机模型 + 自修改指令流（对抗 trace 重放）

128 个 32 位 word 的磁带，初始由 `(K, buildSalt)` 确定性播种。每个码点 = `方言(明文字节) ⊕ 磁带指纹`，其中指纹是前部 64-word 窗口的 FNV-1a。解码一个字节后，该字节被异或**喂回磁带当前位置**，使磁带状态随指令流演化——**自修改**。dump 静态 `$vmp_<n>` 得到密文；dump 运行时 trace 得到一次性的、含环境熵的序列，不可重放。

```java
// BfDialect.encode（BfInterpreter.decodeTape0 逐字节镜像）
for (int i = 0; i < n; i++) {
    int fp = tapeFinger(tape, NOISE_WINDOW) & 0xFF;
    int v = encVmp[i] & 0xFF;
    out[HEADER_LEN + i] = (byte) ((m[v] ^ fp) & 0xFF);
    tape[head % TAPE_CELLS] = (tape[head % TAPE_CELLS] ^ v) & 0xFFFFFFFF; // 自修改
    head++;
    head = applyDecoys(tape, K, buildSalt, level, i, head);
}
```

### 34.4 关键组件③ 膨胀 + 语义抵消对 + 诱饵（对抗局部注意力）

`BfDialect.applyDecoys` 每间隙注入 `level` 条净效应为零的抵消对（XOR⊕XOR / ADD−ADD / 磁带头往返），并把确定性噪声写进指纹窗口——使**磁带指纹依赖诱饵**：静态剥离诱饵会破坏解码（BfInterpreter 同源镜像）。

```java
// BfDialect.applyDecoys：三种自抵消诱饵 + 喂噪声进指纹窗口
if (op == 0) { int v = rng.nextInt(0x10000);
    tape[c] = (tape[c] ^ v) & 0xFFFFFFFF; tape[c] ^= v; ... }        // XOR ⊕ XOR
else if (op == 1) { int v = rng.nextInt(0x10000);
    tape[c] = (int)((tape[c] + v) & 0xFFFFFFFFL);
    tape[c] = (int)((tape[c] - v) & 0xFFFFFFFFL); ... }               // ADD − ADD
// 把确定性噪声写进指纹窗口……
```

### 34.5 关键组件④ 完整性绑定（对抗插桩 dump / 静态补丁）

磁带程序末尾附 4 字节 FNV-1a trailer。任何对磁带字节的静态补丁（agent 改类字节、十六进制改常量池）都使 trailer 校验失败 → 解码返回 `null` → `VmpMethod` 以噪声流 fail-closed，**不给出任何检测信号**。构建侧 `verifyRoundTrip` 额外做「翻转载荷一字节必须解不出」的篡改护栏回归。

```java
// encode：trailer = 载荷 FNV-1a
writeInt(out, HEADER_LEN + n, h);
// decode：先校验 trailer，任何一个磁带字节被静态补丁都拒绝
if (readInt(tapeProgram, HEADER_LEN + n) != h) return null;
```

### 34.6 关键组件⑤ 反插桩 · 无声诱饵（对抗 javaagent trace）

`BfInterpreter.decodeTape` 入口探测 JVM 输入参数中的 `-javaagent / -agentlib / -Xrun`（agent attach、插桩 trace 工具的标配）。命中时**不报错、不打日志**，而是破坏一个关键种子字节（`kk[0] ^= 0x5A`）解码——得到长度相同、结构看似合法但语义全错的指令流。动态分析者拿到一份自信的错误解读且没有反馈信号。

```java
// BfInterpreter.decodeTape：命中 agent 走诱饵路径
boolean decoy = agentProbe();
byte[] kk = K;
if (decoy && K != null && K.length > 0) {
    kk = K.clone();
    kk[0] = (byte) (kk[0] ^ 0x5A);   // 方言/磁带全部错位 -> 语义错误但不崩溃
}
return decodeTape0(tapeProgram, kk);
```

### 34.7 一致性红线（build/runtime 镜像）

`BfRng / vmpToCode / codeToVmp / seedTape / tapeFinger / applyDecoys / decodeTape` 在构建侧 `BfDialect` 与运行侧 `BfInterpreter` **逐字节一致**（同 `VmpMethodInjector↔VmpInterpreter` 既有置换复制模式）。任何改动两侧必须同步；构建侧 `verifyRoundTrip` encode→decode 回环是回归护栏。

### 34.8 配置门控与打包注入

```properties
# ns-full.conf（最强档）
brainfuckShield = true
brainfuckShieldLevel = 3
```

- 配置解析：[ProtectionConfig.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ProtectionConfig.java)（`isBrainfuckShield` / `getBrainfuckShieldLevel`）+ [ConfigLoader.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/config/ConfigLoader.java)（`brainfuckShield` / `brainfuckShieldLevel` 解析）。
- 打包注入：[Packager.java](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/core/packaging/Packager.java#L1402-L1413)`injectRuntimeClasses` + `collectBrainfuckClasses` 必须同时注入 `BfInterpreter` 与其 package-private 嵌套类 `BfInterpreter$BfRng`，否则 VMP 磁带解码抛 CNFE。

### 34.9 红队自评

| 攻击路径 | 难度 | 缓解 |
|---|---|---|
| AI 直接读懂方言代码 | 极高 | 多重随机化（K+buildSalt 每方法/每构建）+ 无先验结构 |
| AI 写通用转译器 | 极高 | 每构建方言不同，工具不可复用（O(1)→O(n)） |
| 字节码层识别解释器模式 | 中 | 复用/交织于 `VmpInterpreter` + 磁带化，无独立「解释器+数据」二分 |
| 插桩 dump 指令流 | 中 | 完整性绑定 + 无声诱饵（攻击者不知拿了假货） |
| 黑盒 fuzz 行为等价重写 | 中低 | 自修改 + 磁带指纹随指令演化，行为不可稳定复现 |
| 决心充分的人工+AI 逐方法攻克 | 最终可行 | 靠成本不对称：发版快于破解周期 |

- **性能权衡**：磁带化在 VMP 解释之上增加一层解码，只作用于已 VMP 化的低频高价值方法；业务热路径仍可用 `keepMember` 保留为 Java（见 `ns-full-fast.conf`）。
- **配置项**：`brainfuckShield = true|false`，`brainfuckShieldLevel = 0..3`（诱饵密度）。

---

## 35. 现有全部混淆方法总览（全体系清点）

除上述 1-34 项外，本项目已实现并集成进 `kboxDedeobfShieldV1` 自研四层纵深体系（S/D/C/X 共 17 模块）与增强壳。以下条目为近年新增、未在 1-33 逐条展开的部分，配置开关见 [ns-full.conf](file:///d:/kboxobf/_bftest/ns-full.conf)（最强档）与各实现文件。

### 35.1 Brainfuck-RLE 全类载荷加载器（`brainfuckLoader`）

- **实现位置**：[BfSecureLoader.java / NativeLoader / ChaCha20](file:///d:/kboxobf/kbox-core/src/main/java/com/kbox/runtime/) + native [kbox_bf_loader.c](file:///d:/kboxobf/kbox-core/src/main/resources/native/)
- 全部受保护类字节塞进 Brainfuck-RLE 载荷：每个 chunk 是完整 8 算子（`+ - > < [ ] . ,`）＋循环结构的 BF 程序，磁盘上**无明文 CAFEBABE**；`name->(offset,len)` 索引作为 `KBII` 有符号头嵌在 blob 头，只在 native 解码堆内解析，Java 侧永不持 offset。
- 逐类定义重查 agent：`kbox_gateCheck` 每次 `defineClassFromBF / getResourceBytes` 前原生重跑模块探针（`instrument.dll/jdwp.dll/dt_socket`），命中即 `indexClear` + wipe 整个解码态 + 拒定义。引导期 `safeBoot` 探测注入参数。
- `getResourceBytes` 对 `.class` 资源 fail-closed 返回 NULL，换 `probeClassFromBF`；解码中间缓冲（RLE→BF→DEFLATE）全部走 native `secureAlloc/secureFree` 用完即擦。
- 引导类 ZKM 式混淆（字符串逐字节 XOR + 按串 salt、每个方法恒假谓词空栈分支）；回归指标 `cafebabe_protected_pkg_hits`。

### 35.2 VMP 构建期/运行期多样性（多态三件套）

- VMP opcode 每方法置换（build 侧 mask + runtime 侧 invPerm）；BF 符号集每构建随机（`BfSymbolSet` 注入 `KBOX_BF_*` 宏到 C）；JNIC native 每构建不同；每次构建 `rle/native/jnic/index` 逐字节不同。
- VM interleave：`VmpTranslator` 伪随机插入 `VmpOp.NOP(0x45)` 垃圾微指令（Pass1/Pass2 同步 seq，分支目标含 NOP），native 端 `T[0x45]=h_NOP` 必须登记否则崩溃，`vmpInterleave=N` 门控。
- 运行时 handler 动态再置换：`VmpInterpreter.runPerm()` 由 per-run ephKey+runSeq 派生置换，`execute()` 每运行重排 `runHandlers[R[slot]]=base[slot]`，dispatch 经 R+slot 双重索引，跨进程 dump 布局不稳定。
- VMP 原生分发循环 + BF runner 加 `VMP_MAX_STEPS(2^31)` 步帽防死循环；原生异常表分发（`nlTryCatch`）经 native 侧查异常表跳 handler。

### 35.3 kboxShield 原生反 VM / 反 Hook（`nativeAntiHook`）

- `kbox_probeVM`：CPUID leaf 0x40000000 供应商指纹 FNV-1a 匹配 VMware/VBox/KVM/Xen/TCG/Bochs/Parallels，**排除 leaf1 ECX bit31 与 "Microsoft Hv"** 防 VBS/HVCI 误报。
- `kbox_probeHooks`：序言跳板扫描（E9/EB/CC/FF25）+ 导出表交叉校验。
- Windows 自哈希扩到全部非可写非 discardable 节（rdata/edata/rsrc），逐节 FNV-1a 折叠 VA/Characteristics/内容；POSIX 用 `dladdr + dl_iterate_phdr` 折叠 PF_X 且 !PF_W 的 LOAD 段；任一处被补丁 `kbox_selfDie()` 以状态码终止。`kbox_getfp` 定位类字节，`FlushInstructionCache` 兜底 icache 侧信道。

### 35.4 SilentShield 弱点驱动审计器（`WeaknessCatalog`）

- 取代原 5 万+ 样本库：25 条专家精编「其他混淆器适配性弱点」目录（ZKM/JNIC/ProGuard/Allatori/DashO/R8-D8 等 9 源），按 SPEC/CONTRACT/DEGRADE/ENV 四大支柱，含 source、weakness、symptom、hardening。`AdaptationAuditor` 自动检出反射/序列化/SPI/EDT 回调（Swing `paintComponent/keyPressed` 等）/异常表/`StringConcatFactory` indy 等模式。
- `ProtectionAction` 12 种防护策略、`RiskLevel` 五级分级；把 SWING_EDT_CALLBACK 等弱点溯源到具体混淆器再下发 `EXCLUDE_FROM_NATIVE`，替代原手动 `nativeEligiblePrefix`。报告写 `silentshield-report.txt`。

### 35.5 kboxDedeobfShieldV1 静态层 S1-S5

- **S1 methodSplit**：方法体切分·异质重组。
- **S2 opaqueStateMachine**：不透明状态机伪造分支（`_SecWvOuqCtUYw` 类，53 分支级守卫）。
- **S3 sentinelInterleave**（待执行）：双解释器 sentinel 交错验签。
- **S4 honeypot**：蜜罐字段/常量诱饵。
- **S5 blobMockFill**：blob 两级重排 mock 填充。

### 35.6 kboxDedeobfShieldV1 动态层 D1-D5

- **D1 stackFrameRedirect** 栈帧重定向（native TLS 映射）；**D2 entropyTimeAnchor** 执行熵·时间锚毒饵（阈值保护防拒启）；**D3 selfWipeSections** 冷热节自擦；**D4 processHeartbeat** 多进程链式心跳；**D5 honeypotPe** 隐式蜜罐 PE。

### 35.7 kboxDedeobfShieldV1 内核语义层 C1-C5

- **C1 oneTimeSemantic** 一次性语义实例；**C2 lineageChain** 血缘会话链；**C3 selfRefAuth** 自反认证沙箱；**C4 multiRep** 形式化多元表示+转换门；**C5 polyGold** 计算镀金。

### 35.8 kboxDedeobfShieldV1 联动自毁层 X1-X2

- **X1 signalPoison** 信号联动 poison；**X2 buildSigBind** 构建期版本签名绑定。

### 35.9 增强壳 nativeShell（M1+M2+M3）

- **M1** 全量字符串加密：函数体安全表达位置（实参/return/赋值）字符串 → XOR 密文静态表 + 懒解密桩，规避 `__asm__/sizeof/文件级初始化器/宏拼接/宽字面量`。
- **M2** 控制流变异：7 个关键壳函数（probeVM/probeHooks/gateCheck/selfDie/watchdog/wipeDecodeState 等）注入不透明谓词前导 + 每构建多态 NOP sled；hypervisor 厂商魔法数打散成运行期掩码表（.text 无 32 位指纹字面量）。
- **M3** IAT/导入隐藏（自研）：12 个 Win32 直连 + 3 个解析原语全部重定向到私有解析器（PEB 遍历 + 导出目录按名 hash 解析，含 forwarder 递归解析与 DEP 指控），API 名以 per-build XOR 密文承载。

### 35.10 硬件密钥环 / 类加密派生（`HardwareKeyRing`）

- 类加密密钥 `SHA-256("KBox-ClassGuard-v1:"+seed+HardwareKeyRing.fingerprint())` 三处派生一致；`stableMachineFeed` 纯静态 fallback 改为 MAC + bootDisk 硬件锚定；`VmpInterpreter` 用 `vmpMaster()+ephemeralKey()` 每运行重键 resident（跨进程 dump 失效）；增强壳 `nativeShell=3` 时 native 编译流水线（BF/JNIC/VMP/crypto）全部套 M1-M2-M3。

---

### 最强配置（全部开启，最高强度）

见 [ns-full.conf](file:///d:/kboxobf/_bftest/ns-full.conf)：`brainfuckShield=true`(L3) + `brainfuckLoader=true` + `enableVmpNative=true` + `nativeShell=3` + `renameIdentifiers/renamePackages` + `encryptStrings(3)/whiteboxStrings` + `obfuscateControlFlow(3)/exceptionJumpObf` + `typeConfusion=2` + `antiDecompilerLevel=3/antiDebug/vmpSelfCheck/integrityCheck/nativeAntiHook/hideCallGraph/fakeDebugInfo/eraseAnnotations/methodInlineExtract` + `enableVmp(vmpCoverage=full)/enableJnic` + `encryptClasses/obfuscateResources` + 全部 S1-S5/D1-D5/C1-C5/X1-X2 拉满（level=3）。回归命令：

```
java -jar kbox-protector.jar --input app.jar --output out-nsfull.jar --config ns-full.conf
java -jar out-nsfull.jar     # 验证 BF-TEST-END + RESOURCE_MATCH=true + EXIT=0
```

---

## 汇总表

| # | 混淆手段 | 实现文件 | 是否有代码示例 |
|---|---------|---------|--------------|
| 1 | 标识符重命名 | NameObfuscator.java | 是 |
| 2 | 字符串常量加密 | StringEncryptor.java | 是 |
| 3 | 不透明谓词 | ControlFlowObfuscator.java | 是 |
| 4 | 控制流平坦化 | Flattener.java | 是 |
| 5 | VMP 指令集 | VmpOp.java | 是 |
| 6 | VMP 字节码翻译 | VmpTranslator.java | 是 |
| 7 | VMP 方法注入 | VmpMethodInjector.java | 是 |
| 8 | VMP 运行时解释器 | VmpInterpreter.java | 是 |
| 9 | JNIC 字节码→C 翻译 | JniCTranslator.java | 是 |
| 10 | JNIC 编排与 loadLibrary | JnicOrchestrator.java | 是 |
| 11 | JNIC 跨平台编译 | NativeCompiler.java | 是 |
| 12 | 类图与依赖分析 | ClassGraph.java + DependencyAnalyzer.java | 是 |
| 13 | 反射安全扫描 | ReflectionScanner.java | 是 |
| 14 | 资源引用更新（SPI/Spring factories 类名同步） | ResourceReferenceUpdater.java | 是 |
| 15 | Manifest 更新 | ManifestUpdater.java | 是 |
| 16 | 运行时类注入 | Packager.java | 是 |
| 17 | Spring Boot Fat Jar 支持 | Packager.java | 是 |
| 18 | 非类文件名混淆（资源名随机化） | ResourceNameObfuscator.java | 是 |
| 19 | 资源内容加密（AES-256-GCM） | ResourceEncryptor.java | 是 |
| 20 | Kotlin 元数据修复（@Metadata 重写） | KotlinMetadataFixer.java | 是 |
| 21 | 资源守护启动器（Main-Class 替换 + 引导） | ResourceGuardLauncher.java | 是 |
| 22 | 资源守护类加载器（运行时透明资源解析） | ResourceGuardClassLoader.java | 是 |
| 23 | 运行时元数据注入（加密映射表 + 种子 + 守护类） | Packager.java | 是 |
| 24 | 反反编译器对抗（goto 链 + 异常表炸弹 + InnerClasses 自引用 + 常量池炸弹） | AntiDecompiler.java | 是 |
| 25 | 反调试（JDWP / JVMTI / 时间检测） | AntiDebug.java | 是 |
| 26 | VMP 解释器自检（资源可读性 + 尺寸校验） | VmpInterpreter.java | 是（部分实现） |
| 27 | Native 反 Hook（序言完整性 + 环境变量清理） | NativeCompiler.java | 是 |
| 28 | 数字水印嵌入（SHA-256 → bit 数组 + 可见注解） | Watermarker.java | 是 |
| 29 | Jar 完整性校验 / 防二次打包 | Packager.java + IntegrityChecker.java | 是 |
| 30 | 异常跳转混淆（IRETURN → athrow + catch） | ExceptionJumpObfuscator.java | 是 |
| 32 | 类方法体动态解密防 Dump（AES-GCM 加密 .class） | Packager.java + ResourceGuardClassLoader.java | 是 |
| 33 | 字符串引用打散与动态拼接（inline 解密，无中心调用） | StringScatterer.java | 是 |
| 34 | BrainfuckShield 二次虚拟化（磁带机私有方言 + 自修改指令流 + 完整性绑定 + 无声诱饵） | BfDialect.java + BfMethodInjector.java + BfInterpreter.java + VmpMethodInjector.java | 是 |
| 35.1 | Brainfuck-RLE 全类载荷加载器（无明文 CAFEBABE + 逐类 gateCheck 反 agent） | BfSecureLoader.java + kbox_bf_loader.c | 是 |
| 35.2 | VMP 多样化（opcode 每方法置换 + interleave NOP + 运行时 handler 再置换 + 步帽） | VmpTranslator.java + VmpInterpreter.java | 是 |
| 35.3 | kboxShield 原生反 VM / 反 Hook（CPUID 指纹 + 导出表校验 + 全节自哈希） | kbox_shield 系列 native | 是 |
| 35.4 | SilentShield 弱点驱动审计器（25 条精编弱点四大支柱） | WeaknessCatalog.java + AdaptationAuditor.java | 是 |
| 35.5 | kboxDedeobfShieldV1 静态层 S1-S5 | methodSplit/S2 opaqueStateMachine/S4 honeypot/S5 blobMockFill | 是 |
| 35.6 | kboxDedeobfShieldV1 动态层 D1-D5 | stackFrameRedirect/entropyTimeAnchor/selfWipeSections/processHeartbeat/honeypotPe | 是 |
| 35.7 | kboxDedeobfShieldV1 内核语义层 C1-C5 | oneTimeSemantic/lineageChain/selfRefAuth/multiRep/polyGold | 是 |
| 35.8 | kboxDedeobfShieldV1 联动自毁层 X1-X2 | signalPoison/buildSigBind | 是 |
| 35.9 | 增强壳 nativeShell（M1 字符串/ M2 控制流/ M3 IAT 隐藏） | NativeShellGuard.java + 私有解析器 | 是 |
| 35.10 | 硬件密钥环 + 类加密派生（HardwareKeyRing） | HardwareKeyRing.java | 是 |

整个 kbox-core 的混淆体系采用「保守回退」哲学：每条 pass 都用 try/catch 包裹，单方法/单类/单资源失败只记录 warning 而不中断构建，保证对任意输入 jar（含 Fat Jar / Spring Boot）都能产出功能等价的受保护 jar。
