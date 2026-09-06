package com.kbox.core.silentshield;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * SilentShield — 其他混淆器适配性弱点目录（Weakness Catalog）。
 *
 * <p>这不是海量样本库，而是一份<b>专家知识驱动的精编目录</b>：把商业混淆器
 * （ZKM / JNIC / ProGuard / Allatori / DashO / R8-D8 等）在多年适配中暴露的
 * <b>适配性弱点</b>逐个固化下来，并为每条弱点明确 KBox 自己的<b>加固对策</b>。
 * 目标是把商业产品的"踩坑历史"转化为我们的"避坑预案"，做到
 * "其他混淆器在哪失败，我们就在哪加固"。
 *
 * <p>每条弱点按商业混淆器适配性四大支柱归位：
 * <ul>
 *   <li><b>SPEC</b> — 规范遵循：JVMS / JNI ABI 的精确语义（StackMapTable、
 *       异常表、JNI 符号、invokedynamic、桥接方法）。</li>
 *   <li><b>CONTRACT</b> — 隐式契约识别：字节码之外的依赖（反射、序列化、SPI、
 *       注解、资源路径、回调分发、入口点）。</li>
 *   <li><b>DEGRADE</b> — 渐进降级：无法安全保护时选择保守方案，宁可少混淆
 *       也不出 bug（GUI EDT 回调等）。</li>
 *   <li><b>ENV</b> — 环境探测：JVM 版本 / 模块系统 / multi-release 感知。</li>
 * </ul>
 *
 * <p>{@link AdaptationAuditor} 在输入 jar 中命中某模式族后，{@link SilentShield}
 * 从本目录取出该族的权威动作与加固说明，落地到配置并写进审查报告——
 * 每条发现都标注"来源混淆器 / 支柱 / 弱点 / 症状 / 加固"，形成可追溯的
 * 适配性审查闭环。
 */
public final class WeaknessCatalog {

    /** 适配性四大支柱标识。 */
    public static final String PILLAR_SPEC = "SPEC";
    public static final String PILLAR_CONTRACT = "CONTRACT";
    public static final String PILLAR_DEGRADE = "DEGRADE";
    public static final String PILLAR_ENV = "ENV";

    private static final WeaknessCatalog INSTANCE = new WeaknessCatalog();

    /** 精编弱点条目（非海量生成；一条一族，覆盖 25 个适配性弱点族）。 */
    private final List<Weakness> entries;
    /** family -> 权威弱点条目。 */
    private final Map<String, Weakness> byFamily;
    /** 全部来源混淆器集合（用于报告统计）。 */
    private final Set<String> sources;

    private WeaknessCatalog() {
        List<Weakness> list = new java.util.ArrayList<>(curated());
        Map<String, Weakness> map = new LinkedHashMap<>();
        Set<String> src = new LinkedHashSet<>();
        for (Weakness w : list) {
            map.put(w.family, w);
            src.add(w.source);
        }
        this.entries = Collections.unmodifiableList(list);
        this.byFamily = Collections.unmodifiableMap(map);
        this.sources = Collections.unmodifiableSet(src);
    }

    public static WeaknessCatalog get() {
        return INSTANCE;
    }

    /** 目录条目数（精编数，25）。 */
    public int size() {
        return entries.size();
    }

    public List<Weakness> entries() {
        return entries;
    }

    /** 覆盖的来源混淆器集合。 */
    public Set<String> sources() {
        return sources;
    }

    /** 某模式族的权威弱点条目（未知族 -> null）。 */
    public Weakness weaknessFor(String family) {
        return byFamily.get(family);
    }

    /** 某模式族对应的权威防护动作（未知族 -> NONE）。 */
    public ProtectionAction actionFor(String family) {
        Weakness w = byFamily.get(family);
        return w == null ? ProtectionAction.NONE : w.action;
    }

    /** 某模式族对应的权威风险（未知族 -> INFO）。 */
    public RiskLevel riskFor(String family) {
        Weakness w = byFamily.get(family);
        return w == null ? RiskLevel.INFO : w.risk;
    }

    /**
     * 一条弱点条目：完整描述"别的混淆器在哪失败 + 我们如何加固"。
     */
    public static final class Weakness {
        /** 目录内唯一编号。 */
        public final int id;
        /** 模式族，与 {@link AdaptationAuditor} 的 family 一一对应。 */
        public final String family;
        /** 暴露该弱点的混淆器来源（可多个，逗号分隔）。 */
        public final String source;
        /** 适配性支柱（SPEC / CONTRACT / DEGRADE / ENV）。 */
        public final String pillar;
        /** 弱点描述：其他混淆器在哪失败。 */
        public final String weakness;
        /** 运行期症状：该弱点会引发什么故障。 */
        public final String symptom;
        /** KBox 的加固对策。 */
        public final String hardening;
        /** 权威风险。 */
        public final RiskLevel risk;
        /** 权威防护动作。 */
        public final ProtectionAction action;
        /** 触发模式（审计命中描述）。 */
        public final String trigger;

        Weakness(int id, String family, String source, String pillar,
                 String weakness, String symptom, String hardening,
                 RiskLevel risk, ProtectionAction action, String trigger) {
            this.id = id;
            this.family = family;
            this.source = source;
            this.pillar = pillar;
            this.weakness = weakness;
            this.symptom = symptom;
            this.hardening = hardening;
            this.risk = risk;
            this.action = action;
            this.trigger = trigger;
        }
    }

    // ------------------------------------------------------------------
    // 精编目录（25 条）——来自对商业混淆器适配失败案例的知识沉淀
    // ------------------------------------------------------------------

    private static List<Weakness> curated() {
        List<Weakness> out = new java.util.ArrayList<>(32);
        int id = 1;

        // ---- CONTRACT：隐式契约识别 ----
        out.add(w(id++, "REFLECTION_FOR_NAME", "ZKM", PILLAR_CONTRACT,
                "Class.forName 的类名字符串与类重命名/字符串加密不同步：字符串变了而目标类已被改名，动态加载断裂",
                "ClassNotFoundException / NoClassDefFoundError 于运行期动态加载点",
                "反射字符串感知：命中 fully.qualified 类名格式的 LDC 即联动 keep 或同步重映射",
                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                "Class.forName(\"{0}\")"));
        out.add(w(id++, "REFLECTION_MEMBER_LOOKUP", "ProGuard", PILLAR_CONTRACT,
                "getDeclaredMethod/getMethod/getField 的成员名字符串不参与 keep 推导，成员改名后查找失败",
                "NoSuchMethodException / NoSuchFieldException",
                "成员级反射名播种 keep 集（__anykept__），命中即保留成员原名",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "Class.{1} lookup on {0} for \"{2}\""));
        out.add(w(id++, "REFLECTION_FIELD_ACCESS", "generic", PILLAR_CONTRACT,
                "Field.get/set 按名字符串访问字段，字段名被混淆后访问断裂",
                "NoSuchFieldException / IllegalAccessException",
                "检测 Field.get/set 作用域并保留对应字段名",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "Field.get/set in {0}.{1}"));
        out.add(w(id++, "PROXY_INTERFACE", "ZKM", PILLAR_CONTRACT,
                "动态代理接口方法按声明名 vtable 解析，重命名接口方法会触发 AbstractMethodError",
                "AbstractMethodError at proxy invocation",
                "Proxy.newProxyInstance 的目标接口整体保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_CLASS,
                "Proxy.newProxyInstance with interface {0}"));
        out.add(w(id++, "SERVICE_LOADER", "Allatori", PILLAR_CONTRACT,
                "SPI provider 类名/无参构造被重命名，ServiceLoader 按 META-INF/services 文本加载失败",
                "ServiceConfigurationError / 功能静默缺失",
                "解析 services 文件 provider FQN 并保留其无参构造",
                RiskLevel.HIGH, ProtectionAction.KEEP_NOARG_CTOR,
                "ServiceLoader.load({0}) / META-INF/services"));
        out.add(w(id++, "SERIALIZABLE_CLASS", "Allatori", PILLAR_CONTRACT,
                "字段改名破坏 Java 序列化按名匹配，serialVersionUID 不保留导致反序列化失配",
                "InvalidClassException / 序列化流失配",
                "保留 serialVersionUID + 可序列化字段名",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_SERIALIZATION,
                "class {0} implements Serializable"));
        out.add(w(id++, "SERIALIZATION_HOOK", "JNIC", PILLAR_CONTRACT,
                "readObject/writeObject/readResolve 钩子被重命名，序列化协议失效并可能绕过反序列化安全校验",
                "反序列化数据被篡改 / 钩子未执行",
                "序列化钩子方法名保留（安全敏感）",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "{0}.{1}{2} is readObject/writeObject/readResolve"));
        out.add(w(id++, "RESOURCE_PATH", "generic", PILLAR_CONTRACT,
                "getResourceAsStream 的路径字符串被加密或资源被重命名，资源加载失败",
                "资源返回 null / 配置缺失",
                "资源路径字符串不加密或与资源重命名保持一致",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_RESOURCE,
                "getResourceAsStream(\"{3}\")"));
        out.add(w(id++, "ANNOTATION_TARGET", "ZKM", PILLAR_CONTRACT,
                "框架注解被擦除或注解目标类被重命名，组件扫描/依赖注入失效",
                "Spring Bean 未注册 / 注入失败",
                "框架注解目标类保留，注解保留遵循 Retention 策略",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_CLASS,
                "@{4} on {0}"));
        out.add(w(id++, "ENTRY_POINT", "generic", PILLAR_CONTRACT,
                "Main-Class 入口被重命名，jar 无法启动",
                "Error: Main method not found in class",
                "Manifest Main-Class + main 签名保留",
                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                "main / entry {0}.{1}{2}"));
        out.add(w(id++, "ENUM_TYPE", "generic", PILLAR_CONTRACT,
                "枚举常量名重命名破坏 valueOf/values 与序列化按名语义",
                "反序列化异常 / 枚举查找失败",
                "枚举常量 + valueOf/values 保留",
                RiskLevel.LOW, ProtectionAction.KEEP_CLASS,
                "enum {0} with constants"));
        out.add(w(id++, "RECORD_TYPE", "ProGuard", PILLAR_CONTRACT,
                "record 组件访问器重命名破坏规范访问器与 RecordAttribute 反射",
                "record 反射访问器丢失",
                "record 组件访问器保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                "record {0} component accessor {1}{2}"));
        out.add(w(id++, "SEALED_CLASS", "generic", PILLAR_CONTRACT,
                "sealed 层次重命名未同步 permits 集，运行期类图不一致",
                "IncompatibleClassChangeError",
                "sealed 层次整体保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_CLASS,
                "sealed {0} permits set"));
        out.add(w(id++, "KOTLIN_METADATA", "ProGuard", PILLAR_CONTRACT,
                "Kotlin @Metadata 内嵌名未随重命名同步，Kotlin 反射/序列化/协程框架失效",
                "kotlinx.serialization / kotlin.reflect 异常",
                "重命名后修复 @Metadata 内嵌名字",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_SIGNATURE,
                "@Metadata on {0}"));

        // ---- SPEC：规范遵循 ----
        out.add(w(id++, "LAMBDA_CAPTURE", "ProGuard", PILLAR_SPEC,
                "invokedynamic bootstrap 中 MethodHandle 目标被重命名，LambdaMetafactory 解析失败",
                "LambdaConversionException / NoSuchMethodError at lambda site",
                "bootstrap 参数内 Handle 目标加入强制关联 keep 集",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                "invokedynamic captures {0}.{1}{2}"));
        out.add(w(id++, "GENERIC_SIGNATURE", "ProGuard", PILLAR_SPEC,
                "Signature 属性未随重命名同步，Spring/Jackson 泛型反射读到旧签名",
                "Spring 泛型注入失败 / Jackson 反序列化丢失泛型",
                "保留 Signature 属性并随重命名同步更新",
                RiskLevel.LOW, ProtectionAction.KEEP_SIGNATURE,
                "{0}.{1}{2} carries Signature attribute"));
        out.add(w(id++, "NATIVE_METHOD", "JNIC", PILLAR_SPEC,
                "native 方法重命名导致 JNI 符号表错位，registerNatives 失败",
                "UnsatisfiedLinkError / registerNatives0 failed",
                "native 方法名保留并与原生符号表对齐",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "native method {0}.{1}{2}"));
        out.add(w(id++, "CALLBACK_INTERFACE", "JNIC", PILLAR_SPEC,
                "回调接口实现方法重命名，vtable 按名分发 AbstractMethodError",
                "AbstractMethodError at callback dispatch",
                "回调接口实现方法保留（vtable 按名分发）",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "{0} implements callback interface, method {1}{2}"));
        out.add(w(id++, "EXCEPTION_TABLE", "JNIC", PILLAR_SPEC,
                "异常表 start/end/handler 语义在转换后错位，异常被吞或错误捕获（JNIC 原生转换尤其高危）",
                "异常被错误捕获 / finally 未执行 / 原生崩溃",
                "异常表目标随控制流变换一致重算，native 转换遵循 JNI Throw 语义",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "{0}.{1}{2} has try/catch/finally handler table"));
        out.add(w(id++, "STACK_MAP_FRAMES", "ProGuard/Allatori", PILLAR_SPEC,
                "控制流平坦化/注入后 StackMapTable 未重算，JVM 验证器拒绝加载",
                "VerifyError at class load",
                "所有变换后 COMPUTE_FRAMES + CheckClassAdapter 自检",
                RiskLevel.HIGH, ProtectionAction.NONE,
                "{0}.{1}{2} requires StackMapTable recomputation"));
        out.add(w(id++, "SYNTHETIC_BRIDGE", "ProGuard", PILLAR_SPEC,
                "桥接方法被移除/重命名，泛型擦除多态断链",
                "AbstractMethodError / ClassCastException at bridge",
                "合成桥接方法保留（擦除一致性）",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                "bridge method {0}.{1}{2}"));
        out.add(w(id++, "STRING_CONCAT_INDY", "R8/D8", PILLAR_SPEC,
                "Java 9+ StringConcatFactory indy 配方被常量折叠/参数重排破坏，字符串拼接错乱",
                "字符串输出错乱 / 静默数据损坏",
                "indy concat 站点保持原样，控制流变换不得重排 concat 实参加载",
                RiskLevel.LOW, ProtectionAction.NONE,
                "StringConcatFactory indy in {0}.{1}{2}"));

        // ---- DEGRADE：渐进降级 ----
        out.add(w(id++, "SWING_EDT_CALLBACK", "JNIC/商用混淆", PILLAR_DEGRADE,
                "GUI 回调下沉 JNIC/VMP 后 EDT 吞掉 VM 异常 → 无画面/无法操作（JNIC 原生转换在此类场景静默失败）",
                "窗口空白 / 按键无响应 / 游戏无法开始",
                "GUI 组件类排除 JNIC/VMP（渐进降级到 Java 执行），仅纯逻辑类下沉",
                RiskLevel.HIGH, ProtectionAction.EXCLUDE_FROM_NATIVE,
                "Swing EDT callback {0}.{1}{2} (paint/key/action)"));

        // ---- ENV：环境探测 ----
        out.add(w(id++, "MULTI_RELEASE", "DashO", PILLAR_ENV,
                "META-INF/versions/N 版本化类未感知，混淆后版本化类与基类不一致",
                "不同 JDK 下行为不一致 / ClassFormatError",
                "版本化资源路径保留 + 各版本类一致变换",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_RESOURCE,
                "multi-release entry {3} under META-INF/versions"));
        out.add(w(id++, "MODULE_INFO", "generic", PILLAR_ENV,
                "module-info 的 requires/exports/opens 被破坏，模块图失效",
                "ModuleResolutionError / IllegalAccessError",
                "module-info 整体保留（模块系统）",
                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                "module-info requires {0}"));

        // =====================================================================
        // 现代 JDK（Java 8..25 时代新增语言特性 / 类文件演进）
        // =====================================================================
        out.add(w(id++, "CLASS_FILE_VERSION", "DashO", PILLAR_ENV,
                "类文件主版本跨度 Java 8(52)..Java 25(69)，解析/重写必须按输入版本精确保留，否则高版本类被降级或拒绝",
                "ClassFormatError / Unsupported class file major version",
                "按输入类文件版本解析+重写（ASM 支持 52..69），不擅自升降版本",
                RiskLevel.HIGH, ProtectionAction.NONE,
                "class {0} file version {1}"));
        out.add(w(id++, "SWITCH_EXPRESSION_INDY", "R8/D8", PILLAR_SPEC,
                "switch 表达式/模式匹配编译为 SwitchBootstraps indy，配方被常量折叠/分支重排破坏后抛错或走错分支",
                "ArrayIndexOutOfBoundsException at switch site / 错误分支",
                "SwitchBootstraps/ObjectMethods indy 站点保持原样，控制流变换不得重排其 case 实参",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "SwitchBootstraps indy in {0}.{1}{2}"));
        out.add(w(id++, "PATTERN_MATCHING", "generic", PILLAR_SPEC,
                "instanceof 模式匹配/switch 模式生成额外局部槽与守卫分支，平坦化/类型混淆可能破坏守卫语义",
                "ClassCastException / 匹配走错分支",
                "模式匹配守卫分支不做破坏性重排；涉及记录模式时保留组件访问器",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "pattern matching in {0}.{1}{2}"));
        out.add(w(id++, "RECORD_SERIALIZATION", "ProGuard", PILLAR_SPEC,
                "record + Serializable 的规范序列化按组件名匹配，组件访问器重命名导致反序列化失配",
                "InvalidClassException / 组件错位",
                "record 组件访问器 + 规范构造器保留，序列化安全",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_SERIALIZATION,
                "record {0} implements Serializable"));

        // =====================================================================
        // Kotlin 生态（协程 / DefaultImpls / data class）
        // =====================================================================
        out.add(w(id++, "KOTLIN_COROUTINES", "Kotlin", PILLAR_SPEC,
                "suspend 函数编译为含 Continuation 参数的状态机（*$*$1 implements ContinuationImpl），其方法体复杂（try/finally/恢复点），"
                        + "重命名状态机或将其下沉 JNIC/VMP 会破坏协程恢复",
                "IllegalStateException at continuation resume / 协程挂起后无法恢复",
                "协程状态机类排除 JNIC/VMP 下沉并避开破坏性控制流变换，Continuation 参数保留",
                RiskLevel.HIGH, ProtectionAction.EXCLUDE_FROM_NATIVE,
                "suspend {0}.{1}{2} / ContinuationImpl state machine"));
        out.add(w(id++, "KOTLIN_DEFAULTIMPLS", "ProGuard", PILLAR_SPEC,
                "接口默认实现生成 $DefaultImpls 静态方法，重命名接口方法未同步 DefaultImpls 会导致接口默认实现断链",
                "AbstractMethodError at default-interface call",
                "接口方法与 $DefaultImpls 静态方法随重命名同步（保持引用一致）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "interface {0} with $DefaultImpls"));
        out.add(w(id++, "KOTLIN_DATA_CLASS", "ProGuard", PILLAR_CONTRACT,
                "data class 的 componentN()/copy()/equals/hashCode 可能被反射/解构引用，重命名后 Kotlin 反射或框架失配",
                "kotlin.reflect 异常 / componentN 丢失",
                "data class 的 componentN/copy/equals/hashCode/toString 保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                "@Metadata(kind=1) data class {0}"));

        // =====================================================================
        // Lombok 生成代码
        // =====================================================================
        out.add(w(id++, "LOMBOK_ACCESSORS", "generic", PILLAR_CONTRACT,
                "Lombok @Data/@Getter/@Setter 生成的访问器被框架按 Bean 反射读取，重命名改变属性名契约",
                "Jackson 属性丢失 / 框架注入失败",
                "带 Lombok 注解类的 getX/setX/isX 访问器保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_BEAN_ACCESSORS,
                "@lombok.{Data,Getter,Setter,Value} on {0}"));
        out.add(w(id++, "LOMBOK_BUILDER", "generic", PILLAR_CONTRACT,
                "@Builder 生成静态 builder()/Builder 类被反射或构建器调用引用，类被重命名/合并破坏构建链",
                "NoSuchMethodError builder() / Builder 类丢失",
                "Lombok Builder 类与 builder() 入口保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_CLASS,
                "@lombok.Builder on {0}"));

        // =====================================================================
        // 框架（Jackson / Spring AOP / Jakarta EE）
        // =====================================================================
        out.add(w(id++, "JACKSON_BEAN_ACCESSORS", "Jackson", PILLAR_CONTRACT,
                "Jackson 按 getter/setter 名做 JSON 属性映射，重命名访问器改变 JSON 契约（序列化/反序列化字段名）",
                "JSON 字段名变化 / 反序列化属性丢失",
                "带 Jackson 注解类的 Bean 访问器保留（保持 JSON 契约）",
                RiskLevel.HIGH, ProtectionAction.KEEP_BEAN_ACCESSORS,
                "com.fasterxml.jackson.annotation.* on {0}"));
        out.add(w(id++, "SPRING_AOP_PROXY", "Spring", PILLAR_CONTRACT,
                "Spring AOP/CGLIB 代理依赖非 final 方法名与 Bean 属性，方法重命名破坏 pointcut 匹配与属性注入",
                "AOP 通知不生效 / 属性注入失败",
                "Spring 注解类的 Bean 访问器 + 被 pointcut 引用的方法保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_BEAN_ACCESSORS,
                "Spring annotation on {0}"));
        out.add(w(id++, "JAKARTA_EE", "Jakarta", PILLAR_CONTRACT,
                "jakarta.* 注解（CDI/JPA/JAX-RS/Validation）按名反射驱动组件扫描与注入，注解目标类重命名失效",
                "CDI Bean 未注册 / JPA 实体映射失败",
                "jakarta.* 注解目标类保留（组件扫描安全）",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_CLASS,
                "@jakarta.* on {0}"));

        // =====================================================================
        // 序列化新形态（过滤器 / Externalizable）
        // =====================================================================
        out.add(w(id++, "SERIALIZATION_FILTER", "generic", PILLAR_CONTRACT,
                "ObjectInputFilter / setSerialFilter 配置的类名模式按名匹配，类重命名导致过滤器失效或绕过安全过滤",
                "反序列化安全过滤被绕过 / 意外类被接受",
                "设置序列化过滤器处引用的类名保持（安全敏感），重命名需同步过滤配置",
                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                "ObjectInputFilter / setSerialFilter in {0}.{1}{2}"));
        out.add(w(id++, "EXTERNALIZABLE", "generic", PILLAR_CONTRACT,
                "writeExternal/readExternal 由 ObjectStream 按名反射调用，重命名后外部序列化协议失效",
                "StreamCorruptedException / 钩子未执行",
                "Externalizable 的 writeExternal/readExternal 保留",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "{0} implements Externalizable"));

        // =====================================================================
        // 现代反射（MethodHandles / VarHandle / JDK 内部）
        // =====================================================================
        out.add(w(id++, "METHODHANDLES_LOOKUP", "ProGuard", PILLAR_CONTRACT,
                "MethodHandles.lookup().findVirtual/findStatic/findConstructor/findGetter/findSetter 以字符串名解析，成员重命名后句柄解析失败",
                "NoSuchMethodError / NoSuchFieldError at handle lookup",
                "MethodHandles 查找的名字播种 keep 集（__anykept__）",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "MethodHandles.lookup().find*(\"{2}\") in {0}.{1}"));
        out.add(w(id++, "VARHANDLE", "ProGuard", PILLAR_CONTRACT,
                "VarHandle 通过 findVarHandle/findStaticVarHandle 按字段名解析，字段重命名后原子访问失效",
                "NoSuchFieldError at varhandle lookup",
                "VarHandle 查找的字段名保留（原子访问契约）",
                RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                "MethodHandles findVarHandle(\"{2}\") in {0}.{1}"));
        out.add(w(id++, "JDK_INTERNAL", "generic", PILLAR_ENV,
                "代码触碰 jdk.internal.* / sun.misc.Unsafe 等 JDK 内部 API，跨 Java 8..25 版本语义不同，重命名/变换不能假设其稳定",
                "跨版本 NoSuchFieldError / IllegalAccessError",
                "JDK 内部 API 引用保持不动，按运行版本行为一致",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "jdk.internal / sun.misc.Unsafe in {0}.{1}{2}"));

        // =====================================================================
        // JavaBeans
        // =====================================================================
        out.add(w(id++, "JAVABEANS_INTROSPECTOR", "generic", PILLAR_CONTRACT,
                "Introspector.getBeanInfo 按 getter/setter 名构建 PropertyDescriptor，重命名破坏 Bean 属性模型",
                "PropertyDescriptor 缺失 / 属性绑定失败",
                "Introspector 作用域的 Bean 访问器保留",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_BEAN_ACCESSORS,
                "java.beans.Introspector.getBeanInfo in {0}.{1}{2}"));

        // =====================================================================
        // GraalVM 原生镜像
        // =====================================================================
        out.add(w(id++, "NATIVE_IMAGE_METADATA", "GraalVM", PILLAR_CONTRACT,
                "META-INF/native-image/*.json（reflect/resource/proxy/jni 配置）在 native-image 构建期按名读取，混淆/加密这些资源会破坏原生镜像构建",
                "native-image 缺反射元数据 / 构建失败",
                "native-image 元数据资源整体保留（不重命名/不加密）",
                RiskLevel.HIGH, ProtectionAction.KEEP_RESOURCE,
                "META-INF/native-image/{3}"));

        // =====================================================================
        // 自定义 ClassLoader
        // =====================================================================
        out.add(w(id++, "CUSTOM_CLASSLOADER", "generic", PILLAR_SPEC,
                "用户 ClassLoader 子类覆写 loadClass/findClass/defineClass 动态加载类，方法重命名或下沉 JNIC/VMP 破坏委派模型",
                "ClassNotFoundException / 自定义加载失效",
                "自定义 ClassLoader 类排除 JNIC/VMP 下沉并保留覆写方法名",
                RiskLevel.HIGH, ProtectionAction.EXCLUDE_FROM_NATIVE,
                "class {0} extends java/lang/ClassLoader"));

        // =====================================================================
        // JPMS 服务
        // =====================================================================
        out.add(w(id++, "JPMS_SERVICES", "generic", PILLAR_CONTRACT,
                "module-info 的 provides/uses 声明 ServiceLoader 服务，provider 类重命名后模块服务解析失败",
                "ServiceConfigurationError at module service load",
                "module-info provides/uses 的 provider 类保留",
                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                "module-info provides/uses {0}"));

        // =====================================================================
        // R8/D8 / Stringer / ZKM / Allatori 理念对照
        // =====================================================================
        out.add(w(id++, "CLASS_MERGING", "R8/D8", PILLAR_SPEC,
                "R8 类合并依赖 inner/outer 引用一致性，混淆器重命名若拆散内部类引用链会触发 NoClassDefFoundError",
                "NoClassDefFoundError at inner-class reference",
                "内部/外部类引用随重命名一致改写（保持嵌套结构）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "inner/outer class {0}"));
        out.add(w(id++, "RESOURCE_SHRINKING", "R8/D8", PILLAR_CONTRACT,
                "R8 资源缩小按代码引用的资源路径裁剪，被引资源若被重命名则加载失败",
                "资源 null / 配置缺失",
                "代码引用的资源路径保留（与资源重命名一致）",
                RiskLevel.MEDIUM, ProtectionAction.KEEP_RESOURCE,
                "referenced resource {3} in {0}.{1}"));
        out.add(w(id++, "STRING_MEMORY_PROTECTION", "Stringer", PILLAR_ENV,
                "Stringer 字符串保护 vs 内存分析：解密后的字符串若长期驻留堆/明文窗口即可被 dump 复现",
                "内存 dump 直接取到明文串",
                "解密后立即擦除明文缓冲（KBox 已落地：WeakReference 缓存 + Arrays.fill 擦除）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "string decrypt site in {0}.{1}{2}"));
        out.add(w(id++, "FLOW_SYMBOLIC_EXECUTION", "ZKM", PILLAR_SPEC,
                "ZKM 流混淆 vs 符号执行：透明谓词/平坦化若可被符号执行求值即失效",
                "谓词被常量折叠 / 平坦化被还原",
                "不透明谓词 + 平坦化 + 运行时状态机（KBox 已落地：opaqueStateMachine 等）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "control-flow transform target {0}.{1}{2}"));
        out.add(w(id++, "SELF_MODIFYING_CODE", "ZKM", PILLAR_SPEC,
                "自修改/分层虚拟化代码 dump 静态段只能得到密文，但若解码流可重放则失效",
                "静态 dump 得到可重放明文流",
                "自修改磁带 + 会话重键（KBox 已落地：BrainfuckShield + resident 重键）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "layered VM/self-modifying code in {0}.{1}{2}"));
        out.add(w(id++, "RENAME_REFERENCE_MODEL", "Allatori", PILLAR_CONTRACT,
                "Allatori 引用一致重命名模型：重命名必须逐引用一致改写，否则同一成员名映射分裂",
                "NoSuchMethodError / 部分引用未改写",
                "重命名按引用拓扑一致改写（KBox ClassRemapper 全量引用一致）",
                RiskLevel.MEDIUM, ProtectionAction.NONE,
                "rename topology {0}.{1}{2}"));

        return out;
    }

    private static Weakness w(int id, String family, String source, String pillar,
                              String weakness, String symptom, String hardening,
                              RiskLevel risk, ProtectionAction action, String trigger) {
        return new Weakness(id, family, source, pillar, weakness, symptom, hardening,
                risk, action, trigger);
    }
}
