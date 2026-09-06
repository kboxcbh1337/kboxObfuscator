package com.kbox.core.silentshield;

/**
 * SilentShield — 自动防护动作（应对策略）。
 *
 * <p>当 {@link AdaptationAuditor} 在输入 jar 中检测到某个特殊代码模式时，
 * SilentShield 从 {@link WeaknessCatalog} 中查询该模式族对应的防护动作，
 * 并将动作落地到配置 / keep 集，从而"预防问题"而非等运行时报错。
 *
 * <p>动作设计对齐商业混淆器的"渐进降级 / 最小侵入"哲学：宁可少混淆，
 * 也不破坏语义。
 */
public enum ProtectionAction {
    /** 无需任何动作（纯记录）。 */
    NONE,
    /** 保留整个类（不重命名类名，反射/SPI/框架入口安全）。 */
    KEEP_CLASS,
    /** 保留具体成员（方法/字段名不重命名，反射查找安全）。 */
    KEEP_MEMBER,
    /** 保留无参构造器（ServiceLoader / 反射实例化）。 */
    KEEP_NOARG_CTOR,
    /** 保留可序列化字段 + serialVersionUID（Java 序列化按名反射）。 */
    KEEP_SERIALIZATION,
    /** 保留签名属性（Signature 属性，Spring/Jackson 泛型反射）。 */
    KEEP_SIGNATURE,
    /** 排除该类的控制流混淆（高复杂度方法平坦化会超时/损坏）。 */
    SKIP_CONTROL_FLOW,
    /** 排除该类的一切 JNIC/VMP 下沉（保持 Java 执行）。 */
    EXCLUDE_FROM_NATIVE,
    /** 保留该资源路径（getResourceAsStream / SPI / 配置加载）。 */
    KEEP_RESOURCE,
    /** 保留该类的 Bean 访问器（getX/setX/isX），供 Jackson/JavaBeans/Lombok 属性反射。 */
    KEEP_BEAN_ACCESSORS,
    /** 该包路径整体保留（SPI / 组件扫描 / 序列化包名依赖）。 */
    KEEP_PACKAGE,
    /** 跳过字符串加密（该处字符串是外部契约，如 JNI 符号/资源名）。 */
    SKIP_STRING_ENCRYPTION,
    /** 渐进降级：关闭高风险 pass 或降低强度（VMP/JNIC/CF 其中之一）。 */
    GRADUAL_DEGRADE;

    /** 动作是否对字节码产生实质影响（用于审计摘要计数）。 */
    public boolean isMutating() {
        return this != NONE && this != GRADUAL_DEGRADE;
    }
}
