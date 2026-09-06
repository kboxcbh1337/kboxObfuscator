package com.kbox.core.silentshield;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;
import org.objectweb.asm.tree.AbstractInsnNode;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.InvokeDynamicInsnNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.LookupSwitchInsnNode;
import org.objectweb.asm.tree.MethodInsnNode;
import org.objectweb.asm.tree.MethodNode;
import org.objectweb.asm.tree.TableSwitchInsnNode;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * AdaptationAuditor — SilentShield 的"深度自检"组件。
 *
 * <p>对标商业混淆器（ZKM/JNIC）的适配哲学——"规范遵循 / 隐式契约识别 /
 * 渐进降级 / 环境探测"四大支柱，本组件对输入 jar 做一次全量适配性体检，
 * 扫描 {@link WeaknessCatalog} 中已固化的 25 类<b>其他混淆器适配性弱点</b>
 * 对应的特殊代码模式：
 *
 * <ul>
 *   <li>反射：{@code Class.forName} / {@code getDeclaredMethod|getField} /
 *       {@code Proxy.newProxyInstance} / {@code ServiceLoader.load}</li>
 *   <li>序列化：{@code Serializable} 类 + readObject/writeObject/readResolve 钩子</li>
 *   <li>SPI：{@code META-INF/services/*} provider 与无参构造器</li>
 *   <li>lambda/MethodHandle：invokedynamic bootstrap 捕获的方法引用</li>
 *   <li>泛型：Signature 属性（Spring/Jackson 反射读取）</li>
 *   <li>资源：{@code getResourceAsStream} 路径 / multi-release 条目</li>
 *   <li>框架注解、native 方法、入口点、回调接口、异常表、switch 栈帧、枚举、
 *       记录、密封类、桥接方法、Kotlin @Metadata、module-info</li>
 *   <li><b>Swing/AWT EDT 回调</b>——GUI 类下沉 JNIC/VMP 会导致"无画面/无法操作"
 *       （EDT 吞掉 VM 异常），是本自检最重要的一档预防。</li>
 * </ul>
 *
 * <p>审计不修改任何字节码；它只产出 {@link AuditFinding} 列表，由
 * {@link SilentShield} 统一去重、匹配 {@link WeaknessCatalog} 并落地防护动作。
 */
public final class AdaptationAuditor {

    private static final String TAG = "ss-audit";

    /** Swing/AWT GUI 组件根类型：继承它们的类必须排除 JNIC/VMP 下沉。 */
    private static final String[] GUI_COMPONENT_ROOTS = {
            "javax/swing/JComponent", "javax/swing/JPanel", "javax/swing/JFrame",
            "javax/swing/JDialog", "javax/swing/JApplet", "javax/swing/JWindow",
            "javax/swing/JInternalFrame", "javax/swing/JLayeredPane",
            "javax/swing/JTabbedPane", "javax/swing/JScrollPane",
            "javax/swing/JSplitPane", "javax/swing/JToolBar", "javax/swing/JMenuBar",
            "javax/swing/JPopupMenu", "javax/swing/table/JTableHeader",
            "javax/swing/text/JTextComponent", "java/awt/Component", "java/awt/Container",
            "java/awt/Frame", "java/awt/Window", "java/awt/Canvas", "java/awt/Panel"
    };

    /** EDT 回调方法名（paint/key/mouse/action/…）。 */
    private static final String[] EDT_CALLBACK_METHODS = {
            "paintComponent", "paint", "paintBorder", "paintChildren",
            "keyPressed", "keyReleased", "keyTyped",
            "mousePressed", "mouseReleased", "mouseClicked", "mouseMoved",
            "mouseDragged", "mouseEntered", "mouseExited",
            "actionPerformed", "update", "doLayout", "validate", "invalidate",
            "focusGained", "focusLost", "itemStateChanged", "stateChanged",
            "valueChanged", "componentResized", "componentMoved", "componentShown",
            "componentHidden", "addNotify", "removeNotify"
    };

    /** 按名字做 vtable 分发、重命名会触发 AbstractMethodError 的回调接口。 */
    private static final Set<String> CALLBACK_INTERFACES = new HashSet<>(Arrays.asList(
            "java/lang/Runnable", "java/util/concurrent/Callable", "java/lang/Comparable",
            "java/util/Comparator", "java/util/Iterator", "java/lang/Iterable",
            "java/awt/event/ActionListener", "java/awt/event/KeyListener",
            "java/awt/event/MouseListener", "java/awt/event/MouseMotionListener",
            "java/awt/event/MouseWheelListener", "java/awt/event/WindowListener",
            "java/awt/event/FocusListener", "java/awt/event/ItemListener",
            "javax/swing/event/ChangeListener", "javax/swing/event/DocumentListener",
            "javax/swing/event/ListSelectionListener", "javax/swing/event/TableModelListener",
            "org/bukkit/event/Listener", "org/bukkit/plugin/Plugin",
            "net/minecraftforge/eventbus/api/IEvent"
    ));

    /** 框架注解 FQN 前缀：命中即隐含运行期反射 / 组件扫描依赖。 */
    private static final String[] FRAMEWORK_ANNOTATION_PREFIXES = {
            "org/springframework/", "javax/persistence/", "jakarta/persistence/",
            "com/fasterxml/jackson/", "javax/ws/rs/", "jakarta/ws/rs/",
            "javax/xml/bind/", "jakarta/xml/bind/", "javax/annotation/",
            "jakarta/annotation/", "javax/inject/", "jakarta/inject/",
            "org/junit/jupiter/api/", "org/testng/annotations/", "kotlin/Metadata",
            "org/bukkit/event/", "net/minecraftforge/", "net/fabricmc/",
            "org/quartz/", "org/slf4j/", "io/micrometer/"
    };

    /** 全量审计入口：扫描所有类 + 所有资源，返回原始发现列表（未去重）。 */
    public List<AuditFinding> audit(ClassGraph graph, ProtectionConfig cfg) {
        List<AuditFinding> out = new ArrayList<>();
        int maxVersion = 0;
        for (ClassNode cn : new ArrayList<>(graph.getClasses().values())) {
            try {
                auditClass(graph, cn, out);
            } catch (Exception e) {
                // 单个类审计失败不得中断整个构建。
                KBoxLog.warn(TAG, "audit failed for " + cn.name + ": " + e.getMessage());
            }
            if (cn.version > maxVersion) maxVersion = cn.version;
        }
        auditResources(graph, out);
        // Java 8..25 类文件版本感知：报告输入 jar 的最高类文件版本（ENV 支柱）。
        if (maxVersion > 0) {
            out.add(new AuditFinding("CLASS_FILE_VERSION", "", String.valueOf(maxVersion),
                    RiskLevel.HIGH, ProtectionAction.NONE,
                    "input max class file version " + maxVersion + " (Java "
                            + versionLabel(maxVersion) + ")",
                    "parse/rewrite at the input class file version (52..69 supported)"));
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    private void auditClass(ClassGraph graph, ClassNode cn, List<AuditFinding> out) {
        // ---- module-info ----
        if ("module-info".equals(cn.name)) {
            out.add(new AuditFinding("MODULE_INFO", cn.name, "", RiskLevel.HIGH,
                    ProtectionAction.KEEP_CLASS,
                    "module-info requires/opens module system metadata",
                    "keep module-info so the module graph stays intact"));
            return;
        }

        // ---- 入口点 ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ("main".equals(mn.name) && "([Ljava/lang/String;)V".equals(mn.desc)
                        && (mn.access & Opcodes.ACC_STATIC) != 0) {
                    out.add(new AuditFinding("ENTRY_POINT", cn.name, "main ([Ljava/lang/String;)V",
                            RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                            "main / entry " + cn.name + ".main",
                            "keep entry point " + cn.name + ".main"));
                }
            }
        }

        // ---- enum / record / sealed ----
        if ((cn.access & Opcodes.ACC_ENUM) != 0) {
            out.add(new AuditFinding("ENUM_TYPE", cn.name, "", RiskLevel.LOW,
                    ProtectionAction.KEEP_CLASS,
                    "enum " + cn.name + " with constants",
                    "keep enum constants + valueOf/values of " + cn.name));
        }
        if ((cn.access & Opcodes.ACC_RECORD) != 0 || "java/lang/Record".equals(cn.superName)) {
            out.add(new AuditFinding("RECORD_TYPE", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_MEMBER,
                    "record " + cn.name + " component accessors",
                    "keep record component accessors of " + cn.name));
        }
        if (cn.permittedSubclasses != null && !cn.permittedSubclasses.isEmpty()) {
            out.add(new AuditFinding("SEALED_CLASS", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_CLASS,
                    "sealed " + cn.name + " permits set",
                    "keep sealed hierarchy of " + cn.name));
        }

        // ---- Serializable ----
        boolean serializable = cn.interfaces != null && cn.interfaces.contains("java/io/Serializable");
        if (serializable) {
            out.add(new AuditFinding("SERIALIZABLE_CLASS", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_SERIALIZATION,
                    "class " + cn.name + " implements Serializable",
                    "keep serializable fields + serialVersionUID of " + cn.name));
        }
        // ---- record + Serializable：规范序列化按组件名匹配 ----
        if (serializable && (cn.access & Opcodes.ACC_RECORD) != 0) {
            out.add(new AuditFinding("RECORD_SERIALIZATION", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_SERIALIZATION,
                    "record " + cn.name + " implements Serializable",
                    "keep record component accessors + canonical ctor for serialization"));
        }
        // ---- Externalizable：writeExternal/readExternal 按名反射 ----
        if (cn.interfaces != null && cn.interfaces.contains("java/io/Externalizable") && cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ("writeExternal".equals(mn.name) && "(Ljava/io/ObjectOutput;)V".equals(mn.desc)
                        || "readExternal".equals(mn.name) && "(Ljava/io/ObjectInput;)V".equals(mn.desc)) {
                    out.add(new AuditFinding("EXTERNALIZABLE", cn.name, mn.name + " " + mn.desc,
                            RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                            cn.name + "." + mn.name + mn.desc + " is an Externalizable hook",
                            "keep externalization hook " + cn.name + "." + mn.name + mn.desc));
                }
            }
        }
        // ---- 自定义 ClassLoader：覆写 loadClass/findClass 委派模型 ----
        if ("java/lang/ClassLoader".equals(cn.superName)) {
            out.add(new AuditFinding("CUSTOM_CLASSLOADER", cn.name, "", RiskLevel.HIGH,
                    ProtectionAction.EXCLUDE_FROM_NATIVE,
                    "class " + cn.name + " extends java/lang/ClassLoader",
                    "exclude custom ClassLoader " + cn.name + " from JNIC/VMP (delegation model)"));
        }
        // ---- Kotlin 生态 ----
        // 接口默认实现 $DefaultImpls（重命名需与接口方法同步）。
        if (cn.name.endsWith("$DefaultImpls")) {
            out.add(new AuditFinding("KOTLIN_DEFAULTIMPLS", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.NONE,
                    "interface default-impl class " + cn.name,
                    "keep $DefaultImpls in sync with interface renames"));
        }
        // 协程状态机：ContinuationImpl 子类（*$*$1）或含 invokeSuspend。
        boolean coroutineMachine = (cn.superName != null
                && cn.superName.startsWith("kotlin/coroutines/jvm/internal/")
                && cn.superName.contains("ContinuationImpl"));
        if (coroutineMachine || hasMethodNamed(cn, "invokeSuspend")) {
            out.add(new AuditFinding("KOTLIN_COROUTINES", cn.name, "", RiskLevel.HIGH,
                    ProtectionAction.EXCLUDE_FROM_NATIVE,
                    "Kotlin coroutine state machine " + cn.name,
                    "exclude coroutine state machine " + cn.name + " from JNIC/VMP"));
        }
        // data class：componentN()/copy() 可能被反射/解构引用。
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ((mn.name.matches("component\\d+") && mn.desc.startsWith("()"))
                        || "copy".equals(mn.name)) {
                    out.add(new AuditFinding("KOTLIN_DATA_CLASS", cn.name, mn.name + " " + mn.desc,
                            RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                            "data class " + cn.name + "." + mn.name + mn.desc,
                            "keep data-class accessor " + cn.name + "." + mn.name + mn.desc));
                }
            }
        }
        // ---- Lombok：@Data/@Getter/@Setter/@Value -> Bean 访问器；@Builder -> 类保留 ----
        if (hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/Data;")
                || hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/Getter;")
                || hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/Setter;")
                || hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/Value;")
                || hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/RequiredArgsConstructor;")) {
            out.add(new AuditFinding("LOMBOK_ACCESSORS", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_BEAN_ACCESSORS,
                    "@lombok accessors on " + cn.name,
                    "keep bean accessors of Lombok-annotated " + cn.name));
        }
        if (hasAnnotationPrefix(cn.visibleAnnotations, "Llombok/Builder;")) {
            out.add(new AuditFinding("LOMBOK_BUILDER", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_CLASS,
                    "@lombok.Builder on " + cn.name,
                    "keep Lombok builder class " + cn.name));
        }
        // ---- Jackson：JSON 契约按访问器名映射 ----
        if (hasAnnotationPrefix(cn.visibleAnnotations, "Lcom/fasterxml/jackson/annotation/")) {
            out.add(new AuditFinding("JACKSON_BEAN_ACCESSORS", cn.name, "", RiskLevel.HIGH,
                    ProtectionAction.KEEP_BEAN_ACCESSORS,
                    "Jackson-annotated class " + cn.name,
                    "keep bean accessors of " + cn.name + " (JSON contract)"));
        }
        // ---- Spring AOP / DI：pointcut 与属性注入按访问器名 ----
        if (hasAnnotationPrefix(cn.visibleAnnotations, "Lorg/springframework/") && hasBeanAccessors(cn)) {
            out.add(new AuditFinding("SPRING_AOP_PROXY", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_BEAN_ACCESSORS,
                    "Spring-annotated bean " + cn.name,
                    "keep bean accessors of Spring bean " + cn.name));
        }
        // ---- Jakarta EE：组件扫描/注入按注解类名 ----
        if (hasAnnotationPrefix(cn.visibleAnnotations, "Ljakarta/")) {
            out.add(new AuditFinding("JAKARTA_EE", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_CLASS,
                    "Jakarta-annotated class " + cn.name,
                    "keep Jakarta-annotated class " + cn.name));
        }
        // ---- JPMS 服务：module-info provides/uses 的 provider 类保留 ----
        if (cn.module != null) {
            if (cn.module.provides != null) {
                for (Object o : cn.module.provides) {
                    org.objectweb.asm.tree.ModuleProvideNode p = (org.objectweb.asm.tree.ModuleProvideNode) o;
                    for (String prov : p.providers) {
                        out.add(new AuditFinding("JPMS_SERVICES", prov, "", RiskLevel.HIGH,
                                ProtectionAction.KEEP_CLASS,
                                "module-info provides " + prov,
                                "keep module provider " + prov));
                    }
                }
            }
            if (cn.module.uses != null) {
                for (Object u : cn.module.uses) {
                    out.add(new AuditFinding("JPMS_SERVICES", (String) u, "", RiskLevel.HIGH,
                            ProtectionAction.KEEP_CLASS,
                            "module-info uses " + u,
                            "keep module service " + u));
                }
            }
        }

        // ---- Swing/AWT GUI 类识别（"无画面" 预防）----
        boolean guiClass = isGuiClass(graph, cn);

        // ---- Kotlin @Metadata ----
        if (hasAnnotation(cn.visibleAnnotations, "Lkotlin/Metadata;")) {
            out.add(new AuditFinding("KOTLIN_METADATA", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_SIGNATURE,
                    "@Metadata on " + cn.name,
                    "fix Kotlin @Metadata after rename on " + cn.name));
        }

        // ---- 类级框架注解 ----
        if (hasFrameworkAnnotation(cn.visibleAnnotations)) {
            out.add(new AuditFinding("ANNOTATION_TARGET", cn.name, "", RiskLevel.MEDIUM,
                    ProtectionAction.KEEP_CLASS,
                    "framework annotation on " + cn.name,
                    "keep class " + cn.name + " (framework annotation)"));
        }

        // ---- native 方法 ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                    out.add(new AuditFinding("NATIVE_METHOD", cn.name, mn.name + " " + mn.desc,
                            RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                            "native method " + cn.name + "." + mn.name + mn.desc,
                            "keep native symbol name " + cn.name + "." + mn.name + mn.desc));
                }
            }
        }

        // ---- 回调接口实现类：重命名其方法会触发 AbstractMethodError ----
        if (cn.interfaces != null) {
            for (String itf : cn.interfaces) {
                if (CALLBACK_INTERFACES.contains(itf)) {
                    if (cn.methods != null) {
                        for (MethodNode mn : (List<MethodNode>) cn.methods) {
                            if ((mn.access & Opcodes.ACC_STATIC) != 0) continue;
                            if ((mn.access & Opcodes.ACC_PRIVATE) != 0) continue;
                            if (mn.name.startsWith("<")) continue;
                            out.add(new AuditFinding("CALLBACK_INTERFACE", cn.name,
                                    mn.name + " " + mn.desc,
                                    RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                                    cn.name + " implements callback interface, method " + mn.name + mn.desc,
                                    "keep overridden callback " + cn.name + "." + mn.name + mn.desc));
                        }
                    }
                    break;
                }
            }
        }

        // ---- 序列化钩子 ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (isSerializationHook(mn.name, mn.desc)) {
                    out.add(new AuditFinding("SERIALIZATION_HOOK", cn.name, mn.name + " " + mn.desc,
                            RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                            cn.name + "." + mn.name + mn.desc + " is a serialization hook",
                            "keep serialization hook " + cn.name + "." + mn.name + mn.desc));
                }
            }
        }

        // ---- 桥接方法 ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ((mn.access & Opcodes.ACC_BRIDGE) != 0 && (mn.access & Opcodes.ACC_SYNTHETIC) != 0) {
                    out.add(new AuditFinding("SYNTHETIC_BRIDGE", cn.name, mn.name + " " + mn.desc,
                            RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                            "bridge method " + cn.name + "." + mn.name + mn.desc,
                            "keep synthetic bridge " + cn.name + "." + mn.name + mn.desc));
                }
            }
        }

        // ---- 字段：Signature 属性 + 框架注解 ----
        if (cn.fields != null) {
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if (fn.signature != null) {
                    out.add(new AuditFinding("GENERIC_SIGNATURE", cn.name, fn.name + " " + fn.desc,
                            RiskLevel.LOW, ProtectionAction.KEEP_SIGNATURE,
                            cn.name + "." + fn.name + fn.desc + " carries Signature attribute",
                            "preserve Signature attribute on " + cn.name + "." + fn.name + fn.desc));
                }
                if (hasFrameworkAnnotation(fn.visibleAnnotations)) {
                    out.add(new AuditFinding("ANNOTATION_TARGET", cn.name, fn.name + " " + fn.desc,
                            RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                            "@framework on field " + cn.name + "." + fn.name,
                            "keep annotated field " + cn.name + "." + fn.name));
                }
            }
        }

        // ---- 方法：指令流扫描 ----
        if (cn.methods == null) return;
        boolean guiCallbackSeen = false;
        for (MethodNode mn : (List<MethodNode>) cn.methods) {
            if (mn.instructions == null) continue;
            boolean hasTryCatch = mn.tryCatchBlocks != null && !mn.tryCatchBlocks.isEmpty();
            boolean hasSwitch = false;
            boolean hasFieldReflect = false;
            boolean jdkInternalSeen = false;

            if (guiClass && isEdtCallback(mn.name)) guiCallbackSeen = true;

            for (AbstractInsnNode ins : mn.instructions) {
                if (ins instanceof MethodInsnNode) {
                    MethodInsnNode mi = (MethodInsnNode) ins;
                    if (mi.owner.equals("java/lang/Class") && "forName".equals(mi.name)) {
                        String cls = prevLdcString(ins);
                        if (cls != null) {
                            out.add(new AuditFinding("REFLECTION_FOR_NAME", cn.name, "", RiskLevel.HIGH,
                                    ProtectionAction.KEEP_CLASS,
                                    "Class.forName(\"" + cls + "\") in " + cn.name + "." + mn.name,
                                    "keep class " + cls.replace('.', '/') + " so dynamic load survives renaming"));
                        }
                    } else if (mi.owner.equals("java/lang/Class")
                            && (mi.name.equals("getDeclaredMethod") || mi.name.equals("getMethod")
                            || mi.name.equals("getDeclaredField") || mi.name.equals("getField"))) {
                        String member = prevLdcString(ins);
                        if (member != null) {
                            out.add(new AuditFinding("REFLECTION_MEMBER_LOOKUP", cn.name, member,
                                    RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                                    "Class." + mi.name + " lookup on " + cn.name + " for \"" + member + "\"",
                                    "keep member \"" + member + "\" for reflective lookup"));
                        }
                    } else if (mi.owner.equals("java/lang/reflect/Proxy") && "newProxyInstance".equals(mi.name)) {
                        out.add(new AuditFinding("PROXY_INTERFACE", cn.name, "", RiskLevel.MEDIUM,
                                ProtectionAction.KEEP_CLASS,
                                "Proxy.newProxyInstance in " + cn.name + "." + mn.name,
                                "keep interfaces; proxies resolve methods by declared name"));
                    } else if (mi.owner.equals("java/util/ServiceLoader") && "load".equals(mi.name)) {
                        String cls = prevLdcClass(ins);
                        if (cls != null) {
                            out.add(new AuditFinding("SERVICE_LOADER", cls.replace('/', '.'), "",
                                    RiskLevel.HIGH, ProtectionAction.KEEP_NOARG_CTOR,
                                    "ServiceLoader.load(" + cls + ") in " + cn.name + "." + mn.name,
                                    "keep provider " + cls + " + its no-arg ctor"));
                        }
                    } else if ((mi.name.equals("getResourceAsStream") || mi.name.equals("getResource"))
                            && (mi.owner.equals("java/lang/Class") || mi.owner.equals("java/lang/ClassLoader"))) {
                        String path = prevLdcString(ins);
                        if (path != null) {
                            out.add(new AuditFinding("RESOURCE_PATH", cn.name, path, RiskLevel.MEDIUM,
                                    ProtectionAction.KEEP_RESOURCE,
                                    "getResourceAsStream(\"" + path + "\") in " + cn.name + "." + mn.name,
                                    "keep resource path " + path + " (or remap consistently)"));
                        }
                    } else if (mi.owner.equals("java/lang/reflect/Field")
                            && (mi.name.startsWith("get") || mi.name.startsWith("set"))) {
                        hasFieldReflect = true;
                    } else if (mi.owner.equals("java/lang/invoke/MethodHandles$Lookup") && mi.name.startsWith("find")) {
                        String member = prevLdcString(ins);
                        String fam = (mi.name.equals("findVarHandle") || mi.name.equals("findStaticVarHandle"))
                                ? "VARHANDLE" : "METHODHANDLES_LOOKUP";
                        if (member != null) {
                            out.add(new AuditFinding(fam, cn.name, member, RiskLevel.HIGH,
                                    ProtectionAction.KEEP_MEMBER,
                                    "MethodHandles." + mi.name + "(\"" + member + "\") in "
                                            + cn.name + "." + mn.name,
                                    "keep member \"" + member + "\" for handle lookup"));
                        } else {
                            out.add(new AuditFinding(fam, cn.name, mn.name + " " + mn.desc, RiskLevel.HIGH,
                                    ProtectionAction.NONE,
                                    "MethodHandles." + mi.name + " in " + cn.name + "." + mn.name + mn.desc,
                                    "recorded: handle lookup with non-literal member name"));
                        }
                    } else if (mi.owner.equals("java/io/ObjectInputFilter$Config") && mi.name.startsWith("set")) {
                        out.add(new AuditFinding("SERIALIZATION_FILTER", cn.name, mn.name + " " + mn.desc,
                                RiskLevel.HIGH, ProtectionAction.KEEP_CLASS,
                                "ObjectInputFilter." + mi.name + " in " + cn.name + "." + mn.name + mn.desc,
                                "keep classes referenced by the serialization filter config"));
                    } else if (mi.owner.startsWith("jdk/internal/") || "sun/misc/Unsafe".equals(mi.owner)) {
                        if (!jdkInternalSeen) {
                            jdkInternalSeen = true;
                            out.add(new AuditFinding("JDK_INTERNAL", cn.name, mn.name + " " + mn.desc,
                                    RiskLevel.MEDIUM, ProtectionAction.NONE,
                                    "JDK internal API " + mi.owner + " in " + cn.name + "." + mn.name + mn.desc,
                                    "recorded: JDK-internal usage is version-sensitive across Java 8..25"));
                        }
                    } else if (mi.owner.equals("java/beans/Introspector") && "getBeanInfo".equals(mi.name)) {
                        String cls = prevLdcClass(ins);
                        if (cls != null) {
                            out.add(new AuditFinding("JAVABEANS_INTROSPECTOR", cls, "", RiskLevel.MEDIUM,
                                    ProtectionAction.KEEP_BEAN_ACCESSORS,
                                    "Introspector.getBeanInfo(" + cls + ") in " + cn.name + "." + mn.name,
                                    "keep bean accessors of introspected class " + cls));
                        }
                    }
                } else if (ins instanceof InvokeDynamicInsnNode) {
                    InvokeDynamicInsnNode id = (InvokeDynamicInsnNode) ins;
                    // Java 9+ StringConcatFactory indy：R8/D8 曾在此类站点因配方被
                    // 常量折叠/参数重排破坏而错乱，检测后如实记录（弱点目录标注）。
                    if (id.bsm != null && "java/lang/invoke/StringConcatFactory".equals(id.bsm.getOwner())) {
                        out.add(new AuditFinding("STRING_CONCAT_INDY", cn.name, mn.name + " " + mn.desc,
                                RiskLevel.LOW, ProtectionAction.NONE,
                                "StringConcatFactory indy in " + cn.name + "." + mn.name + mn.desc,
                                "preserve indy concat recipe; CF must not reorder concat arg loads"));
                    }
                    // switch 表达式/模式匹配（SwitchBootstraps）与 record 规范方法（ObjectMethods）
                    // 的 indy 站点：配方以 case 常量/组件名为实参，破坏即抛错或走错分支。
                    if (id.bsm != null && ("java/lang/runtime/SwitchBootstraps".equals(id.bsm.getOwner())
                            || "java/lang/runtime/ObjectMethods".equals(id.bsm.getOwner()))) {
                        out.add(new AuditFinding("SWITCH_EXPRESSION_INDY", cn.name, mn.name + " " + mn.desc,
                                RiskLevel.MEDIUM, ProtectionAction.NONE,
                                "runtime bootstrap " + id.bsm.getOwner() + " in "
                                        + cn.name + "." + mn.name + mn.desc,
                                "preserve switch/record-object bootstrap sites; do not reorder their args"));
                    }
                    for (Object a : id.bsmArgs) {
                        if (a instanceof Handle) {
                            Handle h = (Handle) a;
                            if (!h.getOwner().startsWith("java/") && !h.getOwner().startsWith("jdk/")) {
                                out.add(new AuditFinding("LAMBDA_CAPTURE", h.getOwner(),
                                        h.getName() + " " + h.getDesc(),
                                        RiskLevel.MEDIUM, ProtectionAction.KEEP_MEMBER,
                                        "invokedynamic captures " + h.getOwner() + "." + h.getName() + h.getDesc(),
                                        "keep captured method " + h.getOwner() + "." + h.getName() + h.getDesc()));
                            }
                        }
                    }
                } else if (ins instanceof TableSwitchInsnNode || ins instanceof LookupSwitchInsnNode) {
                    hasSwitch = true;
                }
            }

            if (hasTryCatch) {
                out.add(new AuditFinding("EXCEPTION_TABLE", cn.name, mn.name + " " + mn.desc,
                        RiskLevel.MEDIUM, ProtectionAction.NONE,
                        cn.name + "." + mn.name + mn.desc + " has try/catch/finally handler table",
                        "recompute exception table targets consistently on " + cn.name + "." + mn.name + mn.desc));
            }
            if (hasSwitch) {
                out.add(new AuditFinding("STACK_MAP_FRAMES", cn.name, mn.name + " " + mn.desc,
                        RiskLevel.HIGH, ProtectionAction.NONE,
                        cn.name + "." + mn.name + mn.desc + " has switch/table frames",
                        "COMPUTE_FRAMES after transform on " + cn.name + "." + mn.name + mn.desc));
            }
            if (hasFieldReflect) {
                out.add(new AuditFinding("REFLECTION_FIELD_ACCESS", cn.name, mn.name + " " + mn.desc,
                        RiskLevel.HIGH, ProtectionAction.KEEP_MEMBER,
                        "Field.get/set in " + cn.name + "." + mn.name + mn.desc,
                        "keep reflective field access members in " + cn.name));
            }

            // 方法级 Signature 属性。
            if (mn.signature != null) {
                out.add(new AuditFinding("GENERIC_SIGNATURE", cn.name, mn.name + " " + mn.desc,
                        RiskLevel.LOW, ProtectionAction.KEEP_SIGNATURE,
                        cn.name + "." + mn.name + mn.desc + " carries Signature attribute",
                        "preserve Signature attribute on " + cn.name + "." + mn.name + mn.desc));
            }
        }

        // ---- GUI EDT 回调（每个 GUI 类只报一条，动作在类级落地）----
        if (guiClass && guiCallbackSeen) {
            out.add(new AuditFinding("SWING_EDT_CALLBACK", cn.name, "", RiskLevel.HIGH,
                    ProtectionAction.EXCLUDE_FROM_NATIVE,
                    "Swing GUI class " + cn.name + " with EDT callbacks (paint/key/mouse/action)",
                    "exclude GUI class " + cn.name + " from JNIC/VMP (EDT exceptions swallowed -> no screen)"));
        }
    }

    /** 资源级审计：SPI 文件、multi-release、module-info。 */
    private void auditResources(ClassGraph graph, List<AuditFinding> out) {
        for (Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            if (path.startsWith("META-INF/services/")) {
                String iface = path.substring("META-INF/services/".length());
                if (iface.isEmpty() || iface.contains("/")) continue;
                String text = new String(e.getValue(), StandardCharsets.UTF_8);
                for (String line : text.split("\\r?\\n")) {
                    String t = line.trim();
                    if (t.isEmpty() || t.startsWith("#")) continue;
                    int h = t.indexOf('#');
                    if (h >= 0) t = t.substring(0, h).trim();
                    if (t.isEmpty()) continue;
                    out.add(new AuditFinding("SERVICE_LOADER", t.replace('.', '/'), "", RiskLevel.HIGH,
                            ProtectionAction.KEEP_NOARG_CTOR,
                            "ServiceLoader provider " + t + " from " + path,
                            "keep provider " + t + " + its no-arg ctor"));
                }
            } else if (path.startsWith("META-INF/versions/")) {
                out.add(new AuditFinding("MULTI_RELEASE", "", path, RiskLevel.MEDIUM,
                        ProtectionAction.KEEP_RESOURCE,
                        "multi-release entry " + path + " under META-INF/versions",
                        "keep versioned resource/class path " + path));
            } else if (path.startsWith("META-INF/native-image/") && path.endsWith(".json")) {
                out.add(new AuditFinding("NATIVE_IMAGE_METADATA", "", path, RiskLevel.HIGH,
                        ProtectionAction.KEEP_RESOURCE,
                        "GraalVM native-image metadata " + path,
                        "keep native-image metadata resource " + path + " (build-time contract)"));
            }
        }
    }

    // ------------------------------------------------------------------
    // 判定工具
    // ------------------------------------------------------------------

    private static boolean isSerializationHook(String name, String desc) {
        return ("readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(desc))
                || ("writeObject".equals(name) && "(Ljava/io/ObjectOutputStream;)V".equals(desc))
                || ("readResolve".equals(name) && "()Ljava/lang/Object;".equals(desc))
                || ("writeReplace".equals(name) && "()Ljava/lang/Object;".equals(desc))
                || ("readObjectNoData".equals(name) && "()V".equals(desc));
    }

    private static boolean hasAnnotation(List<AnnotationNode> annos, String desc) {
        if (annos == null) return false;
        for (AnnotationNode a : annos) {
            if (desc.equals(a.desc)) return true;
        }
        return false;
    }

    private static boolean hasFrameworkAnnotation(List<AnnotationNode> annos) {
        if (annos == null) return false;
        for (AnnotationNode a : annos) {
            String d = a.desc;
            if (d == null || d.length() < 3 || !d.startsWith("L") || !d.endsWith(";")) continue;
            String internal = d.substring(1, d.length() - 1);
            for (String p : FRAMEWORK_ANNOTATION_PREFIXES) {
                if (internal.startsWith(p)) return true;
            }
        }
        return false;
    }

    /** 任意可见注解的描述以给定前缀开头（前缀含 'L' 与结尾 ';'，如 "Llombok/Data;"）。 */
    private static boolean hasAnnotationPrefix(List<AnnotationNode> annos, String prefix) {
        if (annos == null) return false;
        for (AnnotationNode a : annos) {
            if (a.desc != null && a.desc.startsWith(prefix)) return true;
        }
        return false;
    }

    /** 类是否存在 Bean 访问器（getX/setX/isX）——用于 Spring/Jackson 等按属性名契约的场景。 */
    private static boolean hasBeanAccessors(ClassNode cn) {
        if (cn.methods == null) return false;
        for (Object o : cn.methods) {
            MethodNode mn = (MethodNode) o;
            String n = mn.name;
            if (n == null || n.length() <= 3) continue;
            if ((n.startsWith("get") && mn.desc.startsWith("()"))
                    || (n.startsWith("set") && mn.desc.startsWith("(") && mn.desc.endsWith(")V"))
                    || (n.startsWith("is") && mn.desc.startsWith("()Z"))) {
                return true;
            }
        }
        return false;
    }

    private static boolean hasMethodNamed(ClassNode cn, String name) {
        if (cn.methods == null) return false;
        for (Object o : cn.methods) {
            MethodNode mn = (MethodNode) o;
            if (name.equals(mn.name)) return true;
        }
        return false;
    }

    /** 类文件主版本 -> Java 发行版标签（52..69）。 */
    private static String versionLabel(int major) {
        switch (major) {
            case 52: return "8";
            case 53: return "9";
            case 54: return "10";
            case 55: return "11";
            case 56: return "12";
            case 57: return "13";
            case 58: return "14";
            case 59: return "15";
            case 60: return "16";
            case 61: return "17";
            case 62: return "18";
            case 63: return "19";
            case 64: return "20";
            case 65: return "21";
            case 66: return "22";
            case 67: return "23";
            case 68: return "24";
            case 69: return "25";
            default: return "?" + major;
        }
    }

    /** 取前一条（跳过 FrameNode/LineNumberNode）LDC String 常量。 */
    private static String prevLdcString(AbstractInsnNode ins) {
        AbstractInsnNode p = ins.getPrevious();
        while (p != null && p.getOpcode() == 0) p = p.getPrevious();
        if (p != null && p.getOpcode() == Opcodes.LDC) {
            Object cst = ((LdcInsnNode) p).cst;
            if (cst instanceof String) return (String) cst;
        }
        return null;
    }

    /** 向上回溯若干指令，找 LDC Class 常量（ServiceLoader.load(Foo.class)）。 */
    private static String prevLdcClass(AbstractInsnNode ins) {
        AbstractInsnNode p = ins.getPrevious();
        int budget = 8;
        while (p != null && budget-- > 0) {
            if (p.getOpcode() == Opcodes.LDC) {
                Object cst = ((LdcInsnNode) p).cst;
                if (cst instanceof Type) {
                    Type t = (Type) cst;
                    return t.getSort() == Type.OBJECT ? t.getInternalName() : null;
                }
            }
            p = p.getPrevious();
        }
        return null;
    }

    private static boolean isEdtCallback(String name) {
        for (String m : EDT_CALLBACK_METHODS) {
            if (m.equals(name)) return true;
        }
        return false;
    }

    /**
     * 判断类是否为 Swing/AWT GUI 组件：
     * 直接/间接（应用内中间父类）继承 {@code javax/swing/*} 或 {@code java/awt/*} 组件。
     */
    private static boolean isGuiClass(ClassGraph graph, ClassNode cn) {
        String sup = cn.superName;
        if (sup == null) return false;
        if (isGuiRoot(sup)) return true;
        // 应用内中间父类链。
        Set<String> seen = new HashSet<>();
        String cur = sup;
        int guard = 0;
        while (cur != null && !cur.isEmpty() && seen.add(cur) && guard++ < 32) {
            if (isGuiRoot(cur)) return true;
            ClassNode p = graph.getClasses().get(cur);
            if (p == null) break;
            cur = p.superName;
        }
        // 引用图兜底：javax/swing/* 继承边会被 DependencyAnalyzer 记录。
        Set<String> refs = graph.getReferences().get(cn.name);
        if (refs != null) {
            for (String r : refs) {
                if (isGuiRoot(r)) return true;
            }
        }
        return false;
    }

    private static boolean isGuiRoot(String internal) {
        for (String root : GUI_COMPONENT_ROOTS) {
            if (root.equals(internal)) return true;
        }
        return internal.startsWith("javax/swing/");
    }
}
