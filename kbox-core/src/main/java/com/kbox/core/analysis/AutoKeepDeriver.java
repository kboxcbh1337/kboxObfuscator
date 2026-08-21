package com.kbox.core.analysis;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.AnnotationNode;
import org.objectweb.asm.tree.ClassNode;
import org.objectweb.asm.tree.FieldNode;
import org.objectweb.asm.tree.LdcInsnNode;
import org.objectweb.asm.tree.MethodNode;

import java.util.List;

/**
 * Auto-derives <em>keep rules</em> from the bytecode itself so that
 * obfuscation never breaks a working jar without explicit user configuration.
 * This is the KBox equivalent of ProGuard's {@code -keep} inference plus the
 * Spring Boot / Hibernate / Jackson component-scan rules, but automatic.
 *
 * <p>The deriver runs after {@link ReflectionScanner} and seeds the graph
 * keep-set with members that frameworks commonly resolve reflectively:
 *
 * <ol>
 *   <li><b>Serializable classes</b> — every class implementing
 *       {@code java.io.Serializable} keeps its non-transient fields and
 *       {@code serialVersionUID}, because Java serialization writes field
 *       names by reflection.</li>
 *   <li><b>Framework annotations</b> — classes annotated with a runtime-retained
 *       annotation whose FQN looks like a framework annotation
 *       ({@code @Component}, {@code @Service}, {@code @Entity}, {@code @JsonProperty},
 *       etc.) keep the annotated class + the annotated members. Their
 *       annotation types are also kept.</li>
 *   <li><b>Native methods</b> — declared {@code native} methods keep their
 *       class + method name (JNI symbol {@code Java_pkg_Class_method} is
 *       linked by name at runtime; renaming it would break
 *       {@code RegisterNatives}/{@code JNI_OnLoad}).</li>
 *   <li><b>Class-name-shaped string constants</b> — any LDC string that
 *       looks like an FQN (e.g. {@code "com.foo.Bar"}) AND matches a class
 *       in the graph is kept, on the assumption it is fed to
 *       {@code Class.forName} or used as a service-provider key.</li>
 *   <li><b>ServiceLoader files</b> — every entry in
 *       {@code META-INF/services/<interface-FQN>} keeps both the interface
 *       and the listed provider class.</li>
 *   <li><b>Externalizable / readResolve / writeReplace</b> — these hooks
 *       are looked up by name by the JVM; keep them.</li>
 * </ol>
 *
 * <p>All decisions are conservative: the deriver keeps a member if there is
 * <em>any</em> chance it might be referenced reflectively. False positives
 * (keeping more than strictly necessary) only reduce obfuscation coverage;
 * they never break the runtime.
 */
public final class AutoKeepDeriver {

    private static final String TAG = "autokeep";

    /**
     * Well-known callback interfaces whose methods are resolved by the JVM or
     * a framework via vtable dispatch on the original method names. Methods
     * declared in these interfaces (and overrides in implementors) MUST keep
     * their names, otherwise the runtime reports {@code AbstractMethodError}.
     *
     * <p>Examples: AWT/Swing listeners ({@code KeyListener}, {@code MouseListener}),
     * {@code Runnable.run}, {@code Comparator.compare}, {@code Iterator.next}.
     */
    private static final java.util.Set<String> CALLBACK_INTERFACES =
            new java.util.HashSet<>(java.util.Arrays.asList(
                    // AWT / Swing listeners (java.awt.event)
                    "java/awt/event/KeyListener", "java/awt/event/MouseListener",
                    "java/awt/event/MouseMotionListener", "java/awt/event/MouseWheelListener",
                    "java/awt/event/ActionListener", "java/awt/event/FocusListener",
                    "java/awt/event/ComponentListener", "java/awt/event/ContainerListener",
                    "java/awt/event/WindowListener", "java/awt/event/WindowFocusListener",
                    "java/awt/event/WindowStateListener", "java/awt/event/HierarchyListener",
                    "java/awt/event/HierarchyBoundsListener", "java/awt/event/InputMethodListener",
                    "java/awt/event/ItemListener", "java/awt/event/TextListener",
                    "java/awt/event/AdjustmentListener", "java/awt/event/ContainerHandler",
                    // Swing listeners (javax.swing.event)
                    "javax/swing/event/ChangeListener", "javax/swing/event/DocumentListener",
                    "javax/swing/event/UndoableEditListener", "javax/swing/event/TableColumnModelListener",
                    "javax/swing/event/TableModelListener", "javax/swing/event/TreeModelListener",
                    "javax/swing/event/TreeExpansionListener", "javax/swing/event/TreeWillExpandListener",
                    "javax/swing/event/TreeSelectionListener", "javax/swing/event/ListSelectionListener",
                    "javax/swing/event/ListDataListener", "javax/swing/event/CaretListener",
                    "javax/swing/event/HyperlinkListener", "javax/swing/event/MenuListener",
                    "javax/swing/event/PopupMenuListener", "javax/swing/event/InternalFrameListener",
                    "javax/swing/event/AncestorListener", "javax/swing/event/RowSorterListener",
                    "javax/swing/event/CellEditorListener", "javax/swing/event/MouseInputListener",
                    // java.lang / java.util core
                    "java/lang/Runnable", "java/util/concurrent/Callable",
                    "java/lang/Comparable", "java/util/Comparator",
                    "java/util/Iterator", "java/util/ListIterator",
                    "java/lang/Iterable", "java/util/Enumeration",
                    "java/util/function/Function", "java/util/function/Consumer",
                    "java/util/function/Supplier", "java/util/function/Predicate",
                    "java/util/function/BiFunction", "java/util/function/BiConsumer",
                    "java/util/function/BinaryOperator", "java/util/function/UnaryOperator",
                    // Bukkit / Spigot
                    "org/bukkit/event/Listener", "org/bukkit/plugin/Plugin",
                    "org/bukkit/command/CommandExecutor", "org/bukkit/command/TabCompleter",
                    "org/bukkit/scheduler/Runnable", "org/bukkit/util/Consumer",
                    // Forge / Fabric / NeoForge
                    "net/minecraftforge/fml/common/IMod", "net/minecraftforge/eventbus/api/IEvent"
            ));

    /** Well-known framework annotation simple names (FQN suffix after last dot). */
    private static final java.util.Set<String> FRAMEWORK_ANNOTATION_SIMPLE_NAMES =
            new java.util.HashSet<>(java.util.Arrays.asList(
                    // Spring
                    "Component", "Service", "Repository", "Controller",
                    "RestController", "Configuration", "ControllerAdvice",
                    "RestControllerAdvice", "Bean", "Autowired", "Qualifier",
                    "Value", "Lookup", "Lazy", "Scope", "Primary", "Order",
                    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
                    "DeleteMapping", "PatchMapping", "PathVariable",
                    "RequestBody", "RequestParam", "RequestHeader", "CookieValue",
                    "ModelAttribute", "SessionAttributes", "InitBinder",
                    "ExceptionHandler", "ResponseStatus", "CrossOrigin",
                    "Transactional", "EventListener", "Scheduled",
                    "Conditional", "Profile", "Import", "ImportResource",
                    "PropertySource", "ComponentScan", "ConfigurationProperties",
                    "EnableAutoConfiguration", "SpringBootApplication",
                    "Mapper",  // MyBatis
                    // JPA / Hibernate
                    "Entity", "Table", "Column", "Id", "GeneratedValue",
                    "ManyToOne", "OneToMany", "OneToOne", "ManyToMany",
                    "JoinColumn", "JoinTable", "MappedBy", "OrderBy",
                    "NamedQuery", "NamedQueries", "Version", "Basic",
                    "Lob", "Temporal", "Enumerated", "ElementCollection",
                    "Embeddable", "Embedded", "EmbeddedId", "SequenceGenerator",
                    "TableGenerator", "Transient", "Cache", "Cacheable",
                    "PersistenceContext", "EntityManager", "EntityManagerFactory",
                    // Jackson
                    "JsonProperty", "JsonIgnore", "JsonCreator", "JsonValue",
                    "JsonInclude", "JsonPropertyOrder", "JsonRootName",
                    "JsonTypeInfo", "JsonSubTypes", "JsonTypeName",
                    "JsonFormat", "JsonUnwrapped", "JsonView", "JsonFilter",
                    "JsonAnyGetter", "JsonAnySetter", "JsonSetter", "JsonGetter",
                    "JsonAlias", "JsonNaming", "JsonIgnoreProperties",
                    "JsonIgnoreType", "JsonManagedReference", "JsonBackReference",
                    "JsonRawValue", "JsonMerge",
                    // JAX-RS / Jakarta REST
                    "Path", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS",
                    "Produces", "Consumes", "QueryParam", "PathParam",
                    "FormParam", "HeaderParam", "CookieParam", "MatrixParam",
                    "DefaultValue", "Context", "ApplicationPath",
                    // JAXB / XML
                    "XmlElement", "XmlAttribute", "XmlRootElement", "XmlElementWrapper",
                    "XmlElementRef", "XmlElements", "XmlElementWrapper",
                    "XmlAccessorType", "XmlAccessorOrder", "XmlTransient",
                    "XmlValue", "XmlEnum", "XmlEnumValue", "XmlType",
                    "XmlSeeAlso", "XmlRegistry", "XmlElementDecl",
                    // Lombok
                    "Data", "Getter", "Setter", "Builder", "AllArgsConstructor",
                    "NoArgsConstructor", "RequiredArgsConstructor", "Slf4j",
                    "Log", "EqualsAndHashCode", "ToString", "Value",
                    "FieldDefaults", "NonNull", "SneakyThrows", "Synchronized",
                    "Cleanup", "Delegate", "With", "Accessors", "FieldNameConstants",
                    // CDI / JSR-330
                    "Inject", "Named", "Singleton", "Produces", "Disposes",
                    // Micrometer / metrics
                    "Timed", "Counted", "Meter", "Gauge",
                    // JUnit / TestNG
                    "Test", "Before", "After", "BeforeClass", "AfterClass",
                    "BeforeEach", "AfterEach", "BeforeAll", "AfterAll",
                    "ParameterizedTest", "TestFactory", "TestTemplate",
                    "DisplayName", "Tag", "Disabled", "RepeatedTest",
                    "RunWith", "SuiteClasses", "Parameters",
                    // Mockito
                    "Mock", "Spy", "InjectMocks", "Captor", "MockBean",
                    // Misc
                    "PostConstruct", "PreDestroy", "Resource",
                    "Generated", "SuppressWarnings", "Override",
                    "FunctionalInterface", "Deprecated",
                    // gRPC
                    "GrpcService",
                    // Quartz
                    "DisallowConcurrentExecution", "PersistJobDataAfterExecution",
                    // CheckStyle / FindBugs
                    "SuppressFBWarnings", "SuppressWarnings",
                    // Picocli
                    "Command", "Option", "Parameters", "Mixin", "ParentCommand",
                    "Subcommand", "Spec", "ArgGroup",
                    // Bukkit / Spigot / Paper
                    "EventHandler", "Override",
                    // Forge / Fabric / NeoForge
                    "Mod", "SubscribeEvent", "ObjectHolder",
                    // Groovy
                    "CompileStatic", "CompileDynamic", "ToString", "EqualsAndHashCode",
                    // Log4j / SLF4j
                    "Slf4j", "Log4j2"
            ));

    private final ClassGraph graph;
    private final ProtectionConfig cfg;
    private int keptClasses;
    private int keptMembers;
    private int keptFromServices;
    private int keptFromStrings;

    public AutoKeepDeriver(ClassGraph graph, ProtectionConfig cfg) {
        this.graph = graph;
        this.cfg = cfg;
    }

    public void derive() {
        long start = System.currentTimeMillis();
        for (ClassNode cn : graph.getClasses().values()) {
            try {
                deriveOne(cn);
            } catch (Exception e) {
                KBoxLog.warn(TAG, "Auto-keep failed for " + cn.name + ": " + e.getMessage());
            }
        }
        // ServiceLoader files: keep both the interface and the listed providers.
        scanServiceLoaderFiles();
        long ms = System.currentTimeMillis() - start;
        KBoxLog.info(TAG, "Auto-derived keep rules in " + ms + "ms: "
                + keptClasses + " classes, " + keptMembers + " members, "
                + keptFromServices + " SPI entries, " + keptFromStrings + " reflection strings");
    }

    @SuppressWarnings("unchecked")
    private void deriveOne(ClassNode cn) {
        boolean keepClass = false;

        // ---- 1. Serializable — keep fields + serialVersionUID ----
        if (cn.interfaces != null && cn.interfaces.contains("java/io/Serializable")) {
            keepClass = true;
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if ("serialVersionUID".equals(fn.name)
                        && "J".equals(fn.desc)) {
                    graph.keep(new MemberRef(cn.name, "serialVersionUID", "J"));
                    keptMembers++;
                    continue;
                }
                // Transient fields are not serialized, so their name doesn't
                // matter for serialization. Static fields likewise.
                if ((fn.access & Opcodes.ACC_TRANSIENT) != 0) continue;
                if ((fn.access & Opcodes.ACC_STATIC) != 0) continue;
                graph.keep(new MemberRef(cn.name, fn.name, fn.desc));
                keptMembers++;
            }
        }

        // ---- 2. Externalizable hooks: readResolve / writeReplace / readObject / writeObject ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (isSerializationHook(mn.name, mn.desc)) {
                    graph.keep(new MemberRef(cn.name, mn.name, mn.desc));
                    keptMembers++;
                    keepClass = true;
                }
            }
        }

        // ---- 3. Framework annotations ----
        if (cn.visibleAnnotations != null) {
            for (AnnotationNode an : cn.visibleAnnotations) {
                if (isFrameworkAnnotation(an.desc)) {
                    keepClass = true;
                    // Also keep the annotation type itself.
                    graph.keep(MemberRef.ofClass(an.desc.substring(1, an.desc.length() - 1)));
                    keptClasses++;
                    break;
                }
            }
        }
        // Per-method / per-field annotations on user code also imply "keep member".
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (hasFrameworkAnnotation(mn.visibleAnnotations)) {
                    graph.keep(new MemberRef(cn.name, mn.name, mn.desc));
                    keptMembers++;
                    keepClass = true;
                }
            }
        }
        if (cn.fields != null) {
            for (FieldNode fn : (List<FieldNode>) cn.fields) {
                if (hasFrameworkAnnotation(fn.visibleAnnotations)) {
                    graph.keep(new MemberRef(cn.name, fn.name, fn.desc));
                    keptMembers++;
                    keepClass = true;
                }
            }
        }

        // ---- 4. Native methods — keep their name (JNI symbol resolution) ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ((mn.access & Opcodes.ACC_NATIVE) != 0) {
                    graph.keep(new MemberRef(cn.name, mn.name, mn.desc));
                    keptMembers++;
                    keepClass = true;
                }
            }
        }

        // ---- 5. Class-name-shaped string constants ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if (mn.instructions == null) continue;
                for (int i = 0; i < mn.instructions.size(); i++) {
                    if (mn.instructions.get(i).getOpcode() != Opcodes.LDC) continue;
                    Object cst = ((LdcInsnNode) mn.instructions.get(i)).cst;
                    if (!(cst instanceof String)) continue;
                    String s = (String) cst;
                    String maybeInternal = tryAsInternalName(s);
                    if (maybeInternal != null && graph.getClasses().containsKey(maybeInternal)) {
                        // Looks like a class FQN that exists in the graph — assume reflection.
                        graph.keep(MemberRef.ofClass(maybeInternal));
                        keptFromStrings++;
                    }
                }
            }
        }

        // ---- 6. Main / app entry points — always kept ----
        if (cn.methods != null) {
            for (MethodNode mn : (List<MethodNode>) cn.methods) {
                if ("main".equals(mn.name) && "([Ljava/lang/String;)V".equals(mn.desc)
                        && (mn.access & Opcodes.ACC_STATIC) != 0) {
                    keepClass = true;
                    graph.keep(new MemberRef(cn.name, "main", "([Ljava/lang/String;)V"));
                    keptMembers++;
                }
            }
        }

        // ---- 7. Callback interface implementors — keep public methods ----
        // If a class implements a known callback interface (AWT/Swing listeners,
        // Runnable, Comparator, etc.), the JVM/framework resolves the method
        // by name via vtable dispatch. Renaming these methods produces
        // AbstractMethodError at runtime. We conservatively keep ALL non-static,
        // non-private methods of implementors, because we cannot tell which
        // specific method is the override without the interface's method table
        // (which lives in the JDK and is not in the graph).
        if (cn.interfaces != null) {
            for (String iface : cn.interfaces) {
                if (CALLBACK_INTERFACES.contains(iface)) {
                    keepClass = true;
                    if (cn.methods != null) {
                        for (MethodNode mn : (List<MethodNode>) cn.methods) {
                            // Skip static, private, and constructor methods.
                            if ((mn.access & Opcodes.ACC_STATIC) != 0) continue;
                            if ((mn.access & Opcodes.ACC_PRIVATE) != 0) continue;
                            if ("<init>".equals(mn.name) || "<clinit>".equals(mn.name)) continue;
                            graph.keep(new MemberRef(cn.name, mn.name, mn.desc));
                            keptMembers++;
                        }
                    }
                    break; // one matching interface is enough
                }
            }
        }

        if (keepClass) {
            graph.keep(MemberRef.ofClass(cn.name));
            keptClasses++;
        }
    }

    /** True if the descriptor looks like a known framework annotation type. */
    private static boolean isFrameworkAnnotation(String desc) {
        if (desc == null || desc.length() < 3 || !desc.startsWith("L") || !desc.endsWith(";")) {
            return false;
        }
        String internal = desc.substring(1, desc.length() - 1);
        int slash = internal.lastIndexOf('/');
        String simple = slash >= 0 ? internal.substring(slash + 1) : internal;
        if (FRAMEWORK_ANNOTATION_SIMPLE_NAMES.contains(simple)) return true;
        // Also keep annotations declared in well-known framework packages.
        if (internal.startsWith("org/springframework/")
                || internal.startsWith("javax/persistence/")
                || internal.startsWith("jakarta/persistence/")
                || internal.startsWith("com/fasterxml/jackson/")
                || internal.startsWith("javax/ws/rs/")
                || internal.startsWith("jakarta/ws/rs/")
                || internal.startsWith("javax/xml/bind/")
                || internal.startsWith("jakarta/xml/bind/")
                || internal.startsWith("javax/annotation/")
                || internal.startsWith("jakarta/annotation/")
                || internal.startsWith("javax/inject/")
                || internal.startsWith("jakarta/inject/")
                || internal.startsWith("org/junit/jupiter/api/")
                || internal.startsWith("org/testng/annotations/")) {
            return true;
        }
        return false;
    }

    private static boolean hasFrameworkAnnotation(List<AnnotationNode> annos) {
        if (annos == null) return false;
        for (AnnotationNode an : annos) {
            if (isFrameworkAnnotation(an.desc)) return true;
        }
        return false;
    }

    private static boolean isSerializationHook(String name, String desc) {
        if ("readResolve".equals(name) && "()Ljava/lang/Object;".equals(desc)) return true;
        if ("writeReplace".equals(name) && "()Ljava/lang/Object;".equals(desc)) return true;
        if ("readObject".equals(name) && "(Ljava/io/ObjectInputStream;)V".equals(desc)) return true;
        if ("writeObject".equals(name) && "(Ljava/io/ObjectOutputStream;)V".equals(desc)) return true;
        if ("readObjectNoData".equals(name) && "()V".equals(desc)) return true;
        return false;
    }

    /**
     * Returns the internal form of {@code s} if {@code s} looks like a fully
     * qualified class name (e.g. {@code "com.foo.Bar"}), otherwise {@code null}.
     * Heuristic: at least one {@code .}, no spaces, all parts are valid Java
     * identifiers.
     */
    private static String tryAsInternalName(String s) {
        if (s == null || s.length() < 3 || s.length() > 200) return null;
        if (s.indexOf('.') < 0) return null;
        // Cheap reject on obviously-not-class strings.
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '/' || c == ';' || c == '[' || c == '<' || c == '>'
                    || c == '(' || c == ')' || Character.isWhitespace(c)) {
                return null;
            }
        }
        // Each dot-separated segment must be a Java identifier.
        String[] parts = s.split("\\.");
        if (parts.length < 2) return null;
        for (String p : parts) {
            if (p.isEmpty() || !Character.isJavaIdentifierStart(p.charAt(0))) return null;
            for (int i = 1; i < p.length(); i++) {
                if (!Character.isJavaIdentifierPart(p.charAt(i))) return null;
            }
        }
        return s.replace('.', '/');
    }

    /** Reads every {@code META-INF/services/<ifq>} entry and keeps the listed providers. */
    private void scanServiceLoaderFiles() {
        for (java.util.Map.Entry<String, byte[]> e : graph.getResources().entrySet()) {
            String path = e.getKey();
            if (!path.startsWith("META-INF/services/")) continue;
            String serviceInterface = path.substring("META-INF/services/".length());
            if (serviceInterface.isEmpty() || serviceInterface.contains("/")) continue;
            // Keep the service interface FQN (it may not be in the graph if
            // it lives in an external jar — but if it is, keeping it is free).
            String serviceInternal = serviceInterface.replace('.', '/');
            if (graph.getClasses().containsKey(serviceInternal)) {
                graph.keep(MemberRef.ofClass(serviceInternal));
                keptFromServices++;
            }
            // Each non-comment line in the file is a provider FQN.
            String text = new String(e.getValue(), java.nio.charset.StandardCharsets.UTF_8);
            for (String line : text.split("\\r?\\n")) {
                String t = line.trim();
                if (t.isEmpty() || t.startsWith("#")) continue;
                // Strip trailing comments after '#'.
                int hash = t.indexOf('#');
                if (hash >= 0) t = t.substring(0, hash).trim();
                if (t.isEmpty()) continue;
                String internal = t.replace('.', '/');
                if (graph.getClasses().containsKey(internal)) {
                    graph.keep(MemberRef.ofClass(internal));
                    // ServiceLoader instantiates via no-arg ctor.
                    graph.keep(new MemberRef(internal, "<init>", "()V"));
                    keptFromServices++;
                }
            }
        }
    }
}
