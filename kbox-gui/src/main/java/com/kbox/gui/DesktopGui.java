package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.JToolBar;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * KBox 桌面界面（原生 Swing）。
 *
 * <p>布局：菜单栏 + 工具栏 + 左侧「类浏览器」树 + 右侧选项标签页 + 底部日志与进度条。
 * 选项直接映射到 {@link ProtectionConfig}，执行时复用 {@link ProtectionPipeline}。</p>
 *
 * <p>入口 {@link #launch(String, String, String, boolean)} 由 CLI 反射调用。</p>
 */
public final class DesktopGui {

    private final JFrame frame = new JFrame("KBox Obfuscator");
    private final JTextArea logArea = new JTextArea();
    private final JProgressBar progress = new JProgressBar(0, 100);
    private final JLabel status = new JLabel("就绪");
    private final JTree classTree = new JTree(new DefaultMutableTreeNode("（未打开 jar）"));
    private final JTextField searchField = new JTextField();

    private final JTextField inField = new JTextField();
    private final JTextField outField = new JTextField();
    private final JTextField cfgField = new JTextField();
    private final JTextField ccField = new JTextField();
    private final JTextField entryField = new JTextField();

    /** 全部选项的控件：key -> 控件（勾选框 / 下拉 / 文本框）。见 {@link #ALL_OPTIONS}。 */
    private final Map<String, Component> allCtrls = new LinkedHashMap<>();
    /** key -> 控件类型（bool|int|text|list|enum），生成配置文本时用。 */
    private final Map<String, String> allTypes = new LinkedHashMap<>();
    /** 全部选项面板的搜索框（按 key / 中文名过滤）。 */
    private final JTextField optionSearch = new JTextField();
    /** 承载全部选项行的面板；重置默认后需要重排才能显示新控件。 */
    private JPanel optionBody;

    private volatile boolean running = false;

    private DesktopGui(String in, String out, String cfg, boolean verbose) {
        if (in != null) inField.setText(in);
        if (out != null) outField.setText(out);
        if (cfg != null) cfgField.setText(cfg);
        if (out == null && in != null) outField.setText(deriveOut(in));
        if (verbose) KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
    }

    /** CLI {@code --gui} 入口（由 {@code ProtectorCli} 反射调用）。 */
    public static void launch(String in, String out, String cfg, boolean verbose) {
        SwingUtilities.invokeLater(() -> new DesktopGui(in, out, cfg, verbose).build());
    }

    private static String deriveOut(String in) {
        int dot = in.lastIndexOf('.');
        return dot > 0 ? in.substring(0, dot) + "-protected.jar" : in + "-protected.jar";
    }

    // ------------------------------------------------------------------
    // UI construction
    // ------------------------------------------------------------------

    private void build() {
        try {
            for (UIManager.LookAndFeelInfo lf : UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(lf.getName())) { UIManager.setLookAndFeel(lf.getClassName()); break; }
            }
        } catch (Exception ignored) { /* fall back to default L&F */ }

        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setJMenuBar(buildMenuBar());
        frame.add(buildToolBar(), BorderLayout.NORTH);

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                buildClassBrowser(), buildOptionTabs());
        split.setDividerLocation(300);
        split.setResizeWeight(0.28);
        frame.add(split, BorderLayout.CENTER);

        JPanel south = new JPanel(new BorderLayout(6, 2));
        progress.setStringPainted(true);
        progress.setString("");
        south.add(progress, BorderLayout.CENTER);
        south.add(status, BorderLayout.WEST);
        south.setBorder(BorderFactory.createEmptyBorder(2, 6, 4, 6));
        frame.add(south, BorderLayout.SOUTH);

        frame.setSize(1080, 720);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private JMenuBar buildMenuBar() {
        JMenuBar bar = new JMenuBar();

        JMenu file = new JMenu("文件");
        file.add(menuItem("打开 Jar…", e -> pickInput()));
        file.add(menuItem("打开配置…", e -> pickConfig()));
        file.addSeparator();
        file.add(menuItem("退出", e -> frame.dispose()));
        bar.add(file);

        JMenu run = new JMenu("运行");
        run.add(menuItem("执行混淆", e -> runProtection()));
        run.add(menuItem("清空日志", e -> logArea.setText("")));
        bar.add(run);

        JMenu view = new JMenu("视图");
        view.add(menuItem("展开类树", e -> expandAll()));
        view.add(menuItem("折叠类树", e -> collapseAll()));
        JCheckBoxMenuItem dark = new JCheckBoxMenuItem("深色日志");
        dark.addActionListener(e -> applyLogTheme(dark.isSelected()));
        view.add(dark);
        bar.add(view);

        JMenu help = new JMenu("帮助");
        help.add(menuItem("关于 KBox", e -> JOptionPane.showMessageDialog(frame,
                "KBox Obfuscator\n字节码混淆 + JNIC 原生化 + VMP 虚拟化 + kboXShield 原生加壳\n"
                        + "本界面为原生 Swing 桌面界面，选项直接映射到 ProtectionConfig。",
                "关于", JOptionPane.INFORMATION_MESSAGE)));
        help.add(menuItem("帮助文档", e -> JOptionPane.showMessageDialog(frame,
                "配置键与 CLI 用法见 docs/CONFIG.md 与 docs/CLI-USAGE.md；\n"
                        + "常规使用：选择输入 jar → 选择输出 → 执行混淆。",
                "帮助", JOptionPane.INFORMATION_MESSAGE)));
        bar.add(help);
        return bar;
    }

    private JToolBar buildToolBar() {
        JToolBar tb = new JToolBar();
        tb.setFloatable(false);
        tb.add(button("打开 Jar", e -> pickInput()));
        tb.add(button("执行混淆", e -> runProtection()));
        tb.addSeparator();
        JToggleButton themeBtn = new JToggleButton("深色日志");
        themeBtn.addActionListener(e -> applyLogTheme(themeBtn.isSelected()));
        tb.add(themeBtn);
        return tb;
    }

    private Component buildClassBrowser() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createTitledBorder("类浏览器（输入 jar 结构）"));
        JPanel top = new JPanel(new BorderLayout(4, 0));
        top.add(new JLabel("搜索:"), BorderLayout.WEST);
        top.add(searchField, BorderLayout.CENTER);
        JButton find = new JButton("定位");
        find.addActionListener(e -> searchTree());
        top.add(find, BorderLayout.EAST);
        p.add(top, BorderLayout.NORTH);
        classTree.setRootVisible(true);
        classTree.setShowsRootHandles(true);
        p.add(new JScrollPane(classTree), BorderLayout.CENTER);
        return p;
    }

    private Component buildOptionTabs() {
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("基础", buildBasics());
        tabs.addTab("全部选项", buildAllOptions());
        tabs.addTab("日志", buildLog());
        return tabs;
    }

    private Component buildBasics() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = gbc();
        addRow(p, c, 0, "输入 jar:", inField, "浏览…", e -> pickInput());
        addRow(p, c, 1, "输出 jar:", outField, "浏览…", e -> pickOutput());
        addRow(p, c, 2, "配置文件:", cfgField, "浏览…", e -> pickConfig());
        addRow(p, c, 3, "C 编译器(cc):", ccField, "浏览…", e -> pickCc());
        addRow(p, c, 4, "入口类:", entryField, null, null);
        c.gridx = 0; c.gridy = 5; c.gridwidth = 3; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        JButton run = new JButton("执行混淆");
        run.setFont(run.getFont().deriveFont(Font.BOLD));
        run.addActionListener(e -> runProtection());
        p.add(run, c);
        c.gridy = 6; c.weighty = 1; p.add(Box.createVerticalGlue(), c);
        return p;
    }

    // ------------------------------------------------------------------
    // 全部选项（schema 驱动）
    //
    // 每个键都与 ConfigLoader 真实支持的配置键一一对应；执行时把界面值逐键写成
    // 一份 .conf 再交给 ConfigLoader 解析 —— 因此"界面能点的 = 引擎认识的"，
    // 不会出现只在界面里好看、引擎不认的假开关，也不会漏掉某个 pass 的开关。
    //
    // 表项：{ 分组, 配置键, 显示名, 类型(bool|int|text|list|full), 默认值, 最小值, 最大值 }
    //   full 类型 = 勾选框，写 "full"/"off"（用于 nativeCoverage / vmpCoverage 这类枚举）
    //   list 类型 = 文本框，逗号分隔（ConfigLoader 的 addAll 语义）
    // ------------------------------------------------------------------
    private static final String[][] ALL_OPTIONS = {
        {"预设", "allMax", "最大强度（allMax，一键全开）", "bool", "false", "0", "0"},

        {"基础 / 重命名", "renameIdentifiers", "标识符重命名", "bool", "true", "0", "0"},
        {"基础 / 重命名", "renamePackages", "包名重命名", "bool", "false", "0", "0"},
        {"基础 / 重命名", "obfuscateEntryPoint", "混淆入口点", "bool", "true", "0", "0"},
        {"基础 / 重命名", "autoKeepRules", "自动 keep 推导", "bool", "true", "0", "0"},
        {"基础 / 重命名", "neverFail", "永不失败（降级继续）", "bool", "false", "0", "0"},
        {"基础 / 重命名", "rollbackToOriginalBytes", "校验失败回滚原字节", "bool", "false", "0", "0"},
        {"基础 / 重命名", "quiet", "安静模式（-dontnote）", "bool", "false", "0", "0"},
        {"基础 / 重命名", "suppressWarnings", "抑制警告（-dontwarn）", "bool", "false", "0", "0"},
        {"基础 / 重命名", "parallelThreads", "并行线程数（0=自动）", "int", "0", "0", "64"},
        {"基础 / 重命名", "gpuAccel", "GPU 加速", "bool", "false", "0", "0"},
        {"基础 / 重命名", "useDefaultLibraryPrefixes", "内置库前缀识别", "bool", "true", "0", "0"},

        {"字符串 / 常量", "encryptStrings", "字符串加密", "bool", "true", "0", "0"},
        {"字符串 / 常量", "stringEncryptionStrength", "字符串加密强度", "int", "1", "1", "3"},
        {"字符串 / 常量", "scatterStrings", "字符串分片", "bool", "false", "0", "0"},
        {"字符串 / 常量", "whiteboxStrings", "白盒字符串", "bool", "false", "0", "0"},
        {"字符串 / 常量", "fixedXorKey", "固定 XOR 密钥", "bool", "false", "0", "0"},
        {"字符串 / 常量", "obfuscateConstants", "常量查表加密", "bool", "false", "0", "0"},
        {"字符串 / 常量", "mbaConstants", "交织表达式常量（MBA）", "int", "0", "0", "2"},
        {"字符串 / 常量", "mbaRewrite", "运行时 MBA 重写", "int", "0", "0", "5"},

        {"控制流", "obfuscateControlFlow", "控制流混淆", "bool", "true", "0", "0"},
        {"控制流", "controlFlowStrength", "控制流强度", "int", "2", "1", "3"},
        {"控制流", "flattenerMinInsns", "平坦化最小指令数", "int", "16", "0", "100000"},
        {"控制流", "flattenerMaxInsns", "平坦化最大指令数", "int", "256", "0", "100000"},
        {"控制流", "opaqueStateMachine", "运行时状态机", "int", "0", "0", "3"},
        {"控制流", "exceptionJumpObf", "异常跳转混淆", "bool", "false", "0", "0"},
        {"控制流", "methodInlineExtract", "方法内联 / 拆分", "bool", "false", "0", "0"},
        {"控制流", "methodSplit", "方法切分强度", "int", "0", "0", "3"},
        {"控制流", "hideCallGraph", "调用图隐藏", "bool", "false", "0", "0"},

        {"类体 / 资源", "encryptClasses", "类体加密", "bool", "false", "0", "0"},
        {"类体 / 资源", "obfuscateResources", "资源名混淆", "bool", "false", "0", "0"},

        {"原生化 / JNIC", "enableJnic", "JNIC 原生化", "bool", "false", "0", "0"},
        {"原生化 / JNIC", "nativeCoverage", "JNIC 全覆盖", "full", "off", "0", "0"},
        {"原生化 / JNIC", "jniPlatform", "JNI 平台（留空=自动）", "text", "", "0", "0"},
        {"原生化 / JNIC", "jnicEplDriven", "JNIC 由 EPL 清单驱动", "bool", "false", "0", "0"},
        {"原生化 / JNIC", "failOnNativeError", "原生编译失败即失败", "bool", "false", "0", "0"},
        {"原生化 / JNIC", "nativeMethod", "指定 native 方法", "list", "", "0", "0"},
        {"原生化 / JNIC", "nativeEligiblePrefix", "可原生化前缀", "list", "", "0", "0"},
        {"原生化 / JNIC", "nativeExcludePrefix", "原生化排除前缀", "list", "", "0", "0"},
        {"原生化 / JNIC", "jnicExcludePrefix", "JNIC 排除前缀", "list", "", "0", "0"},

        {"虚拟机 / VMP", "enableVmp", "VMP 虚拟化", "bool", "false", "0", "0"},
        {"虚拟机 / VMP", "vmpCoverage", "VMP 全覆盖", "full", "off", "0", "0"},
        {"虚拟机 / VMP", "enableVmpNative", "VMP 原生化（vmp.bin）", "bool", "false", "0", "0"},
        {"虚拟机 / VMP", "vmpSelfCheck", "VMP 自检", "bool", "false", "0", "0"},
        {"虚拟机 / VMP", "vmpInterleave", "VMP 交织档位", "int", "0", "0", "3"},
        {"虚拟机 / VMP", "vmpMethod", "指定 VMP 方法", "list", "", "0", "0"},
        {"虚拟机 / VMP", "vmpExcludePrefix", "VMP 排除前缀", "list", "", "0", "0"},

        {"混沌 / BFVM", "enableBfvm", "BFVM", "bool", "false", "0", "0"},
        {"混沌 / BFVM", "bfvmMethod", "指定 BFVM 方法", "list", "", "0", "0"},
        {"混沌 / BFVM", "brainfuckShield", "BrainfuckShield", "bool", "false", "0", "0"},
        {"混沌 / BFVM", "brainfuckShieldLevel", "BFShield 档位", "int", "3", "0", "3"},
        {"混沌 / BFVM", "brainfuckLoader", "Brainfuck 加载器", "bool", "false", "0", "0"},
        {"混沌 / BFVM", "brainfuckMcHybrid", "BF × MC 混合模式", "bool", "false", "0", "0"},
        {"混沌 / BFVM", "enableOtp", "K-OTP 一次性程序（需 JNIC）", "bool", "false", "0", "0"},
        {"混沌 / BFVM", "mainClass", "入口类（无 Main-Class / -cp 启动）", "text", "", "0", "0"},

        {"原生壳", "nativeShell", "nativeShell 档位", "int", "3", "0", "3"},
        {"原生壳", "protectNativeLibs", "jar 内原生库加壳", "bool", "false", "0", "0"},
        {"原生壳", "shieldNativeOutput", "JNIC/VMP 产物加壳", "bool", "true", "0", "0"},
        {"原生壳", "cc", "C 编译器路径（cc）", "text", "", "0", "0"},

        {"反分析", "antiDebug", "反调试", "bool", "false", "0", "0"},
        {"反分析", "antiDecompilerLevel", "反编译器对抗等级", "int", "0", "0", "3"},
        {"反分析", "integrityCheck", "完整性自检", "bool", "false", "0", "0"},
        {"反分析", "nativeAntiHook", "原生反 Hook", "bool", "false", "0", "0"},
        {"反分析", "reflectionGate", "反射门控", "bool", "false", "0", "0"},
        {"反分析", "fakeDebugInfo", "调试信息伪造", "bool", "false", "0", "0"},
        {"反分析", "nullGuard", "空值守卫", "bool", "false", "0", "0"},
        {"反分析", "watermark", "水印文本", "text", "", "0", "0"},
        {"反分析", "plaintextAudit", "产物明文自检（构建结束扫描）", "bool", "true", "0", "0"},

        {"元数据擦除", "eraseAnnotations", "注解擦除", "bool", "false", "0", "0"},
        {"元数据擦除", "eraseDebugInfo", "调试元数据擦除（SourceFile/LNT…）", "bool", "true", "0", "0"},
        {"元数据擦除", "eraseSignatures", "泛型/嵌套元数据擦除", "bool", "false", "0", "0"},

        {"高级强度旋钮", "typeConfusion", "类型混淆（高风险）", "int", "0", "0", "2"},
        {"高级强度旋钮", "honeypot", "蜜罐", "int", "0", "0", "3"},
        {"高级强度旋钮", "sentinelInterleave", "哨兵交织", "int", "0", "0", "3"},
        {"高级强度旋钮", "stackFrameRedirect", "栈帧重定向", "int", "0", "0", "3"},
        {"高级强度旋钮", "entropyTimeAnchor", "熵时间锚", "int", "0", "0", "3"},
        {"高级强度旋钮", "selfWipeSections", "节自擦除", "int", "0", "0", "3"},
        {"高级强度旋钮", "processHeartbeat", "进程心跳", "int", "0", "0", "3"},
        {"高级强度旋钮", "honeypotPe", "PE 蜜罐", "int", "0", "0", "3"},
        {"高级强度旋钮", "oneTimeSemantic", "一次语义", "int", "0", "0", "3"},
        {"高级强度旋钮", "lineageChain", "谱系链", "int", "0", "0", "3"},
        {"高级强度旋钮", "selfRefAuth", "自引用认证", "int", "0", "0", "3"},
        {"高级强度旋钮", "multiRep", "多副本", "int", "0", "0", "3"},
        {"高级强度旋钮", "polyGold", "polyGold", "int", "0", "0", "3"},
        {"高级强度旋钮", "signalPoison", "信号投毒", "int", "0", "0", "3"},
        {"高级强度旋钮", "buildSigBind", "构建签名绑定", "int", "0", "0", "3"},
        {"高级强度旋钮", "blobMockFill", "Blob 填充", "int", "0", "0", "3"},

        {"适配 / 报告 / 许可", "silentShield", "SilentShield 静默加固", "bool", "false", "0", "0"},
        {"适配 / 报告 / 许可", "silentShieldReport", "SilentShield 报告路径", "text", "", "0", "0"},
        {"适配 / 报告 / 许可", "modernStackAdapt", "现代技术栈主动适配", "bool", "false", "0", "0"},
        {"适配 / 报告 / 许可", "adaptabilityReport", "适配性验收报告路径", "text", "", "0", "0"},
        {"适配 / 报告 / 许可", "autoAdaptMinecraft", "MC mod 自动适配", "bool", "false", "0", "0"},
        {"适配 / 报告 / 许可", "fixKotlinMetadata", "Kotlin 元数据修复", "bool", "true", "0", "0"},
        {"适配 / 报告 / 许可", "mappingFile", "反混淆映射输出路径", "text", "", "0", "0"},
        {"适配 / 报告 / 许可", "useMapping", "复用映射文件", "text", "", "0", "0"},
        {"适配 / 报告 / 许可", "licPublicKey", "许可公钥", "text", "", "0", "0"},
        {"适配 / 报告 / 许可", "licAppSecret", "许可应用密钥", "text", "", "0", "0"},

        {"保留 / 排除清单", "keepPrefix", "keep 类前缀", "list", "", "0", "0"},
        {"保留 / 排除清单", "keepMember", "keep 成员", "list", "", "0", "0"},
        {"保留 / 排除清单", "entryPoint", "入口类", "list", "", "0", "0"},
        {"保留 / 排除清单", "keepAttributes", "保留属性", "list", "", "0", "0"},
        {"保留 / 排除清单", "excludeControlFlow", "控制流排除前缀", "list", "", "0", "0"},
        {"保留 / 排除清单", "bodyExcludePrefix", "方法体混淆排除前缀", "list", "", "0", "0"},
        {"保留 / 排除清单", "libraryPrefix", "库前缀", "list", "", "0", "0"},
        {"保留 / 排除清单", "userPrefix", "用户代码前缀", "list", "", "0", "0"},
        {"保留 / 排除清单", "encryptResource", "需加密资源", "list", "", "0", "0"},
        {"保留 / 排除清单", "excludeResource", "排除资源", "list", "", "0", "0"},
        {"保留 / 排除清单", "encryptClassPrefix", "需加密类前缀", "list", "", "0", "0"},
    };

    private Component buildAllOptions() {
        JPanel root = new JPanel(new BorderLayout(0, 6));
        root.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));

        JPanel top = new JPanel(new BorderLayout(6, 0));
        top.add(new JLabel("搜索（键名 / 中文名）："), BorderLayout.WEST);
        top.add(optionSearch, BorderLayout.CENTER);
        JButton reset = new JButton("重置默认");
        reset.addActionListener(e -> { resetOptionsToDefault(); optionSearch.setText(""); });
        top.add(reset, BorderLayout.EAST);
        root.add(top, BorderLayout.NORTH);

        buildOptionControls();
        final JPanel body = new JPanel();
        body.setLayout(new BoxLayout(body, BoxLayout.Y_AXIS));
        optionBody = body;
        root.add(new JScrollPane(body), BorderLayout.CENTER);
        rebuildOptionRows(body);
        optionSearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(body); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(body); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(body); }
        });
        return root;
    }

    /** 按表创建全部控件（只建一次），初值取表里的默认值。 */
    private void buildOptionControls() {
        allCtrls.clear();
        allTypes.clear();
        for (String[] o : ALL_OPTIONS) {
            String key = o[1], label = o[2], type = o[3], def = o[4];
            allTypes.put(key, type);
            switch (type) {
                case "bool":
                case "full": {
                    JCheckBox cb = new JCheckBox(label, "bool".equals(type)
                            ? Boolean.parseBoolean(def) : "full".equalsIgnoreCase(def));
                    cb.setToolTipText(key);
                    allCtrls.put(key, cb);
                    break;
                }
                case "int": {
                    int lo = Integer.parseInt(o[5]), hi = Integer.parseInt(o[6]);
                    JComboBox<String> cb = new JComboBox<>();
                    for (int v = lo; v <= hi && (v - lo) <= 64; v++) cb.addItem(String.valueOf(v));
                    if (hi - lo > 64) { cb.removeAllItems(); cb.addItem(def); cb.setEditable(true); }
                    cb.setSelectedItem(def);
                    cb.setToolTipText(key);
                    allCtrls.put(key, cb);
                    break;
                }
                default: {
                    JTextField tf = new JTextField(def, 12);
                    tf.setToolTipText("list".equals(type) ? key + "（逗号分隔）" : key);
                    allCtrls.put(key, tf);
                }
            }
        }
    }

    /** 依据搜索框重排分组显示（控件实例复用，值不丢）。 */
    private void rebuildOptionRows(JPanel body) {
        body.removeAll();
        String filter = optionSearch.getText().trim().toLowerCase();
        String group = null;
        JPanel panel = null;
        GridBagConstraints c = null;
        int y = 0;
        for (String[] o : ALL_OPTIONS) {
            String key = o[1], label = o[2], type = o[3];
            if (!filter.isEmpty()
                    && !key.toLowerCase().contains(filter)
                    && !label.toLowerCase().contains(filter)) {
                continue;
            }
            if (!o[0].equals(group)) {
                group = o[0];
                panel = new JPanel(new GridBagLayout());
                panel.setBorder(BorderFactory.createTitledBorder(group));
                c = gbc();
                y = 0;
                body.add(panel);
                body.add(Box.createVerticalStrut(6));
            }
            Component ctl = allCtrls.get(key);
            c.gridx = 0; c.gridy = y; c.weightx = 0; c.fill = GridBagConstraints.NONE;
            panel.add(new JLabel("int".equals(type) || "bool".equals(type) || "full".equals(type)
                    ? label : label + ":"), c);
            c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
            panel.add(ctl, c);
            y++;
        }
        if (panel == null) {
            body.add(new JLabel(filter.isEmpty() ? "（无可选项）" : "（无匹配项：" + filter + "）"));
        }
        body.revalidate();
        body.repaint();
    }

    private void resetOptionsToDefault() {
        allCtrls.clear();
        allTypes.clear();
        buildOptionControls();
        // The visible rows still reference the OLD control instances; rebuilding
        // them is what actually shows the reset values.
        if (optionBody != null) rebuildOptionRows(optionBody);
    }

    /** 单个选项的当前值（写进 .conf 的字符串形式）。 */
    private String confValue(String key) {
        Component c = allCtrls.get(key);
        String t = allTypes.get(key);
        if (c == null || t == null) return null;
        switch (t) {
            case "bool": return String.valueOf(((JCheckBox) c).isSelected());
            case "full": return ((JCheckBox) c).isSelected() ? "full" : "off";
            case "int": {
                JComboBox<?> cb = (JComboBox<?>) c;
                // Editable combos (wide ranges) keep typed text in the editor, not
                // in the selection model — read the editor first.
                Object v = cb.isEditable() && cb.getEditor() != null
                        ? cb.getEditor().getItem() : cb.getSelectedItem();
                return v == null ? "0" : String.valueOf(v).trim();
            }
            default: return ((JTextField) c).getText().trim();
        }
    }

    /**
     * 把界面全部选项写成 .conf 文本。
     *
     * <p>{@code allMax} 必须写在**最前面**（ConfigLoader 的契约：预设先展开，
     * 后续行可覆盖单键）。勾选 allMax 时只额外写"用户改过默认值"的键，这样
     * 既能一键全开、又能对个别项微调，而不会被界面上的默认值把预设冲淡。</p>
     */
    private String uiConfText() {
        JCheckBox max = (JCheckBox) allCtrls.get("allMax");
        boolean maxOn = max != null && max.isSelected();
        StringBuilder sb = new StringBuilder();
        sb.append("# generated by KBox desktop UI\n");
        sb.append("allMax = ").append(maxOn).append('\n');
        for (String[] o : ALL_OPTIONS) {
            String key = o[1];
            if ("allMax".equals(key)) continue;
            String v = confValue(key);
            if (v == null || v.isEmpty()) continue;
            if (maxOn && v.equals(o[4])) continue;   // preset already covers it
            sb.append(key).append(" = ").append(v).append('\n');
        }
        String cc = ccField.getText().trim();
        if (!cc.isEmpty()) sb.append("cc = ").append(cc).append('\n');
        String ep = entryField.getText().trim();
        if (!ep.isEmpty()) sb.append("entryPoint = ").append(ep).append('\n');
        return sb.toString();
    }

    /** 把某个配置文件的键值回填到界面控件（未知键保持原样，仍由合并配置保留）。 */
    private void loadConfigIntoUi(java.nio.file.Path p) {
        try {
            for (String raw : java.nio.file.Files.readAllLines(p, StandardCharsets.UTF_8)) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) continue;
                int hash = line.indexOf(" #");
                if (hash > 0) line = line.substring(0, hash).trim();
                int eq = line.indexOf('=');
                if (eq <= 0) continue;
                setControlValue(line.substring(0, eq).trim(), line.substring(eq + 1).trim());
            }
        } catch (Exception ex) {
            KBoxLog.warn("gui", "读取配置到界面失败: " + ex.getMessage());
        }
    }

    private void setControlValue(String key, String val) {
        Component c = allCtrls.get(key);
        String t = allTypes.get(key);
        if (c == null || t == null) return;
        switch (t) {
            case "bool":
                ((JCheckBox) c).setSelected("true".equalsIgnoreCase(val)
                        || "1".equals(val) || "yes".equalsIgnoreCase(val));
                break;
            case "full":
                ((JCheckBox) c).setSelected("full".equalsIgnoreCase(val));
                break;
            case "int":
                ((JComboBox<?>) c).setSelectedItem(val);
                break;
            default:
                ((JTextField) c).setText(val);
        }
    }

    private Component buildLog() {
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        applyLogTheme(false);
        return new JScrollPane(logArea);
    }

    // ------------------------------------------------------------------
    // Actions
    // ------------------------------------------------------------------

    private void pickInput() {
        File f = choose("选择输入 jar", "jar");
        if (f != null) {
            inField.setText(f.getAbsolutePath());
            if (outField.getText().isBlank()) outField.setText(deriveOut(f.getAbsolutePath()));
            loadTree(f);
        }
    }

    private void pickOutput() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("选择输出路径");
        fc.setFileFilter(new FileNameExtensionFilter("Jar 文件 (*.jar)", "jar"));
        if (fc.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) outField.setText(fc.getSelectedFile().getAbsolutePath());
    }

    private void pickConfig() {
        File f = choose("选择配置文件", "conf");
        if (f != null) {
            cfgField.setText(f.getAbsolutePath());
            // 把配置文件里的键值回填到「全部选项」控件，避免界面显示与真实生效值不一致。
            loadConfigIntoUi(f.toPath());
        }
    }

    private void pickCc() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("选择 C 编译器");
        if (fc.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) ccField.setText(fc.getSelectedFile().getAbsolutePath());
    }

    private File choose(String title, String ext) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.setFileFilter(new FileNameExtensionFilter("*." + ext, ext));
        return fc.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION ? fc.getSelectedFile() : null;
    }

    private void applyLogTheme(boolean dark) {
        logArea.setBackground(dark ? new Color(0x11, 0x14, 0x12) : Color.WHITE);
        logArea.setForeground(dark ? new Color(0x8C, 0xFF, 0x9E) : new Color(0x20, 0x20, 0x20));
        logArea.setCaretColor(logArea.getForeground());
    }

    /** 把输入 jar 的包/类结构填入左侧「类浏览器」树。 */
    private void loadTree(File jar) {
        DefaultMutableTreeNode root = new DefaultMutableTreeNode(jar.getName());
        Map<String, DefaultMutableTreeNode> pkgNodes = new TreeMap<>();
        try (ZipFile zf = new ZipFile(jar)) {
            Enumeration<? extends ZipEntry> en = zf.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                String name = e.getName();
                if (!name.endsWith(".class")) continue;
                String internal = name.substring(0, name.length() - ".class".length());
                int slash = internal.lastIndexOf('/');
                String pkg = slash < 0 ? "(default)" : internal.substring(0, slash).replace('/', '.');
                String simple = slash < 0 ? internal : internal.substring(slash + 1);
                DefaultMutableTreeNode pn = pkgNodes.computeIfAbsent(pkg, k -> {
                    DefaultMutableTreeNode n = new DefaultMutableTreeNode(k);
                    root.add(n);
                    return n;
                });
                pn.add(new DefaultMutableTreeNode(simple));
            }
        } catch (Exception ex) {
            root.add(new DefaultMutableTreeNode("读取失败: " + ex.getMessage()));
        }
        classTree.setModel(new DefaultTreeModel(root));
        expandAll();
        status.setText(jar.getName() + " 已加载");
    }

    private void searchTree() {
        String q = searchField.getText().trim().toLowerCase();
        if (q.isEmpty()) return;
        DefaultMutableTreeNode root = (DefaultMutableTreeNode) classTree.getModel().getRoot();
        Enumeration<javax.swing.tree.TreeNode> en = root.preorderEnumeration();
        while (en.hasMoreElements()) {
            javax.swing.tree.TreeNode n = en.nextElement();
            if (n.toString().toLowerCase().contains(q)) {
                TreePath path = new TreePath(((DefaultMutableTreeNode) n).getPath());
                classTree.scrollPathToVisible(path);
                classTree.setSelectionPath(path);
                return;
            }
        }
        status.setText("未找到: " + q);
    }

    private void expandAll() {
        for (int i = 0; i < classTree.getRowCount(); i++) classTree.expandRow(i);
    }

    private void collapseAll() {
        for (int i = classTree.getRowCount() - 1; i >= 0; i--) classTree.collapseRow(i);
    }

    /** 主流程：加载配置 → 套用界面覆盖 → 后台线程跑 {@link ProtectionPipeline}。 */
    private void runProtection() {
        if (running) { JOptionPane.showMessageDialog(frame, "已有任务正在执行。", "提示", JOptionPane.WARNING_MESSAGE); return; }
        String in = inField.getText().trim();
        String out = outField.getText().trim();
        if (in.isEmpty() || out.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "请先选择输入与输出 jar。", "缺少输入", JOptionPane.WARNING_MESSAGE);
            return;
        }
        logArea.setText("");
        running = true;
        progress.setValue(0);
        status.setText("执行中…");

        KBoxLog.setOut(new PrintStream(new AreaStream(logArea), true, StandardCharsets.UTF_8));
        KBoxLog.setListener(new KBoxLog.ProgressListener() {
            @Override public void onStage(int stage, int total, String name) {
                if (total > 0) progress.setValue((int) (100.0 * stage / total));
                progress.setString("[" + stage + "/" + total + "] " + name);
            }
            @Override public void onProgress(int percent, String detail) {
                progress.setString(percent + "%  " + (detail == null ? "" : detail));
            }
            @Override public void onComplete(String summary) {
                progress.setString(summary);
            }
        });

        Thread worker = new Thread(() -> {
            try {
                ProtectionConfig cfg = loadConfigFromUi();
                Path outPath = Paths.get(out);
                Path workDir = outPath.toAbsolutePath().getParent() != null
                        ? outPath.toAbsolutePath().getParent().resolve("kbox-work")
                        : Paths.get("kbox-work");
                new ProtectionPipeline(Paths.get(in), outPath, cfg, workDir).run();
                SwingUtilities.invokeLater(() -> {
                    status.setText("完成：" + out);
                    progress.setValue(100);
                });
            } catch (Throwable t) {
                KBoxLog.error("gui", "保护失败: " + t, t);
                SwingUtilities.invokeLater(() -> {
                    status.setText("失败：" + t.getMessage());
                    JOptionPane.showMessageDialog(frame, "保护失败：\n" + t, "错误", JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                running = false;
                SwingUtilities.invokeLater(() -> progress.setString(""));
            }
        }, "kbox-gui-worker");
        worker.setDaemon(true);
        worker.start();
    }

    /**
     * 生成"配置文件 + 界面全部选项"的合并配置并加载。
     *
     * <p>界面上的每个控件都会写成一个真实的 {@code key = value}（键取自 {@link #ALL_OPTIONS}，
     * 与 {@code ConfigLoader} 支持键一一对应），与用户选择的配置文件逐行合并后交给
     * {@link ConfigLoader#load}。因此界面就是引擎能力的完整投影：新增一个配置键，
     * 只需在 {@link #ALL_OPTIONS} 里加一行。</p>
     */
    private ProtectionConfig loadConfigFromUi() throws java.io.IOException {
        StringBuilder conf = new StringBuilder();
        String cfgPath = cfgField.getText().trim();
        if (!cfgPath.isEmpty()) {
            java.nio.file.Path p = Paths.get(cfgPath);
            if (java.nio.file.Files.isRegularFile(p)) {
                conf.append(new String(java.nio.file.Files.readAllBytes(p), StandardCharsets.UTF_8))
                        .append('\n');
            }
        }
        conf.append(uiConfText());
        java.nio.file.Path tmp = java.nio.file.Files.createTempFile("kbox-gui-", ".conf");
        java.nio.file.Files.write(tmp, conf.toString().getBytes(StandardCharsets.UTF_8));
        tmp.toFile().deleteOnExit();
        return ConfigLoader.load(tmp);
    }

    // ------------------------------------------------------------------
    // Small widget helpers
    // ------------------------------------------------------------------

    private static JMenuItem menuItem(String text, java.awt.event.ActionListener l) {
        JMenuItem mi = new JMenuItem(text);
        mi.addActionListener(l);
        return mi;
    }

    private static JButton button(String text, java.awt.event.ActionListener l) {
        JButton b = new JButton(text);
        b.addActionListener(l);
        return b;
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private static void addRow(JPanel p, GridBagConstraints c, int y, String label,
                               JTextField field, String btnText, java.awt.event.ActionListener act) {
        c.gridx = 0; c.gridy = y; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        p.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        p.add(field, c);
        if (btnText != null) {
            c.gridx = 2; c.weightx = 0; c.fill = GridBagConstraints.NONE;
            p.add(button(btnText, act), c);
        }
    }

    /** {@link PrintStream} that appends everything to a {@link JTextArea} on the EDT. */
    private static final class AreaStream extends OutputStream {
        private final JTextArea area;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        AreaStream(JTextArea area) { this.area = area; }

        @Override public synchronized void write(int b) {
            if (b == '\n') flushLine(); else buf.write(b);
        }

        private void flushLine() {
            final String line = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            buf.reset();
            SwingUtilities.invokeLater(() -> {
                area.append(line);
                area.append("\n");
                area.setCaretPosition(area.getDocument().getLength());
            });
        }
    }
}
