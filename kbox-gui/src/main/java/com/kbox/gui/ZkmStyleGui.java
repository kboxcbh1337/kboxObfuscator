package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import javax.swing.BorderFactory;
import javax.swing.Box;
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
 * ZKM 式 Swing 界面（Zelix KlassMaster 风格布局的精神移植）。
 *
 * <p>原版界面是内嵌 HTTP 服务 + 浏览器（{@link ProtectorGui}）。本类提供一套**原生 Swing** 的替代界面，
 * 布局对齐 ZKM 的经典结构：菜单栏 + 工具栏 + 左侧「类浏览器」树 + 右侧选项标签页 + 底部日志与进度条。
 * 入口 {@link #launch(String, String, String, boolean)} 与 {@link ProtectorGui#launch} 同签名，便于运行时二选一。</p>
 *
 * <p><b>移植说明（诚实）</b>：ZKM27 只发布了编译后的 {@code .class}（无源码）。逐类反编译移植存在版权/许可风险，
 * 因此本类是**按 ZKM 的布局与交互习惯从零用 Swing 重写**，而非复制 ZKM 的代码。选项直接映射到
 * {@link ProtectionConfig}，执行时复用同一套 {@link ProtectionPipeline}，与 HTML UI 行为一致。</p>
 */
public final class ZkmStyleGui {

    private final JFrame frame = new JFrame("KBox Obfuscator — ZKM 式界面");
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

    /** key -> checkbox (bool options). */
    private final Map<String, JCheckBox> bools = new LinkedHashMap<>();
    /** key -> combo (int/enum options). */
    private final Map<String, JComboBox<String>> ints = new LinkedHashMap<>();

    private volatile boolean running = false;

    private ZkmStyleGui(String in, String out, String cfg, boolean verbose) {
        if (in != null) inField.setText(in);
        if (out != null) outField.setText(out);
        if (cfg != null) cfgField.setText(cfg);
        if (out == null && in != null) outField.setText(deriveOut(in));
        if (verbose) KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
    }

    /** 与 {@link ProtectorGui#launch} 对齐的反射入口。 */
    public static void launch(String in, String out, String cfg, boolean verbose) {
        SwingUtilities.invokeLater(() -> new ZkmStyleGui(in, out, cfg, verbose).build());
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
        file.add(menuItem("使用原版 HTML UI…", e -> switchToHtmlUi()));
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
                "KBox Obfuscator\nZKM 级字节码混淆 + JNIC + VMP + kboXShield 原生加壳\n"
                        + "本界面为 ZKM 布局的 Swing 重写（非 ZKM 源码移植）。",
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
        tabs.addTab("混淆选项", buildToggles());
        tabs.addTab("高级", buildAdvanced());
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

    private Component buildToggles() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = gbc();
        c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        int y = 0;
        y = addToggle(p, c, y, "renameIdentifiers", "标识符重命名", true);
        y = addToggle(p, c, y, "encryptStrings", "字符串加密", true);
        y = addToggle(p, c, y, "obfuscateControlFlow", "控制流混淆", true);
        y = addToggle(p, c, y, "obfuscateConstants", "常量查表加密", false);
        y = addToggle(p, c, y, "typeConfusion", "类型混淆(高风险)", false);
        y = addToggle(p, c, y, "encryptClasses", "类体加密", false);
        y = addToggle(p, c, y, "enableVmp", "VMP 虚拟化", false);
        y = addToggle(p, c, y, "enableJnic", "JNIC 原生化", false);
        y = addToggle(p, c, y, "obfuscateResources", "资源混淆", false);
        y = addToggle(p, c, y, "antiDebug", "反调试", false);
        y = addToggle(p, c, y, "integrityCheck", "完整性自检", false);
        y = addToggle(p, c, y, "protectNativeLibs", "jar 内原生库加壳", false);
        y = addToggle(p, c, y, "shieldNativeOutput", "JNIC/VMP 产物加壳", true);
        c.gridy = y; c.weighty = 1; p.add(Box.createVerticalGlue(), c);
        return p;
    }

    private Component buildAdvanced() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints c = gbc();
        int y = 0;
        y = addSelect(p, c, y, "controlFlowStrength", "控制流强度", new String[]{"1", "2", "3"}, "2");
        y = addSelect(p, c, y, "stringEncryptionStrength", "字符串强度", new String[]{"1", "2", "3"}, "1");
        y = addSelect(p, c, y, "mbaConstants", "交织表达式常量", new String[]{"0", "1", "2"}, "0");
        y = addSelect(p, c, y, "mbaRewrite", "运行时 MBA 重写", new String[]{"0", "1", "2", "3"}, "0");
        y = addSelect(p, c, y, "antiDecompilerLevel", "反编译器等级", new String[]{"0", "1", "2", "3"}, "0");
        y = addSelect(p, c, y, "nativeShell", "nativeShell", new String[]{"0", "1", "2", "3"}, "3");
        y = addSelect(p, c, y, "typeConfusionStrength", "类型混淆强度", new String[]{"0", "1", "2"}, "0");
        y = addToggle(p, c, y, "enableVmpNative", "VMP 原生化", false);
        y = addToggle(p, c, y, "jnicFullCoverage", "JNIC 全覆盖", false);
        y = addToggle(p, c, y, "vmpFullCoverage", "VMP 全覆盖", false);
        y = addToggle(p, c, y, "brainfuckShield", "BrainfuckShield", false);
        y = addToggle(p, c, y, "brainfuckLoader", "Brainfuck 加载器", false);
        y = addToggle(p, c, y, "brainfuckMcHybrid", "BF×MC 混合模式", false);
        y = addToggle(p, c, y, "fixKotlinMetadata", "Kotlin 元数据修复", true);
        y = addToggle(p, c, y, "autoAdaptMinecraft", "MC mod 自动适配", false);
        c.gridy = y; c.weighty = 1; p.add(Box.createVerticalGlue(), c);
        return p;
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
        if (f != null) cfgField.setText(f.getAbsolutePath());
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

    private void switchToHtmlUi() {
        try {
            Class<?> c = Class.forName("com.kbox.gui.ProtectorGui");
            c.getMethod("launch", String.class, String.class, String.class, boolean.class)
                    .invoke(null, inField.getText(), outField.getText(), cfgField.getText(), Boolean.FALSE);
            frame.dispose();
        } catch (Throwable t) {
            JOptionPane.showMessageDialog(frame, "无法切换到 HTML UI: " + t, "错误", JOptionPane.ERROR_MESSAGE);
        }
    }

    private void applyLogTheme(boolean dark) {
        logArea.setBackground(dark ? new Color(0x11, 0x14, 0x12) : Color.WHITE);
        logArea.setForeground(dark ? new Color(0x8C, 0xFF, 0x9E) : new Color(0x20, 0x20, 0x20));
        logArea.setCaretColor(logArea.getForeground());
    }

    /** 把输入 jar 的包/类/成员结构填入左侧「类浏览器」树（ZKM 的类浏览近似）。 */
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
                ProtectionConfig cfg = ConfigLoader.load(cfgField.getText().isBlank() ? null : Paths.get(cfgField.getText().trim()));
                applyUiToConfig(cfg);
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
        }, "kbox-zkm-worker");
        worker.setDaemon(true);
        worker.start();
    }

    /** 把界面控件写回 {@link ProtectionConfig}（作为配置文件之上的覆盖）。 */
    private void applyUiToConfig(ProtectionConfig p) {
        String cc = ccField.getText().trim();
        if (!cc.isEmpty()) p.setCc(cc);
        String ep = entryField.getText().trim();
        if (!ep.isEmpty()) p.getEntryPoints().add(ep);

        setBool(p, "renameIdentifiers", p::setRenameIdentifiers);
        setBool(p, "encryptStrings", p::setEncryptStrings);
        setBool(p, "obfuscateControlFlow", p::setObfuscateControlFlow);
        setBool(p, "obfuscateConstants", p::setObfuscateConstants);
        setBool(p, "encryptClasses", p::setEncryptClasses);
        setBool(p, "enableVmp", p::setEnableVmp);
        setBool(p, "enableJnic", p::setEnableJnic);
        setBool(p, "obfuscateResources", p::setObfuscateResources);
        setBool(p, "antiDebug", p::setAntiDebug);
        setBool(p, "integrityCheck", p::setIntegrityCheck);
        setBool(p, "protectNativeLibs", p::setProtectNativeLibs);
        setBool(p, "shieldNativeOutput", p::setShieldNativeOutput);
        setBool(p, "enableVmpNative", p::setEnableVmpNative);
        setBool(p, "brainfuckShield", p::setBrainfuckShield);
        setBool(p, "brainfuckLoader", p::setBrainfuckLoader);
        setBool(p, "fixKotlinMetadata", p::setFixKotlinMetadata);
        setBool(p, "autoAdaptMinecraft", p::setAutoAdaptMinecraft);

        JCheckBox tc = bools.get("typeConfusion");
        if (tc != null) p.setTypeConfusionStrength(tc.isSelected() ? intOf("typeConfusionStrength", 1) : 0);
        JCheckBox jf = bools.get("jnicFullCoverage");
        if (jf != null && jf.isSelected()) { p.setJnicFullCoverage(true); p.setEnableJnic(true); }
        JCheckBox vf = bools.get("vmpFullCoverage");
        if (vf != null && vf.isSelected()) { p.setVmpFullCoverage(true); p.setEnableVmp(true); }

        p.setControlFlowStrength(intOf("controlFlowStrength", 2));
        p.setStringEncryptionStrength(intOf("stringEncryptionStrength", 1));
        p.setMbaConstants(intOf("mbaConstants", 0));
        p.setMbaRewrite(intOf("mbaRewrite", 0));
        p.setAntiDecompilerLevel(intOf("antiDecompilerLevel", 0));
        p.setNativeShell(intOf("nativeShell", 3));
    }

    private void setBool(ProtectionConfig p, String key, java.util.function.Consumer<Boolean> setter) {
        JCheckBox cb = bools.get(key);
        if (cb != null) setter.accept(cb.isSelected());
    }

    private int intOf(String key, int dflt) {
        JComboBox<String> cb = ints.get(key);
        if (cb == null || cb.getSelectedItem() == null) return dflt;
        try { return Integer.parseInt(((String) cb.getSelectedItem()).trim()); }
        catch (Exception e) { return dflt; }
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

    private int addToggle(JPanel p, GridBagConstraints c, int y, String key, String label, boolean dflt) {
        JCheckBox cb = new JCheckBox(label, dflt);
        bools.put(key, cb);
        c.gridx = 0; c.gridy = y; c.gridwidth = 2; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        p.add(cb, c);
        c.gridwidth = 1;
        return y + 1;
    }

    private int addSelect(JPanel p, GridBagConstraints c, int y, String key, String label,
                          String[] options, String dflt) {
        c.gridx = 0; c.gridy = y; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        p.add(new JLabel(label), c);
        JComboBox<String> cb = new JComboBox<>(options);
        cb.setSelectedItem(dflt);
        ints.put(key, cb);
        c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        p.add(cb, c);
        return y + 1;
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
