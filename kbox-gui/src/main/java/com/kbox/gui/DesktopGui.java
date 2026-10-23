package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.JToggleButton;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.plaf.basic.BasicProgressBarUI;
import javax.swing.text.BadLocationException;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeCellRenderer;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import java.awt.BasicStroke;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GradientPaint;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
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
 * KBox 桌面界面 —— 深色「保护工作台」视觉系统。
 *
 * <p>纯 Swing 自绘（无第三方外观依赖）：渐变品牌头、卡片式分区、扁平控件、
 * 终端式日志、状态条。所有界面选项仍直接映射到 {@link ProtectionConfig}，
 * 执行时复用 {@link ProtectionPipeline}。</p>
 *
 * <p>入口 {@link #launch(String, String, String, boolean)} 由 CLI 反射调用。</p>
 */
public final class DesktopGui {

    // ------------------------------------------------------------------
    // 视觉系统
    // ------------------------------------------------------------------

    private static final class C {
        static final Color BG = new Color(0x0A0E14);
        static final Color SIDEBAR = new Color(0x0C1118);
        static final Color SURFACE = new Color(0x111823);
        static final Color SURFACE_ALT = new Color(0x16202C);
        static final Color BORDER = new Color(0x1F2A38);
        static final Color TEXT = new Color(0xE6EDF7);
        static final Color MUTED = new Color(0x8794A6);
        static final Color ACCENT = new Color(0x37E0C1);
        static final Color ACCENT_DIM = new Color(0x1E8F7C);
        static final Color VIOLET = new Color(0x8B93FF);
        static final Color DANGER = new Color(0xFF6B6B);
        static final Color WARN = new Color(0xF0B35E);
        static final Color OK = new Color(0x66D48B);
        static final Color CONSOLE = new Color(0x080C11);
    }

    /** 用于字形覆盖检测的中文探针。 */
    private static final String CJK_PROBE = "\u4e2d\u6587\u6d4b\u8bd5";

    /**
     * UI 字体：必须优先选择真正包含中文字形的字体。
     * Swing/AWT 不会像 Windows GDI 那样做 font-linking，选了不含 CJK 的
     * Latin 字体（如 Segoe UI / Cascadia Mono / Consolas）时中文会渲染成
     * 口口（tofu）。这里用 {@link Font#canDisplayUpTo} 逐个校验字形覆盖。
     */
    private static final Font UI = pickCjkFont(new String[]{
            "Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC",
            "Noto Sans CJK SC", "Source Han Sans SC", "Segoe UI"
    }, Font.SANS_SERIF);
    private static final Font UI_BOLD = UI.deriveFont(Font.BOLD);
    /** 等宽字体：优先中文等宽族，其次逻辑 Monospaced（复合字体，CJK 走 fallback）。 */
    private static final Font MONO = pickMonoFont();

    /**
     * 等宽字体选择：真·中文等宽字体稀缺（本机常见只有 NSimSun/SimSun，
     * 且不一定安装）。逻辑字体 {@code Monospaced} 是复合字体，拉丁字符保持
     * 等宽，缺失的 CJK 字形由 fallback 链补足，是控制台最稳妥的选择。
     */
    private static Font pickMonoFont() {
        String[] all = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames();
        for (String want : new String[]{"Sarasa Mono SC", "Noto Sans Mono CJK SC",
                "NSimSun", "SimSun"}) {
            String family = findFamily(all, want);
            if (family == null) continue;
            Font f = new Font(family, Font.PLAIN, 13);
            if (f.canDisplayUpTo(CJK_PROBE) < 0) return f;
        }
        Font logical = new Font(Font.MONOSPACED, Font.PLAIN, 13);
        if (logical.canDisplayUpTo(CJK_PROBE) < 0) return logical;
        return pickCjkFont(new String[]{"Microsoft YaHei UI", "Microsoft YaHei",
                "Cascadia Mono", "Consolas"}, Font.MONOSPACED);
    }

    /**
     * 选择第一个「已安装且能显示中文」的字体族；都不满足时退回逻辑字体
     * （逻辑字体是复合字体，带 fallback 链），最后兜底扫描全部已安装字体。
     */
    private static Font pickCjkFont(String[] candidates, String fallback) {
        String[] all = java.awt.GraphicsEnvironment.getLocalGraphicsEnvironment()
                .getAvailableFontFamilyNames();
        for (String want : candidates) {
            String family = findFamily(all, want);
            if (family == null) continue;
            Font f = new Font(family, Font.PLAIN, 13);
            if (f.canDisplayUpTo(CJK_PROBE) < 0) return f;
        }
        Font logical = new Font(fallback, Font.PLAIN, 13);
        if (logical.canDisplayUpTo(CJK_PROBE) < 0) return logical;
        for (String family : all) {
            Font f = new Font(family, Font.PLAIN, 13);
            if (f.canDisplayUpTo(CJK_PROBE) < 0) return f;
        }
        return logical;
    }

    private static String findFamily(String[] all, String want) {
        for (String f : all) {
            if (f.equalsIgnoreCase(want)) return f;
        }
        return null;
    }

    // ------------------------------------------------------------------
    // 状态
    // ------------------------------------------------------------------

    private final JFrame frame = new JFrame("KBox Obfuscator");
    private final JTextField inField = new JTextField();
    private final JTextField outField = new JTextField();
    private final JTextField cfgField = new JTextField();
    private final JTextField ccField = new JTextField();
    private final JTextField entryField = new JTextField();

    private final Map<String, Component> allCtrls = new LinkedHashMap<>();
    private final Map<String, String> allTypes = new LinkedHashMap<>();
    private final JTextField optionSearch = new JTextField();
    private JPanel optionBody;

    private final JTextPane console = new JTextPane();
    private final JProgressBar progress = new JProgressBar(0, 1000);
    private final JLabel status = new JLabel("就绪");
    private final JLabel headerState = new JLabel("IDLE");
    private final JLabel summaryLabel = new JLabel("");
    private final JTree classTree = new JTree(new DefaultMutableTreeNode("（未打开 jar）"));
    private final JTextField searchField = new JTextField();

    private final CardLayout cards = new CardLayout();
    private final JPanel content = new JPanel(cards);
    private final Map<String, JToggleButton> navButtons = new LinkedHashMap<>();
    /** 总览页的 SROX 镜像控件（与「全部选项」里的真实配置控件双向同步）。 */
    private JCheckBox sroxMirrorCb;
    private JComboBox<String> sroxMirrorLevel;
    private JTextField sroxMirrorReport;

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
    // 构建
    // ------------------------------------------------------------------

    private void build() {
        try {
            UIManager.setLookAndFeel(UIManager.getCrossPlatformLookAndFeelClassName());
        } catch (Exception ignored) {
            // 自绘控件不依赖外观
        }
        UIManager.put("Tree.selectionBackground", C.SURFACE_ALT);
        UIManager.put("Tree.selectionForeground", C.TEXT);
        UIManager.put("Tree.background", C.SIDEBAR);
        UIManager.put("Tree.foreground", C.TEXT);
        // 标准组件（菜单/对话框/文件选择器/表格/提示条等）不走自绘路径，
        // 必须显式覆盖 LAF 默认字体，否则中文会回落到无 CJK 字形的默认面。
        String[] fontKeys = {
                "Label.font", "Button.font", "ToggleButton.font", "CheckBox.font",
                "RadioButton.font", "ComboBox.font", "Menu.font", "MenuItem.font",
                "CheckBoxMenuItem.font", "RadioButtonMenuItem.font", "PopupMenu.font",
                "ToolBar.font", "ToolTip.font", "Table.font", "TableHeader.font",
                "Tree.font", "List.font", "TextField.font", "TextArea.font",
                "TextPane.font", "EditorPane.font", "PasswordField.font",
                "FormattedTextField.font", "Spinner.font", "TitledBorder.font",
                "OptionPane.messageFont", "OptionPane.buttonFont",
                "InternalFrame.titleFont", "TabbedPane.font"
        };
        for (String k : fontKeys) UIManager.put(k, UI);

        frame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        frame.setMinimumSize(new Dimension(1180, 760));
        frame.getContentPane().setBackground(C.BG);
        frame.setLayout(new BorderLayout());

        frame.add(buildHeader(), BorderLayout.NORTH);
        frame.add(buildSidebar(), BorderLayout.WEST);

        // 选项控件必须先创建：总览页的 SROX 区块会镜像其中的值。
        buildOptionControls();

        content.setOpaque(true);
        content.setBackground(C.BG);
        content.add(buildOverview(), "overview");
        content.add(buildAllOptions(), "options");
        content.add(buildClassBrowser(), "classes");
        content.add(buildLog(), "log");
        frame.add(content, BorderLayout.CENTER);

        frame.add(buildFooter(), BorderLayout.SOUTH);
        showPage("overview");
        refreshSummary();

        frame.setSize(1280, 820);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    private JComponent buildHeader() {
        JPanel header = new JPanel(new BorderLayout(18, 0)) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setPaint(new GradientPaint(0, 0, new Color(0x0D1A22),
                        getWidth(), 0, new Color(0x11121F)));
                g2.fillRect(0, 0, getWidth(), getHeight());
                g2.setPaint(new GradientPaint(0, getHeight() - 1, C.ACCENT_DIM,
                        getWidth(), getHeight() - 1, new Color(0x2A2350)));
                g2.fillRect(0, getHeight() - 1, getWidth(), 1);
                g2.dispose();
            }
        };
        header.setOpaque(false);
        header.setBorder(BorderFactory.createEmptyBorder(16, 24, 16, 24));

        JPanel brand = new JPanel();
        brand.setOpaque(false);
        brand.setLayout(new BoxLayout(brand, BoxLayout.Y_AXIS));
        JLabel title = new JLabel("KBOX  /  PROTECTION STUDIO");
        title.setFont(UI_BOLD.deriveFont(19f));
        title.setForeground(C.TEXT);
        JLabel sub = new JLabel("字节码混淆 · JNIC 原生化 · VMP · kboXShield · SROX 自研究变换");
        sub.setFont(UI.deriveFont(12f));
        sub.setForeground(C.MUTED);
        brand.add(title);
        brand.add(Box.createVerticalStrut(4));
        brand.add(sub);
        header.add(brand, BorderLayout.WEST);

        JPanel right = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 12, 0));
        right.setOpaque(false);
        headerState.setFont(MONO.deriveFont(Font.BOLD, 11f));
        headerState.setForeground(C.ACCENT);
        headerState.setBorder(BorderFactory.createCompoundBorder(
                new RoundBorder(C.BORDER, 20), BorderFactory.createEmptyBorder(6, 12, 6, 12)));
        right.add(headerState);
        FlatButton run = new FlatButton("开始保护", true);
        run.setPreferredSize(new Dimension(128, 36));
        run.addActionListener(e -> runProtection());
        right.add(run);
        header.add(right, BorderLayout.EAST);
        return header;
    }

    private JComponent buildSidebar() {
        JPanel side = new JPanel(new BorderLayout());
        side.setBackground(C.SIDEBAR);
        side.setPreferredSize(new Dimension(232, 0));
        side.setBorder(BorderFactory.createMatteBorder(0, 0, 0, 1, C.BORDER));

        JPanel nav = new JPanel();
        nav.setOpaque(false);
        nav.setLayout(new BoxLayout(nav, BoxLayout.Y_AXIS));
        nav.setBorder(BorderFactory.createEmptyBorder(22, 16, 12, 16));
        nav.add(navItem("overview", "总览", "保护目标与强度策略"));
        nav.add(navItem("options", "全部选项", "引擎支持的完整配置"));
        nav.add(navItem("classes", "类浏览器", "输入 jar 的结构"));
        nav.add(navItem("log", "运行日志", "构建输出与状态"));
        side.add(nav, BorderLayout.NORTH);

        JPanel foot = new JPanel();
        foot.setOpaque(false);
        foot.setLayout(new BoxLayout(foot, BoxLayout.Y_AXIS));
        foot.setBorder(BorderFactory.createEmptyBorder(12, 22, 20, 22));
        JLabel v = new JLabel("v3.0.3  ·  SROX ENGINE");
        v.setFont(MONO.deriveFont(10.5f));
        v.setForeground(new Color(0x5A6879));
        JLabel s = new JLabel("构建期自研究表示变换");
        s.setFont(UI.deriveFont(11f));
        s.setForeground(new Color(0x5A6879));
        foot.add(v);
        foot.add(Box.createVerticalStrut(4));
        foot.add(s);
        side.add(foot, BorderLayout.SOUTH);
        return side;
    }

    private JToggleButton navItem(String key, String title, String sub) {
        JToggleButton b = new JToggleButton() {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                boolean sel = isSelected();
                if (sel) {
                    g2.setColor(C.SURFACE_ALT);
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                    g2.setColor(C.ACCENT);
                    g2.fillRoundRect(0, 8, 3, getHeight() - 16, 3, 3);
                } else if (getModel().isRollover()) {
                    g2.setColor(new Color(0x121A24));
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                }
                g2.setColor(sel ? C.TEXT : C.MUTED);
                g2.setFont(UI_BOLD.deriveFont(13f));
                g2.drawString(title, 16, 24);
                g2.setColor(sel ? new Color(0x9FB0C4) : new Color(0x5F6D7E));
                g2.setFont(UI.deriveFont(10.5f));
                g2.drawString(sub, 16, 40);
                g2.dispose();
            }
        };
        b.setOpaque(false);
        b.setContentAreaFilled(false);
        b.setBorderPainted(false);
        b.setFocusPainted(false);
        b.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        b.setPreferredSize(new Dimension(200, 50));
        b.setMaximumSize(new Dimension(Integer.MAX_VALUE, 50));
        b.addActionListener(e -> showPage(key));
        navButtons.put(key, b);
        return b;
    }

    private void showPage(String key) {
        cards.show(content, key);
        for (Map.Entry<String, JToggleButton> e : navButtons.entrySet()) {
            e.getValue().setSelected(e.getKey().equals(key));
        }
    }

    private JComponent buildFooter() {
        JPanel footer = new JPanel(new BorderLayout(14, 0));
        footer.setBackground(C.SIDEBAR);
        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, C.BORDER),
                BorderFactory.createEmptyBorder(8, 20, 8, 20)));

        status.setFont(UI.deriveFont(11.5f));
        status.setForeground(C.MUTED);
        footer.add(status, BorderLayout.WEST);

        progress.setBorderPainted(false);
        progress.setBackground(new Color(0x16202C));
        progress.setForeground(C.ACCENT);
        progress.setStringPainted(false);
        progress.setPreferredSize(new Dimension(0, 6));
        progress.setUI(new BasicProgressBarUI() {
            @Override protected void paintDeterminate(Graphics g, JComponent c) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(progress.getBackground());
                g2.fillRoundRect(0, 0, c.getWidth(), c.getHeight(), 6, 6);
                int w = (int) (c.getWidth() * progress.getPercentComplete());
                g2.setColor(C.ACCENT);
                g2.fillRoundRect(0, 0, Math.max(6, w), c.getHeight(), 6, 6);
                g2.dispose();
            }
        });
        footer.add(progress, BorderLayout.CENTER);
        return footer;
    }

    // ------------------------------------------------------------------
    // 总览页
    // ------------------------------------------------------------------

    private JComponent buildOverview() {
        JPanel page = new JPanel(new BorderLayout(0, 14));
        page.setOpaque(true);
        page.setBackground(C.BG);
        page.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));

        JPanel titleRow = new JPanel(new BorderLayout());
        titleRow.setOpaque(false);
        JPanel t = new JPanel();
        t.setOpaque(false);
        t.setLayout(new BoxLayout(t, BoxLayout.Y_AXIS));
        JLabel h = new JLabel("保护工作台");
        h.setFont(UI_BOLD.deriveFont(24f));
        h.setForeground(C.TEXT);
        JLabel d = new JLabel("选择目标、确定强度，然后交给流水线。所有开关都会写入真实配置键。");
        d.setFont(UI.deriveFont(12.5f));
        d.setForeground(C.MUTED);
        t.add(h);
        t.add(Box.createVerticalStrut(6));
        t.add(d);
        titleRow.add(t, BorderLayout.WEST);
        summaryLabel.setFont(MONO.deriveFont(11f));
        summaryLabel.setForeground(C.MUTED);
        titleRow.add(summaryLabel, BorderLayout.EAST);
        page.add(titleRow, BorderLayout.NORTH);

        JPanel body = new JPanel(new GridBagLayout());
        body.setOpaque(false);
        GridBagConstraints gc = new GridBagConstraints();
        gc.gridx = 0; gc.gridy = 0; gc.weightx = 1; gc.weighty = 0;
        gc.fill = GridBagConstraints.BOTH; gc.insets = new Insets(0, 0, 14, 0);
        body.add(buildTargetCard(), gc);

        gc.gridy = 1;
        body.add(buildStrategyCard(), gc);

        gc.gridy = 2; gc.weighty = 1;
        body.add(buildSummaryCard(), gc);
        page.add(new JScrollPane(body) {{
            setBorder(null);
            getViewport().setBackground(C.BG);
            setOpaque(false);
            getVerticalScrollBar().setUnitIncrement(16);
        }}, BorderLayout.CENTER);
        return page;
    }

    private JComponent buildTargetCard() {
        JPanel card = card("目标文件", "输入产物、输出位置与工具链");
        GridBagConstraints c = gbc();
        int y = 0;
        addRow(card, c, y++, "输入 jar", inField, "浏览", e -> pickInput());
        addRow(card, c, y++, "输出 jar", outField, "浏览", e -> pickOutput());
        addRow(card, c, y++, "配置文件", cfgField, "浏览", e -> pickConfig());
        addRow(card, c, y++, "C 编译器", ccField, "浏览", e -> pickCc());
        addRow(card, c, y, "入口类（可选）", entryField, null, null);
        return card;
    }

    private JComponent buildStrategyCard() {
        JPanel card = card("强度策略", "预设会写入全部相关配置键，仍可在「全部选项」中微调");
        JPanel body = new JPanel(new BorderLayout(0, 12));
        body.setOpaque(false);

        JPanel presets = new JPanel(new java.awt.GridLayout(1, 3, 10, 0));
        presets.setOpaque(false);
        ButtonGroup bg = new ButtonGroup();
        String[][] defs = {
                {"基础", "重命名 + 字符串 + 控制流", "basic"},
                {"均衡", "叠加 VMP / JNIC / 原生壳", "balanced"},
                {"极限", "allMax：全引擎特性", "max"}
        };
        for (String[] d : defs) {
            JToggleButton tile = new JToggleButton() {
                @Override protected void paintComponent(Graphics g) {
                    Graphics2D g2 = (Graphics2D) g.create();
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                            RenderingHints.VALUE_ANTIALIAS_ON);
                    boolean sel = isSelected();
                    g2.setColor(sel ? new Color(0x123029) : C.SURFACE_ALT);
                    g2.fillRoundRect(0, 0, getWidth(), getHeight(), 12, 12);
                    g2.setColor(sel ? C.ACCENT : C.BORDER);
                    g2.setStroke(new BasicStroke(sel ? 1.6f : 1f));
                    g2.drawRoundRect(1, 1, getWidth() - 3, getHeight() - 3, 12, 12);
                    g2.setColor(sel ? C.TEXT : new Color(0xCFDAE8));
                    g2.setFont(UI_BOLD.deriveFont(13.5f));
                    g2.drawString(d[0], 14, 24);
                    g2.setColor(sel ? new Color(0x9FE8DA) : C.MUTED);
                    g2.setFont(UI.deriveFont(11f));
                    g2.drawString(d[1], 14, 44);
                    g2.dispose();
                }
            };
            tile.setOpaque(false);
            tile.setContentAreaFilled(false);
            tile.setBorderPainted(false);
            tile.setFocusPainted(false);
            tile.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            tile.setPreferredSize(new Dimension(0, 64));
            tile.addActionListener(e -> applyPreset(d[2]));
            bg.add(tile);
            presets.add(tile);
        }
        body.add(presets, BorderLayout.NORTH);

        JPanel srox = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 12, 4));
        srox.setOpaque(false);
        JLabel tag = new JLabel("SROX");
        tag.setFont(MONO.deriveFont(Font.BOLD, 11f));
        tag.setForeground(C.VIOLET);
        srox.add(tag);
        sroxMirrorCb = new JCheckBox("自研究表示变换");
        sroxMirrorCb.setOpaque(false);
        sroxMirrorCb.setForeground(C.TEXT);
        sroxMirrorCb.setFont(UI.deriveFont(12.5f));
        sroxMirrorCb.setSelected(!"false".equals(confValue("nativeSrox")));
        sroxMirrorCb.addActionListener(e ->
                setControlValue("nativeSrox", String.valueOf(sroxMirrorCb.isSelected())));
        srox.add(sroxMirrorCb);

        JLabel lv = new JLabel("等级");
        lv.setFont(UI.deriveFont(11.5f));
        lv.setForeground(C.MUTED);
        srox.add(lv);
        sroxMirrorLevel = new JComboBox<>(new String[] {"0", "1", "2", "3"});
        styleCombo(sroxMirrorLevel);
        String lv0 = confValue("nativeSroxLevel");
        sroxMirrorLevel.setSelectedItem(lv0 == null ? "3" : lv0);
        sroxMirrorLevel.addActionListener(e ->
                setControlValue("nativeSroxLevel", String.valueOf(sroxMirrorLevel.getSelectedItem())));
        srox.add(sroxMirrorLevel);

        JLabel rep = new JLabel("报告");
        rep.setFont(UI.deriveFont(11.5f));
        rep.setForeground(C.MUTED);
        srox.add(rep);
        sroxMirrorReport = new JTextField(confValue("nativeSroxReport"), 22);
        styleField(sroxMirrorReport);
        sroxMirrorReport.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { syncSroxToOptions(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { syncSroxToOptions(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { syncSroxToOptions(); }
        });
        srox.add(sroxMirrorReport);

        JLabel hint = new JLabel("PE 壳构建期闭环：候选生成 → 语义差分验证 → 回滚");
        hint.setFont(UI.deriveFont(10.5f));
        hint.setForeground(new Color(0x627084));
        srox.add(hint);
        body.add(srox, BorderLayout.CENTER);
        GridBagConstraints bc = new GridBagConstraints();
        bc.gridx = 0; bc.gridy = 1; bc.gridwidth = 2; bc.weightx = 1;
        bc.weighty = 1; bc.fill = GridBagConstraints.BOTH;
        card.add(body, bc);
        return card;
    }

    private void syncSroxToOptions() {
        if (sroxMirrorReport != null) {
            setControlValue("nativeSroxReport", sroxMirrorReport.getText().trim());
        }
    }

    /** 配置回填/重置后，把真实控件的值同步到总览页镜像控件。 */
    private void syncSroxMirrors() {
        if (sroxMirrorCb != null) {
            sroxMirrorCb.setSelected(!"false".equals(confValue("nativeSrox")));
        }
        if (sroxMirrorLevel != null) {
            String v = confValue("nativeSroxLevel");
            sroxMirrorLevel.setSelectedItem(v == null ? "3" : v);
        }
        if (sroxMirrorReport != null) {
            sroxMirrorReport.setText(confValue("nativeSroxReport") == null
                    ? "" : confValue("nativeSroxReport"));
        }
    }

    private JComponent buildSummaryCard() {
        JPanel card = card("当前策略摘要", "界面选择会转换为真实的 key = value 配置");
        JPanel row = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.LEFT, 8, 8));
        row.setOpaque(false);
        for (String key : new String[] {"renameIdentifiers", "encryptStrings",
                "obfuscateControlFlow", "enableVmp", "enableJnic",
                "nativeSrox", "brainfuckShield"}) {
            JLabel chip = new JLabel(key);
            chip.setFont(MONO.deriveFont(10.5f));
            chip.setForeground(C.MUTED);
            chip.setBorder(BorderFactory.createCompoundBorder(
                    new RoundBorder(C.BORDER, 12), BorderFactory.createEmptyBorder(4, 10, 4, 10)));
            chip.setName("chip:" + key);
            row.add(chip);
        }
        GridBagConstraints rc = new GridBagConstraints();
        rc.gridx = 0; rc.gridy = 1; rc.gridwidth = 2; rc.weightx = 1;
        rc.fill = GridBagConstraints.HORIZONTAL;
        card.add(row, rc);
        return card;
    }

    private void refreshSummary() {
        StringBuilder sb = new StringBuilder();
        Component c = allCtrls.get("allMax");
        boolean max = c instanceof JCheckBox && ((JCheckBox) c).isSelected();
        sb.append(max ? "PRESET: MAX" : "PRESET: CUSTOM");
        sb.append("   ·   ");
        sb.append(confValue("controlFlowStrength") == null ? "" : "CF " + confValue("controlFlowStrength"));
        sb.append("   ·   ");
        sb.append(confValue("nativeShell") == null ? "" : "SHELL " + confValue("nativeShell"));
        summaryLabel.setText(sb.toString());

        for (Component comp : allChildren(content)) {
            String n = comp.getName();
            if (n == null || !n.startsWith("chip:")) continue;
            final String key = n.substring(5);
            if (!(comp instanceof JLabel)) continue;
            JLabel chip = (JLabel) comp;
            boolean on = isOn(key);
            chip.setText((on ? "● " : "○ ") + key);
            chip.setForeground(on ? C.ACCENT : new Color(0x5C6A7B));
        }
    }

    private static java.util.List<Component> allChildren(Component root) {
        java.util.List<Component> out = new java.util.ArrayList<>();
        collect(root, out);
        return out;
    }

    private static void collect(Component c, java.util.List<Component> out) {
        out.add(c);
        if (c instanceof java.awt.Container) {
            for (Component k : ((java.awt.Container) c).getComponents()) {
                collect(k, out);
            }
        }
    }

    private boolean isOn(String key) {
        Component c = allCtrls.get(key);
        String t = allTypes.get(key);
        if (c == null || t == null) return false;
        if ("bool".equals(t) || "full".equals(t)) return ((JCheckBox) c).isSelected();
        if ("int".equals(t)) {
            String v = confValue(key);
            return v != null && !"0".equals(v);
        }
        return false;
    }

    private void applyPreset(String id) {
        if ("basic".equals(id)) {
            setControlValue("allMax", "false");
            setControlValue("renameIdentifiers", "true");
            setControlValue("encryptStrings", "true");
            setControlValue("obfuscateControlFlow", "true");
            setControlValue("controlFlowStrength", "2");
            setControlValue("enableVmp", "false");
            setControlValue("enableJnic", "false");
            setControlValue("nativeSrox", "true");
            setControlValue("nativeSroxLevel", "2");
        } else if ("balanced".equals(id)) {
            setControlValue("allMax", "false");
            setControlValue("renameIdentifiers", "true");
            setControlValue("renamePackages", "true");
            setControlValue("encryptStrings", "true");
            setControlValue("obfuscateControlFlow", "true");
            setControlValue("controlFlowStrength", "3");
            setControlValue("enableVmp", "true");
            setControlValue("enableJnic", "true");
            setControlValue("nativeShell", "3");
            setControlValue("nativeSrox", "true");
            setControlValue("nativeSroxLevel", "3");
        } else {
            setControlValue("allMax", "true");
            setControlValue("nativeSrox", "true");
            setControlValue("nativeSroxLevel", "3");
        }
        refreshSummary();
    }

    // ------------------------------------------------------------------
    // 全部选项
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

        {"原生壳 / SROX", "nativeShell", "nativeShell 档位", "int", "3", "0", "3"},
        {"原生壳 / SROX", "protectNativeLibs", "jar 内原生库加壳", "bool", "false", "0", "0"},
        {"原生壳 / SROX", "shieldNativeOutput", "JNIC/VMP 产物加壳", "bool", "true", "0", "0"},
        {"原生壳 / SROX", "nativeSrox", "SROX 自研究变换", "bool", "true", "0", "0"},
        {"原生壳 / SROX", "nativeSroxLevel", "SROX 研究等级（0-3）", "int", "3", "0", "3"},
        {"原生壳 / SROX", "nativeSroxReport", "SROX 报告路径", "text", "", "0", "0"},
        {"原生壳 / SROX", "cc", "C 编译器路径（cc）", "text", "", "0", "0"},

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

    private JComponent buildAllOptions() {
        JPanel root = new JPanel(new BorderLayout(0, 12));
        root.setBackground(C.BG);
        root.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));

        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setOpaque(false);
        JLabel h = new JLabel("全部选项");
        h.setFont(UI_BOLD.deriveFont(20f));
        h.setForeground(C.TEXT);
        top.add(h, BorderLayout.WEST);

        JPanel tools = new JPanel(new BorderLayout(8, 0));
        tools.setOpaque(false);
        optionSearch.setToolTipText("按配置键或中文名过滤");
        styleField(optionSearch);
        tools.add(optionSearch, BorderLayout.CENTER);
        FlatButton reset = new FlatButton("重置默认", false);
        reset.addActionListener(e -> {
            resetOptionsToDefault();
            optionSearch.setText("");
            refreshSummary();
        });
        tools.add(reset, BorderLayout.EAST);
        top.add(tools, BorderLayout.EAST);
        root.add(top, BorderLayout.NORTH);

        optionBody = new JPanel();
        optionBody.setOpaque(false);
        optionBody.setLayout(new BoxLayout(optionBody, BoxLayout.Y_AXIS));
        JScrollPane sp = new JScrollPane(optionBody);
        sp.setBorder(null);
        sp.getViewport().setBackground(C.BG);
        sp.getVerticalScrollBar().setUnitIncrement(18);
        root.add(sp, BorderLayout.CENTER);
        rebuildOptionRows(optionBody);
        optionSearch.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(optionBody); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(optionBody); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { rebuildOptionRows(optionBody); }
        });
        return root;
    }

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
                    cb.setOpaque(false);
                    cb.setForeground(C.TEXT);
                    cb.setFont(UI.deriveFont(12.5f));
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
                    styleCombo(cb);
                    allCtrls.put(key, cb);
                    break;
                }
                default: {
                    JTextField tf = new JTextField(def);
                    styleField(tf);
                    tf.setToolTipText("list".equals(type) ? key + "（逗号分隔）" : key);
                    allCtrls.put(key, tf);
                }
            }
        }
    }

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
                panel = card(group, null);
                c = gbc();
                y = 0;
                body.add(panel);
                body.add(Box.createVerticalStrut(10));
            }
            Component ctl = allCtrls.get(key);
            c.gridx = 0; c.gridy = y; c.weightx = 0; c.fill = GridBagConstraints.NONE;
            JLabel lb = new JLabel(("int".equals(type) || "bool".equals(type) || "full".equals(type))
                    ? label : label);
            lb.setFont(UI.deriveFont(12f));
            lb.setForeground(new Color(0xC3CEDD));
            panel.add(lb, c);
            c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
            panel.add(ctl, c);
            y++;
        }
        if (panel == null) {
            JLabel none = new JLabel(filter.isEmpty() ? "（无可选项）" : "（无匹配项：" + filter + "）");
            none.setForeground(C.MUTED);
            body.add(none);
        }
        body.revalidate();
        body.repaint();
    }

    private void resetOptionsToDefault() {
        allCtrls.clear();
        allTypes.clear();
        buildOptionControls();
        if (optionBody != null) rebuildOptionRows(optionBody);
        syncSroxMirrors();
    }

    private String confValue(String key) {
        Component c = allCtrls.get(key);
        String t = allTypes.get(key);
        if (c == null || t == null) return null;
        switch (t) {
            case "bool": return String.valueOf(((JCheckBox) c).isSelected());
            case "full": return ((JCheckBox) c).isSelected() ? "full" : "off";
            case "int": {
                JComboBox<?> cb = (JComboBox<?>) c;
                Object v = cb.isEditable() && cb.getEditor() != null
                        ? cb.getEditor().getItem() : cb.getSelectedItem();
                return v == null ? "0" : String.valueOf(v).trim();
            }
            default: return ((JTextField) c).getText().trim();
        }
    }

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
            if (maxOn && v.equals(o[4])) continue;
            sb.append(key).append(" = ").append(v).append('\n');
        }
        String cc = ccField.getText().trim();
        if (!cc.isEmpty()) sb.append("cc = ").append(cc).append('\n');
        String ep = entryField.getText().trim();
        if (!ep.isEmpty()) sb.append("entryPoint = ").append(ep).append('\n');
        return sb.toString();
    }

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
            syncSroxMirrors();
            refreshSummary();
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

    // ------------------------------------------------------------------
    // 类浏览器 / 日志
    // ------------------------------------------------------------------

    private JComponent buildClassBrowser() {
        JPanel page = new JPanel(new BorderLayout(0, 12));
        page.setBackground(C.BG);
        page.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));

        JPanel top = new JPanel(new BorderLayout(10, 0));
        top.setOpaque(false);
        JLabel h = new JLabel("类浏览器");
        h.setFont(UI_BOLD.deriveFont(20f));
        h.setForeground(C.TEXT);
        top.add(h, BorderLayout.WEST);

        JPanel tools = new JPanel(new BorderLayout(8, 0));
        tools.setOpaque(false);
        searchField.setToolTipText("搜索包名 / 类名");
        styleField(searchField);
        tools.add(searchField, BorderLayout.CENTER);
        FlatButton find = new FlatButton("定位", false);
        find.addActionListener(e -> searchTree());
        tools.add(find, BorderLayout.EAST);
        top.add(tools, BorderLayout.EAST);
        page.add(top, BorderLayout.NORTH);

        classTree.setRootVisible(true);
        classTree.setShowsRootHandles(true);
        classTree.setBackground(C.SIDEBAR);
        classTree.setForeground(C.TEXT);
        classTree.setRowHeight(22);
        classTree.setCellRenderer(new DefaultTreeCellRenderer() {
            @Override public Component getTreeCellRendererComponent(JTree tree, Object value,
                    boolean sel, boolean exp, boolean leaf, int row, boolean hasFocus) {
                JLabel l = (JLabel) super.getTreeCellRendererComponent(
                        tree, value, sel, exp, leaf, row, hasFocus);
                l.setFont(UI.deriveFont(12f));
                l.setForeground(sel ? C.TEXT : new Color(0xB9C6D6));
                l.setBackground(sel ? C.SURFACE_ALT : C.SIDEBAR);
                l.setOpaque(sel);
                return l;
            }
        });
        JScrollPane sp = new JScrollPane(classTree);
        sp.setBorder(BorderFactory.createLineBorder(C.BORDER));
        sp.getViewport().setBackground(C.SIDEBAR);
        page.add(sp, BorderLayout.CENTER);
        return page;
    }

    private JComponent buildLog() {
        console.setEditable(false);
        console.setBackground(C.CONSOLE);
        console.setForeground(new Color(0xB6C6D8));
        console.setFont(MONO.deriveFont(12f));
        console.setBorder(BorderFactory.createEmptyBorder(10, 12, 10, 12));

        JPanel page = new JPanel(new BorderLayout(0, 12));
        page.setBackground(C.BG);
        page.setBorder(BorderFactory.createEmptyBorder(22, 24, 18, 24));
        JPanel top = new JPanel(new BorderLayout());
        top.setOpaque(false);
        JLabel h = new JLabel("运行日志");
        h.setFont(UI_BOLD.deriveFont(20f));
        h.setForeground(C.TEXT);
        top.add(h, BorderLayout.WEST);
        JPanel tools = new JPanel(new java.awt.FlowLayout(java.awt.FlowLayout.RIGHT, 8, 0));
        tools.setOpaque(false);
        FlatButton clear = new FlatButton("清空", false);
        clear.addActionListener(e -> console.setText(""));
        FlatButton copy = new FlatButton("复制全部", false);
        copy.addActionListener(e -> {
            java.awt.datatransfer.StringSelection sel =
                    new java.awt.datatransfer.StringSelection(console.getText());
            java.awt.Toolkit.getDefaultToolkit().getSystemClipboard().setContents(sel, null);
        });
        tools.add(clear);
        tools.add(copy);
        top.add(tools, BorderLayout.EAST);
        page.add(top, BorderLayout.NORTH);

        JScrollPane sp = new JScrollPane(console);
        sp.setBorder(BorderFactory.createLineBorder(C.BORDER));
        sp.getViewport().setBackground(C.CONSOLE);
        sp.getVerticalScrollBar().setUnitIncrement(18);
        page.add(sp, BorderLayout.CENTER);
        return page;
    }

    // ------------------------------------------------------------------
    // 动作
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
        if (fc.showSaveDialog(frame) == JFileChooser.APPROVE_OPTION) {
            outField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void pickConfig() {
        File f = choose("选择配置文件", "conf");
        if (f != null) {
            cfgField.setText(f.getAbsolutePath());
            loadConfigIntoUi(f.toPath());
        }
    }

    private void pickCc() {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle("选择 C 编译器");
        if (fc.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION) {
            ccField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private File choose(String title, String ext) {
        JFileChooser fc = new JFileChooser();
        fc.setDialogTitle(title);
        fc.setFileFilter(new FileNameExtensionFilter("*." + ext, ext));
        return fc.showOpenDialog(frame) == JFileChooser.APPROVE_OPTION ? fc.getSelectedFile() : null;
    }

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
        for (int i = 0; i < classTree.getRowCount(); i++) classTree.expandRow(i);
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

    private void runProtection() {
        if (running) {
            javax.swing.JOptionPane.showMessageDialog(frame, "已有任务正在执行。", "提示",
                    javax.swing.JOptionPane.WARNING_MESSAGE);
            return;
        }
        String in = inField.getText().trim();
        String out = outField.getText().trim();
        if (in.isEmpty() || out.isEmpty()) {
            javax.swing.JOptionPane.showMessageDialog(frame, "请先选择输入与输出 jar。", "缺少输入",
                    javax.swing.JOptionPane.WARNING_MESSAGE);
            return;
        }
        console.setText("");
        running = true;
        progress.setValue(0);
        status.setText("执行中…");
        headerState.setText("RUNNING");
        headerState.setForeground(C.WARN);
        showPage("log");

        KBoxLog.setOut(new PrintStream(new ConsoleStream(console), true, StandardCharsets.UTF_8));
        KBoxLog.setListener(new KBoxLog.ProgressListener() {
            @Override public void onStage(int stage, int total, String name) {
                if (total > 0) progress.setValue((int) (1000.0 * stage / total));
                status.setText("[" + stage + "/" + total + "] " + name);
            }
            @Override public void onProgress(int percent, String detail) {
                status.setText(percent + "%  " + (detail == null ? "" : detail));
            }
            @Override public void onComplete(String summary) {
                status.setText(summary);
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
                    headerState.setText("DONE");
                    headerState.setForeground(C.ACCENT);
                    progress.setValue(1000);
                });
            } catch (Throwable t) {
                KBoxLog.error("gui", "保护失败: " + t, t);
                SwingUtilities.invokeLater(() -> {
                    status.setText("失败：" + t.getMessage());
                    headerState.setText("FAILED");
                    headerState.setForeground(C.DANGER);
                    javax.swing.JOptionPane.showMessageDialog(frame, "保护失败：\n" + t, "错误",
                            javax.swing.JOptionPane.ERROR_MESSAGE);
                });
            } finally {
                running = false;
            }
        }, "kbox-gui-worker");
        worker.setDaemon(true);
        worker.start();
    }

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
    // 自绘控件
    // ------------------------------------------------------------------

    /** 圆角边框。 */
    private static final class RoundBorder extends javax.swing.border.AbstractBorder {
        private final Color color;
        private final int radius;

        RoundBorder(Color color, int radius) {
            this.color = color;
            this.radius = radius;
        }

        @Override public void paintBorder(Component c, Graphics g, int x, int y, int w, int h) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(color);
            g2.drawRoundRect(x, y, w - 1, h - 1, radius, radius);
            g2.dispose();
        }

        @Override public Insets getBorderInsets(Component c) {
            return new Insets(1, 1, 1, 1);
        }
    }

    /** 卡片容器：圆角表面 + 标题。 */
    private JPanel card(String title, String subtitle) {
        JPanel p = new JPanel(new GridBagLayout()) {
            @Override protected void paintComponent(Graphics g) {
                Graphics2D g2 = (Graphics2D) g.create();
                g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING,
                        RenderingHints.VALUE_ANTIALIAS_ON);
                g2.setColor(C.SURFACE);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 14, 14);
                g2.setColor(C.BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 14, 14);
                if (subtitle != null) {
                    g2.setColor(new Color(0x2A3546));
                    g2.fillRect(18, 52, Math.max(24, getWidth() - 36), 1);
                }
                g2.dispose();
            }
        };
        p.setOpaque(false);
        p.setBorder(BorderFactory.createEmptyBorder(subtitle == null ? 12 : 16, 18,
                subtitle == null ? 12 : 18, 18));
        if (subtitle != null) {
            GridBagConstraints hc = new GridBagConstraints();
            hc.gridx = 0; hc.gridy = 0; hc.gridwidth = 2; hc.weightx = 1;
            hc.anchor = GridBagConstraints.WEST; hc.insets = new Insets(0, 0, 12, 0);
            JPanel head = new JPanel();
            head.setOpaque(false);
            head.setLayout(new BoxLayout(head, BoxLayout.Y_AXIS));
            JLabel t = new JLabel(title);
            t.setFont(UI_BOLD.deriveFont(14.5f));
            t.setForeground(C.TEXT);
            JLabel s = new JLabel(subtitle);
            s.setFont(UI.deriveFont(11f));
            s.setForeground(C.MUTED);
            head.add(t);
            head.add(Box.createVerticalStrut(3));
            head.add(s);
            p.add(head, hc);
        }
        return p;
    }

    /** 扁平按钮（主按钮带青色渐变）。 */
    private static final class FlatButton extends JButton {
        private final boolean primary;
        private boolean hover;

        FlatButton(String text, boolean primary) {
            super(text);
            this.primary = primary;
            setOpaque(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setFont(primary ? UI_BOLD.deriveFont(13f) : UI.deriveFont(12.5f));
            setForeground(primary ? new Color(0x05201B) : C.TEXT);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(BorderFactory.createEmptyBorder(8, 16, 8, 16));
            addMouseListener(new MouseAdapter() {
                @Override public void mouseEntered(MouseEvent e) { hover = true; repaint(); }
                @Override public void mouseExited(MouseEvent e) { hover = false; repaint(); }
            });
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            if (primary) {
                g2.setPaint(new GradientPaint(0, 0, C.ACCENT, getWidth(), getHeight(),
                        hover ? new Color(0x6FEFD6) : new Color(0x2FC9AE)));
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
            } else {
                g2.setColor(hover ? new Color(0x1B2735) : C.SURFACE_ALT);
                g2.fillRoundRect(0, 0, getWidth(), getHeight(), 10, 10);
                g2.setColor(hover ? new Color(0x33445A) : C.BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, 10, 10);
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    private static void styleField(JTextField f) {
        f.setBackground(new Color(0x0D141D));
        f.setForeground(C.TEXT);
        f.setCaretColor(C.ACCENT);
        f.setFont(UI.deriveFont(12.5f));
        f.setSelectionColor(new Color(0x1E5B52));
        f.setSelectedTextColor(C.TEXT);
        f.setBorder(BorderFactory.createCompoundBorder(
                new RoundBorder(C.BORDER, 8), BorderFactory.createEmptyBorder(6, 10, 6, 10)));
    }

    private static void styleCombo(JComboBox<String> cb) {
        cb.setBackground(new Color(0x0D141D));
        cb.setForeground(C.TEXT);
        cb.setFont(UI.deriveFont(12f));
        cb.setBorder(new RoundBorder(C.BORDER, 8));
        cb.setPreferredSize(new Dimension(96, 28));
    }

    private static GridBagConstraints gbc() {
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(6, 4, 6, 8);
        c.anchor = GridBagConstraints.WEST;
        return c;
    }

    private static void addRow(JPanel p, GridBagConstraints c, int y, String label,
                               JTextField field, String btnText,
                               java.awt.event.ActionListener act) {
        c.gridx = 0; c.gridy = y + 1; c.weightx = 0; c.fill = GridBagConstraints.NONE;
        JLabel l = new JLabel(label);
        l.setFont(UI.deriveFont(12f));
        l.setForeground(new Color(0xB7C4D4));
        p.add(l, c);
        c.gridx = 1; c.weightx = 1; c.fill = GridBagConstraints.HORIZONTAL;
        styleField(field);
        p.add(field, c);
        if (btnText != null) {
            c.gridx = 2; c.weightx = 0; c.fill = GridBagConstraints.NONE;
            FlatButton b = new FlatButton(btnText, false);
            b.addActionListener(act);
            p.add(b, c);
        }
    }

    /** 终端式日志：按级别着色，批量刷新到 EDT。 */
    private static final class ConsoleStream extends OutputStream {
        private final JTextPane pane;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        ConsoleStream(JTextPane pane) {
            this.pane = pane;
        }

        @Override public synchronized void write(int b) {
            if (b == '\n') {
                flushLine();
            } else {
                buf.write(b);
            }
        }

        private void flushLine() {
            final String line = new String(buf.toByteArray(), StandardCharsets.UTF_8);
            buf.reset();
            SwingUtilities.invokeLater(() -> {
                StyledDocument doc = pane.getStyledDocument();
                SimpleAttributeSet a = new SimpleAttributeSet();
                StyleConstants.setFontFamily(a, MONO.getFamily());
                StyleConstants.setFontSize(a, 12);
                Color color = new Color(0xB6C6D8);
                if (line.contains("[ERROR]")) color = C.DANGER;
                else if (line.contains("[WARN ]") || line.contains("[WARN]")) color = C.WARN;
                else if (line.contains("[OK]") || line.contains("Done in")) color = C.OK;
                else if (line.contains(">>>")) color = C.ACCENT;
                StyleConstants.setForeground(a, color);
                try {
                    doc.insertString(doc.getLength(), line + "\n", a);
                } catch (BadLocationException ignored) {
                    // ignore
                }
                pane.setCaretPosition(doc.getLength());
            });
        }
    }
}
