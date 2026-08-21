package com.kbox.gui;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * ZKM-style Swing UI for KBox. Single window with tabbed interface:
 * <ul>
 *   <li><b>Targets tab</b>: Input / Output / Config file pickers + toolchain</li>
 *   <li><b>Obfuscation tab</b>: Toggles for rename, strings, control-flow, VMP, JNIC, class encryption</li>
 *   <li><b>Anti-Analysis tab</b>: Anti-decompiler level, anti-debug, watermark, integrity, exception-jump, native anti-hook</li>
 *   <li><b>Log tab</b>: Live log area + progress bar</li>
 * </ul>
 *
 * <p>The GUI is launchable both standalone (via {@link #main}) and from the CLI
 * with the {@code --gui} flag (via {@link #launch}). It receives progress
 * updates via {@link KBoxLog.ProgressListener}.
 */
public final class ProtectorGui extends JFrame {

    // Target fields
    private final JTextField inField = new JTextField(30);
    private final JTextField outField = new JTextField(30);
    private final JTextField cfgField = new JTextField(30);
    private final JTextField ccField = new JTextField("C:\\msys64\\mingw64\\bin\\gcc.exe", 30);

    // Obfuscation toggles
    private final JCheckBox renameBox = new JCheckBox("Rename identifiers", true);
    private final JCheckBox stringBox = new JCheckBox("Encrypt strings", true);
    private final JCheckBox scatterBox = new JCheckBox("Scatter strings (inline decryption)", false);
    private final JCheckBox cfBox = new JCheckBox("Control-flow obfuscation", true);
    private final JCheckBox classEncBox = new JCheckBox("Class encryption (AES-256-GCM, anti-dump)", false);
    private final JCheckBox vmpBox = new JCheckBox("Enable VMP (per-method)", false);
    private final JCheckBox jnicBox = new JCheckBox("Enable JNIC (per-method)", false);
    private final JCheckBox resourceBox = new JCheckBox("Resource obfuscation (rename + encrypt)", true);
    private final JCheckBox kotlinBox = new JCheckBox("Kotlin @Metadata fixup", true);

    // Anti-analysis toggles
    private final JComboBox<String> antiDecLevel = new JComboBox<>(new String[]{
            "0 = disabled", "1 = light (goto-chain 5k)",
            "2 = medium (+ex-bomb +inner-cycle)", "3 = aggressive (+cp-bomb, 30k labels)"
    });
    private final JCheckBox antiDebugBox = new JCheckBox("Anti-debug (JDWP/JVMTI/timing/attach detection)", false);
    private final JCheckBox vmpSelfCheckBox = new JCheckBox("VMP interpreter self-check (bytecode hash)", false);
    private final JCheckBox integrityBox = new JCheckBox("Jar integrity check (SHA-256, anti-repackage)", false);
    private final JCheckBox exJumpBox = new JCheckBox("Exception-jump obfuscation (athrow + catch)", false);
    private final JCheckBox nativeAntiHookBox = new JCheckBox("Native anti-hook (entry integrity + env scrub)", false);
    private final JTextField watermarkField = new JTextField(20);

    // Strength controls
    private final JComboBox<String> cfStrength = new JComboBox<>(new String[]{"1 = light", "2 = medium", "3 = aggressive"});
    private final JComboBox<String> strStrength = new JComboBox<>(new String[]{"1 = XOR", "2 = AES"});

    // File selection controls
    private final JComboBox<String> scopeCombo = new JComboBox<>(new String[]{
            "ALL = obfuscate everything",
            "SELECTIVE = only obfuscate listed files",
            "EXCLUDE = obfuscate all except listed files"
    });
    private final JComboBox<String> mcPresetCombo = new JComboBox<>(new String[]{
            "None", "NEOFORGE", "FORGE", "FABRIC", "BUKKIT", "MIXIN"
    });
    private final JTextArea includeArea = new JTextArea(5, 30);
    private final JTextArea excludeArea = new JTextArea(5, 30);

    // Log + progress
    private final JTextArea log = new JTextArea();
    private final JProgressBar progressBar = new JProgressBar(0, 100);
    private final JLabel stageLabel = new JLabel("Ready");
    private final JButton runBtn = new JButton("Protect");
    private final JButton cancelBtn = new JButton("Quit");

    private ProtectorGui() {
        super("KBox Obfuscator — ZKM-level + JNIC + VMP Protection");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout(8, 8));

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Targets", buildTargetsTab());
        tabs.addTab("Obfuscation", buildObfTab());
        tabs.addTab("File Selection", buildFileSelectionTab());
        tabs.addTab("Anti-Analysis", buildAntiTab());
        add(tabs, BorderLayout.NORTH);
        add(buildLogPanel(), BorderLayout.CENTER);
        add(buildButtons(), BorderLayout.SOUTH);

        pack();
        setLocationRelativeTo(null);
        setSize(new Dimension(900, 680));
        cfStrength.setSelectedIndex(1);
        strStrength.setSelectedIndex(0);
        antiDecLevel.setSelectedIndex(0);

        // Install progress listener.
        KBoxLog.setListener(new KBoxLog.ProgressListener() {
            @Override public void onStage(int stage, int total, String name) {
                SwingUtilities.invokeLater(() -> {
                    stageLabel.setText("Stage " + stage + "/" + total + ": " + name);
                    progressBar.setValue(0);
                    progressBar.setString("0%");
                });
            }
            @Override public void onProgress(int percent, String detail) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(percent);
                    progressBar.setString(percent + "%");
                });
            }
            @Override public void onComplete(String summary) {
                SwingUtilities.invokeLater(() -> {
                    progressBar.setValue(100);
                    progressBar.setString("Done");
                    stageLabel.setText(summary);
                });
            }
        });
    }

    private JPanel buildTargetsTab() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("Protection targets"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 0;
        addRow(p, c, "Input jar", inField, "Browse…", () -> pick(inField, true));
        addRow(p, c, "Output jar", outField, "Browse…", () -> pick(outField, false));
        addRow(p, c, "Config (optional)", cfgField, "Browse…", () -> pick(cfgField, false));
        c.gridx = 0; c.gridy++; p.add(new JLabel("C compiler:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(ccField, c);
        c.gridwidth = 1;
        return p;
    }

    private JPanel buildObfTab() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("Obfuscation options"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 0; c.gridwidth = 3;
        p.add(renameBox, c);
        c.gridy++; p.add(stringBox, c);
        c.gridy++; p.add(scatterBox, c);
        c.gridy++; p.add(cfBox, c);
        c.gridy++; p.add(classEncBox, c);
        c.gridy++; p.add(vmpBox, c);
        c.gridy++; p.add(jnicBox, c);
        c.gridy++; p.add(resourceBox, c);
        c.gridy++; p.add(kotlinBox, c);
        c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("CF strength:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(cfStrength, c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("String enc:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(strStrength, c);
        return p;
    }

    private JPanel buildAntiTab() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("Anti-analysis options"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.gridy = 0; c.gridwidth = 3;
        p.add(antiDebugBox, c);
        c.gridy++; p.add(vmpSelfCheckBox, c);
        c.gridy++; p.add(integrityBox, c);
        c.gridy++; p.add(exJumpBox, c);
        c.gridy++; p.add(nativeAntiHookBox, c);
        c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("Anti-decompiler:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(antiDecLevel, c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("Watermark:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(watermarkField, c);
        return p;
    }

    private JPanel buildFileSelectionTab() {
        JPanel p = new JPanel(new GridBagLayout());
        p.setBorder(BorderFactory.createTitledBorder("Fine-grained file selection"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(3, 3, 3, 3);
        c.fill = GridBagConstraints.HORIZONTAL;

        c.gridx = 0; c.gridy = 0; p.add(new JLabel("Scope:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(scopeCombo, c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("MC preset:"), c);
        c.gridx = 1; c.gridwidth = 2; p.add(mcPresetCombo, c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("Include patterns:"), c);
        c.gridx = 1; c.gridwidth = 2;
        includeArea.setText("# One pattern per line, e.g.:\n# com/myapp/**\n# com/foo/Bar");
        p.add(new JScrollPane(includeArea), c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; p.add(new JLabel("Exclude patterns:"), c);
        c.gridx = 1; c.gridwidth = 2;
        excludeArea.setText("# One pattern per line, e.g.:\n# com/myapp/api/*\n# com/myapp/config/**");
        p.add(new JScrollPane(excludeArea), c); c.gridwidth = 1;

        c.gridx = 0; c.gridy++; c.gridwidth = 3;
        p.add(new JLabel("<html><i>Glob syntax: ** = any path segments, * = within a package. "
                + "MC preset applies keep rules for the selected mod loader.</i></html>"), c);
        return p;
    }

    private void addRow(JPanel p, GridBagConstraints c, String label, JTextField field,
                        String btnText, Runnable onClick) {
        c.gridx = 0; p.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1.0; p.add(field, c); c.weightx = 0.0;
        JButton b = new JButton(btnText);
        b.addActionListener(e -> onClick.run());
        c.gridx = 2; p.add(b, c);
        c.gridy++;
    }

    private void pick(JTextField target, boolean open) {
        JFileChooser fc = new JFileChooser();
        if (target.getText() != null && !target.getText().isEmpty())
            fc.setSelectedFile(Paths.get(target.getText()).toFile());
        int r = open ? fc.showOpenDialog(this) : fc.showSaveDialog(this);
        if (r == JFileChooser.APPROVE_OPTION) target.setText(fc.getSelectedFile().getAbsolutePath());
    }

    private JPanel buildLogPanel() {
        JPanel p = new JPanel(new BorderLayout(4, 4));
        p.setBorder(BorderFactory.createTitledBorder("Log"));

        // Progress bar at top.
        JPanel progPanel = new JPanel(new BorderLayout(4, 4));
        progPanel.add(stageLabel, BorderLayout.NORTH);
        progressBar.setStringPainted(true);
        progressBar.setString("0%");
        progPanel.add(progressBar, BorderLayout.SOUTH);
        p.add(progPanel, BorderLayout.NORTH);

        // Log area in center.
        log.setEditable(false);
        log.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 12));
        JScrollPane scroll = new JScrollPane(log);
        scroll.setPreferredSize(new Dimension(850, 250));
        p.add(scroll, BorderLayout.CENTER);

        // Mirror KBoxLog into the log area.
        KBoxLog.setOut(new java.io.PrintStream(new java.io.OutputStream() {
            private final StringBuilder buf = new StringBuilder();
            @Override public void write(int b) {
                buf.append((char) b);
                if (b == '\n') { flush(); }
            }
            @Override public void flush() {
                final String line = buf.toString();
                buf.setLength(0);
                SwingUtilities.invokeLater(() -> {
                    log.append(line);
                    // Auto-scroll to bottom.
                    log.setCaretPosition(log.getDocument().getLength());
                });
            }
        }));
        return p;
    }

    private JPanel buildButtons() {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        runBtn.addActionListener(e -> doRun());
        cancelBtn.addActionListener(e -> dispose());
        p.add(runBtn);
        p.add(cancelBtn);
        return p;
    }

    private void doRun() {
        String in = inField.getText().trim();
        String out = outField.getText().trim();
        if (in.isEmpty() || out.isEmpty()) {
            JOptionPane.showMessageDialog(this, "Input and Output are required");
            return;
        }
        runBtn.setEnabled(false);
        progressBar.setValue(0);
        progressBar.setString("0%");
        log.setText("");

        new Thread(() -> {
            try {
                ProtectionConfig cfg = ConfigLoader.load(cfgField.getText().trim().isEmpty()
                        ? null : Paths.get(cfgField.getText().trim()));
                // Apply GUI toggles.
                cfg.setRenameIdentifiers(renameBox.isSelected());
                cfg.setEncryptStrings(stringBox.isSelected());
                cfg.setScatterStrings(scatterBox.isSelected());
                cfg.setObfuscateControlFlow(cfBox.isSelected());
                cfg.setEncryptClasses(classEncBox.isSelected());
                cfg.setEnableVmp(vmpBox.isSelected());
                cfg.setEnableJnic(jnicBox.isSelected());
                cfg.setObfuscateResources(resourceBox.isSelected());
                cfg.setFixKotlinMetadata(kotlinBox.isSelected());
                cfg.setControlFlowStrength(cfStrength.getSelectedIndex() + 1);
                cfg.setStringEncryptionStrength(strStrength.getSelectedIndex() + 1);

                // Anti-analysis.
                cfg.setAntiDecompilerLevel(antiDecLevel.getSelectedIndex());
                cfg.setAntiDebug(antiDebugBox.isSelected());
                cfg.setVmpSelfCheck(vmpSelfCheckBox.isSelected());
                cfg.setIntegrityCheck(integrityBox.isSelected());
                cfg.setExceptionJumpObf(exJumpBox.isSelected());
                cfg.setNativeAntiHook(nativeAntiHookBox.isSelected());
                String wm = watermarkField.getText().trim();
                if (!wm.isEmpty()) cfg.setWatermark(wm);

                String cc = ccField.getText().trim();
                if (!cc.isEmpty()) cfg.setCc(cc);

                // File selection scope.
                cfg.setObfuscationScope(ProtectionConfig.ObfuscationScope.values()[scopeCombo.getSelectedIndex()]);
                for (String line : includeArea.getText().split("\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) cfg.getIncludePatterns().add(line);
                }
                for (String line : excludeArea.getText().split("\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) cfg.getExcludePatterns().add(line);
                }

                // Minecraft mod preset.
                String preset = (String) mcPresetCombo.getSelectedItem();
                if (preset != null && !preset.equals("None")) {
                    try {
                        com.kbox.core.minecraft.MinecraftModPresets.applyPreset(cfg,
                                com.kbox.core.minecraft.MinecraftModPresets.ModLoader.valueOf(preset));
                    } catch (Exception ex) {
                        KBoxLog.warn("gui", "Failed to apply MC preset: " + ex.getMessage());
                    }
                }

                // Enable verbose (DEBUG) logging so the GUI shows everything.
                KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);

                Path workDir = Paths.get(out).getParent() == null
                        ? Paths.get(".")
                        : Paths.get(out).getParent().resolve("kbox-work");
                new ProtectionPipeline(Paths.get(in), Paths.get(out), cfg, workDir).run();
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this, "Protection complete:\n" + out));
            } catch (Exception ex) {
                StringWriter sw = new StringWriter();
                ex.printStackTrace(new PrintWriter(sw));
                KBoxLog.error("gui", "Protection failed", ex);
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(this, "Failed:\n" + sw));
            } finally {
                SwingUtilities.invokeLater(() -> runBtn.setEnabled(true));
            }
        }, "kbox-protector").start();
    }

    /** Entry point used by {@code --gui} from the CLI. */
    public static void launch(String in, String out, String cfg, boolean verbose) {
        if (verbose) KBoxLog.setLevel(KBoxLog.LEVEL_DEBUG);
        SwingUtilities.invokeLater(() -> {
            ProtectorGui g = new ProtectorGui();
            if (in != null) g.inField.setText(in);
            if (out != null) g.outField.setText(out);
            if (cfg != null) g.cfgField.setText(cfg);
            g.setVisible(true);
        });
    }

    public static void main(String[] args) {
        try { UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); }
        catch (Exception ignored) {}
        launch(null, null, null, false);
    }
}
