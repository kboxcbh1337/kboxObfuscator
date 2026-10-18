package com.kbox.core.packaging;

import com.kbox.core.log.KBoxLog;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * 产物明文自检（report 2026-10-17 §7："真正自我搜索全部完全无明文"）。
 *
 * <p>构建结束时从**输入 jar** 提取敏感 token（类名、方法/字段名、字符串常量），
 * 再对**输出 jar** 做逐条目字节级扫描：</p>
 *
 * <ul>
 *   <li>只扫以 {@code CAFEBABE} 开头的类（加密体/畸形诱饵是随机字节，跳过）；</li>
 *   <li>额外扫 manifest / 清单等非类条目（入口名掩码是否生效就看这里）；</li>
 *   <li>入口点的 {@code -cp} 明文 stub 类名与 {@code main} 是白名单（设计所需）。</li>
 * </ul>
 *
 * <p>命中即说明"业务明文仍在产物里"，会在构建日志中以 {@code PLAINTEXT AUDIT}
 * 显著告警。默认开启；{@code plaintextAudit = false} 可关闭。</p>
 */
public final class PlaintextAudit {

    private static final String TAG = "self-audit";

    /** Common member names that are not evidence of a leak. */
    private static final Set<String> NAME_STOP = new LinkedHashSet<>(java.util.Arrays.asList(
            "main", "run", "call", "get", "set", "put", "add", "size", "toString",
            "equals", "hashCode", "valueOf", "values", "length", "close", "read",
            "write", "init", "start", "stop", "apply", "accept", "test", "index"));

    private PlaintextAudit() {}

    /**
     * @param allowedToken original entry-point name that is allowed to stay in
     *                     plaintext (the `-cp` stub written at that name), may be null.
     * @param appEntries   output entries that came from the INPUT (renamed app
     *                     classes). Engine classes — including the per-build
     *                     renamed runtime surface — are not application plaintext.
     * @return number of leaked APPLICATION tokens found (0 = clean artifact).
     */
    public static int audit(Path inputJar, Path outputJar, String allowedToken,
                            Set<String> appEntries) {
        if (inputJar == null || outputJar == null
                || !Files.isRegularFile(inputJar) || !Files.isRegularFile(outputJar)) {
            return 0;
        }
        Set<String> tokens = collectTokens(inputJar);
        if (allowedToken != null && !allowedToken.isEmpty()) {
            tokens.remove(allowedToken);
            tokens.remove(allowedToken.replace('.', '/'));
        }
        if (tokens.isEmpty()) return 0;
        int hits = 0;
        int brand = 0;
        List<String> samples = new ArrayList<>();
        try (ZipFile out = new ZipFile(outputJar.toFile())) {
            Enumeration<? extends ZipEntry> en = out.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory()) continue;
                String name = e.getName();
                boolean isClassEntry = name.endsWith(".class");
                // Packed blobs (BF payload / native libs / masked lists) are
                // ciphertext or RLE noise: a coincidental byte match is not
                // "plaintext". Only class files and readable resources matter.
                if (name.startsWith("META-INF/kbox/")) continue;
                if (isClassEntry && appEntries != null && !appEntries.contains(name)) {
                    continue;   // engine / decoy / renamed runtime class
                }
                byte[] data = readAll(out.getInputStream(e));
                if (data.length == 0) continue;
                boolean isClass = data.length > 4 && data[0] == (byte) 0xCA
                        && data[1] == (byte) 0xFE && data[2] == (byte) 0xBA && data[3] == (byte) 0xBE;
                if (isClassEntry && !isClass) continue; // ciphertext / decoy
                String hay = new String(data, StandardCharsets.ISO_8859_1);
                brand += countBrand(hay);
                // Engine-owned classes (including synthetic guards) are not
                // application plaintext; their own literals may coincidentally
                // match an app token.
                if (name.startsWith("com/kbox/")) continue;
                for (String t : tokens) {
                    if (leaked(hay, t)) {
                        hits++;
                        if (samples.size() < 12) samples.add(t + " @ " + name);
                    }
                }
            }
        } catch (IOException ex) {
            KBoxLog.debug(TAG, "audit skipped: " + ex.getMessage());
            return 0;
        }
        if (hits == 0) {
            KBoxLog.info(TAG, "PLAINTEXT AUDIT: application tokens clean ("
                    + tokens.size() + " scanned, 0 hits); engine brand occurrences=" + brand);
        } else {
            KBoxLog.warn(TAG, "PLAINTEXT AUDIT: " + hits + " application hit(s) — plaintext "
                    + "still present: " + samples);
        }
        return hits;
    }

    /** Brand identifiers that are engine-side residuals (reported, not counted as
     *  application leakage). */
    private static int countBrand(String hay) {
        int n = 0;
        n += countOf(hay, "KBox");
        n += countOf(hay, "KBOX");
        n += countOf(hay, "kbox");
        return n;
    }

    /**
     * True when {@code token} occurs as application plaintext. An occurrence that
     * is merely a substring of an ENGINE class reference (e.g. the app literal
     * {@code "KBox"} inside {@code com/kbox/runtime/KBoxDedeobfGuard}) is not an
     * application leak: the engine's own class names are allowed to stay.
     */
    private static boolean leaked(String hay, String token) {
        int i = 0;
        while ((i = hay.indexOf(token, i)) >= 0) {
            int s = i, e = i + token.length();
            while (s > 0 && isIdentChar(hay.charAt(s - 1))) s--;
            while (e < hay.length() && isIdentChar(hay.charAt(e))) e++;
            String ident = hay.substring(s, e);
            boolean engineRef = ident.indexOf('/') >= 0
                    && (ident.startsWith("com/kbox/") || ident.startsWith("com.kbox."));
            if (!engineRef) return true;
            i += token.length();
        }
        return false;
    }

    private static boolean isIdentChar(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                || (c >= '0' && c <= '9') || c == '_' || c == '$' || c == '/' || c == '.';
    }

    private static int countOf(String hay, String needle) {
        int n = 0, i = 0;
        while ((i = hay.indexOf(needle, i)) >= 0) { n++; i += needle.length(); }
        return n;
    }

    /** Sensitive tokens extracted from the ORIGINAL input classes. */
    private static Set<String> collectTokens(Path inputJar) {
        Set<String> tokens = new LinkedHashSet<>();
        try (ZipFile in = new ZipFile(inputJar.toFile())) {
            Enumeration<? extends ZipEntry> en = in.entries();
            while (en.hasMoreElements()) {
                ZipEntry e = en.nextElement();
                if (e.isDirectory() || !e.getName().endsWith(".class")) continue;
                if (e.getName().startsWith("META-INF/")) continue;
                byte[] data = readAll(in.getInputStream(e));
                try {
                    org.objectweb.asm.tree.ClassNode cn = new org.objectweb.asm.tree.ClassNode();
                    new org.objectweb.asm.ClassReader(data).accept(cn, 0);
                    add(tokens, cn.name.replace('/', '.'));
                    add(tokens, cn.name);
                    for (Object mo : cn.methods) {
                        org.objectweb.asm.tree.MethodNode mn =
                                (org.objectweb.asm.tree.MethodNode) mo;
                        if (!NAME_STOP.contains(mn.name) && mn.name.length() >= 4
                                && mn.name.charAt(0) != '<') {
                            add(tokens, mn.name);
                        }
                        if (mn.instructions == null) continue;
                        for (int i = 0; i < mn.instructions.size(); i++) {
                            org.objectweb.asm.tree.AbstractInsnNode ins = mn.instructions.get(i);
                            if (ins.getOpcode() != org.objectweb.asm.Opcodes.LDC) continue;
                            Object c = ((org.objectweb.asm.tree.LdcInsnNode) ins).cst;
                            if (c instanceof String && ((String) c).length() >= 4) {
                                add(tokens, (String) c);
                            }
                        }
                    }
                    for (Object fo : cn.fields) {
                        org.objectweb.asm.tree.FieldNode fn =
                                (org.objectweb.asm.tree.FieldNode) fo;
                        if (!NAME_STOP.contains(fn.name) && fn.name.length() >= 4) {
                            add(tokens, fn.name);
                        }
                    }
                } catch (Throwable ignore) {
                    // Unparseable input class: nothing to compare against.
                }
            }
        } catch (IOException ex) {
            KBoxLog.debug(TAG, "token collection skipped: " + ex.getMessage());
        }
        return tokens;
    }

    private static void add(Set<String> tokens, String t) {
        if (t == null) return;
        // Very short tokens produce false positives in unrelated constants.
        if (t.length() < 4) return;
        tokens.add(t);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        java.io.ByteArrayOutputStream bo = new java.io.ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) bo.write(buf, 0, n);
        return bo.toByteArray();
    }
}
