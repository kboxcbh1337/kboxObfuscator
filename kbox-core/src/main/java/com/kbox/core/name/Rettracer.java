package com.kbox.core.name;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ProGuard 兼容 Retrace（条目 29）：读 {@code MappingWriter} 产物，
 * 把混淆后的堆栈跟踪还原回原始类名/方法名。
 *
 * <p>用法：{@code --retrace mapping.txt [stacktrace.txt]}（无输入文件时读 stdin）。
 * 支持 {@code at a.b.c.d(e.java:12)} 与 {@code Caused by: a.b.c.X: msg} 两种行。</p>
 */
public final class Rettracer {

    private static final Pattern AT_LINE =
            Pattern.compile("(.*?at\\s+)([\\w.$]+)\\.([\\w$<>]+)\\((.*)\\)(\\s*)");
    private static final Pattern CAUSED_LINE =
            Pattern.compile("(.*?(?:Caused by|Exception in thread[^:]*):\\s*)([\\w.$]+)(:.*)?");

    /** 类映射：混淆名（点号） -> 原名（点号）。 */
    private final Map<String, String> classes = new HashMap<>();
    /** 成员映射：混淆类名 -> (新方法名 -> 原 "name(params)")。 */
    private final Map<String, Map<String, String>> members = new HashMap<>();

    public static void run(Path mappingPath, Path stackPath) throws IOException {
        Rettracer r = new Rettracer();
        r.load(mappingPath);
        StringBuilder sb = new StringBuilder();
        if (stackPath != null) {
            for (String line : Files.readAllLines(stackPath, StandardCharsets.UTF_8)) {
                sb.append(r.retraceLine(line)).append('\n');
            }
        } else {
            try (BufferedReader br = new BufferedReader(
                    new java.io.InputStreamReader(System.in, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(r.retraceLine(line)).append('\n');
                }
            }
        }
        System.out.print(sb);
    }

    public void load(Path mappingPath) throws IOException {
        String current = null;
        for (String line : Files.readAllLines(mappingPath, StandardCharsets.UTF_8)) {
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith(" ") || line.startsWith("\t")) {
                if (current == null) continue;
                String t = line.trim();
                int arrow = t.lastIndexOf(" -> ");
                if (arrow < 0) continue;
                String origDecl = t.substring(0, arrow).trim();
                String newName = t.substring(arrow + 4).trim();
                members.computeIfAbsent(current, k -> new HashMap<>()).put(newName, origDecl);
                continue;
            }
            int arrow = line.indexOf(" -> ");
            if (arrow < 0) continue;
            String orig = line.substring(0, arrow).trim();
            String obf = line.substring(arrow + 4).trim();
            if (obf.endsWith(":")) obf = obf.substring(0, obf.length() - 1).trim();
            classes.put(obf, orig);
            current = obf;
        }
    }

    public String retraceLine(String line) {
        Matcher m = AT_LINE.matcher(line);
        if (m.matches()) {
            String cls = m.group(2);
            String orig = classes.get(cls);
            if (orig == null) return line;
            String method = m.group(3);
            Map<String, String> mm = members.get(cls);
            String origMethod = method;
            if (mm != null) {
                String v = mm.get(method);
                if (v != null) {
                    int sp = v.indexOf(' ');
                    String decl = sp >= 0 ? v.substring(sp + 1) : v;
                    int paren = decl.indexOf('(');
                    origMethod = paren > 0 ? decl.substring(0, paren) : decl;
                }
            }
            return m.group(1) + orig + "." + origMethod + "(" + m.group(4) + ")" + m.group(5);
        }
        m = CAUSED_LINE.matcher(line);
        if (m.matches()) {
            String orig = classes.get(m.group(2));
            if (orig == null) return line;
            return m.group(1) + orig + (m.group(3) == null ? "" : m.group(3));
        }
        return line;
    }
}
