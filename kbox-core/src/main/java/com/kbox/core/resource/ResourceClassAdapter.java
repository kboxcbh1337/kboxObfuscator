package com.kbox.core.resource;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.name.Mapping;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeMap;

/**
 * ProGuard 资源适配（条目 24）：
 * <ul>
 *   <li>{@code adaptResourceFileNames} —— 类名形状的资源路径跟随类重命名
 *       （如 {@code com/example/Foo.json} → {@code a/b/C.json}，扩展名保留）。</li>
 *   <li>{@code adaptResourceFileContents} —— 文本资源内容中以点号/斜杠形式
 *       出现的、且恰好是被重命名类的类名常量跟随重命名（带边界校验，
 *       只替换完整 token，避免误伤子串）。</li>
 * </ul>
 *
 * <p>META-INF/services、spring.factories 等框架文件的定向改写仍由
 * {@code ResourceReferenceUpdater} 负责（打包期执行）；本 pass 是通用通道，
 * 在重命名阶段后立即运行。</p>
 */
public final class ResourceClassAdapter {

    private static final String TAG = "res-adapt";

    private final ClassGraph graph;
    private final com.kbox.core.config.ProtectionConfig cfg;
    private final Mapping mapping;

    public ResourceClassAdapter(ClassGraph graph, com.kbox.core.config.ProtectionConfig cfg,
                                Mapping mapping) {
        this.graph = graph;
        this.cfg = cfg;
        this.mapping = mapping;
    }

    public void apply() {
        if (!cfg.isAdaptResourceFileNames() && !cfg.isAdaptResourceFileContents()) return;
        Map<String, String> cm = mapping.getClassMap();
        if (cm.isEmpty()) return;

        int renamedFiles = 0;
        int touchedFiles = 0;
        Map<String, byte[]> res = graph.getResources();
        Map<String, byte[]> out = new LinkedHashMap<>();

        // 文件名适配：按内部名（最长优先）匹配路径前缀。
        Map<String, String> byLenDesc = new TreeMap<>((a, b) -> {
            int c = Integer.compare(b.length(), a.length());
            return c != 0 ? c : a.compareTo(b);
        });
        byLenDesc.putAll(cm);

        for (Map.Entry<String, byte[]> e : res.entrySet()) {
            String path = e.getKey();
            byte[] data = e.getValue();
            if (cfg.isAdaptResourceFileNames()) {
                String newPath = adaptPath(path, byLenDesc);
                if (!newPath.equals(path)) {
                    path = newPath;
                    renamedFiles++;
                }
            }
            if (cfg.isAdaptResourceFileContents() && isText(path) && data != null) {
                String text = new String(data, StandardCharsets.UTF_8);
                String adapted = adaptContents(text, cm);
                if (!adapted.equals(text)) {
                    data = adapted.getBytes(StandardCharsets.UTF_8);
                    touchedFiles++;
                }
            }
            out.put(path, data);
        }
        res.clear();
        res.putAll(out);
        KBoxLog.info(TAG, "adaptResourceFileNames=" + cfg.isAdaptResourceFileNames()
                + " adaptResourceFileContents=" + cfg.isAdaptResourceFileContents()
                + " renamed_paths=" + renamedFiles + " rewritten_contents=" + touchedFiles);
    }

    private String adaptPath(String path, Map<String, String> cm) {
        if (path.startsWith("META-INF/")) return path;
        int dot = path.lastIndexOf('.');
        String base = dot > 0 ? path.substring(0, dot) : path;
        String ext = dot > 0 ? path.substring(dot) : "";
        String mapped = cm.get(base);
        if (mapped != null) return mapped + ext;
        // 点号形式类资源（com/example/Foo.properties）
        String dotted = base.replace('/', '.');
        String md = cm.get(dotted);
        if (md != null) return md.replace('/', '.') + ext;
        return path;
    }

    private String adaptContents(String text, Map<String, String> cm) {
        String result = text;
        for (Map.Entry<String, String> e : cm.entrySet()) {
            String oldDotted = e.getKey().replace('/', '.');
            String newDotted = e.getValue().replace('/', '.');
            result = replaceToken(result, oldDotted, newDotted);
            result = replaceToken(result, e.getKey(), e.getValue());
        }
        return result;
    }

    /** 整词替换：前后都不能是 Java 标识符字符（避免 com.example.Foo 误伤 com.example.Foo2）。 */
    private static String replaceToken(String text, String from, String to) {
        if (from == null || from.isEmpty() || from.equals(to)) return text;
        StringBuilder sb = new StringBuilder(text.length() + 64);
        int i = 0;
        while (i < text.length()) {
            int hit = text.indexOf(from, i);
            if (hit < 0) {
                sb.append(text, i, text.length());
                break;
            }
            boolean okBefore = hit == 0 || !isIdentChar(text.charAt(hit - 1));
            int end = hit + from.length();
            boolean okAfter = end >= text.length() || !isIdentChar(text.charAt(end));
            if (okBefore && okAfter) {
                sb.append(text, i, hit).append(to);
                i = end;
            } else {
                sb.append(text, i, end);
                i = end;
            }
        }
        return sb.toString();
    }

    private static boolean isIdentChar(char c) {
        return Character.isJavaIdentifierPart(c);
    }

    private static boolean isText(String path) {
        String p = path.toLowerCase(java.util.Locale.ROOT);
        return p.endsWith(".txt") || p.endsWith(".json") || p.endsWith(".xml")
                || p.endsWith(".properties") || p.endsWith(".yml") || p.endsWith(".yaml")
                || p.endsWith(".csv") || p.endsWith(".conf") || p.endsWith(".cfg")
                || p.endsWith(".factories") || p.endsWith(".imports");
    }
}
