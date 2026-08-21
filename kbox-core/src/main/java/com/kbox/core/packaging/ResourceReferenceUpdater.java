package com.kbox.core.packaging;

import com.kbox.core.KBoxException;
import com.kbox.core.log.KBoxLog;
import org.objectweb.asm.Type;

import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * Updates class-name references inside text resources so renamed classes keep
 * being found by framework code:
 * <ul>
 *   <li>{@code META-INF/services/<service-class>}: the file <em>name</em> is a
 *       fully-qualified class name; we rename it.</li>
 *   <li>{@code META-INF/spring.factories} / {@code spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports}:
 *       each line / FQCN entry is rewritten.</li>
 *   <li>Any other resource whose content is comma/newline-separated FQCNs is
 *       best-effort rewritten (cheap, idempotent).</li>
 * </ul>
 *
 * References to classes that were <em>not</em> renamed are left untouched.
 */
public final class ResourceReferenceUpdater {

    private static final String TAG = "resource";
    private final Map<String, String> classMap; // old dotted -> new dotted

    public ResourceReferenceUpdater(Map<String, String> classMap) {
        this.classMap = classMap;
    }

    public String rewrite(String path, byte[] content) {
        // Rewrite the path itself (META-INF/services/<service-class>).
        String newPath = rewriteClassName(path);
        String text = new String(content, StandardCharsets.UTF_8);
        String newText;
        if (path.startsWith("META-INF/services/")) {
            // ServiceLoader file: each line is an implementing FQCN.
            newText = rewriteLines(text);
        } else if (path.endsWith("spring.factories")
                || path.endsWith("AutoConfiguration.imports")
                || path.endsWith("org.springframework.boot.autoconfigure.AutoConfiguration.imports")) {
            newText = rewriteFqcns(text);
        } else {
            newText = text;
        }
        if (!newPath.equals(path) || !newText.equals(text)) {
            KBoxLog.debug(TAG, "Updated " + path + (newPath.equals(path) ? "" : " -> " + newPath));
        }
        return newPath + "\u0000" + newText;
    }

    /** Rewrite each comma-separated FQCN token in a free-form text block. */
    private String rewriteFqcns(String text) {
        StringBuilder sb = new StringBuilder(text.length());
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            // Read a token consisting of Java identifier chars + dots.
            if (Character.isJavaIdentifierStart(c)) {
                int start = i;
                while (i < text.length() && (Character.isJavaIdentifierPart(text.charAt(i)) || text.charAt(i) == '.')) i++;
                String tok = text.substring(start, i);
                sb.append(map(tok));
            } else {
                sb.append(c); i++;
            }
        }
        return sb.toString();
    }

    private String rewriteLines(String text) {
        String[] lines = text.split("\n");
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            sb.append(map(lines[i].trim()));
            if (i < lines.length - 1) sb.append('\n');
        }
        return sb.toString();
    }

    private String rewriteClassName(String path) {
        if (path.startsWith("META-INF/services/")) {
            String cls = path.substring("META-INF/services/".length());
            return "META-INF/services/" + map(cls);
        }
        return path;
    }

    /** Maps a dotted FQCN to its renamed form; leaves non-matching strings alone. */
    private String map(String dotted) {
        if (dotted == null || dotted.isEmpty()) return dotted;
        String mapped = classMap.get(dotted);
        if (mapped != null) return mapped;
        return dotted;
    }
}
