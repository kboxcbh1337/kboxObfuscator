package com.kbox.core.name;

import com.kbox.core.config.ProtectionConfig;
import com.kbox.core.log.KBoxLog;
import com.kbox.core.resource.ResourceMapping;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

/**
 * Writes a ProGuard-compatible deobfuscation mapping file after all transforms.
 * The output format is compatible with ProGuard's {@code -printmapping} output,
 * which tools like Retrace, JADX, and most stack-trace deobfuscators can parse.
 *
 * <p>Format:
 * <pre>
 * com.example.OriginalClass -> com.example.a:
 *     int originalField -> b
 *     java.lang.String originalMethod(...) -> c
 * </pre>
 *
 * <p>When the mapping file is set via {@code mappingFile} config, the writer
 * is invoked at the end of the pipeline. Resources are written in a separate
 * block under a {@code # RESOURCE MAPPING:} header.
 */
public final class MappingWriter {

    private static final String TAG = "mapping";

    /**
     * Write the deobfuscation mapping to {@code cfg.getMappingFile()}.
     * The file is written in UTF-8 with ProGuard-compatible syntax.
     *
     * @param mapping    the rename mapping (must be called after
     *                   {@link NameObfuscator#compute()} and remapping)
     * @param cfg        the protection config holding the output path
     * @param resMapping optional resource name mapping (may be null)
     */
    public static void write(Mapping mapping, ProtectionConfig cfg,
                             ResourceMapping resMapping) {
        String path = cfg.getMappingFile();
        if (path == null || path.isEmpty()) return;
        try {
            Path outPath = Paths.get(path);
            Path parent = outPath.getParent();
            if (parent != null) Files.createDirectories(parent);
            StringBuilder sb = new StringBuilder(8192);
            sb.append("# KBox Obfuscator v1.0 — Deobfuscation Mapping\n");
            sb.append("# Generated ").append(new java.util.Date()).append("\n");
            if (cfg.getWatermark() != null) {
                sb.append("# Watermark: ").append(cfg.getWatermark()).append("\n");
            }
            sb.append("\n");

            // Write class mappings
            Map<String, String> classMap = mapping.getClassMap();
            for (Map.Entry<String, String> e : classMap.entrySet()) {
                String orig = e.getKey().replace('/', '.');
                String renamed = e.getValue().replace('/', '.');
                // Skip identity mappings (kept classes)
                if (orig.equals(renamed)) continue;
                sb.append(orig).append(" -> ").append(renamed).append(":\n");

                // Write method mappings for this class
                String prefix = e.getKey() + "#";
                for (Map.Entry<String, String> me : mapping.getMethodMap().entrySet()) {
                    if (!me.getKey().startsWith(prefix)) continue;
                    // key = "owner#name#desc"
                    String rest = me.getKey().substring(prefix.length());
                    int hash2 = rest.lastIndexOf('#');
                    if (hash2 < 0) continue;
                    String mname = rest.substring(0, hash2);
                    String mdesc = rest.substring(hash2 + 1);
                    String mapped = me.getValue();
                    if (mname.equals(mapped)) continue; // identity
                    sb.append("    ").append(descriptorToJava(mdesc))
                            .append(" ").append(mname)
                            .append(" -> ").append(mapped).append("\n");
                }

                // Write field mappings for this class
                for (Map.Entry<String, String> fe : mapping.getFieldMap().entrySet()) {
                    if (!fe.getKey().startsWith(prefix)) continue;
                    String rest = fe.getKey().substring(prefix.length());
                    int hash2 = rest.lastIndexOf('#');
                    if (hash2 < 0) continue;
                    String fname = rest.substring(0, hash2);
                    String fdesc = rest.substring(hash2 + 1);
                    String mapped = fe.getValue();
                    if (fname.equals(mapped)) continue; // identity
                    sb.append("    ").append(descriptorToJava(fdesc))
                            .append(" ").append(fname)
                            .append(" -> ").append(mapped).append("\n");
                }
            }

            // Write resource mappings
            if (resMapping != null) {
                Map<String, ResourceMapping.Entry> resMap = resMapping.entries();
                if (!resMap.isEmpty()) {
                    sb.append("\n# RESOURCE MAPPING:\n");
                    for (Map.Entry<String, ResourceMapping.Entry> e : resMap.entrySet()) {
                        sb.append("    ").append(e.getKey())
                                .append(" -> ").append(e.getValue().newPath)
                                .append(e.getValue().encrypted ? " [encrypted]" : "").append("\n");
                    }
                }
            }

            sb.append("\n# End of mapping\n");
            Files.write(outPath, sb.toString().getBytes(StandardCharsets.UTF_8));
            KBoxLog.info(TAG, "Deobfuscation mapping written to " + outPath.toAbsolutePath());
        } catch (IOException e) {
            KBoxLog.warn(TAG, "Failed to write deobfuscation mapping to " + path + ": " + e.getMessage());
        }
    }

    /**
     * Converts an ASM descriptor to a human-readable Java type string.
     * Handles primitives, arrays, and reference types.
     */
    private static String descriptorToJava(String desc) {
        if (desc == null || desc.isEmpty()) return "void";
        int arrayDepth = 0;
        while (desc.charAt(arrayDepth) == '[') arrayDepth++;
        String base;
        switch (desc.charAt(arrayDepth)) {
            case 'B': base = "byte"; break;
            case 'C': base = "char"; break;
            case 'D': base = "double"; break;
            case 'F': base = "float"; break;
            case 'I': base = "int"; break;
            case 'J': base = "long"; break;
            case 'S': base = "short"; break;
            case 'Z': base = "boolean"; break;
            case 'V': base = "void"; break;
            case 'L': base = desc.substring(arrayDepth + 1, desc.length() - 1).replace('/', '.'); break;
            default: base = "Object"; break;
        }
        StringBuilder sb = new StringBuilder(base);
        for (int i = 0; i < arrayDepth; i++) sb.append("[]");
        return sb.toString();
    }
}