package com.kbox.core.shield;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Rebuilds a DLL export directory for a packed PE.
 *
 * <p>Why this is required: the packer relocates the original sections to a new
 * RVA range and stores their content as encrypted payload. The input's
 * {@code .edata} therefore ends up pointing at ciphertext, so after packing the
 * loader sees an export directory full of garbage and {@code GetProcAddress}
 * cannot resolve anything (measured: {@code exportsAfter=[]}).
 *
 * <p>This class appends a new cleartext section containing a freshly built
 * {@code IMAGE_EXPORT_DIRECTORY}:
 * <ul>
 *   <li>every export name and ordinal is carried over from the input,</li>
 *   <li>each function RVA is translated through the input→output section map
 *       (the packer shifts sections by a constant, but the mapping is derived
 *       from the actual section names/addresses, not from a guessed constant),</li>
 *   <li>forwarded exports (RVA inside the export directory) are re-emitted as
 *       forwarder strings,</li>
 *   <li>the DataDirectory[0] entry and SizeOfImage are updated.</li>
 * </ul>
 *
 * <p>If anything cannot be translated (unknown section, malformed table) the
 * rebuild returns {@code null} and the caller refuses to ship the file.
 */
final class PeExports {

    private PeExports() {}

    /** Parsed input export metadata. */
    static final class Info {
        String dllName = "";
        int base;
        int exportRva;
        int exportSize;
        /** ordinal index (0-based) -> function RVA, or forwarder string RVA. */
        int[] funcRvas = new int[0];
        String[] names = new String[0];
        int[] nameOrdinals = new int[0];
        /** true when the EAT entry points inside the export directory (forwarder). */
        boolean[] forwarded = new boolean[0];

        boolean empty() { return names.length == 0; }
    }

    /** One PE section (name + virtual/raw placement). */
    static final class Sec {
        String name;
        int virtualSize;
        int virtualAddress;
        int rawSize;
        int rawPtr;
        int characteristics;
    }

    /** Minimal PE view used by the rebuild. */
    static final class Pe {
        boolean valid;
        boolean isDll;
        int machine;
        int peOff;
        int numSections;
        int optSize;
        int optOff;
        int sectionAlignment = 0x1000;
        int fileAlignment = 0x200;
        int sizeOfImage;
        int sizeOfHeaders;
        int magic;
        int ddOff;
        final List<Sec> sections = new ArrayList<>();

        static Pe parse(byte[] b) {
            Pe p = new Pe();
            if (b == null || b.length < 0x40 || b[0] != 'M' || b[1] != 'Z') return p;
            int pe = u4(b, 0x3C);
            if (pe <= 0 || pe + 24 > b.length) return p;
            if (b[pe] != 'P' || b[pe + 1] != 'E') return p;
            p.valid = true;
            p.peOff = pe;
            p.machine = u2(b, pe + 4);
            p.numSections = u2(b, pe + 6);
            p.optSize = u2(b, pe + 20);
            p.isDll = (u2(b, pe + 22) & 0x2000) != 0;
            p.optOff = pe + 24;
            p.magic = u2(b, p.optOff);
            boolean pe32plus = p.magic == 0x20B;
            p.sectionAlignment = u4(b, p.optOff + 32);
            p.fileAlignment = u4(b, p.optOff + 36);
            p.sizeOfImage = u4(b, p.optOff + 56);
            p.sizeOfHeaders = u4(b, p.optOff + 60);
            p.ddOff = p.optOff + (pe32plus ? 112 : 96);
            int st = p.optOff + p.optSize;
            for (int i = 0; i < p.numSections; i++) {
                int s = st + i * 40;
                if (s + 40 > b.length) break;
                Sec sec = new Sec();
                sec.name = readName(b, s);
                sec.virtualSize = u4(b, s + 8);
                sec.virtualAddress = u4(b, s + 12);
                sec.rawSize = u4(b, s + 16);
                sec.rawPtr = u4(b, s + 20);
                sec.characteristics = u4(b, s + 36);
                p.sections.add(sec);
            }
            return p;
        }

        int rvaToOff(int rva) {
            for (Sec s : sections) {
                int size = Math.max(s.rawSize, s.virtualSize);
                if (Integer.compareUnsigned(rva, s.virtualAddress) >= 0
                        && Integer.compareUnsigned(rva, s.virtualAddress + Math.max(size, 1)) < 0) {
                    return s.rawPtr + (rva - s.virtualAddress);
                }
            }
            return -1;
        }
    }

    // ------------------------------------------------------------------
    //  Reading the input export table
    // ------------------------------------------------------------------

    static Info read(byte[] b, Pe pe) {
        Info in = new Info();
        if (!pe.valid) return in;
        int expRva = u4(b, pe.ddOff);
        int expSize = u4(b, pe.ddOff + 4);
        in.exportRva = expRva;
        in.exportSize = expSize;
        if (expRva == 0 || expSize == 0) return in;
        int eo = pe.rvaToOff(expRva);
        if (eo < 0 || eo + 40 > b.length) return in;
        int nameRva = u4(b, eo + 12);
        in.base = u4(b, eo + 16);
        int nFunc = u4(b, eo + 20);
        int nNames = u4(b, eo + 24);
        int af = u4(b, eo + 28);
        int an = u4(b, eo + 32);
        int ao = u4(b, eo + 36);
        if (nFunc < 0 || nFunc > 65535 || nNames < 0 || nNames > 65535) return in;
        int no = pe.rvaToOff(nameRva);
        if (no > 0) in.dllName = readCString(b, no);
        int afo = pe.rvaToOff(af);
        int ano = pe.rvaToOff(an);
        int aoo = pe.rvaToOff(ao);
        if (afo < 0 || ano < 0 || aoo < 0) return in;
        in.funcRvas = new int[nFunc];
        in.forwarded = new boolean[nFunc];
        for (int i = 0; i < nFunc; i++) {
            int v = u4(b, afo + i * 4);
            in.funcRvas[i] = v;
            in.forwarded[i] = v != 0
                    && Integer.compareUnsigned(v, expRva) >= 0
                    && Integer.compareUnsigned(v, expRva + expSize) < 0;
        }
        List<String> names = new ArrayList<>();
        List<Integer> ords = new ArrayList<>();
        for (int i = 0; i < nNames; i++) {
            int nr = u4(b, ano + i * 4);
            int nOff = pe.rvaToOff(nr);
            if (nOff <= 0) continue;
            names.add(readCString(b, nOff));
            ords.add(u2(b, aoo + i * 2));
        }
        in.names = names.toArray(new String[0]);
        in.nameOrdinals = new int[ords.size()];
        for (int i = 0; i < ords.size(); i++) in.nameOrdinals[i] = ords.get(i);
        return in;
    }

    // ------------------------------------------------------------------
    //  Rebuilding
    // ------------------------------------------------------------------

    /**
     * Appends a cleartext export section to {@code packed} and rewrites the
     * export data directory. Returns the new file bytes, or {@code null} when
     * any mapping step fails (caller must refuse the artifact).
     */
    static byte[] rebuild(byte[] input, byte[] packed) {
        Pe inPe = Pe.parse(input);
        Pe outPe = Pe.parse(packed);
        if (!inPe.valid || !outPe.valid) return null;
        Info info = read(input, inPe);
        if (info.empty()) return null;

        // input section name -> output section (same name, first match)
        Map<String, Sec> outByName = new HashMap<>();
        for (Sec s : outPe.sections) outByName.put(s.name, s);

        // Translate every function RVA (and forwarder string) into output space.
        Map<Integer, Integer> fwdRvaMap = new LinkedHashMap<>();
        int[] newFunc = new int[info.funcRvas.length];
        for (int i = 0; i < info.funcRvas.length; i++) {
            int v = info.funcRvas[i];
            if (v == 0) { newFunc[i] = 0; continue; }
            if (info.forwarded[i]) {
                int so = inPe.rvaToOff(v);
                if (so <= 0) return null;
                String target = readCString(input, so);
                if (target.isEmpty()) return null;
                // Placeholder; the real RVA is assigned after the blob layout.
                fwdRvaMap.put(i, target.hashCode()); // value unused, key marks index
                newFunc[i] = -1;
                continue;
            }
            int mapped = mapRva(inPe, outPe, outByName, v);
            if (mapped < 0) return null;
            newFunc[i] = mapped;
        }

        // Build the blob: directory + EAT + name ptrs + ordinals + strings.
        int nFunc = newFunc.length;
        int nNames = info.names.length;
        String dllName = info.dllName.isEmpty() ? "kbox.dll" : info.dllName;
        List<String> fwdStrings = new ArrayList<>();
        int[] fwdIndexToString = new int[nFunc];
        java.util.Arrays.fill(fwdIndexToString, -1);
        for (int i = 0; i < nFunc; i++) {
            if (newFunc[i] == -1) {
                fwdIndexToString[i] = fwdStrings.size();
                fwdStrings.add(info.forwarded[i] ? forwarderText(input, inPe, info.funcRvas[i]) : "");
            }
        }

        int dirSize = 40;
        int eatOff = dirSize;
        int namesPtrOff = eatOff + nFunc * 4;
        int ordOff = namesPtrOff + nNames * 4;
        int strOff = ordOff + nNames * 2;
        // strings: dll name + export names + forwarder targets
        ByteArrayOutputStream strBuf = new ByteArrayOutputStream();
        int dllNameOff = strOff;
        writeCString(strBuf, dllName);
        int[] nameStrOff = new int[nNames];
        for (int i = 0; i < nNames; i++) {
            nameStrOff[i] = strOff + strBuf.size();
            writeCString(strBuf, info.names[i]);
        }
        int[] fwdStrOff = new int[fwdStrings.size()];
        for (int i = 0; i < fwdStrings.size(); i++) {
            fwdStrOff[i] = strOff + strBuf.size();
            writeCString(strBuf, fwdStrings.get(i));
        }
        int blobLen = strOff + strBuf.size();

        // ---- x64 exception handling -------------------------------------
        // The packer shifts every original section; both the RUNTIME_FUNCTION
        // entries (.pdata) and the per-function UNWIND_INFO exception-handler
        // RVAs (.xdata) keep their old values, so unwinding a packed C++
        // function fails ("has no image-section"). We re-emit both tables in
        // cleartext in the new section, with every RVA translated.
        //
        // Layout: [export dir][.pdata table][.xdata copy]
        int lastVa = 0;
        for (Sec s : outPe.sections) {
            lastVa = Math.max(lastVa, s.virtualAddress + Math.max(s.virtualSize, 1));
        }
        int newVa = align(lastVa, Math.max(outPe.sectionAlignment, 0x1000));
        int pdataOff = align(blobLen, 4);
        List<int[]> pdataRows = readPdataRows(input, inPe, outPe, outByName);
        int pdataLen = pdataRows == null ? 0 : pdataRows.size() * 12;
        int xdataOff = align(pdataOff + pdataLen, 4);
        byte[] xdataCopy = null;
        int xdataInVa = 0;
        if (pdataRows != null && !pdataRows.isEmpty()) {
            Sec xin = findSection(inPe, ".xdata");
            if (xin != null) {
                int len = Math.max(xin.rawSize, xin.virtualSize);
                if (xin.rawPtr >= 0 && xin.rawPtr + len <= input.length) {
                    xdataInVa = xin.virtualAddress;
                    xdataCopy = new byte[len];
                    System.arraycopy(input, xin.rawPtr, xdataCopy, 0, len);
                    patchUnwindHandlers(input, inPe, outPe, outByName, xdataCopy,
                            pdataRows, xdataInVa, newVa + xdataOff);
                }
            }
        }
        byte[] pdata = null;
        if (pdataRows != null && !pdataRows.isEmpty()) {
            pdata = new byte[pdataLen];
            int xdataNewVa = newVa + xdataOff;
            for (int i = 0; i < pdataRows.size(); i++) {
                int[] r = pdataRows.get(i);
                int newUnwind = (xdataCopy == null || r[2] == 0)
                        ? r[2] : xdataNewVa + (r[2] - xdataInVa);
                w32(pdata, i * 12, r[0]);
                w32(pdata, i * 12 + 4, r[1]);
                w32(pdata, i * 12 + 8, newUnwind);
            }
        }
        int totalLen = xdataOff + (xdataCopy == null ? 0 : xdataCopy.length);

        int rawPtr = align(packed.length, Math.max(outPe.fileAlignment, 0x200));
        int rawSize = align(totalLen, Math.max(outPe.fileAlignment, 0x200));
        int newSizeOfImage = align(newVa + totalLen, Math.max(outPe.sectionAlignment, 0x1000));

        byte[] out = new byte[rawPtr + rawSize];
        System.arraycopy(packed, 0, out, 0, packed.length);

        // Section table must fit inside the header block.
        int st = outPe.optOff + outPe.optSize;
        int newSecTableEnd = st + (outPe.numSections + 1) * 40;
        if (newSecTableEnd > outPe.sizeOfHeaders || newSecTableEnd > out.length) return null;
        int ns = st + outPe.numSections * 40;
        byte[] nm = ".kbxed".getBytes(StandardCharsets.US_ASCII);
        System.arraycopy(nm, 0, out, ns, Math.min(nm.length, 8));
        w32(out, ns + 8, totalLen);       // VirtualSize
        w32(out, ns + 12, newVa);         // VirtualAddress
        w32(out, ns + 16, rawSize);       // SizeOfRawData
        w32(out, ns + 20, rawPtr);        // PointerToRawData
        w32(out, ns + 24, 0);
        w32(out, ns + 28, 0);
        w16(out, ns + 32, 0);
        w16(out, ns + 34, 0);
        w32(out, ns + 36, 0x40000040);    // INITIALIZED_DATA | MEM_READ
        w16(out, outPe.peOff + 6, outPe.numSections + 1);
        w32(out, outPe.optOff + 56, newSizeOfImage);
        // DataDirectory[0] = export
        w32(out, outPe.ddOff, newVa);
        w32(out, outPe.ddOff + 4, blobLen);

        // Directory
        int b0 = rawPtr;
        w32(out, b0 + 0, 0);
        w32(out, b0 + 4, 0);
        w16(out, b0 + 8, 0);
        w16(out, b0 + 10, 0);
        w32(out, b0 + 12, newVa + dllNameOff);
        w32(out, b0 + 16, info.base);
        w32(out, b0 + 20, nFunc);
        w32(out, b0 + 24, nNames);
        w32(out, b0 + 28, newVa + eatOff);
        w32(out, b0 + 32, newVa + namesPtrOff);
        w32(out, b0 + 36, newVa + ordOff);
        // EAT
        for (int i = 0; i < nFunc; i++) {
            int v = newFunc[i];
            if (v == -1) v = newVa + fwdStrOff[fwdIndexToString[i]];
            w32(out, b0 + eatOff + i * 4, v);
        }
        // Name pointers + ordinals
        for (int i = 0; i < nNames; i++) {
            w32(out, b0 + namesPtrOff + i * 4, newVa + nameStrOff[i]);
        }
        for (int i = 0; i < nNames; i++) {
            w16(out, b0 + ordOff + i * 2, info.nameOrdinals[i]);
        }
        // Strings
        byte[] sb = strBuf.toByteArray();
        System.arraycopy(sb, 0, out, b0 + strOff, sb.length);
        // Exception directory (.pdata) + relocated .xdata copy
        if (pdata != null) {
            System.arraycopy(pdata, 0, out, b0 + pdataOff, pdata.length);
            w32(out, outPe.ddOff + 24, newVa + pdataOff);
            w32(out, outPe.ddOff + 28, pdata.length);
        }
        if (xdataCopy != null) {
            System.arraycopy(xdataCopy, 0, out, b0 + xdataOff, xdataCopy.length);
        }
        return out;
    }

    /**
     * Reads the input .pdata table and translates every RUNTIME_FUNCTION RVA
     * into output space. Returns {@code null} for non-x64 images or when the
     * input has no exception directory.
     */
    private static List<int[]> readPdataRows(byte[] input, Pe in, Pe out,
                                             Map<String, Sec> outByName) {
        if (in.machine != 0x8664) return null;
        int exRva = u4(input, in.ddOff + 24);
        int exSize = u4(input, in.ddOff + 28);
        if (exRva == 0 || exSize < 12) return null;
        int off = in.rvaToOff(exRva);
        if (off < 0) return null;
        int n = exSize / 12;
        List<int[]> rows = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            int base = off + i * 12;
            if (base + 12 > input.length) break;
            int begin = u4(input, base);
            int end = u4(input, base + 4);
            int unwind = u4(input, base + 8);
            if (begin == 0 && unwind == 0) continue;
            int nb = begin == 0 ? 0 : mapRva(in, out, outByName, begin);
            int ne = end == 0 ? 0 : mapRva(in, out, outByName, end);
            if ((begin != 0 && nb < 0) || (end != 0 && ne < 0) || unwind == 0) {
                continue; // entry belongs to a section that was not carried over
            }
            rows.add(new int[]{nb, ne, unwind});
        }
        return rows;
    }

    /**
     * Rewrites exception-handler RVAs (and chained-unwind references) inside a
     * copy of the input .xdata so they address the relocated code.
     */
    private static void patchUnwindHandlers(byte[] input, Pe in, Pe out,
                                            Map<String, Sec> outByName,
                                            byte[] xdata, List<int[]> rows,
                                            int xdataInVa, int xdataNewVa) {
        Sec xin = findSection(in, ".xdata");
        for (int[] r : rows) {
            int unwind = r[2];
            if (unwind == 0) continue;
            int o = unwind - xdataInVa;
            if (o < 0 || o + 4 > xdata.length) continue;
            int flags = (xdata[o] & 0xFF) >>> 3;
            int codes = xdata[o + 2] & 0xFF;
            int p = (o + 4 + codes * 2 + 3) & ~3;
            if ((flags & 3) != 0 && p + 4 <= xdata.length) {
                int h = u4(xdata, p);
                if (h != 0) {
                    int nh = mapRva(in, out, outByName, h);
                    if (nh > 0) w32(xdata, p, nh);
                }
                // The 4 bytes after the personality RVA are the handler-data RVA
                // (for GCC's SEH personality this points into
                // .gcc_except_table). It must be translated too, otherwise the
                // catch clause table is never found and the exception escapes.
                if (p + 8 <= xdata.length) {
                    int hd = u4(xdata, p + 4);
                    if (hd != 0) {
                        int nhd = mapRva(in, out, outByName, hd);
                        if (nhd > 0) w32(xdata, p + 4, nhd);
                    }
                }
            }
            if ((flags & 4) != 0 && codes >= 1) {
                int co = o + 4 + (codes - 1) * 2;
                if (co + 12 <= xdata.length) {
                    int b0 = u4(xdata, co);
                    int e0 = u4(xdata, co + 4);
                    int u0 = u4(xdata, co + 8);
                    int nb = b0 == 0 ? 0 : mapRva(in, out, outByName, b0);
                    int ne = e0 == 0 ? 0 : mapRva(in, out, outByName, e0);
                    if (nb >= 0 && ne >= 0) {
                        w32(xdata, co, nb);
                        w32(xdata, co + 4, ne);
                    }
                    if (u0 != 0 && xin != null) {
                        int rel = u0 - xin.virtualAddress;
                        if (rel >= 0 && rel < xdata.length) {
                            w32(xdata, co + 8, rel + xdataNewVa);
                        }
                    }
                }
            }
        }
    }

    private static Sec findSection(Pe pe, String name) {
        for (Sec s : pe.sections) {
            if (name.equals(s.name)) return s;
        }
        return null;
    }

    /** Maps an input RVA to the output RVA via section name + section delta. */
    private static int mapRva(Pe in, Pe out, Map<String, Sec> outByName, int rva) {
        for (Sec s : in.sections) {
            int size = Math.max(s.rawSize, s.virtualSize);
            if (Integer.compareUnsigned(rva, s.virtualAddress) >= 0
                    && Integer.compareUnsigned(rva, s.virtualAddress + Math.max(size, 1)) < 0) {
                Sec o = outByName.get(s.name);
                if (o == null) return -1;
                return o.virtualAddress + (rva - s.virtualAddress);
            }
        }
        return -1;
    }

    private static String forwarderText(byte[] in, Pe pe, int rva) {
        int off = pe.rvaToOff(rva);
        return off <= 0 ? "" : readCString(in, off);
    }

    // ------------------------------------------------------------------
    //  Small helpers
    // ------------------------------------------------------------------

    private static int align(int v, int a) {
        if (a <= 1) return v;
        int r = v % a;
        return r == 0 ? v : v + (a - r);
    }

    private static String readName(byte[] b, int o) {
        int e = o;
        while (e < o + 8 && b[e] != 0) e++;
        return new String(b, o, e - o, StandardCharsets.US_ASCII);
    }

    private static String readCString(byte[] b, int o) {
        int e = o;
        while (e < b.length && b[e] != 0) e++;
        return new String(b, o, e - o, StandardCharsets.US_ASCII);
    }

    private static void writeCString(ByteArrayOutputStream out, String s) {
        byte[] b = s.getBytes(StandardCharsets.US_ASCII);
        out.write(b, 0, b.length);
        out.write(0);
    }

    private static int u2(byte[] b, int o) {
        if (o + 2 > b.length) return 0;
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private static int u4(byte[] b, int o) {
        if (o + 4 > b.length) return 0;
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8)
                | ((b[o + 2] & 0xFF) << 16) | ((b[o + 3] & 0xFF) << 24);
    }

    private static void w16(byte[] b, int o, int v) {
        b[o] = (byte) v;
        b[o + 1] = (byte) (v >>> 8);
    }

    private static void w32(byte[] b, int o, int v) {
        b[o] = (byte) v;
        b[o + 1] = (byte) (v >>> 8);
        b[o + 2] = (byte) (v >>> 16);
        b[o + 3] = (byte) (v >>> 24);
    }
}
