package com.kbox.core.jnic;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Build-time integrity baseline for the native decoder.
 *
 * <p>Computes the expected FNV-1a image hash over the compiled native library
 * (exactly the same algorithm the runtime {@code kbox_selfCheck()} in
 * {@code kbox_bf_loader.c} runs over the <b>mapped</b> image), then patches the
 * 8-byte constant into the decoder's dedicated read-only {@code .kboxexp}
 * section:
 * <pre>
 *   [0..3] expected image hash (uint32, LE)
 *   [4..7] magic 'KBOX' (0x4B424F58, LE) proving the constant was injected
 * </pre>
 *
 * <p>Because the runtime hash skips the {@code .kboxexp} section by name, the
 * constant's own value does not affect the hash, so a build-time expectation is
 * possible without a self-referential chicken-and-egg. The expected value is
 * compiled in and <b>cannot be re-baselined</b> by a runtime patch — the
 * "patch the check call sites, then let the first check re-derive the baseline
 * from the already-patched image" attack now flips the hash and is caught.
 *
 * <p>PE32/PE32+ and 64-bit little-endian ELF are supported (matching the two
 * platforms the native decoder actually self-hashes on). Any other format, or
 * a missing {@code .kboxexp} section, leaves the constant untouched; the
 * decoder then falls back to a runtime baseline (degraded, unhardened build)
 * so the protected app still runs.
 */
public final class NativeImageHash {

    /** Magic written to the high 32 bits of the .kboxexp constant. XOR-masked
     *  so the stored PE bytes are NOT ASCII "KBOX" (坑④). MUST match the native
     *  side's KBOX_EXPECTED_MAGIC. */
    private static final long MAGIC = 0x4B424F58L ^ 0x2D7E1A93L;   // masked
    private static final long FNV_OFFSET = 0x811c9dc5L;
    private static final long FNV_PRIME = 0x01000193L;
    private static final long MASK32 = 0xFFFFFFFFL;

    /** IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_DISCARDABLE (PE). */
    private static final long PECN_SKIP = 0x80000000L | 0x02000000L;

    private NativeImageHash() {
    }

    /** Outcome of the build-time hash + patch attempt. */
    public static final class Expected {
        public final boolean patched;
        public final long hash;      // uint32 expected hash (0 when not computed)
        public final String log;
        Expected(boolean patched, long hash, String log) {
            this.patched = patched;
            this.hash = hash;
            this.log = log;
        }
    }

    /**
     * Computes the expected integrity hash over {@code lib} and patches it into
     * the {@code .kboxexp} section. {@code salt} must equal the per-build
     * {@code KBOX_TEXT_SALT} compiled into the decoder.
     */
    public static Expected computeAndPatch(Path lib, long salt) {
        byte[] buf;
        try {
            buf = Files.readAllBytes(lib);
        } catch (IOException e) {
            return new Expected(false, 0, "read failed: " + e.getMessage());
        }
        if (isPe(buf)) return patchPe(buf, lib, salt);
        if (isElf64Le(buf)) return patchElf(buf, lib, salt);
        return new Expected(false, 0, "unsupported image format (expected PE or ELF64-LE), not patched");
    }

    /* ------------------------------------------------------------------ */
    /* Format detection                                                   */
    /* ------------------------------------------------------------------ */

    private static boolean isPe(byte[] b) {
        if (b.length < 0x40 || (b[0] & 0xFF) != 'M' || (b[1] & 0xFF) != 'Z') return false;
        int e_lfanew = (int) u32(b, 0x3C);
        if (e_lfanew < 0 || e_lfanew + 24 > b.length) return false;
        return u32(b, e_lfanew) == 0x00004550L; // "PE\0\0"
    }

    private static boolean isElf64Le(byte[] b) {
        if (b.length < 64) return false;
        return (b[0] & 0xFF) == 0x7F && b[1] == 'E' && b[2] == 'L' && b[3] == 'F'
                && b[4] == 2     // ELFCLASS64
                && b[5] == 1;    // ELFDATA2LSB
    }

    /* ------------------------------------------------------------------ */
    /* PE                                                                 */
    /* ------------------------------------------------------------------ */

    private static Expected patchPe(byte[] b, Path lib, long salt) {
        int e_lfanew = (int) u32(b, 0x3C);
        int numSec = u16(b, e_lfanew + 6);
        int optSize = u16(b, e_lfanew + 20);
        int oh = e_lfanew + 24;
        int magic = u16(b, oh);
        boolean pe32p = (magic == 0x20B);
        if (magic != 0x20B && magic != 0x10B) {
            return new Expected(false, 0, "PE optional header magic " + String.format("0x%04X", magic) + " unsupported");
        }
        long sizeOfImage = pe32p ? u32(b, oh + 56) : u32(b, oh + 60);
        int secBase = oh + optSize;
        if (secBase + numSec * 40 > b.length) {
            return new Expected(false, 0, "PE section table out of range, not patched");
        }
        long h = FNV_OFFSET ^ (salt & MASK32);
        int patchedAt = -1;
        int patchedLen = 0;
        StringBuilder sb = new StringBuilder(96);
        int hashedSec = 0;
        java.util.ArrayList<long[]> hashedRanges = new java.util.ArrayList<>(8);
        // DIR64/HIGHLOW base-reloc target RVAs, sorted ascending. The runtime
        // hash skips exactly these bytes too (kbox_hashImage in kbox_bf_loader.c),
        // so the expected value matches regardless of the mapped load base.
        long[] relocRvas = collectRelocRvas(b, oh, pe32p);
        int ri = 0;
        for (int i = 0; i < numSec; i++) {
            int s = secBase + i * 40;
            long ch = u32(b, s + 36);
            long va = u32(b, s + 12);
            long vs = u32(b, s + 8);       // VirtualSize
            long rawLen = u32(b, s + 16);  // SizeOfRawData
            long rawOff = u32(b, s + 20);  // PointerToRawData
            String name = secName(b, s);
            if ((ch & PECN_SKIP) != 0) continue;
            if (name.equals(".kboxexp")) {
                // Remember for patching, but do NOT fold into the hash.
                patchedAt = (int) rawOff;
                patchedLen = (int) rawLen;
                continue;
            }
            if (name.equals(".idata")) {
                // The IAT / import thunks are rewritten by import resolution at
                // load time; their memory content never equals the file.
                continue;
            }
            long n = vs;
            if (va + n > sizeOfImage) n = sizeOfImage - va;
            if (n <= 0) continue;
            hashedRanges.add(new long[]{va, va + n});
            h ^= va;
            h ^= ch;
            h = (h * FNV_PRIME) & MASK32;
            boolean rawFits = rawOff + rawLen <= b.length;
            for (long j = 0; j < n; j++) {
                long rva = va + j;
                while (ri < relocRvas.length && relocRvas[ri] < rva) ri++;
                if (ri < relocRvas.length && relocRvas[ri] == rva) continue; // relocated byte
                int by = 0;
                if (rawFits && j < rawLen) by = b[(int) (rawOff + j)] & 0xFF;
                h ^= by;
                h = (h * FNV_PRIME) & MASK32;
            }
            hashedSec++;
            if (sb.length() > 0) sb.append(' ');
            sb.append(name).append('(').append(n).append(')');
        }
        // Diagnostic: base relocations whose target falls inside a hashed section
        // would break the file==mapped-image invariant IF the loader applied them
        // (non-preferred base). Both sides now skip those bytes, so a build is
        // still correct — this is just an informational count of skipped bytes.
        int relocInHashed = 0;
        for (long r : relocRvas) {
            for (long[] range : hashedRanges) {
                if (r >= range[0] && r < range[1]) { relocInHashed++; break; }
            }
        }
        if (relocInHashed > 0) {
            sb.append(" [WARN ").append(relocInHashed)
              .append(" base-reloc(s) target hashed sections: file hash may not "
                      + "match mapped image if loaded at non-preferred base]");
        }
        if (patchedAt < 0) {
            return new Expected(false, 0, "PE has no .kboxexp section (hash over "
                    + hashedSec + " sections computed but not patched; runtime will use fallback)");
        }
        if (patchedLen < 8) {
            return new Expected(false, h, ".kboxexp too small (" + patchedLen + "B) to patch");
        }
        if (patchedAt + 8 > b.length) {
            return new Expected(false, h, ".kboxexp raw offset out of file, not patched");
        }
        // The section must still hold the zero placeholder (it is the only
        // object in .kboxexp); otherwise the layout assumption is wrong and we
        // must not risk corrupting it.
        boolean placeholder = true;
        for (int i = 0; i < 8; i++) {
            if (b[patchedAt + i] != 0) { placeholder = false; break; }
        }
        if (!placeholder) {
            return new Expected(false, h, ".kboxexp not at zero placeholder, not patched");
        }
        writeU32(b, patchedAt, h & MASK32);
        writeU32(b, patchedAt + 4, MAGIC);
        long r0 = u32(b, patchedAt);
        long r1 = u32(b, patchedAt + 4);
        if (r0 != (h & MASK32) || r1 != MAGIC) {
            return new Expected(false, h, ".kboxexp patch verify failed, not written");
        }
        try {
            Files.write(lib, b);
        } catch (IOException e) {
            return new Expected(false, h, ".kboxexp write failed: " + e.getMessage());
        }
        return new Expected(true, h & MASK32,
                String.format("PE patched .kboxexp hash=0x%08X (sections: %s)", h & MASK32, sb));
    }

    /* ------------------------------------------------------------------ */
    /* ELF64 (little-endian)                                               */
    /* ------------------------------------------------------------------ */

    private static Expected patchElf(byte[] b, Path lib, long salt) {
        long phOff = u64(b, 32);
        int phEntSz = u16(b, 54);
        int phNum = u16(b, 56);
        long shOff = u64(b, 40);
        int shEntSz = u16(b, 58);
        int shNum = u16(b, 60);
        int shStrNdx = u16(b, 62);
        if (phEntSz < 40 || phOff + (long) phNum * phEntSz > b.length) {
            return new Expected(false, 0, "ELF phdr out of range, not patched");
        }
        long h = FNV_OFFSET ^ (salt & MASK32);
        int hashed = 0;
        for (int i = 0; i < phNum; i++) {
            long p = phOff + (long) i * phEntSz;
            long type = u32(b, (int) p);
            long flags = u32(b, (int) p + 4);
            long off = u64(b, (int) p + 8);
            long vaddr = u64(b, (int) p + 16);
            long filesz = u64(b, (int) p + 32);
            if (type != 1) continue;                 // PT_LOAD
            if ((flags & 4) != 0) continue;          // PF_W
            if ((flags & 1) == 0) continue;          // !PF_X
            if (filesz == 0) continue;
            h ^= vaddr;
            h ^= flags;
            h = (h * FNV_PRIME) & MASK32;
            long max = off + filesz > b.length ? b.length - off : filesz;
            for (long j = 0; j < max; j++) {
                int by = b[(int) (off + j)] & 0xFF;
                h ^= by;
                h = (h * FNV_PRIME) & MASK32;
            }
            hashed++;
        }
        // Locate .kboxexp via the section header string table.
        if (shEntSz < 64 || shNum <= 0 || shStrNdx >= shNum
                || shOff + (long) shNum * shEntSz > b.length) {
            return new Expected(false, h, "ELF has no usable shdr (hash over "
                    + hashed + " LOAD segments computed but not patched)");
        }
        long shstrOff = u64(b, (int) (shOff + (long) shStrNdx * shEntSz) + 24);
        long shstrSize = u64(b, (int) (shOff + (long) shStrNdx * shEntSz) + 32);
        int patchedAt = -1;
        for (int i = 0; i < shNum; i++) {
            int sh = (int) (shOff + (long) i * shEntSz);
            long nameOff = u32(b, sh);
            long off = u64(b, sh + 24);
            if (nameOff + 8 > shstrSize || off + 8 > b.length) continue;
            String nm = elfName(b, (int) (shstrOff + nameOff));
            if (nm.equals(".kboxexp")) {
                patchedAt = (int) off;
                break;
            }
        }
        if (patchedAt < 0) {
            return new Expected(false, h, "ELF has no .kboxexp section (hash over "
                    + hashed + " LOAD segments computed but not patched)");
        }
        if (patchedAt + 8 > b.length) {
            return new Expected(false, h, ".kboxexp raw offset out of file, not patched");
        }
        boolean placeholder = true;
        for (int i = 0; i < 8; i++) {
            if (b[patchedAt + i] != 0) { placeholder = false; break; }
        }
        if (!placeholder) {
            return new Expected(false, h, ".kboxexp not at zero placeholder, not patched");
        }
        writeU32(b, patchedAt, h & MASK32);
        writeU32(b, patchedAt + 4, MAGIC);
        try {
            Files.write(lib, b);
        } catch (IOException e) {
            return new Expected(false, h, ".kboxexp write failed: " + e.getMessage());
        }
        return new Expected(true, h & MASK32,
                String.format("ELF patched .kboxexp hash=0x%08X (code LOAD segs: %d)", h & MASK32, hashed));
    }

    /* ------------------------------------------------------------------ */
    /* PE/ELF metadata stripping (anti-static: debug / symbol / toolchain) */
    /* ------------------------------------------------------------------ */

    private static final long PECN_DISCARDABLE = 0x02000000L;
    private static final long PECN_LNK_REMOVE  = 0x00000800L;

    /**
     * Removes debug metadata & toolchain identity from a compiled native image.
     * On PE: zeroes the DEBUG data-directory entry, dead-zeros the
     * {@code .debug*} / {@code .comment} sections (and marks them discardable so
     * <b>neither</b> the build-time nor the runtime image hash folds them — both
     * skip discardable sections, so the expected hash stays consistent), and
     * wipes any surviving {@code *.pdb} path string. On ELF: dead-zeros the
     * {@code .comment} / {@code .debug_*} / {@code .symtab} / {@code .strtab} /
     * {@code .gnu_debuglink} / {@code .note.gnu.build-id} sections. Best-effort,
     * never throws. Must be called BEFORE {@link #computeAndPatch} so the
     * build-time expected hash covers exactly the shipped (stripped) image.
     */
    public static String strip(Path lib) {
        byte[] b;
        try {
            b = Files.readAllBytes(lib);
        } catch (IOException e) {
            return "strip: read failed: " + e.getMessage();
        }
        String log;
        if (isPe(b)) log = stripPe(b);
        else if (isElf64Le(b)) log = stripElf(b);
        else return "strip: unsupported image format (PE or ELF64-LE expected), untouched";
        try {
            Files.write(lib, b);
            return log;
        } catch (IOException e) {
            return "strip: write failed: " + e.getMessage();
        }
    }

    private static String stripPe(byte[] b) {
        int e_lfanew = (int) u32(b, 0x3C);
        int numSec = u16(b, e_lfanew + 6);
        int optSize = u16(b, e_lfanew + 20);
        int oh = e_lfanew + 24;
        int magic = u16(b, oh);
        boolean pe32p = (magic == 0x20B);
        int dbgStripped = 0, secStripped = 0, pdbRuns = 0;
        // 1) Zero the DEBUG data directory entry (index 6) — no debug directory
        //    for a debugger/analyzer to walk (and no PDB path to resolve).
        int dd = (pe32p ? oh + 112 : oh + 96) + 6 * 8;
        if (dd + 8 <= b.length) {
            long va = u32(b, dd), sz = u32(b, dd + 4);
            if (va != 0 || sz != 0) {
                writeU32(b, dd, 0);
                writeU32(b, dd + 4, 0);
                dbgStripped++;
            }
        }
        // 2) Dead sections: .debug* (CodeView/DWARF records) and .comment (GCC /
        //    MSVC toolchain version string). Zero their raw payload and mark
        //    discardable so the runtime image hash skips them identically.
        int secBase = oh + optSize;
        if (secBase + numSec * 40 <= b.length) {
            for (int i = 0; i < numSec; i++) {
                int s = secBase + i * 40;
                String name = secName(b, s);
                if (!(name.startsWith(".debug") || name.equals(".comment"))) continue;
                writeU32(b, s + 16, 0);              // SizeOfRawData = 0
                long ch = u32(b, s + 36);
                ch |= PECN_DISCARDABLE | PECN_LNK_REMOVE;
                writeU32(b, s + 36, ch);
                secStripped++;
            }
        }
        // 3) Wipe any surviving "*.pdb" path string (belt & braces: a PDB path
        //    occasionally lands in .rdata, outside a .debug section). Zero the
        //    contiguous printable run containing the token.
        for (int i = 0; i + 3 < b.length; i++) {
            boolean hit = ((b[i] == 'p' || b[i] == 'P')
                        && (b[i + 1] == 'd' || b[i + 1] == 'D')
                        && (b[i + 2] == 'b' || b[i + 2] == 'B')
                        && b[i + 3] == '.');
            if (!hit) continue;
            int s = i;
            while (s > 0 && b[s - 1] >= 0x20 && b[s - 1] <= 0x7E) s--;
            int e2 = i + 4;
            while (e2 < b.length && b[e2] >= 0x20 && b[e2] <= 0x7E) e2++;
            for (int k = s; k < e2; k++) b[k] = 0;
            pdbRuns++;
            i = e2;
        }
        return "strip[pe]: debugdir=" + dbgStripped + " deadSec=" + secStripped
                + " pdbRuns=" + pdbRuns;
    }

    private static String stripElf(byte[] b) {
        long shOff = u64(b, 40);
        int shEntSz = u16(b, 58);
        int shNum = u16(b, 60);
        int shStrNdx = u16(b, 62);
        if (shEntSz < 64 || shNum <= 0 || shStrNdx >= shNum
                || shOff + (long) shNum * shEntSz > b.length) {
            return "strip[elf]: no usable shdr, untouched";
        }
        long shstrOff = u64(b, (int) (shOff + (long) shStrNdx * shEntSz) + 24);
        long shstrSize = u64(b, (int) (shOff + (long) shStrNdx * shEntSz) + 32);
        int stripped = 0;
        for (int i = 0; i < shNum; i++) {
            int sh = (int) (shOff + (long) i * shEntSz);
            long nameOff = u32(b, sh);
            long off = u64(b, sh + 24);
            long size = u64(b, sh + 32);
            if (nameOff >= shstrSize || off + size > b.length) continue;
            String nm = elfName(b, (int) (shstrOff + nameOff));
            if (!(nm.equals(".comment") || nm.startsWith(".debug")
                    || nm.equals(".symtab") || nm.equals(".strtab")
                    || nm.equals(".gnu_debuglink") || nm.equals(".note.gnu.build-id"))) {
                continue;
            }
            for (long k = 0; k < size; k++) b[(int) (off + k)] = 0;
            stripped++;
        }
        return "strip[elf]: deadSec=" + stripped;
    }

    /* ------------------------------------------------------------------ */
    /* byte accessors                                                     */
    /* ------------------------------------------------------------------ */

    /** Collects DIR64/HIGHLOW base-reloc target RVAs (ascending) from the .reloc
     *  directory. Both this builder and the runtime {@code kbox_hashImage} skip
     *  exactly these bytes while hashing, so the expected value is independent
     *  of the base the module happens to be loaded at. */
    private static long[] collectRelocRvas(byte[] b, int oh, boolean pe32p) {
        int dd = (pe32p ? oh + 112 : oh + 96) + 5 * 8; // BASERELOC directory
        long relocVa = u32(b, dd);
        long relocSize = u32(b, dd + 4);
        if (relocVa == 0 || relocSize == 0) return new long[0];
        int numSec = u16(b, (oh - 24) + 6);
        int secBase = oh + u16(b, (oh - 24) + 20);
        // The directory's VirtualAddress is an RVA — translate to a file offset
        // through the section table (the runtime parses base + RVA directly from
        // the mapped image, which is the same thing).
        long relocFile = rvaToFileOff(b, secBase, numSec, relocVa);
        if (relocFile < 0) return new long[0];
        java.util.ArrayList<Long> list = new java.util.ArrayList<>(64);
        long off = 0;
        while (off + 8 <= relocSize) {
            int block = (int) (relocFile + off);
            if (block + 8 > b.length) break;
            long blockVa = u32(b, block);
            long blockSize = u32(b, block + 4);
            if (blockSize < 8 || block + blockSize > b.length) break;
            long entries = (blockSize - 8) / 2;
            for (long j = 0; j < entries; j++) {
                int e = u16(b, (int) (block + 8 + j * 2));
                int t = e >> 12;
                if (t != 3 && t != 10) continue; // HIGHLOW, DIR64
                list.add(blockVa + (e & 0xFFF));
            }
            off += blockSize;
        }
        long[] out = new long[list.size()];
        for (int i = 0; i < out.length; i++) out[i] = list.get(i);
        java.util.Arrays.sort(out); // blocks are already ascending; cheap safety
        return out;
    }

    /** Translates a section RVA into a raw file offset via the PE section table,
     *  or -1 when no section contains it. */
    private static long rvaToFileOff(byte[] b, int secBase, int numSec, long rva) {
        for (int i = 0; i < numSec; i++) {
            int s = secBase + i * 40;
            long va = u32(b, s + 12);
            long vs = u32(b, s + 8);
            long rawLen = u32(b, s + 16);
            long rawOff = u32(b, s + 20);
            long size = Math.max(vs, rawLen);
            if (rva >= va && rva < va + size) return rawOff + (rva - va);
        }
        return -1;
    }

    private static String secName(byte[] b, int s) {
        StringBuilder sb = new StringBuilder(8);
        for (int i = 0; i < 8; i++) {
            int c = b[s + i] & 0xFF;
            if (c == 0) break;
            sb.append((char) c);
        }
        return sb.toString();
    }

    private static String elfName(byte[] b, int off) {
        StringBuilder sb = new StringBuilder(16);
        for (int i = off; i < b.length; i++) {
            if (b[i] == 0) break;
            sb.append((char) (b[i] & 0xFF));
        }
        return sb.toString();
    }

    private static int u16(byte[] b, int o) {
        return (b[o] & 0xFF) | ((b[o + 1] & 0xFF) << 8);
    }

    private static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xFF))
                | ((long) (b[o + 1] & 0xFF) << 8)
                | ((long) (b[o + 2] & 0xFF) << 16)
                | ((long) (b[o + 3] & 0xFF) << 24);
    }

    private static long u64(byte[] b, int o) {
        long v = 0;
        for (int i = 7; i >= 0; i--) v = (v << 8) | (b[o + i] & 0xFF);
        return v;
    }

    private static void writeU32(byte[] b, int o, long v) {
        b[o] = (byte) (v & 0xFF);
        b[o + 1] = (byte) ((v >>> 8) & 0xFF);
        b[o + 2] = (byte) ((v >>> 16) & 0xFF);
        b[o + 3] = (byte) ((v >>> 24) & 0xFF);
    }
}
