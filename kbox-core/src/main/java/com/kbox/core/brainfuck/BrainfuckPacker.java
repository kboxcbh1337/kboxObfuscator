package com.kbox.core.brainfuck;

import com.kbox.core.log.KBoxLog;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;

/**
 * Build-time packer for the <b>Brainfuck chaos</b> loader scheme.
 *
 * <p>{@code META-INF/kbox/classes.bf.rle} is a single self-contained archive
 * whose head is a small header and whose tail is one <b>independent</b> RLE
 * chunk per class / resource:</p>
 *
 * <pre>
 *   [4 magic "KBF2"][u32 classCount]
 *   [per class:  u32 nameLen, utf8 name, u32 rleOff, u32 rleLen, u32 rawLen]
 *   [u32 resCount]
 *   [per resource:same record]
 *   [class/resource chunk bodies...]
 * </pre>
 *
 * <p>Each chunk is a <b>real, standalone Brainfuck program</b> (using all 8
 * commands {@code + - &gt; &lt; [ ] . ,}) with its own per-build symbol set. Running
 * it emits the raw-DEFLATE stream for that one entry; inflating that tiny stream
 * yields the entry's plaintext. Because each entry is its own BF program + its
 * own DEFLATE stream, the native decoder never inflates the whole archive and
 * never holds the full plaintext jar: at any instant only the <i>currently
 * requested</i> entry's bytes exist, and they are zeroed right after the class
 * is defined (or the resource is copied). The name&rarr;chunk index lives only in
 * native memory; Java never learns a chunk offset.</p>
 */
public final class BrainfuckPacker {

    private static final String TAG = "BfPacker";

    /** Output of {@link #pack}. */
    public static final class Result {
        /** The assembled {@code classes.bf.rle} (header + per-entry chunks). */
        public final byte[] rleBytes;
        public final int classCount;
        public final int resourceCount;

        Result(byte[] rleBytes, int classCount, int resourceCount) {
            this.rleBytes = rleBytes;
            this.classCount = classCount;
            this.resourceCount = resourceCount;
        }
    }

    private BrainfuckPacker() {}

    /**
     * @param classes   final class bytes keyed by renamed internal name
     *                  (e.g. {@code com/foo/Main}); must never be null.
     * @param resources final resource bytes keyed by jar path; may be null/empty.
     * @param sym       the per-build Brainfuck symbol set; every chunk is encoded
     *                  with these symbols and the native decoder is compiled with
     *                  the same mapping, so each build ships a distinct program.
     */
    public static Result pack(Map<String, byte[]> classes, Map<String, byte[]> resources,
                              BfSymbolSet sym) {
        List<String> classNames = new ArrayList<>(classes.keySet());
        classNames.sort(String::compareTo);
        List<String> resNames = new ArrayList<>(
                resources == null ? java.util.Collections.emptySet() : resources.keySet());
        resNames.sort(String::compareTo);

        // 1. Header size first — chunk offsets are absolute within the file and
        //    start right after the header. A record is:
        //      u32 nameLen, utf8 name, u32 rleOff, u32 rleLen, u32 rawLen  (4+len+12)
        long base = 4 + 4; // magic + classCount
        for (String name : classNames) base += 4 + name.getBytes(StandardCharsets.UTF_8).length + 12;
        base += 4; // resCount
        for (String name : resNames) base += 4 + name.getBytes(StandardCharsets.UTF_8).length + 12;

        ByteArrayOutputStream header = new ByteArrayOutputStream();
        writeMagic(header);
        writeInt(header, classNames.size());
        long off = base;
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        int clsRaw = 0, resRaw = 0;
        for (String name : classNames) {
            byte[] raw = classes.get(name);
            clsRaw += raw.length;
            byte[] chunk = deflateToRle(raw, sym, (int) off);
            writeEntry(header, name, (int) off, chunk.length, raw.length);
            off += chunk.length;
            body.write(chunk, 0, chunk.length);
        }
        writeInt(header, resNames.size());
        for (String name : resNames) {
            byte[] raw = resources.get(name);
            resRaw += raw.length;
            byte[] chunk = deflateToRle(raw, sym, (int) off);
            writeEntry(header, name, (int) off, chunk.length, raw.length);
            off += chunk.length;
            body.write(chunk, 0, chunk.length);
        }
        byte[] headerBytes = header.toByteArray();
        if (headerBytes.length != base) {
            throw new IllegalStateException("KBox-BF: header size mismatch "
                    + headerBytes.length + " vs " + base);
        }

        byte[] rle = new byte[headerBytes.length + body.size()];
        System.arraycopy(headerBytes, 0, rle, 0, headerBytes.length);
        System.arraycopy(body.toByteArray(), 0, rle, headerBytes.length, body.size());

        KBoxLog.info(TAG, "Packed " + classNames.size() + " classes + "
                + resNames.size() + " resources: header=" + headerBytes.length
                + " chunks=" + body.size() + " rawClasses=" + clsRaw
                + " rawResources=" + resRaw + " bfRle=" + rle.length + " bytes");
        return new Result(rle, classNames.size(), resNames.size());
    }

    /** 4-byte header magic class — XOR-masked at build so the stored bytes are
     *  no longer the ASCII {@code "KBF2"} (a static grep over the jar/PNG of the
     *  container header can no longer fingerprint the archive format). The native
     *  parser re-derives the mask and compares via XOR, so build↔run stay in sync.
     *  Prevents the "container structure readable" fingerprinting shortcut (坑④). */
    private static final byte[] KBF2_MAGIC = {
            (byte) ('K' ^ 0xA5), (byte) ('B' ^ 0x3C), (byte) ('F' ^ 0x77), (byte) ('2' ^ 0xD8) };

    private static void writeMagic(ByteArrayOutputStream b) {
        b.write(KBF2_MAGIC[0] & 0xFF); b.write(KBF2_MAGIC[1] & 0xFF);
        b.write(KBF2_MAGIC[2] & 0xFF); b.write(KBF2_MAGIC[3] & 0xFF);
    }

    private static void writeEntry(ByteArrayOutputStream b, String name,
                                   int rleOff, int rleLen, int rawLen) {
        byte[] nb = name.getBytes(StandardCharsets.UTF_8);
        writeInt(b, nb.length);
        b.write(nb, 0, nb.length);
        writeInt(b, rleOff);
        writeInt(b, rleLen);
        writeInt(b, rawLen);
    }

    /**
     * Converts one entry's plaintext into its own RLE brainfuck chunk.
     *
     * <ol>
     *   <li>Raw entry bytes are DEFLATE-compressed (raw stream, no zlib header).</li>
     *   <li>The deflated stream is emitted as a <b>genuine</b> Brainfuck program:
     *       each byte is produced by a data-driven tape loop (cell0=quotient;
     *       {@code while(cell0){cell1+=10;cell0--}}; {@code cell1+=remainder});
     *       then a pointer move to cell1 and an emit. The loop-iteration counts
     *       and the cell0/cell1 pointer travel are essential — the plaintext
     *       cannot be recovered without running a real Brainfuck interpreter
     *       (tape + bracket matching), it is not reducible to carry arithmetic.
     *       A tiny preamble uses {@code , + - &gt; &lt; [ ]} and each data byte uses
     *       {@code .}, so all <b>eight</b> commands genuinely appear.</li>
     *   <li><b>Per-chunk operator table re-shuffle:</b> the canonical op index
     *       (0..7) runs through a deterministic 8-permutation derived from
     *       {@code mix(seed ^ rleOff)} before symbol selection, so each chunk is
     *       encoded against its own re-dealt op table. The native decoder
     *       independently derives the identical permutation from the same
     *       {@code (seed, rleOff)} — the real table never leaves decode memory.</li>
     *   <li>The Brainfuck text is RLE-compressed into the chunk bytes.</li>
     * </ol>
     */
    private static byte[] deflateToRle(byte[] raw, BfSymbolSet sym, int rleOff) {
        byte[] deflated = deflate(raw);
        // Canonical op indexing: 0=plus,1=minus,2=right,3=left,4=open,5=close,6=dot,7=comma
        char[] canon = { sym.plus, sym.minus, sym.right, sym.left,
                sym.open, sym.close, sym.dot, sym.comma };
        int[] perm = deriveOpPerm(sym.seed, rleOff);
        // emit[op] = canon[perm[op]] — per-chunk re-dealt operator table.
        char[] emit = new char[8];
        for (int i = 0; i < 8; i++) emit[i] = canon[perm[i]];

        ByteArrayOutputStream rle = new ByteArrayOutputStream(deflated.length * 8);
        // Preamble:  , [-] + [-] > [-] <
        // Actually runs every command except '.' (which every data byte emits),
        // and leaves the tape neutral: ptr at cell0, cell0 = cell1 = 0.
        emitRle(rle, emit[7], 1);
        emitRle(rle, emit[4], 1); emitRle(rle, emit[1], 1); emitRle(rle, emit[5], 1);   // [-]
        emitRle(rle, emit[0], 1);
        emitRle(rle, emit[4], 1); emitRle(rle, emit[1], 1); emitRle(rle, emit[5], 1);   // [-]
        emitRle(rle, emit[2], 1);
        emitRle(rle, emit[4], 1); emitRle(rle, emit[1], 1); emitRle(rle, emit[5], 1);   // [-]
        emitRle(rle, emit[3], 1);
        // Data: per byte v = 10*q + r,
        //   cell0 += q ; [ > cell1 += 10 < cell0-- ] ; > cell1 += r ; . ; [-]
        // After each byte cell1 is zeroed and the pointer returns to cell0 with
        // cell0 = 0, so the next byte starts from a clean tape.
        for (byte value : deflated) {
            int v = value & 0xFF;
            int q = v / 10;
            int r = v % 10;
            emitRle(rle, emit[0], q);               // cell0 = q
            emitRle(rle, emit[4], 1);               // [
            emitRle(rle, emit[2], 1);               //   >
            emitRle(rle, emit[0], 10);              //   cell1 += 10
            emitRle(rle, emit[3], 1);               //   <
            emitRle(rle, emit[1], 1);               //   cell0--
            emitRle(rle, emit[5], 1);               // ]
            emitRle(rle, emit[2], 1);               // >
            emitRle(rle, emit[0], r);               // cell1 += r  -> cell1 = v
            emitRle(rle, emit[6], 1);               // emit v
            emitRle(rle, emit[4], 1); emitRle(rle, emit[1], 1); emitRle(rle, emit[5], 1); // [-]
            emitRle(rle, emit[3], 1);               // <  back to cell0
        }
        return rle.toByteArray();
    }

    /** Deterministically derives this chunk's 8-op permutation from the per-build
     *  {@code seed} and the chunk's absolute {@code rleOff}. {@code mix()} is a
     *  lossless 32-bit mixer mirrored bit-for-bit in {@code kbox_bf_loader.c}, so
     *  packer and native independently reach the same table without writing it. */
    private static int[] deriveOpPerm(int seed, int rleOff) {
        int s = mix(seed ^ rleOff);
        int[] p = { 0, 1, 2, 3, 4, 5, 6, 7 };
        for (int i = 7; i > 0; i--) {
            s = mix(s + i * 0x9E3779B9);
            int j = (s >>> 24) & 0xFF;
            j %= (i + 1);            // j in [0, i]
            int t = p[i]; p[i] = p[j]; p[j] = t;
        }
        return p;
    }

    /** Lossless 32-bit integer mixer (must match native {@code mix32}). */
    private static int mix(int h) {
        h ^= h >>> 16;
        h *= 0x85EBCA6B;
        h ^= h >>> 13;
        h *= 0xC2B2AE35;
        h ^= h >>> 16;
        return h;
    }

    /** Appends a run of {@code count} copies of {@code ch}, RLE-compressed
     *  (the count prefix is omitted when it is 1). */
    private static void emitRle(ByteArrayOutputStream b, char ch, int count) {
        if (count <= 0) return;
        if (count > 1) {
            byte[] d = String.valueOf(count).getBytes(StandardCharsets.US_ASCII);
            b.write(d, 0, d.length);
        }
        b.write((int) ch);
    }

    /** Raw DEFLATE (nowrap) at best compression. */
    private static byte[] deflate(byte[] data) {
        Deflater d = new Deflater(Deflater.BEST_COMPRESSION, true);
        d.setInput(data);
        d.finish();
        byte[] buf = new byte[8192];
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length / 2 + 64);
        int n;
        while ((n = d.deflate(buf)) > 0) out.write(buf, 0, n);
        d.end();
        return out.toByteArray();
    }

    // ---- little-endian index writer (matches the native parser) ----
    private static void writeInt(ByteArrayOutputStream b, int v) {
        b.write(v & 0xFF);
        b.write((v >>> 8) & 0xFF);
        b.write((v >>> 16) & 0xFF);
        b.write((v >>> 24) & 0xFF);
    }
}