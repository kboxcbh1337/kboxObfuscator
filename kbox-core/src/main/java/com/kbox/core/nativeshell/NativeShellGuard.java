package com.kbox.core.nativeshell;

import com.kbox.core.log.KBoxLog;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Build-time native shell hardening pass ("超越原 kboxShield 的增强版").
 *
 * <p>Applied to the kboxShield-carrying native C source <b>before</b> the toolchain
 * compiles it, so the shipped image (decode/guard logic) carries none of the
 * weaknesses of a plain {@code gcc -O2 -s} build. All transforms are <b>fail-safe</b>:
 * they only touch contexts where the emitted C is provably valid — anything the
 * scanner is unsure about is left byte-for-byte alone, so the transform can never
 * break a valid C translation unit. Levels gate monotonic coverage:</p>
 *
 * <ul>
 *   <li><b>M1 — 全量字符串加密</b> (nativeShell ≥ 1): every <em>function-body</em>
 *       string literal in a safe expression position (function-call arguments,
 *       grouped/returned expressions, function-body assignments) is moved into a
 *       per-build random-XOR static table and referenced through a lazy decrypt
 *       stub, so the running image has no plaintext module/API/path/format
 *       strings. File-scope initializers, aggregate initializers, {@code sizeof()},
 *       array-capacity initializers, adjacent-literal concatenation, wide/raw
 *       literals, comments and preprocessor lines are left alone.</li>
 *   <li><b>M2 — 控制流变异</b> (nativeShell ≥ 2): injects an opaque-predicate
 *       preamble plus a per-build polymorphic NOP sled at the top of the critical
 *       shield functions ({@code kbox_probeVM}/{@code kbox_probeHooks}/
 *       {@code kbox_gateCheck}/{@code kbox_selfDie}/{@code kbox_watchdog}/
 *       {@code kbox_wipeDecodeState}), and splices the hypervisor-vendor FNV
 *       magic constants of {@code kbox_probeVM} into a per-build XOR-masked table
 *       so the 32-bit vendor fingerprints never appear as greppable literals in
 *       {@code .text}.</li>
 *   <li><b>M3 — IAT/导入隐藏</b> (nativeShell ≥ 3): the direct Win32 imports
 *       (VirtualAlloc/VirtualFree/VirtualProtect/CreateThread/CloseHandle/
 *       TerminateProcess/GetCurrentProcess/GetCurrentProcessId/IsDebuggerPresent/
 *       GetModuleHandleExW/LoadLibraryA/WriteProcessMemory) plus the resolution
 *       primitives (GetProcAddress/GetModuleHandleA/GetModuleHandleW) are
 *       redirected through a private resolver that reads the process PEB and each
 *       loaded module's export directory at runtime. No kernel32/ntdll API name
 *       survives in the shipped image's import directory, and API names are held
 *       as per-build XOR ciphertext — so a static import/strings scan no longer
 *       reveals the anti-debug / self-protection surface. M1 plus additionally
 *       covers assignment / return-string expressions at level ≥ 3 too.</li>
 * </ul>
 *
 * <p>Every injected table uses a fresh {@link SecureRandom} key, so two builds of
 * the same source produce byte-different binaries (build-to-build polymorphism on
 * top of the existing KBOX_BF_* / KBOX_HOOKS polymorphism). The native
 * {@code kbox_selfCheck} (whole-image SHA digest on the shipped image) is the
 * M4 shell self-verification layer — it already covers every guard function in
 * this compilation unit, so a single-byte patch of any of them is caught on the
 * next probe/watchdog tick and hard-killed via {@code kbox_selfDie()}.</p>
 */
public final class NativeShellGuard {

    private static final String TAG = "native-shell";
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /* Critical shield functions whose preamble we mutate. The two watchdog forms
     * (Win32 / POSIX) both appear; the signatures below are exact substrings of
     * kbox_bf_loader.c so indexOf targets the right opening brace. */
    private static final String[] GUARD_FNS = {
        "static int kbox_probeVM(void) {",
        "static int kbox_probeHooks(void) {",
        "static int kbox_gateCheck(void) {",
        "static void kbox_selfDie(void) {",
        "static DWORD WINAPI kbox_watchdog(LPVOID arg) {",
        "static void* kbox_watchdog(void* arg) {",
        "static void kbox_wipeDecodeState(void) {",
    };

    /* The seven external-hypervisor vendor fingerprints kbox_probeVM matches.
     * Kept here (Java) and baked into the generated image only in XOR-masked form
     * under a per-build key, so the raw 0x1148211du &-friends never appear in the
     * shipped binary. */
    private static final long[] VENDOR_FNV = {
        0x1148211dL, 0x063611baL, 0x1b350931L, 0xa7c94cb1L,
        0x71fb35c5L, 0xa53286a3L, 0xd7c7c893L
    };

    private static volatile int level = 0;

    private NativeShellGuard() {}

    /** Sets the active hardening level (0..3). Called from the pipeline with the
     *  config's {@code nativeShell} value before any native build. */
    public static void setLevel(int l) { level = Math.max(0, l); }
    public static int level() { return level; }

    /**
     * Returns {@code src} with the native-shell hardening passes applied, or the
     * source unchanged when {@code lvl} is 0. Safe to call on any C source.
     */
    public static String guardSource(String src, int lvl) {
        if (lvl <= 0) return src;
        Ctx ctx = new Ctx(new SecureRandom(), lvl);
        String t = src;
        if (lvl >= 1) t = M1.apply(t, ctx);
        if (lvl >= 2) t = M2.mutate(t, ctx);
        if (lvl >= 3) t = M3.apply(t, ctx);
        String pre = ctx.preamble.toString();
        if (pre.isEmpty()) return t;
        return pre + "\n" + t;
    }

    /** Convenience wrapper reading the static level. */
    public static String guardSource(String src) {
        return guardSource(src, level);
    }

    /* ------------------------------------------------------------------ */
    /* Shared per-invocation state                                         */
    /* ------------------------------------------------------------------ */
    private static final class Ctx {
        final SecureRandom rnd;
        final int lvl;
        final byte[] key = new byte[16];
        final long poly;                       // per-build random for sled/predicate
        final Map<String, Integer> litIndex;   // literal -> table index (content keyed)
        final List<byte[]> litBytes;           // index -> decrypted plaintext bytes
        final StringBuilder preamble = new StringBuilder(1024);
        Ctx(SecureRandom rnd, int lvl) {
            this.rnd = rnd;
            this.lvl = lvl;
            rnd.nextBytes(key);
            this.poly = rnd.nextLong() & 0x7fffffffffffffffL;
            this.litIndex = new LinkedHashMap<>();
            this.litBytes = new ArrayList<>();
        }
        /** Registers a literal's plaintext bytes, returns a stable index. */
        int reg(String content, byte[] bytes) {
            Integer idx = litIndex.get(content);
            if (idx != null) return idx;
            idx = litBytes.size();
            litIndex.put(content, idx);
            litBytes.add(bytes);
            return idx;
        }
    }

    /* ================================================================= */
    /* M1 — full function-body string-literal erasure                     */
    /* ================================================================= */
    private static final class M1 {

        static String apply(String src, Ctx ctx) {
            List<int[]> repl = new ArrayList<>();   // {start, close(exclusive)} to splice
            int n = src.length();
            Deque<Bracket> stack = new ArrayDeque<>();
            int braceDepth = 0;
            int stmtStart = 0;                       // after last ';' '{' '}' (code)
            char lastC = 0, lastC2 = 0;              // two most recent code chars
            String lastWord = "";                    // most recent identifier token
            // Macro identifiers defined to expand to string literals (e.g. the
            // VMP descriptor builder's `#define MR "..."`). A literal adjacent to
            // such a macro participates in compile-time string concatenation and
            // must stay a literal token — turning it into a stub call would break
            // the concatenation. Scan the whole file so a late-concat use site is
            // still caught even though it appears before the prefixed `#define`.
            Set<String> strMacros = collectStrMacros(src);
            int i = 0;
            while (i < n) {
                char c = src.charAt(i);
                // -- whitespace / preprocessor / comments / char literals --
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { i++; continue; }
                if (c == '/') {
                    if (i + 1 < n && src.charAt(i + 1) == '*') { int e = src.indexOf("*/", i + 2); i = e < 0 ? n : e + 2; continue; }
                    if (i + 1 < n && src.charAt(i + 1) == '/') { int e = src.indexOf('\n', i + 2); i = e < 0 ? n : e + 1; continue; }
                }
                if (c == '#') { int e = src.indexOf('\n', i + 1); i = e < 0 ? n : e + 1; continue; }
                if (c == '\'') { i = skipCharLit(src, i); continue; }

                // -- string literal candidate --
                if (c == '"') {
                    int close = findStrClose(src, i);
                    if (close >= 0) {
                        boolean prefixed = i > 0 && (isIdent(src.charAt(i - 1)) || src.charAt(i - 1) == '.' || src.charAt(i - 1) == 'R');
                        if (!prefixed) {
                            int nx = nextSig(src, close + 1);
                            // skip literals participating in string-literal concatenation
                            // (adjacent `"..."` or a macro expanding to a string literal)
                            boolean concatFwd = nx < n && (src.charAt(nx) == '"'
                                    || src.charAt(nx) == '[')
                                    || (nx < n && strMacros.contains(identAt(src, nx)));
                            boolean concatBack = lastWord != null && strMacros.contains(lastWord);
                            if (!concatFwd && !concatBack && braceDepth >= 1) {
                                byte[] bytes = decode(src, i + 1, close);   // null => uncertain
                                if (bytes != null && bytes.length > 0 && isSafeExpr(ctx, lastC, lastWord, stack, src, stmtStart, i)) {
                                    String content = src.substring(i + 1, close);
                                    int idx = ctx.reg(content, bytes);
                                    repl.add(new int[]{i, close + 1, idx});
                                }
                            }
                        }
                    }
                    int cc = close >= 0 ? close + 1 : i + 1;
                    i = cc;
                    continue;
                }

                // -- brackets --
                if (c == '{') {
                    boolean init = (lastC == '=' || lastC == '{' || lastC == ',');
                    stack.push(new Bracket('{', init));
                    braceDepth++;
                    i++; lastC = '{'; lastWord = ""; stmtStart = i; continue;
                }
                if (c == '}') { if (!stack.isEmpty()) stack.pop(); braceDepth--; i++; lastC = '}'; lastWord = ""; stmtStart = i; continue; }
                if (c == '(') {
                    boolean noStr = identBeforeIs(src, i, "sizeof")
                            || identBeforeIs(src, i, "asm")
                            || identBeforeIs(src, i, "__asm")
                            || identBeforeIs(src, i, "__asm__")
                            || asmHead(src, i);
                    stack.push(new Bracket('(', false, noStr));
                    i++; lastC = '('; lastWord = ""; continue;
                }
                if (c == ')') { if (!stack.isEmpty()) stack.pop(); i++; lastC = ')'; lastWord = ""; continue; }
                if (c == '[') { stack.push(new Bracket('[', false)); i++; lastC = '['; lastWord = ""; continue; }
                if (c == ']') { if (!stack.isEmpty()) stack.pop(); i++; lastC = ']'; continue; }
                if (c == ';') { i++; lastC = ';'; lastWord = ""; stmtStart = i; continue; }

                // -- identifiers / punctuation --
                if (isIdent(c)) {
                    int j = i;
                    while (j < n && isIdent(src.charAt(j))) j++;
                    lastC2 = lastC; lastC = src.charAt(j - 1);
                    lastWord = src.substring(i, j);
                    i = j;
                    continue;
                }
                // other punctuation / operators
                lastC2 = lastC;
                lastC = c;
                lastWord = "";
                i++;
            }
            if (repl.isEmpty()) return src;

            StringBuilder out = new StringBuilder(src.length() + 512);
            int pos = 0;
            for (int[] seg : repl) {
                out.append(src, pos, seg[0]);
                out.append(SYM.NAME).append(seg[2]).append("()");
                pos = seg[1];
            }
            out.append(src, pos, src.length());
            emit(out, ctx);
            return out.toString();
        }

        /* True when the literal at src[pos] is in a provably-safe expression
         * position for rewriting to _ksL<i>(). */
        private static boolean isSafeExpr(Ctx ctx, char lastC, String lastWord,
                                          Deque<Bracket> stack, String src, int stmtStart, int pos) {
            Bracket top = stack.peek();
            if (top != null && top.open == '{' && top.aggInit) return false; // aggregate element
            if (top != null && top.open == '[') return false;                // array subscript
            if (top != null && top.open == '(' && top.sizeofParen) return false; // sizeof/asm("...")
            switch (lastC) {
                case '(':
                    return true;   // function argument / grouped expression
                case ',':
                    return top != null && top.open == '(';   // call-arg list (not init list)
                default:
                    break;
            }
            if ("return".equals(lastWord)) return ctx.lvl >= 2;
            if (lastC == '=' && ctx.lvl >= 3 && !stmtHasStatic(src, stmtStart, pos)) return true;
            return false;
        }

        private static boolean stmtHasStatic(String src, int from, int to) {
            if (from < 0) from = 0;
            int k = src.lastIndexOf("static", to);
            return k >= from;
        }

        /** True if the '(' at pos belongs to an inline-asm statement such as
         *  {@code __asm__ volatile(...)} / {@code asm [volatile] (stmt)} — those
         *  require a compile-time string-literal operand, so any string inside
         *  must NOT be rewritten. Scans back up to a few qualifier words. */
        private static boolean asmHead(String s, int pos) {
            int j = pos;
            for (int k = 0; k < 4 && j > 0; k++) {
                int e = j;
                while (e - 1 >= 0 && isIdent(s.charAt(e - 1))) e--;
                if (e == j) return false;               // no identifier before '('
                String w = s.substring(e, j);
                if (w.equals("asm") || w.equals("__asm") || w.equals("__asm__")) return true;
                j = e;
                int m = j;
                while (m - 1 >= 0 && (s.charAt(m - 1) == ' ' || s.charAt(m - 1) == '\t'
                        || s.charAt(m - 1) == '\n')) m--;
                if (m == j) return false;
                j = m;
            }
            return false;
        }

        /* --- C lexical helpers --- */
        private static boolean isIdent(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
        }

        /** Index of the closing '"' for the literal opening at q, honoring '\\'. */
        private static int findStrClose(String s, int q) {
            int i = q + 1;
            while (i < s.length()) {
                char c = s.charAt(i);
                if (c == '\\') { i += 2; continue; }
                if (c == '"') return i;
                i++;
            }
            return -1;
        }

        private static int skipCharLit(String s, int i) {
            int j = i + 1;
            while (j < s.length()) {
                char c = s.charAt(j);
                if (c == '\\') { j += 2; continue; }
                if (c == '\'') return j + 1;
                j++;
            }
            return i + 1;
        }

        private static int nextSig(String s, int from) {
            int j = from;
            while (j < s.length()) {
                char c = s.charAt(j);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { j++; continue; }
                if (c == '/' && j + 1 < s.length() && s.charAt(j + 1) == '*') { int e = s.indexOf("*/", j + 2); j = e < 0 ? s.length() : e + 2; continue; }
                if (c == '/' && j + 1 < s.length() && s.charAt(j + 1) == '/') { int e = s.indexOf('\n', j + 2); j = e < 0 ? s.length() : e + 1; continue; }
                return j;
            }
            return s.length();
        }

        /** Reads the identifier token starting at {@code pos}, or "" if none. */
        private static String identAt(String s, int pos) {
            if (pos < 0 || pos >= s.length()) return "";
            char c = s.charAt(pos);
            if (!isIdent(c)) return "";
            int j = pos;
            while (j < s.length() && isIdent(s.charAt(j))) j++;
            return s.substring(pos, j);
        }

        /** Names of macros defined to expand into a string literal, e.g.
         *  {@code #define MR "Lcom/..."}. Such macros, when written adjacent to a
         *  string literal, make that literal part of a compile-time concatenation
         *  (never turn a concat participant into a stub call). */
        private static Set<String> collectStrMacros(String src) {
            Set<String> out = new HashSet<>();
            int i = 0, n = src.length();
            while (i < n) {
                char c = src.charAt(i);
                if (c == '#') {
                    int e = src.indexOf('\n', i + 1);
                    int lineEnd = (e < 0) ? n : e;
                    String line = i + 1 < lineEnd ? src.substring(i + 1, lineEnd) : "";
                    int w = 0;
                    while (w < line.length() && (line.charAt(w) == ' ' || line.charAt(w) == '\t')) w++;
                    String rest = line.substring(w);
                    if (rest.startsWith("define")) {
                        String after = rest.substring(6);
                        int k = 0;
                        while (k < after.length() && (after.charAt(k) == ' ' || after.charAt(k) == '\t')) k++;
                        int idEnd = k;
                        while (idEnd < after.length() && isIdent(after.charAt(idEnd))) idEnd++;
                        String name = after.substring(k, idEnd);
                        int q = idEnd;
                        while (q < after.length() && (after.charAt(q) == ' ' || after.charAt(q) == '\t')) q++;
                        String afterNs = q < after.length() ? after.substring(q) : "";
                        // optional parenthesized params handled by rejecting '(' right after name
                        if (!name.isEmpty() && !afterNs.isEmpty() && afterNs.charAt(0) == '"') {
                            out.add(name);
                        }
                    }
                    i = (e < 0) ? n : e + 1;
                } else {
                    i++;
                }
            }
            return out;
        }

        /** True if the identifier token ending right before '(' at pos is {@code word}. */
        private static boolean identBeforeIs(String s, int pos, String word) {
            int j = pos;
            while (j - 1 >= 0 && isIdent(s.charAt(j - 1))) j--;
            return pos - j == word.length() && s.regionMatches(j, word, 0, word.length());
        }

        private static char prev2(char cur, char old) { return cur; }

        /** Decodes the raw body between (open+1, close) into the exact bytes the
         *  compiler would emit for the literal. Returns null when uncertain (raw
         *  high bytes, unknown escapes, universal chars) so we skip the literal. */
        private static byte[] decode(String s, int open, int close) {
            List<Byte> out = new ArrayList<>();
            int i = open;
            while (i < close) {
                char c = s.charAt(i);
                if (c != '\\') {
                    if (c > 0x7F) return null;
                    out.add((byte) c);
                    i++;
                    continue;
                }
                // escape
                if (i + 1 >= close) return null;
                char e = s.charAt(i + 1);
                if (e == 'u' || e == 'U') return null;   // universal character name
                int code = simpleEsc(e);
                if (code >= 0) {
                    out.add((byte) code);
                    i += 2;
                    continue;
                }
                if (e == 'x') {
                    int j = i + 2, v = 0, cnt = 0;
                    while (j < close && cnt < 2) {
                        int d = hexDigit(s.charAt(j));
                        if (d < 0) break;
                        v = (v << 4) | d;
                        cnt++; j++;
                    }
                    if (cnt == 0) return null;
                    out.add((byte) v);
                    i = j;
                    continue;
                }
                if (e >= '0' && e <= '7') {
                    int j = i + 1, v = 0, cnt = 0;
                    while (j < close && cnt < 3 && s.charAt(j) >= '0' && s.charAt(j) <= '7') {
                        v = (v << 3) | (s.charAt(j) - '0');
                        cnt++; j++;
                    }
                    out.add((byte) v);
                    i = j;
                    continue;
                }
                return null;   // unknown escape -> skip literal
            }
            byte[] a = new byte[out.size()];
            for (int k = 0; k < a.length; k++) a[k] = out.get(k);
            return a;
        }

        private static int simpleEsc(char e) {
            switch (e) {
                case 'n': return 0x0A;
                case 't': return 0x09;
                case 'r': return 0x0D;
                case '0': return 0x00;
                case 'a': return 0x07;
                case 'b': return 0x08;
                case 'f': return 0x0C;
                case 'v': return 0x0B;
                case '\\': return 0x5C;
                case '\'': return 0x27;
                case '"': return 0x22;
                case '?': return 0x3F;
                case 'e': return 0x1B;
                default: return -1;
            }
        }

        private static int hexDigit(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }

        /** Emits the key + per-literal ciphertext + lazy decrypt stubs into the
         *  preamble, which is prepended before the (now encrypted) source. */
        private static void emit(StringBuilder out, Ctx ctx) {
            if (ctx.litBytes.isEmpty()) return;
            StringBuilder t = new StringBuilder(2048 + ctx.litBytes.size() * 96);
            t.append("/* KBox native-shell M1: encrypted function-body strings. */\n");
            t.append("static const unsigned char ").append(SYM.KEY).append("[16] = {")
              .append(hexArray(ctx.key)).append("};\n");
            for (int idx = 0; idx < ctx.litBytes.size(); idx++) {
                byte[] p = ctx.litBytes.get(idx);
                byte[] c = new byte[p.length];
                for (int j = 0; j < p.length; j++) c[j] = (byte) (p[j] ^ ctx.key[j & 15]);
                t.append("static const unsigned char ").append(SYM.CT).append(idx)
                 .append('[').append(c.length).append("]={").append(hexArray(c)).append("};\n");
                t.append("static char ").append(SYM.PT).append(idx).append('[')
                 .append(p.length + 1).append("];\n");
                t.append("static unsigned char ").append(SYM.FLG).append(idx).append(";\n");
                t.append("static const char* ").append(SYM.NAME).append(idx).append("(void){int _k=0;if(!")
                 .append(SYM.FLG).append(idx).append("){for(_k=0;_k<").append(c.length)
                 .append(";_k++)((unsigned char*)").append(SYM.PT).append(idx)
                 .append(")[_k]=").append(SYM.CT).append(idx).append("[_k]^").append(SYM.KEY)
                 .append("[_k&15];").append(SYM.PT).append(idx).append('[').append(p.length)
                 .append("]=0;").append(SYM.FLG).append(idx).append("=1;}return ")
                 .append(SYM.PT).append(idx).append(";}\n");
            }
            ctx.preamble.append(t);
        }

        private static String hexArray(byte[] a) {
            StringBuilder sb = new StringBuilder(a.length * 5);
            for (int i = 0; i < a.length; i++) {
                if (i > 0) sb.append(',');
                sb.append("0x").append(HEX[(a[i] >>> 4) & 0xF]).append(HEX[a[i] & 0xF]);
            }
            return sb.toString();
        }
    }

    /* Generated symbol base names (compact, unlikely to collide with the C file). */
    private static final class SYM {
        static final String KEY   = "_ksK";
        static final String CT    = "_ks_C";
        static final String PT    = "_ks_D";
        static final String FLG   = "_ks_F";
        static final String NAME  = "_ksL";
        /* M3 manual-IAT resolver symbols. */
        static final String K3KEY  = "_ks3K";
        static final String K3DATA = "_ks3D";
        static final String K3OFF  = "_ks3O";
        static final String K3LEN  = "_ks3L";
        static final String K3PT   = "_ks3P";
        static final String K3SLOT = "_ks3S";
        static final String K3CACHE= "_ks3C";
        static final String K3CH   = "_ks3H";
    }

    /** A bracket context used to classify literals. */
    private static final class Bracket {
        final char open;
        final boolean aggInit;   // '{' that began an aggregate initializer (= {, {, , {)
        final boolean sizeofParen;
        Bracket(char open, boolean init) { this.open = open; this.aggInit = init; this.sizeofParen = false; }
        Bracket(char open, boolean init, boolean sizeofParen) { this.open = open; this.aggInit = init; this.sizeofParen = sizeofParen; }
    }

    /* ================================================================= */
    /* M2 — control-flow mutation + vendor-constant scattering            */
    /* ================================================================= */
    private static final class M2 {

        static String mutate(String src, Ctx ctx) {
            String t = src;
            for (String sig : GUARD_FNS) t = injectPreamble(t, sig, ctx);
            t = scrambleVendor(t, ctx);
            return t;
        }

        private static String injectPreamble(String src, String sig, Ctx ctx) {
            int at = src.indexOf(sig);
            if (at < 0) return src;
            int brace = src.indexOf('{', at);
            if (brace < 0) return src;
            return src.substring(0, brace + 1) + "\n" + preamble(ctx) + src.substring(brace + 1);
        }

        /** Opaque-predicate preamble + polymorphic NOP sled (per-build). */
        private static String preamble(Ctx ctx) {
            long x = ctx.poly;
            long b = (x * 0x9E3779B97F4A7C15L) & 0xFF;
            long v0 = 0x411ecfL ^ (x & 0xFF);
            long mul = 0x2545F491L + (x & 0x1F) * 3;
            StringBuilder t = new StringBuilder(1024);
            t.append("  /* KBox native-shell opaque preamble (per-build). */\n");
            t.append("  { volatile long long _ks_ob = ").append(v0).append(";\n");
            t.append("    _ks_ob = (_ks_ob * ").append(mul).append(" + ").append(b).append(") & 0x7fffffff;\n");
            t.append("    if ((_ks_ob & 1) != 0) { _ks_ob = _ks_ob + 1 - 1; }\n");
            int nps = 3 + (int) (x % 4);
            for (int i = 0; i < nps; i++) {
                long r = (x >>> (i % 8)) & 0x1F;
                if (r < 8) t.append("    (void)(_ks_ob + ").append(i + 1).append(");\n");
                else       t.append("    _ks_ob ^= (long long)").append(r * 3 + 1).append(";\n");
            }
            t.append("    (void)_ks_ob;\n");
            t.append("  }\n");
            return t.toString();
        }

        /** Replaces kbox_probeVM's vendor literal switch with a runtime-masked
         *  if-chain so the 32-bit vendor fingerprints vanish from .text. */
        private static String scrambleVendor(String src, Ctx ctx) {
            String sw = "switch (kbox_fnv32(vnd, 12)) {";
            int s = src.indexOf(sw);
            if (s < 0) return src;
            String close = "default: break;";
            int dc = src.indexOf(close, s);
            if (dc < 0) return src;
            int brace = src.indexOf('}', dc + close.length());
            if (brace < 0 || brace <= s) return src;

            long[] mk = new long[VENDOR_FNV.length];
            for (int i = 0; i < mk.length; i++) mk[i] = (ctx.rnd.nextLong() & 0xFFFFFFFFL);
            StringBuilder t = new StringBuilder(1024);
            t.append("  /* KBox native-shell M2b: vendor fingerprints masked at runtime. */\n");
            t.append("  { static const uint32_t _mo[7]={");
            for (int i = 0; i < VENDOR_FNV.length; i++) {
                if (i > 0) t.append(',');
                t.append("0x").append(String.format("%08x", VENDOR_FNV[i] ^ mk[i])).append("u");
            }
            t.append("};\n");
            t.append("    static const uint32_t _mkv[7]={");
            for (int i = 0; i < mk.length; i++) {
                if (i > 0) t.append(',');
                t.append("0x").append(String.format("%08x", mk[i])).append("u");
            }
            t.append("};\n");
            t.append("    uint32_t _ks_fv=kbox_fnv32(vnd,12);\n");
            for (int i = 0; i < VENDOR_FNV.length; i++) {
                t.append("    if (_ks_fv==(_mo[").append(i).append("]^_mkv[").append(i).append("])) return 1;\n");
            }
            t.append("    return 0;\n  }\n");
            return src.substring(0, s) + t + src.substring(brace + 1);
        }
    }

    /* ================================================================= */
    /* M3 — IAT hiding: private manual import resolution                  */
    /*                                                                    */
    /* Replaces direct kernel32/ntdll imports with a PEB-walking resolver  */
    /* so no API name appears in the shipped image's import directory.    */
    /* Injected right after `#include <windows.h>` (types are available), */
    /* before any other code / reflective include that calls Win32.        */
    /* ================================================================= */
    private static final class M3 {

        /* kernel32-resolved (fixed-name) API set — each becomes a kimp_ wrapper. */
        private static final String[] API = {
            "VirtualAlloc", "VirtualFree", "VirtualProtect",
            "CreateThread", "CloseHandle", "TerminateProcess",
            "GetCurrentProcess", "GetCurrentProcessId", "IsDebuggerPresent",
            "GetModuleHandleExW", "LoadLibraryA", "WriteProcessMemory",
            /* L3 probe additions — DR7 hw-breakpoint scan + page-attr recheck. */
            "GetCurrentThread", "GetThreadContext", "VirtualQuery",
        };
        /* module names used to locate kernel32 (fallback kernelbase). */
        private static final String[] MOD = { "kernel32.dll", "kernelbase.dll" };
        /* specials — resolved semantically, no fixed ciphertext entry needed. */
        private static final String[] SPECIAL = {
            "GetProcAddress", "GetModuleHandleA", "GetModuleHandleW",
        };

        static String apply(String src, Ctx ctx) {
            int at = src.indexOf("#include <windows.h>");
            if (at < 0) return src;                 // non-Windows (or no OS headers)
            int nl = src.indexOf('\n', at);
            int ins = (nl < 0) ? at + 20 : nl + 1;  // after the include line
            return src.substring(0, ins) + build(ctx) + src.substring(ins);
        }

        private static String[] all() {
            String[] a = new String[API.length + MOD.length];
            System.arraycopy(API, 0, a, 0, API.length);
            System.arraycopy(MOD, 0, a, API.length, MOD.length);
            return a;
        }

        private static String build(Ctx ctx) {
            String[] all = all();
            int e = all.length;
            int[] off = new int[e], len = new int[e];
            int total = 0;
            for (int i = 0; i < e; i++) { len[i] = all[i].length(); off[i] = total; total += len[i]; }
            byte[] key = ctx.key;
            StringBuilder sb = new StringBuilder(4096 + total * 6);
            sb.append("\n#if defined(_WIN32)\n");
            sb.append("/* ===== KBox native-shell M3: manual IAT (private resolver) ===== */\n");
            sb.append("/* No kernel32/ntdll API name is imported directly; every call is\n");
            sb.append("   resolved at runtime off the PEB + export directories. Keys,\n");
            sb.append("   ciphertext and slot layout change per build. */\n");
            sb.append("static unsigned kksfnvstr(const char* s){unsigned h=0x811c9dc5u;if(!s)return h;for(;*s;s++){unsigned char c=(unsigned char)*s;if(c>='A'&&c<='Z')c=(unsigned char)(c+32);h=(h^c)*0x01000193u;}return h;}\n");
            sb.append("static unsigned kksfnvmod(const unsigned short*w,int n){unsigned h=0x811c9dc5u;for(int i=0;i<n;i++){unsigned c=w[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return h;}\n");
            sb.append("static const unsigned char ").append(SYM.K3KEY).append("[16]={").append(hex(key)).append("};\n");
            sb.append("static const unsigned char ").append(SYM.K3DATA).append('[').append(total)
              .append("]={").append(cipher(all, off, len, key)).append("};\n");
            sb.append("static const unsigned short ").append(SYM.K3OFF).append("[").append(e).append("]={");
            for (int i = 0; i < e; i++) { if (i > 0) sb.append(','); sb.append(off[i]); }
            sb.append("};\n");
            sb.append("static const unsigned char ").append(SYM.K3LEN).append('[').append(e).append("]={");
            for (int i = 0; i < e; i++) { if (i > 0) sb.append(','); sb.append(len[i]); }
            sb.append("};\n");
            sb.append("static char ").append(SYM.K3PT).append('[').append(total + 1).append("];\n");
            sb.append("static void* ").append(SYM.K3SLOT).append('[').append(e).append("];\n");
            sb.append("static void* ").append(SYM.K3CACHE).append(";static unsigned ").append(SYM.K3CH)
              .append(";\n");
            // ksDec
            sb.append("static const char* ksDec(int i){int o=").append(SYM.K3OFF)
              .append("[i],l=").append(SYM.K3LEN).append("[i],j;for(j=0;j<l;j++)")
              .append(SYM.K3PT).append("[o+j]=(char)(").append(SYM.K3DATA)
              .append("[o+j]^").append(SYM.K3KEY).append("[(o+j)&15]);")
              .append(SYM.K3PT).append("[o+l]=0;return ").append(SYM.K3PT).append("+o;}\n");
            // ksGetModByHash (PEB walk)
            sb.append("static void* ksGetModByHash(unsigned target){\n");
            sb.append("  if(").append(SYM.K3CACHE).append("&&").append(SYM.K3CH).append("==target)return ")
              .append(SYM.K3CACHE).append(";\n");
            sb.append("  void*peb=0;\n#if defined(_WIN64)\n");
            sb.append("  __asm__ __volatile__(\"movq %%gs:0x60,%0\":\"=r\"(peb));\n");
            sb.append("  enum{LDR_OFF=0x18,INLOAD=0x10,DL=0x30,SLEN=0x58,SBUF=0x60};\n#else\n");
            sb.append("  __asm__ __volatile__(\"movl %%fs:0x30,%0\":\"=r\"(peb));\n");
            sb.append("  enum{LDR_OFF=0x0C,INLOAD=0x0C,DL=0x18,SLEN=0x24,SBUF=0x28};\n#endif\n");
            sb.append("  if(!peb)return 0;\n  void*ldr=*(void**)((unsigned char*)peb+LDR_OFF);\n");
            sb.append("  if(!ldr)return 0;\n  unsigned char*head=(unsigned char*)ldr+INLOAD;\n");
            sb.append("  unsigned char*cur=*(unsigned char**)head;\n");
            sb.append("  for(int k=0;cur&&cur!=head&&k<1024;k++,cur=*(unsigned char**)cur){\n");
            sb.append("    void*db=*(void**)(cur+DL);\n");
            sb.append("    if(db){unsigned short ln=*(unsigned short*)(cur+SLEN);\n");
            sb.append("      unsigned short*bf=*(unsigned short**)(cur+SBUF);\n");
            sb.append("      if(bf&&ln>=2&&kksfnvmod(bf,ln>>1)==target){")
              .append(SYM.K3CACHE).append("=db;").append(SYM.K3CH).append("=target;return db;}}\n");
            sb.append("  }\n  return 0;\n}\n");
            // ksExpByName (export directory parse, follows forwarder exports)
            sb.append("static void* ksExpByNameD(void*mod,const char*name,int depth){\n");
            sb.append("  if(!mod||!name||depth>=8)return 0;\n");
            sb.append("  IMAGE_DOS_HEADER*dos=(IMAGE_DOS_HEADER*)mod;\n");
            sb.append("  if(dos->e_magic!=IMAGE_DOS_SIGNATURE)return 0;\n");
            sb.append("  IMAGE_NT_HEADERS*nt=(IMAGE_NT_HEADERS*)((unsigned char*)mod+dos->e_lfanew);\n");
            sb.append("  if(nt->Signature!=IMAGE_NT_SIGNATURE)return 0;\n");
            sb.append("  IMAGE_DATA_DIRECTORY*dd=&nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];\n");
            sb.append("  if(!dd->VirtualAddress||!dd->Size)return 0;\n");
            sb.append("  IMAGE_EXPORT_DIRECTORY*ed=(IMAGE_EXPORT_DIRECTORY*)((unsigned char*)mod+dd->VirtualAddress);\n");
            sb.append("  const DWORD*fns=(const DWORD*)((unsigned char*)mod+ed->AddressOfFunctions);\n");
            sb.append("  const DWORD*nms=(const DWORD*)((unsigned char*)mod+ed->AddressOfNames);\n");
            sb.append("  const WORD*ords=(const WORD*)((unsigned char*)mod+ed->AddressOfNameOrdinals);\n");
            sb.append("  DWORD i,lo=dd->VirtualAddress,hi=dd->VirtualAddress+dd->Size;\n");
            sb.append("  for(i=0;i<ed->NumberOfNames;i++){\n");
            sb.append("    const char*nm2=(const char*)((unsigned char*)mod+nms[i]);\n");
            sb.append("    if(strcmp(nm2,name)==0){\n");
            sb.append("      DWORD rva=fns[ords[i]];\n");
            sb.append("      if(rva>=nt->OptionalHeader.SizeOfImage)return 0;\n");
            sb.append("      /* Forwarder export (kernel32 -> kernelbase on modern Win): the\n");
            sb.append("         function RVA lies inside the export-data section and holds a\n");
            sb.append("         \"DLL.Function\" string. Calling it directly would jump into a\n");
            sb.append("         non-executable page (DEP fault); chase the real target instead. */\n");
            sb.append("      if(rva>=lo&&rva<hi){\n");
            sb.append("        const char*fwd=(const char*)((unsigned char*)mod+rva);\n");
            sb.append("        const char*dot=fwd?strchr(fwd,'.'):0;\n");
            sb.append("        if(dot&&dot>fwd&&dot[1]){\n");
            sb.append("          char mb[80];DWORD j,L=(DWORD)(dot-fwd);\n");
            sb.append("          if(L>=sizeof(mb)-4)return 0;\n");
            sb.append("          for(j=0;j<L;j++)mb[j]=fwd[j];\n");
            sb.append("          /* Forwarder module name is bare (\"KERNELBASE\", no extension) but\n");
            sb.append("             the PEB lists the loaded image as \"kernelbase.dll\"; append the\n");
            sb.append("             suffix unless the name already carries a '.' extension. */\n");
            sb.append("          if(L<4||mb[L-4]!='.'){mb[L]='.';mb[L+1]='d';mb[L+2]='l';mb[L+3]='l';L+=4;}\n");
            sb.append("          mb[L]=0;\n");
            sb.append("          void*m=ksGetModByHash(kksfnvstr(mb));\n");
            sb.append("          if(m)return ksExpByNameD(m,dot+1,depth+1);\n");
            sb.append("        }\n");
            sb.append("        return 0;\n");
            sb.append("      }\n");
            sb.append("      return (void*)((unsigned char*)mod+rva);\n");
            sb.append("    }\n");
            sb.append("  }\n  return 0;\n}\n");
            sb.append("static void* ksExpByName(void*mod,const char*name){return ksExpByNameD(mod,name,0);}\n");
            // ksK32 + ksProc
            sb.append("static void* ksK32(void){void*b;b=ksGetModByHash(kksfnvstr(ksDec(").append(API.length)
              .append(")));if(b)return b;return ksGetModByHash(kksfnvstr(ksDec(").append(API.length + 1).append(")));}\n");
            sb.append("static void* ksProc(int i){void*p=").append(SYM.K3SLOT)
              .append("[i];if(!p){const char*s=ksDec(i);char nm[64];int j=0;")
              .append("while((nm[j]=s[j])&&j+1<63)j++;nm[j]=0;void*k32=ksK32();")
              .append("if(k32)p=ksExpByName(k32,nm);")
              .append(SYM.K3SLOT).append("[i]=p;}return p;}\n");
            // enum indices
            sb.append("enum{");
            for (int i = 0; i < e; i++) { if (i > 0) sb.append(','); sb.append("KS_I_").append(i); }
            sb.append("};\n");
            // #define redirection
            for (String s : API) sb.append("#define ").append(s).append(" kimp_").append(s).append("\n");
            for (String s : SPECIAL) sb.append("#define ").append(s).append(" kimp_").append(s).append("\n");
            // wrappers: one per API, signatures matched to the real Win32 prototypes.
            sb.append(wrappers(API));
            // special semantic wrappers
            sb.append("static __attribute__((unused)) void* kimp_GetModuleHandleA(const char*name){return name?ksGetModByHash(kksfnvstr(name)):0;}\n");
            sb.append("static __attribute__((unused)) void* kimp_GetModuleHandleW(const unsigned short*name){if(!name)return 0;unsigned h=0x811c9dc5u;for(int i=0;name[i];i++){unsigned c=name[i];if(c>='A'&&c<='Z')c+=32;h=(h^(c&0xFF))*0x01000193u;}return ksGetModByHash(h);}\n");
            sb.append("static __attribute__((unused)) void* kimp_GetProcAddress(void*mod,const char*name){return ksExpByName(mod,name);}\n");
            sb.append("#endif\n");
            return sb.toString();
        }

        /* Fixed-signature wrappers; returns a C translation-unit fragment.
         * Each entry: {name, returnType, paramTypesCSV}. Param types are chosen so
         * every call site in the shielded translation units (which were written
         * against the real Win32 prototypes) matches implicitly:
         *   - single/out pointers are typed `void*`  (any `T*`/fn-ptr -> void*)
         *   - scalar DWORD/USIZE values are `unsigned long`/`size_t`
         * The internal function-pointer cast is derived from the SAME types, so no
         * `-Wincompatible-pointer-types` can arise between the decl and the call. */
        private static String wrappers(String[] api) {
            String[][] sig = {
                {"VirtualAlloc",        "void*",    "void*,size_t,unsigned long,unsigned long"},
                {"VirtualFree",         "int",      "void*,size_t,unsigned long"},
                {"VirtualProtect",      "int",      "void*,size_t,unsigned long,unsigned long*"},
                {"CreateThread",        "void*",    "void*,void*,void*,void*,void*,void*"},
                {"CloseHandle",         "int",      "void*"},
                {"TerminateProcess",    "int",      "void*,unsigned"},
                {"GetCurrentProcess",   "void*",    ""},
                {"GetCurrentProcessId", "unsigned", ""},
                {"IsDebuggerPresent",   "int",      ""},
                {"GetModuleHandleExW",  "int",      "unsigned long,const void*,void*"},
                {"LoadLibraryA",        "void*",    "const char*"},
                {"WriteProcessMemory",  "int",      "void*,void*,const void*,size_t,size_t*"},
                /* L3 additions: HANDLE is void*; CONTEXT and MBI structs are
                   void* (opaque at the wrapper layer); VirtualQuery returns
                   SIZE_T (size_t) and takes (LPCVOID, PMEMORY_BASIC_INFORMATION,
                   SIZE_T). */
                {"GetCurrentThread",    "void*",    ""},
                {"GetThreadContext",    "int",      "void*,void*"},
                {"VirtualQuery",        "size_t",   "const void*,void*,size_t"},
            };
            StringBuilder sb = new StringBuilder(2048);
            for (String[] s : sig) sb.append(fixedWrapper(s));
            return sb.toString();
        }

        /* One wrapper: (Ret) kimp_Name(P0 a,P1 b,...){ void*_kf=ksProc(KS_I_i);
         *   if(!_kf)return 0; return ((Ret(*)(P0,P1,...))_kf)(a,b,...); }
         * The resolvers local is `_kf` so it can never collide with a parameter
         * that happens to be named `f` (e.g. CreateThread's `... unsigned*f`). */
        private static String fixedWrapper(String[] s) {
            String name = s[0], ret = s[1], cast = s[2];   // params fully derived from cast
            StringBuilder b = new StringBuilder(256);
            b.append("static __attribute__((unused)) ").append(ret).append(" kimp_").append(name)
             .append('(').append(paramDecls(cast)).append("){void*_kf=ksProc(KS_I_")
             .append(idxOf(name)).append(");if(!_kf)return 0;\n  return ((")
             .append(ret).append("(*)(").append(cast.isEmpty() ? "void" : cast)
             .append("))_kf)(").append(argNames(cast)).append(");}\n");
            return b.toString();
        }

        /* "T0,T1,T2" -> "T0 a,T1 b,T2 c". */
        private static String paramDecls(String cast) {
            if (cast.isEmpty()) return "";
            String[] ts = cast.split(",");
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < ts.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(ts[i].trim()).append(' ').append((char) ('a' + i));
            }
            return sb.toString();
        }

        private static int idxOf(String name) {
            for (int i = 0; i < API.length; i++) if (API[i].equals(name)) return i;
            return -1;
        }

        private static String argNames(String cast) {
            if (cast.isEmpty()) return "";
            StringBuilder sb = new StringBuilder();
            int n = cast.split(",").length;
            for (int i = 0; i < n; i++) { if (i > 0) sb.append(','); sb.append((char) ('a' + i)); }
            return sb.toString();
        }

        private static String cipher(String[] all, int[] off, int[] len, byte[] key) {
            StringBuilder sb = new StringBuilder();
            int g = 0;
            for (int i = 0; i < all.length; i++) {
                for (int j = 0; j < len[i]; j++, g++) {
                    if (g > 0) sb.append(',');
                    int c = all[i].charAt(j) & 0xFF;
                    sb.append("0x").append(hex1((c ^ key[g & 15]) & 0xFF));
                }
            }
            return sb.toString();
        }

        private static String hex(byte[] a) {
            StringBuilder sb = new StringBuilder(a.length * 5);
            for (int i = 0; i < a.length; i++) { if (i > 0) sb.append(','); sb.append("0x").append(hex1(a[i] & 0xFF)); }
            return sb.toString();
        }

        private static String hex1(int v) { return new String(new char[]{ HEX[(v >>> 4) & 0xF], HEX[v & 0xF] }); }
    }

    /* Engine bootstrap helper used once at pipeline start (see ProtectionPipeline). */
    public static void pump(int lvl) {
        setLevel(lvl);
        if (lvl > 0) KBoxLog.info(TAG, "Native shell hardening level " + lvl + " active (M1 strings"
                + (lvl >= 2 ? " + M2 control-flow/vendor" : "")
                + (lvl >= 3 ? " + M3 IAT-hiding/import-erasure" : "") + ")");
    }
}