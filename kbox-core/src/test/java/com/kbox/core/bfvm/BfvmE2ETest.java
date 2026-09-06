package com.kbox.core.bfvm;

import org.junit.Test;

import javax.tools.ToolProvider;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * End-to-end test (ported from the standalone kbox-bfvm module): compiles real Java
 * sources with javac, converts every eligible method body into a Brainfuck program via
 * {@link BfVm}, loads the transformed classes and verifies they behave identically to
 * the original JVM bytecode. Exercises the full build ({@code BfMethodCompiler} +
 * {@code BfProgramWriter}) and runtime ({@code BfInterpreter} + {@code VmCore}) path.
 */
public class BfvmE2ETest {

    private static final String CALC =
            "package com.kbox.core.bfvm.fixture;\n"
                    + "public class Calc {\n"
                    + "  public static int add(int a,int b){ return a+b; }\n"
                    + "  public static int sub(int a,int b){ return a-b; }\n"
                    + "  public static int mul(int a,int b){ return a*b; }\n"
                    + "  public static int div(int a,int b){ return a/b; }\n"
                    + "  public static int rem(int a,int b){ return a%b; }\n"
                    + "  public static int neg(int a){ return -a; }\n"
                    + "  public static int shl(int a,int b){ return a<<b; }\n"
                    + "  public static int ushr(int a,int b){ return a>>>b; }\n"
                    + "  public static int and(int a,int b){ return a&b; }\n"
                    + "  public static int or(int a,int b){ return a|b; }\n"
                    + "  public static int xor(int a,int b){ return a^b; }\n"
                    + "  public static long ladd(long a,long b){ return a+b; }\n"
                    + "  public static float fdiv(float a,float b){ return a/b; }\n"
                    + "  public static double dmul(double a,double b){ return a*b; }\n"
                    + "  public static int max(int a,int b){ return a>b?a:b; }\n"
                    + "  public static int abs(int a){ return a<0?-a:a; }\n"
                    + "  public static int fact(int n){ int r=1; for(int i=2;i<=n;i++) r*=i; return r; }\n"
                    + "  public static int fib(int n){ return n<=1?n:fib(n-1)+fib(n-2); }\n"
                    + "  public static String concat(int a,int b){ return \"sum=\"+a+\"+\"+b; }\n"
                    + "  public static int sumChars(String s){ int t=0; for(int i=0;i<s.length();i++){ t += s.charAt(i); } return t; }\n"
                    + "  public static boolean isEven(int n){ return (n&1)==0; }\n"
                    + "  public static int arrLen(int[] a){ return a.length; }\n"
                    + "  public static int sumArr(int[] a){ int s=0; for(int x:a) s+=x; return s; }\n"
                    + "  public static int[] range(int n){ int[] r=new int[n]; for(int i=0;i<n;i++) r[i]=i; return r; }\n"
                    + "  public static long conv(int a){ long l=a; double d=l; return (long)d; }\n"
                    + "  public static boolean isString(Object o){ return o instanceof String; }\n"
                    + "  public static String cast(Object o){ return (String)o; }\n"
                    + "  public static int pick(int x){ switch(x){ case 0: return 10; case 1: return 20; default: return -1; } }\n"
                    + "  public static long lcmp(long a,long b){ return a<b?-1:(a>b?1:0); }\n"
                    + "  public static String[] box(){ return new String[]{\"a\",\"b\",\"c\"}; }\n"
                    + "  public static String boxGet(int i){ return box()[i]; }\n"
                    + "  public static int stat;\n"
                    + "  public static void setStat(int v){ stat=v; }\n"
                    + "  public static int getStat(){ return stat; }\n"
                    + "  public static void main(String[] a){ System.out.println(\"RES=\"+concat(3,4)); }\n"
                    + "}\n";

    private static final String PT =
            "package com.kbox.core.bfvm.fixture;\n"
                    + "public class Pt {\n"
                    + "  public int x; public int y;\n"
                    + "  public Pt(int x,int y){ this.x=x; this.y=y; }\n"
                    + "  public int sum(){ return x+y; }\n"
                    + "  public static int sumOf(Pt p){ return p.x+p.y; }\n"
                    + "  public void set(int x,int y){ this.x=x; this.y=y; }\n"
                    + "  public String describe(){ return \"(\"+x+\",\"+y+\")\"; }\n"
                    + "}\n";

    @Test
    public void convertsAllEligibleMethods() throws Exception {
        Map<String, byte[]> orig = compile(CALC, PT);
        BfVmResult calc = BfVm.protect(orig.get("com.kbox.core.bfvm.fixture.Calc"));
        assertTrue(calc.transformed.contains("add(II)I"));
        assertTrue(calc.transformed.contains("fib(I)I"));
        assertTrue(calc.transformed.contains("fact(I)I"));
        assertTrue(calc.transformed.contains("concat(II)Ljava/lang/String;"));
        assertTrue(calc.transformed.contains("main([Ljava/lang/String;)V"));
        assertTrue(calc.transformed.contains("pick(I)I"));
        assertTrue(calc.transformed.contains("box()[Ljava/lang/String;"));
        // only <clinit> may be skipped; nothing else should be
        for (String s : calc.skipped) {
            assertTrue("unexpected skip: " + s, s.startsWith("<clinit>"));
        }
        BfVmResult pt = BfVm.protect(orig.get("com.kbox.core.bfvm.fixture.Pt"));
        assertTrue(pt.transformed.contains("sum()I"));
        assertTrue(pt.transformed.contains("describe()Ljava/lang/String;"));
        for (String s : pt.skipped) {
            assertTrue("unexpected skip: " + s, s.startsWith("<init>"));
        }
    }

    @Test
    public void staticArithmeticRoundTrip() throws Exception {
        Class<?> c = loadTransformed("Calc");
        assertEquals(5, callInt(c, "add", new Class<?>[]{int.class, int.class}, 2, 3));
        assertEquals(6, callInt(c, "sub", new Class<?>[]{int.class, int.class}, 10, 4));
        assertEquals(42, callInt(c, "mul", new Class<?>[]{int.class, int.class}, 6, 7));
        assertEquals(6, callInt(c, "div", new Class<?>[]{int.class, int.class}, 20, 3));
        assertEquals(2, callInt(c, "rem", new Class<?>[]{int.class, int.class}, 20, 3));
        assertEquals(5, callInt(c, "neg", new Class<?>[]{int.class}, -5));
        assertEquals(16, callInt(c, "shl", new Class<?>[]{int.class, int.class}, 1, 4));
        assertEquals(2147483644, callInt(c, "ushr", new Class<?>[]{int.class, int.class}, -8, 1));
        assertEquals(8, callInt(c, "and", new Class<?>[]{int.class, int.class}, 12, 10));
        assertEquals(14, callInt(c, "or", new Class<?>[]{int.class, int.class}, 12, 10));
        assertEquals(6, callInt(c, "xor", new Class<?>[]{int.class, int.class}, 12, 10));
    }

    @Test
    public void wideArithmetic() throws Exception {
        Class<?> c = loadTransformed("Calc");
        assertEquals(10000000001L, callLong(c, "ladd", new Class<?>[]{long.class, long.class}, 10000000000L, 1L));
        assertEquals(0.25f, callFloat(c, "fdiv", new Class<?>[]{float.class, float.class}, 1f, 4f), 1e-6f);
        assertEquals(3.0d, callDouble(c, "dmul", new Class<?>[]{double.class, double.class}, 1.5d, 2.0d), 1e-9d);
    }

    @Test
    public void controlFlowAndRecursion() throws Exception {
        Class<?> c = loadTransformed("Calc");
        assertEquals(9, callInt(c, "max", new Class<?>[]{int.class, int.class}, 3, 9));
        assertEquals(9, callInt(c, "max", new Class<?>[]{int.class, int.class}, 9, 3));
        assertEquals(7, callInt(c, "abs", new Class<?>[]{int.class}, -7));
        assertEquals(7, callInt(c, "abs", new Class<?>[]{int.class}, 7));
        assertEquals(120, callInt(c, "fact", new Class<?>[]{int.class}, 5));
        assertEquals(1, callInt(c, "fact", new Class<?>[]{int.class}, 1));
        assertEquals(55, callInt(c, "fib", new Class<?>[]{int.class}, 10));
        assertEquals(-1, callInt(c, "lcmp", new Class<?>[]{long.class, long.class}, 1L, 2L));
        assertEquals(0, callInt(c, "lcmp", new Class<?>[]{long.class, long.class}, 2L, 2L));
        assertEquals(1, callInt(c, "lcmp", new Class<?>[]{long.class, long.class}, 3L, 2L));
        assertEquals(10, callInt(c, "pick", new Class<?>[]{int.class}, 0));
        assertEquals(20, callInt(c, "pick", new Class<?>[]{int.class}, 1));
        assertEquals(-1, callInt(c, "pick", new Class<?>[]{int.class}, 9));
    }

    @Test
    public void stringsObjectsAndArrays() throws Exception {
        Class<?> c = loadTransformed("Calc");
        assertEquals("sum=3+4", call(c, "concat", new Class<?>[]{int.class, int.class}, 3, 4));
        // charAt returns char (reflection boxes as Character); the VM must treat it
        // as int-category for arithmetic. Regression for the reflection boundary.
        assertEquals(294, callInt(c, "sumChars", new Class<?>[]{String.class}, "abc"));
        assertEquals(Boolean.TRUE, call(c, "isEven", new Class<?>[]{int.class}, 4));
        assertEquals(Boolean.FALSE, call(c, "isEven", new Class<?>[]{int.class}, 5));
        assertEquals(3, callInt(c, "arrLen", new Class<?>[]{int[].class}, new int[]{1, 2, 3}));
        assertEquals(10, callInt(c, "sumArr", new Class<?>[]{int[].class}, new int[]{1, 2, 3, 4}));
        int[] r = (int[]) call(c, "range", new Class<?>[]{int.class}, 5);
        assertArrayEquals(new int[]{0, 1, 2, 3, 4}, r);
        assertEquals(123L, callLong(c, "conv", new Class<?>[]{int.class}, 123));
        assertEquals(Boolean.TRUE, call(c, "isString", new Class<?>[]{Object.class}, "x"));
        assertEquals(Boolean.FALSE, call(c, "isString", new Class<?>[]{Object.class}, Integer.valueOf(1)));
        assertEquals("hi", call(c, "cast", new Class<?>[]{Object.class}, "hi"));
        String[] b = (String[]) call(c, "box", new Class<?>[]{});
        assertEquals(3, b.length);
        assertEquals("b", b[1]);
        assertEquals("b", call(c, "boxGet", new Class<?>[]{int.class}, 1));
    }

    @Test
    public void staticFieldsAcrossMethods() throws Exception {
        Class<?> c = loadTransformed("Calc");
        call(c, "setStat", new Class<?>[]{int.class}, 42);
        assertEquals(42, callInt(c, "getStat", new Class<?>[]{}));
    }

    @Test
    public void instanceMethods() throws Exception {
        Class<?> pt = loadTransformed("Pt");
        Object p = pt.getConstructor(int.class, int.class).newInstance(3, 4);
        assertEquals(7, callIntInstance(pt, "sum", p));
        assertEquals(7, callInt(pt, "sumOf", new Class<?>[]{pt}, p));
        callInstance(pt, "set", p, 10, 20);
        assertEquals(30, callIntInstance(pt, "sum", p));
        assertEquals("(10,20)", callOn(pt, "describe", new Class<?>[]{}, p));
    }

    @Test
    public void mainPrintsThroughBf() throws Exception {
        Class<?> c = loadTransformed("Calc");
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(bos, true, StandardCharsets.UTF_8);
        PrintStream old = System.out;
        System.setOut(ps);
        try {
            c.getMethod("main", String[].class).invoke(null, (Object) new String[0]);
        } finally {
            System.setOut(old);
        }
        assertTrue(bos.toString(StandardCharsets.UTF_8.name()).contains("RES=sum=3+4"));
    }

    // ---- helpers ----

    private Class<?> loadTransformed(String simple) throws Exception {
        Map<String, byte[]> orig = compile(CALC, PT);
        Map<String, byte[]> trans = new LinkedHashMap<>();
        for (Map.Entry<String, byte[]> e : orig.entrySet()) {
            trans.put(e.getKey(), BfVm.protect(e.getValue()).bytes);
        }
        MapLoader loader = new MapLoader(trans);
        Thread t = Thread.currentThread();
        ClassLoader prev = t.getContextClassLoader();
        t.setContextClassLoader(loader);
        try {
            return loader.loadClass("com.kbox.core.bfvm.fixture." + simple);
        } finally {
            t.setContextClassLoader(prev);
        }
    }

    private static Object call(Class<?> c, String name, Class<?>[] pt, Object... args) throws Exception {
        return c.getMethod(name, pt).invoke(null, args);
    }

    private static Object callOn(Class<?> c, String name, Class<?>[] pt, Object self, Object... args) throws Exception {
        return c.getMethod(name, pt).invoke(self, args);
    }

    private static int callInt(Class<?> c, String name, Class<?>[] pt, Object... args) throws Exception {
        return ((Number) c.getMethod(name, pt).invoke(null, args)).intValue();
    }

    private static long callLong(Class<?> c, String name, Class<?>[] pt, Object... args) throws Exception {
        return ((Number) c.getMethod(name, pt).invoke(null, args)).longValue();
    }

    private static float callFloat(Class<?> c, String name, Class<?>[] pt, Object... args) throws Exception {
        return ((Number) c.getMethod(name, pt).invoke(null, args)).floatValue();
    }

    private static double callDouble(Class<?> c, String name, Class<?>[] pt, Object... args) throws Exception {
        return ((Number) c.getMethod(name, pt).invoke(null, args)).doubleValue();
    }

    private static int callIntInstance(Class<?> c, String name, Object self) throws Exception {
        return ((Number) c.getMethod(name).invoke(self)).intValue();
    }

    private static void callInstance(Class<?> c, String name, Object self, Object... args) throws Exception {
        c.getMethod(name, int.class, int.class).invoke(self, args);
    }

    private static Map<String, byte[]> compile(String... sources) throws Exception {
        Path dir = Files.createTempDirectory("bfvm-src");
        Path out = Files.createTempDirectory("bfvm-out");
        List<String> files = new ArrayList<>();
        for (int i = 0; i < sources.length; i++) {
            java.util.regex.Matcher m = java.util.regex.Pattern
                    .compile("public\\s+class\\s+(\\w+)").matcher(sources[i]);
            String fileName = (m.find() ? m.group(1) : "F" + i) + ".java";
            Path f = dir.resolve(fileName);
            Files.write(f, sources[i].getBytes(StandardCharsets.UTF_8));
            files.add(f.toString());
        }
        List<String> argList = new ArrayList<>();
        argList.add("-d");
        argList.add(out.toString());
        argList.add("--release");
        argList.add("8");
        argList.addAll(files);
        ByteArrayOutputStream err = new ByteArrayOutputStream();
        int rc = ToolProvider.getSystemJavaCompiler()
                .run(null, null, err, argList.toArray(new String[0]));
        assertEquals("javac failed:\n" + err.toString("UTF-8"), 0, rc);
        Map<String, byte[]> result = new LinkedHashMap<>();
        collect(out, out, result);
        return result;
    }

    private static void collect(Path root, Path dir, Map<String, byte[]> out) throws IOException {
        for (Path p : Files.newDirectoryStream(dir)) {
            if (Files.isDirectory(p)) {
                collect(root, p, out);
            } else if (p.toString().endsWith(".class")) {
                String rel = root.relativize(p).toString().replace('\\', '/');
                String name = rel.substring(0, rel.length() - 6).replace('/', '.');
                out.put(name, Files.readAllBytes(p));
            }
        }
    }

    /** Parent-first class loader exposing the transformed classes; the parent sees BfRuntime. */
    private static final class MapLoader extends ClassLoader {
        private final Map<String, byte[]> defs;

        MapLoader(Map<String, byte[]> defs) {
            super(BfvmE2ETest.class.getClassLoader());
            this.defs = defs;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] b = defs.get(name);
            if (b == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, b, 0, b.length);
        }
    }
}
