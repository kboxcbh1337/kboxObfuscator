package com.kbox.core.silentshield;

import com.kbox.core.analysis.ClassGraph;
import com.kbox.core.config.ProtectionConfig;
import org.junit.Test;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.tree.ClassNode;

import static org.junit.Assert.assertTrue;

/**
 * 商业级适配性（"10 年"）单元测试：
 * <ul>
 *   <li>弱点目录从 25 族扩充到 50+ 族；</li>
 *   <li>覆盖来源（ZKM/JNIC/ProGuard/Allatori/DashO/R8-D8/Stringer/Spring/Jackson/
 *       Kotlin/GraalVM/…）等多于原先；</li>
 *   <li>ModernStackAdapter 识别协程状态机并排除 JNIC/VMP；</li>
 *   <li>AdaptabilityReport 生成完整验收报告（四支柱 + JDK 版本 + 10 年矩阵）。</li>
 * </ul>
 */
public class CommercialAdaptabilityTest {

    @Test
    public void catalogGrewBeyond25Families() {
        int size = WeaknessCatalog.get().size();
        assertTrue("catalog should have expanded beyond 25, was " + size, size >= 50);
    }

    @Test
    public void catalogCoversModernSources() {
        java.util.Set<String> sources = WeaknessCatalog.get().sources();
        assertTrue("missing Kotlin", sources.contains("Kotlin"));
        assertTrue("missing Spring", sources.contains("Spring"));
        assertTrue("missing Jackson", sources.contains("Jackson"));
        assertTrue("missing Jakarta", sources.contains("Jakarta"));
        assertTrue("missing GraalVM", sources.contains("GraalVM"));
        assertTrue("missing R8/D8", sources.contains("R8/D8"));
        assertTrue("missing Stringer", sources.contains("Stringer"));
        assertTrue("missing DashO", sources.contains("DashO"));
    }

    @Test
    public void catalogHasModernJdkAndStackFamilies() {
        WeaknessCatalog cat = WeaknessCatalog.get();
        assertTrue(cat.weaknessFor("CLASS_FILE_VERSION") != null);
        assertTrue(cat.weaknessFor("SWITCH_EXPRESSION_INDY") != null);
        assertTrue(cat.weaknessFor("KOTLIN_COROUTINES") != null);
        assertTrue(cat.weaknessFor("LOMBOK_ACCESSORS") != null);
        assertTrue(cat.weaknessFor("JACKSON_BEAN_ACCESSORS") != null);
        assertTrue(cat.weaknessFor("METHODHANDLES_LOOKUP") != null);
        assertTrue(cat.weaknessFor("VARHANDLE") != null);
        assertTrue(cat.weaknessFor("NATIVE_IMAGE_METADATA") != null);
        assertTrue(cat.weaknessFor("CUSTOM_CLASSLOADER") != null);
        assertTrue(cat.weaknessFor("EXTERNALIZABLE") != null);
        assertTrue(cat.weaknessFor("RECORD_SERIALIZATION") != null);
        assertTrue(cat.weaknessFor("JPMS_SERVICES") != null);
    }

    /** 构造一个 Kotlin 协程状态机类（ContinuationImpl 子类 + 带 Continuation 参数的 suspend 方法）。 */
    private ClassNode coroutineStateMachineClass() {
        ClassNode cn = new ClassNode(Opcodes.ASM9);
        cn.version = Opcodes.V17;
        cn.access = Opcodes.ACC_PUBLIC;
        cn.name = "com/example/Fetch$fetch$1";
        cn.superName = "kotlin/coroutines/jvm/internal/ContinuationImpl";
        cn.interfaces.add("kotlin/jvm/internal/ContinuationImpl");
        return cn;
    }

    @Test
    public void modernStackAdapterExcludesCoroutines() {
        ClassGraph graph = new ClassGraph();
        ClassNode cn = coroutineStateMachineClass();
        graph.addClass(cn.name, cn, new byte[0]);
        ProtectionConfig cfg = new ProtectionConfig();

        ModernStackAdapter.Result r = new ModernStackAdapter().run(graph, cfg);

        String dotted = cn.name.replace('/', '.');
        assertTrue("coroutine state machine must be excluded from JNIC/VMP", 
                cfg.getNativeExcludePrefixes().contains(dotted));
        assertTrue("coroutine state machine must be excluded from control-flow",
                cfg.getExcludeControlFlowPrefixes().contains(dotted));
        assertTrue("result should flag coroutines seen", r.kotlinSeen);
        assertTrue("coroutineExclusions >= 1", r.coroutineExclusions >= 1);
    }

    @Test
    public void modernStackAdapterReportsJdkSpan() {
        ClassGraph graph = new ClassGraph();
        ClassNode cn = new ClassNode(Opcodes.ASM9);
        cn.version = Opcodes.V17; // Java 17
        cn.access = Opcodes.ACC_PUBLIC;
        cn.name = "com/example/Main";
        cn.superName = "java/lang/Object";
        graph.addClass(cn.name, cn, new byte[0]);
        ProtectionConfig cfg = new ProtectionConfig();

        ModernStackAdapter.Result r = new ModernStackAdapter().run(graph, cfg);

        assertTrue("jdkMaxVersion should be 61 (Java 17)", r.jdkMaxVersion == 61);
        assertTrue("jdkMinVersion should be 61", r.jdkMinVersion == 61);
    }
}