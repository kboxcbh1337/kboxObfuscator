package com.kbox.maven;

import com.kbox.core.ProtectionPipeline;
import com.kbox.core.config.ConfigLoader;
import com.kbox.core.config.ProtectionConfig;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * {@code kbox:protect} goal — applies the KBox protection pipeline to a jar.
 *
 * <pre>
 *   &lt;plugin&gt;
 *     &lt;groupId&gt;com.kbox&lt;/groupId&gt;
 *     &lt;artifactId&gt;kbox-maven-plugin&lt;/artifactId&gt;
 *     &lt;version&gt;1.0.0&lt;/version&gt;
 *     &lt;executions&gt;
 *       &lt;execution&gt;
 *         &lt;phase&gt;package&lt;/phase&gt;
 *         &lt;goals&gt;&lt;goal&gt;protect&lt;/goal&gt;&lt;/goals&gt;
 *       &lt;/execution&gt;
 *     &lt;/executions&gt;
 *     &lt;configuration&gt;
 *       &lt;input&gt;${project.build.directory}/${project.build.finalName}.jar&lt;/input&gt;
 *       &lt;output&gt;${project.build.directory}/${project.build.finalName}-protected.jar&lt;/output&gt;
 *       &lt;configFile&gt;${project.basedir}/kbox.conf&lt;/configFile&gt;
 *     &lt;/configuration&gt;
 *   &lt;/plugin&gt;
 * </pre>
 */
@Mojo(name = "protect", defaultPhase = LifecyclePhase.PACKAGE, threadSafe = true)
public class ProtectMojo extends AbstractMojo {

    @Parameter(required = true)
    private String input;

    @Parameter(required = true)
    private String output;

    @Parameter
    private String configFile;

    @Parameter(defaultValue = "false")
    private boolean verbose;

    @Override
    public void execute() throws MojoExecutionException {
        try {
            ProtectionConfig cfg = ConfigLoader.load(
                    configFile == null || configFile.isEmpty() ? null : Paths.get(configFile));
            Path in = Paths.get(input);
            Path out = Paths.get(output);
            Path workDir = out.getParent() == null ? Paths.get(".") : out.getParent().resolve("kbox-work");
            getLog().info("KBox: protecting " + in + " -> " + out);
            new ProtectionPipeline(in, out, cfg, workDir).run();
        } catch (Exception e) {
            throw new MojoExecutionException("KBox protection failed", e);
        }
    }

    // Setters used by Maven for property injection when @Parameter is reflected on private fields.
    public void setInput(String input) { this.input = input; }
    public void setOutput(String output) { this.output = output; }
    public void setConfigFile(String configFile) { this.configFile = configFile; }
    public void setVerbose(boolean verbose) { this.verbose = verbose; }
}
