package hudson.plugins.active_directory.docker;

import org.junit.AssumptionViolatedException;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.testcontainers.DockerClientFactory;

/**
 * Junit 4 {@code Rule} that will skip the test if the docker client is not available.
 * This rule must have a lower {@link Rule#order} specified that any other {@code Rule} that 
 * uses docker in order to skip tests, otherwise the other rules would fail first causing build failures.
 * e.g. <pre><code>
    {@literal @}Rule(order = -10)
    public RequireDockerRule rdr = new RequireDockerRule();
 }
 * </code></pre>
 */
public class RequireDockerRule implements TestRule {

    @Override
    public Statement apply(Statement base, Description description) {
        if (DockerClientFactory.instance().isDockerAvailable()) {
            return base;
        }
        return new DockerNotAvailbleStatement();
    }

    private static class DockerNotAvailbleStatement extends  Statement {

        @Override
        public void evaluate() throws Throwable {
            throw new AssumptionViolatedException("Docker is not available and this test requires docker");
        }
    }

}
