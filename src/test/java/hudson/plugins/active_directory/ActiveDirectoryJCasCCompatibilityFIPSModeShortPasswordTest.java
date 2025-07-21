package hudson.plugins.active_directory;

import static org.junit.Assert.assertThrows;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsSessionRule;

public class ActiveDirectoryJCasCCompatibilityFIPSModeShortPasswordTest {

    @Rule
    public JenkinsSessionRule r = new JenkinsSessionRule();

    @ClassRule
    public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Test
    public void checkOfIncorrectConfigurationsWithShortPasswordInFIPSMode() throws Throwable {
        String resourcePath = "configuration-as-code-fips-short-password.yaml";
        String resourceContent = getResourceContent(resourcePath);
        Assert.assertNotNull(resourcePath);
        Assert.assertNotNull(resourceContent);
        r.then(step -> assertThrows(IllegalStateException.class, () -> configureWithResource(resourcePath)));
    }

    private String getResourceContent(String resourcePath) throws IOException {
        return new String(Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)).readAllBytes(), StandardCharsets.UTF_8);
    }

    private void configureWithResource(String config) throws ConfiguratorException {
        ConfigurationAsCode.get().configure(Objects.requireNonNull(getClass().getResource(config)).toExternalForm());
    }
}
