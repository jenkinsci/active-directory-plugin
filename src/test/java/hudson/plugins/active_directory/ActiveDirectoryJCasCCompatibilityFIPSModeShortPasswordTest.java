package hudson.plugins.active_directory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.RestartableJenkinsRule;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;

public class ActiveDirectoryJCasCCompatibilityFIPSModeShortPasswordTest {

    @Rule
    public RestartableJenkinsRule r = new RestartableJenkinsRule();

    @ClassRule
    public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void checkOfIncorrectConfigurationsWithShortPasswordInFIPSMode() throws IOException {
        thrown.expect(IllegalStateException.class);
        thrown.expectMessage(Messages.passwordTooShortFIPS());

        String resourcePath = "configuration-as-code-fips-short-password.yaml";
        String resourceContent = this.getResourceContent(resourcePath);
        Assert.assertNotNull(resourcePath);
        Assert.assertNotNull(resourceContent);
        this.r.then((step) -> {
            this.configureWithResource(resourcePath);
        });
    }

    private String getResourceContent(String resourcePath) throws IOException {
        return IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream(resourcePath))
                , StandardCharsets.UTF_8);
    }

    private void configureWithResource(String config) throws ConfiguratorException {
        ConfigurationAsCode.get().configure(new String[]{ this.getClass().getResource(config).toExternalForm()});
    }

}
