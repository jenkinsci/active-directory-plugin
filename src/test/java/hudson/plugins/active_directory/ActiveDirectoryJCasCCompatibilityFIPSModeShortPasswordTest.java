package hudson.plugins.active_directory;

import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.jvnet.hudson.test.junit.jupiter.JenkinsSessionExtension;

class ActiveDirectoryJCasCCompatibilityFIPSModeShortPasswordTest {

    @RegisterExtension
    private final JenkinsSessionExtension r = new JenkinsSessionExtension();

    private static String fipsSystemProperty;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
    }

    @AfterAll
    static void afterAll() {
        if (fipsSystemProperty != null) {
            System.setProperty("jenkins.security.FIPS140.COMPLIANCE", fipsSystemProperty);
        } else {
            System.clearProperty("jenkins.security.FIPS140.COMPLIANCE");
        }
    }

    @Test
    void checkOfIncorrectConfigurationsWithShortPasswordInFIPSMode() throws Throwable {
        String resourcePath = "configuration-as-code-fips-short-password.yaml";
        String resourceContent = getResourceContent(resourcePath);
        assertNotNull(resourcePath);
        assertNotNull(resourceContent);
        r.then(step -> assertThrows(IllegalStateException.class, () -> configureWithResource(resourcePath)));
    }

    private String getResourceContent(String resourcePath) throws IOException {
        return new String(Objects.requireNonNull(getClass().getResourceAsStream(resourcePath)).readAllBytes(), StandardCharsets.UTF_8);
    }

    private void configureWithResource(String config) throws ConfiguratorException {
        ConfigurationAsCode.get().configure(Objects.requireNonNull(getClass().getResource(config)).toExternalForm());
    }
}
