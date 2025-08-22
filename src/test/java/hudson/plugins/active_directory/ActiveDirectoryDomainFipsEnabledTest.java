package hudson.plugins.active_directory;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import hudson.ExtensionList;
import hudson.util.FormValidation;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import static hudson.Functions.isWindows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.any;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assertions.*;
import static org.jvnet.hudson.test.LogRecorder.recorded;

@WithJenkins
class ActiveDirectoryDomainFipsEnabledTest {

    private final LogRecorder l = new LogRecorder().record("hudson.diagnosis.OldDataMonitor", Level.INFO).capture(1000);

    private static String fipsSystemProperty;

    private JenkinsRule j;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
    }

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
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
    void smokeTests() {
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = ExtensionList.lookupSingleton(ActiveDirectoryDomain.DescriptorImpl.class);

        // error message should be displayed if a FIPS non-compliant option is chosen
        FormValidation resultError = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.TRUST_ALL_CERTIFICATES);
        assertEquals(FormValidation.Kind.ERROR, resultError.kind, "Insecure TLS configuration should not be allowed");

        // if a FIPS compliant option is chosen, no error message should be displayed
        FormValidation resultOk = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.JDK_TRUSTSTORE);
        assertEquals(FormValidation.Kind.OK, resultOk.kind, "Secure TLS configuration should be allowed");

        assertThrows(IllegalArgumentException.class,
                     () -> new ActiveDirectoryDomain("name", "the_server", "site", "bindName", "bindPassword", TlsConfiguration.TRUST_ALL_CERTIFICATES),
                     "Insecure TLS configuration should not be allowed");

        assertDoesNotThrow(() -> {
            new ActiveDirectoryDomain("name", "the_server", "site", "bindName",
                    "bindPasswordFIPS", TlsConfiguration.JDK_TRUSTSTORE);
        }, "Secure TLS configuration should be allowed");
    }

    @Test
    void cascTest() {
        assertThrows(ConfiguratorException.class,
                     () -> ConfigurationAsCode.get().configure(Paths.get("src/test/resources/hudson/plugins/active_directory/ActiveDirectoryDomainFipsEnabledTest/configuration-as-code-insecure.yaml").toString()),
                     "Insecure TLS configuration should not be allowed");
        assertDoesNotThrow(() -> ConfigurationAsCode.get().configure(Paths.get("src/test/resources/hudson/plugins/active_directory/ActiveDirectoryDomainFipsEnabledTest/configuration-as-code-secure.yaml").toString()), "Secure TLS configuration should be allowed");
    }

    @Test
    @LocalData
    void testBlowsUpOnStart() {
        assumeFalse(isWindows(), "TODO needs triage");
        assertThat(l, recorded(any(String.class), hasProperty("message", containsString("Choosing an insecure TLS configuration in FIPS mode is not allowed"))));
    }

    @Test
    void testInvalidTlsConfiguration() throws Exception {
        assumeFalse(isWindows(), "JENKINS-73847");
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = getActiveDirectorySecurityRealm();
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        JenkinsRule.WebClient webClient = j.createWebClient();
        HtmlPage htmlPage = webClient.goTo("configureSecurity");
        HtmlForm htmlForm = htmlPage.getFormByName("config");
        htmlForm.getSelectByName("_.tlsConfiguration").setSelectedAttribute("TRUST_ALL_CERTIFICATES", true);
        webClient.waitForBackgroundJavaScript(1000);
        assertThat(htmlForm.getTextContent(), containsString(Messages.TlsConfiguration_CertificateError()));
        FailingHttpStatusCodeException e = assertThrows(FailingHttpStatusCodeException.class, () -> j.submit(htmlForm));
        assertEquals(500, e.getStatusCode());
    }

    @Test
    void testPasswordTooShortInFIPSMode() {
        // Create an instance of ActiveDirectoryDomain with a short password and assert exception
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> new ActiveDirectoryDomain("example.com", "server", "site", "bindName", "short", TlsConfiguration.JDK_TRUSTSTORE));

        // Verify the exception message
        assertEquals(Messages.passwordTooShortFIPS(), exception.getMessage());
    }

    @Test
    void testPasswordValidInFIPSMode() {
        // Create an instance of ActiveDirectoryDomain with a valid password
        ActiveDirectoryDomain domain = new ActiveDirectoryDomain("example.com", "server", "site", "bindName", "validPassword123", TlsConfiguration.JDK_TRUSTSTORE);

        // Verify the domain object is created successfully
        assertEquals("example.com", domain.getName());
        assertEquals("server:3268", domain.getServers());
        assertEquals("site", domain.getSite());
        assertEquals("bindName", domain.getBindName());
        assertEquals("validPassword123", domain.getBindPassword().getPlainText());
    }

    @Test
    void testDoCheckBindPasswordFIPSModeShortPassword() {
        // Create an instance of the DescriptorImpl class
        ActiveDirectoryDomain.DescriptorImpl descriptor = new ActiveDirectoryDomain.DescriptorImpl();

        // Test with a password less than 14 characters
        FormValidation result = descriptor.doCheckBindPassword("shortPass");
        assertEquals(FormValidation.error(Messages.passwordTooShortFIPS()).getMessage(), result.getMessage());
    }

    @Test
    void testDoCheckBindPasswordFIPSModeValidPassword() {
        // Create an instance of the DescriptorImpl class
        ActiveDirectoryDomain.DescriptorImpl descriptor = new ActiveDirectoryDomain.DescriptorImpl();

        // Test with a password of 14 characters or more
        FormValidation result = descriptor.doCheckBindPassword("validPassword123");
        assertEquals(FormValidation.ok().getMessage(), result.getMessage());
    }

    private static @NotNull ActiveDirectorySecurityRealm getActiveDirectorySecurityRealm() {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain("name", "server"
                , "site", "name", "passwordforFIPS", TlsConfiguration.JDK_TRUSTSTORE);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        return new ActiveDirectorySecurityRealm(null, domains, null, null, null
                , null, GroupLookupStrategy.RECURSIVE, false, true, null, true, null, true);
    }
}
