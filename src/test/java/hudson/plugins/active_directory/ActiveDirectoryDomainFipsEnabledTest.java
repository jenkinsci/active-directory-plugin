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
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import io.jenkins.plugins.casc.ConfigurationAsCode;
import io.jenkins.plugins.casc.ConfiguratorException;
import org.jvnet.hudson.test.recipes.LocalData;
import static hudson.Functions.isWindows;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.any;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.jvnet.hudson.test.LoggerRule.recorded;

public class ActiveDirectoryDomainFipsEnabledTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @Rule
    public LoggerRule loggerRule = new LoggerRule().record("hudson.diagnosis.OldDataMonitor", Level.INFO).capture(1000);

    @ClassRule
    public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Test
    public void smokeTests() {

        ActiveDirectoryDomain.DescriptorImpl adDescriptor = ExtensionList.lookupSingleton(ActiveDirectoryDomain.DescriptorImpl.class);

        // error message should be displayed if a FIPS non-compliant option is chosen
        FormValidation resultError = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.TRUST_ALL_CERTIFICATES);
        assertEquals("Insecure TLS configuration should not be allowed", FormValidation.Kind.ERROR, resultError.kind);

        // if a FIPS compliant option is chosen, no error message should be displayed
        FormValidation resultOk = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.JDK_TRUSTSTORE);
        assertEquals("Secure TLS configuration should be allowed", FormValidation.Kind.OK, resultOk.kind);

        assertThrows("Insecure TLS configuration should not be allowed", IllegalArgumentException.class,
                     () -> new ActiveDirectoryDomain("name", "the_server", "site", "bindName", "bindPassword", TlsConfiguration.TRUST_ALL_CERTIFICATES));

        try {
            new ActiveDirectoryDomain("name", "the_server", "site", "bindName",
                                                                     "bindPasswordFIPS", TlsConfiguration.JDK_TRUSTSTORE);
        } catch (Exception e) {
            fail("Secure TLS configuration should be allowed");
        }
    }

    @Test
    public void cascTest() {
        assertThrows("Insecure TLS configuration should not be allowed", ConfiguratorException.class,
                     () -> ConfigurationAsCode.get().configure(Paths.get("src/test/resources/hudson/plugins/active_directory/ActiveDirectoryDomainFipsEnabledTest/configuration-as-code-insecure.yaml").toString()));
        try {
            ConfigurationAsCode.get().configure(Paths.get("src/test/resources/hudson/plugins/active_directory/ActiveDirectoryDomainFipsEnabledTest/configuration-as-code-secure.yaml").toString());
        } catch (Exception e) {
            fail("Secure TLS configuration should be allowed");
        }
    }

    @Test
    @LocalData
    public void testBlowsUpOnStart() throws Throwable {

        assumeFalse("TODO needs triage", isWindows());
        assertThat(loggerRule, recorded(any(String.class), hasProperty("message", containsString("Choosing an insecure TLS configuration in FIPS mode is not allowed"))));

    }

    @Test(expected = FailingHttpStatusCodeException.class)
    public void testInvalidTlsConfiguration() throws Exception {
        assumeFalse("JENKINS-73847", isWindows());

        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = getActiveDirectorySecurityRealm();
        jenkinsRule.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        JenkinsRule.WebClient webClient = jenkinsRule.createWebClient();
        HtmlPage htmlPage = webClient.goTo("configureSecurity");
        HtmlForm htmlForm = htmlPage.getFormByName("config");
        htmlForm.getSelectByName("_.tlsConfiguration").setSelectedAttribute("TRUST_ALL_CERTIFICATES", true);
        webClient.waitForBackgroundJavaScript(1000);
        assertThat(htmlForm.getTextContent(), containsString(Messages.TlsConfiguration_CertificateError()));

        assertEquals(500, jenkinsRule.submit(htmlForm).getWebResponse().getStatusCode());
    }

    @Test
    public void testPasswordTooShortInFIPSMode() {
        // Create an instance of ActiveDirectoryDomain with a short password and assert exception
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            new ActiveDirectoryDomain("example.com", "server", "site", "bindName", "short", TlsConfiguration.JDK_TRUSTSTORE);
        });

        // Verify the exception message
        assertEquals(Messages.passwordTooShortFIPS(), exception.getMessage());
    }

    @Test
    public void testPasswordValidInFIPSMode() {
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
    public void testDoCheckBindPasswordFIPSModeShortPassword() {
        // Create an instance of the DescriptorImpl class
        ActiveDirectoryDomain.DescriptorImpl descriptor = new ActiveDirectoryDomain.DescriptorImpl();

        // Test with a password less than 14 characters
        FormValidation result = descriptor.doCheckBindPassword("shortPass");
        assertEquals(FormValidation.error(Messages.passwordTooShortFIPS()).getMessage(), result.getMessage());
    }

    @Test
    public void testDoCheckBindPasswordFIPSModeValidPassword() {
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
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null
                , null, GroupLookupStrategy.RECURSIVE, false, true, null, true, null, true);
        return activeDirectorySecurityRealm;
    }
}
