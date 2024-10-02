package hudson.plugins.active_directory;

import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import hudson.ExtensionList;
import hudson.util.FormValidation;
import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.WebResponse;
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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
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
        FormValidation resultError = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.TRUST_ALL_CERTIFICATES.name());
        assertEquals("Insecure TLS configuration should not be allowed", FormValidation.Kind.ERROR, resultError.kind);

        // if a FIPS compliant option is chosen, no error message should be displayed
        FormValidation resultOk = adDescriptor.doCheckTlsConfiguration(TlsConfiguration.JDK_TRUSTSTORE.name());
        assertEquals("Secure TLS configuration should be allowed", FormValidation.Kind.OK, resultOk.kind);

        assertThrows("Insecure TLS configuration should not be allowed", IllegalArgumentException.class,
                     () -> new ActiveDirectoryDomain("name", "the_server", "site", "bindName", "bindPassword", TlsConfiguration.TRUST_ALL_CERTIFICATES));

        try {
            new ActiveDirectoryDomain("name", "the_server", "site", "bindName",
                                                                     "bindPassword", TlsConfiguration.JDK_TRUSTSTORE);
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

        assertThat(loggerRule, recorded(any(String.class), hasProperty("message", containsString("Choosing an insecure TLS configuration in FIPS mode is not allowed"))));

    }

    @Test(expected = FailingHttpStatusCodeException.class)
    public void testSaveButton() throws Exception {
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

    private static @NotNull ActiveDirectorySecurityRealm getActiveDirectorySecurityRealm() {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain("name", "server"
                , "site", "name", "password", TlsConfiguration.JDK_TRUSTSTORE);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null
                , null, GroupLookupStrategy.RECURSIVE, false, true, null, true, null, true);
        return activeDirectorySecurityRealm;
    }
}
