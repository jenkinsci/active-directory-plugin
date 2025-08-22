package hudson.plugins.active_directory;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlPage;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.any;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.hasProperty;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.jvnet.hudson.test.LogRecorder.recorded;

import static hudson.Functions.isWindows;

@WithJenkins
class ActiveDirectoryDomainFIPSEnabledIntegrationTest {

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

    /**
     * Tests the readResolve method when a previous invalid TLS configuration is in place
     *
     * <p>NB: This is not a supported use case according to JEP definition. Checking anyway</p>
     */
    @LocalData
    @Test
    void testInvalidPreviousTLSConfiguration() {
		assertThat(l, recorded(any(String.class), hasProperty("message", containsString("Choosing an insecure TLS configuration in FIPS mode is not allowed"))));
    }

    /**
     * Tests the readResolve method when a previous invalid bind password configuration is in place
     *
     */
    @LocalData
    @Test
    void testInvalidPreviousBindPasswordConfiguration() {
		assertThat(l, recorded(any(String.class), hasProperty("message", containsString(Messages.passwordTooShortFIPS()))));
    }

    /**
     * Tests the behavior of the "Save" button when a short password is configured.
     */
    @Test
    void testActiveDirectoryDomainSaveButtonClick() throws Exception {
		submitConfig("Save");
    }

    private void submitConfig(String button) throws Exception {
		ActiveDirectorySecurityRealm activeDirectorySecurityRealm = getActiveDirectorySecurityRealm();
		j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);

		JenkinsRule.WebClient webClient = j.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");
		HtmlForm form = configPage.getFormByName("config");

		form.getInputByName("_.bindPassword").setValue("short");
		if(!isWindows()) {
		    // JENKINS-73847
		    form.getSelectByName("_.tlsConfiguration").setSelectedAttribute("JDK_TRUSTSTORE", true);
		}

		// Expect FailingHttpStatusCodeException when finding the "Submit" button and clicking it
		assertThrows(FailingHttpStatusCodeException.class, () -> getButtonByText(form, button).click());

    }

    /**
     * Tests the behavior of the "Apply" button when a short password is configured.
     */
    @Test
    void testActiveDirectoryDomainApplyButtonClick() throws Exception {
		submitConfig("Apply");
    }

    /**
     * Tests the behavior of the "Test Domain" button when a short password is configured.
     *
     */
    @Test
    void testActiveDirectoryDomainTestDomainButtonClickWithShortPassword() throws Exception {

		assumeFalse(isWindows(), "JENKINS-73847");

		ActiveDirectorySecurityRealm activeDirectorySecurityRealm = getActiveDirectorySecurityRealm();
		j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);

		JenkinsRule.WebClient webClient = j.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");

		// Wait for JavaScript to finish loading the page
		webClient.waitForBackgroundJavaScript(5000);
		HtmlForm form = configPage.getFormByName("config");

		// Wait for JavaScript to finish loading the page
		webClient.waitForBackgroundJavaScript(5000);

		form.getInputByName("_.bindPassword").setValue("short");
		// Click the "Test Domain" button
		HtmlPage resultPage = getButtonByText(form, "Test Domain").click();

		webClient.waitForBackgroundJavaScript(2000); // Wait for up to 5 seconds

		String responseContent = resultPage.asNormalizedText();
		//Check that the password is too short message is present
		assertTrue(responseContent.contains(Messages.passwordTooShortFIPS()));
    }

    private HtmlButton getButtonByText(HtmlForm form, String text) {
		for (HtmlElement e : form.getElementsByTagName("button")) {
			if (e.getTextContent().contains(text)) {
				return ((HtmlButton) e);
			}
		}
		throw new AssertionError(String.format("Button [%s] not found", text));
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
