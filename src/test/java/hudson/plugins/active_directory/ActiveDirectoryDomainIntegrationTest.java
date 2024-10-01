package hudson.plugins.active_directory;

import org.htmlunit.FailingHttpStatusCodeException;
import org.htmlunit.html.HtmlButton;
import org.htmlunit.html.HtmlElement;
import org.htmlunit.html.HtmlForm;
import org.htmlunit.html.HtmlInput;
import org.htmlunit.html.HtmlPage;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

public class ActiveDirectoryDomainIntegrationTest {
	@Rule
	public JenkinsRule jenkins = new JenkinsRule();

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@ClassRule
	public static FlagRule<String> fipsSystemPropertyRule =
			FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");


	/**
	 * Tests the behavior of the "Save" button when a short password is configured.
	 *
	 * <p>For the preconfigured value, the password is "small" in the local data.
	 * When the "Save" button is clicked, an exception is expected because the password
	 * does not meet the minimum length requirement.</p>
	 *
	 */
	@LocalData
	@Test
	public void testActiveDirectoryDomainSaveButtonClick() throws Exception {
		JenkinsRule.WebClient webClient = jenkins.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");
		HtmlForm form = configPage.getFormByName("config");

		//Check that the password is too short message is present
		assertTrue(form.asNormalizedText().contains(Messages.passwordTooShortFIPS()));

		// Expect FailingHttpStatusCodeException
		thrown.expect(FailingHttpStatusCodeException.class);

		// Find the "Submit" button and click it
		getButtonByText(form, "Save").click();
	}

	/**
	 * Tests the behavior of the "Save" button when a short password is configured.
	 *
	 * <p>For the preconfigured value, the password is "small" in the local data.
	 * When the "Apply" button is clicked, an exception is expected because the password
	 * does not meet the minimum length requirement.</p>
	 *
	 */
	@LocalData
	@Test
	public void testActiveDirectoryDomainApplyButtonClick() throws Exception {
		JenkinsRule.WebClient webClient = jenkins.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");
		HtmlForm form = configPage.getFormByName("config");

		//Check that the password is too short message is present
		assertTrue(form.asNormalizedText().contains(Messages.passwordTooShortFIPS()));

		// Expect FailingHttpStatusCodeException
		thrown.expect(FailingHttpStatusCodeException.class);

		// Find the "Apply" button and click it
		getButtonByText(form, "Apply").click();
	}

	/**
	 * Tests the behavior of the "Apply" button when a valid password is initially configured. then updated to a
	 * short password
	 *
	 * <p>For the preconfigured value, the password is "samell" in the local data.
	 * When the "Apply" button is clicked, an exception is expected because the password
	 * does not meet the minimum length requirement.</p>
	 *
	 */
	@LocalData
	@Test
	public void testActiveDirectoryDomainSettingShortPassword() throws Exception {
		JenkinsRule.WebClient webClient = jenkins.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");
		HtmlForm form = configPage.getFormByName("config");

		//Since password is valid is should not contain password too short message
		assertFalse(form.asNormalizedText().contains(Messages.passwordTooShortFIPS()));
		//Since password is valid, it should not throw exception oon clicking apply
		assertEquals(200, getButtonByText(form, "Apply").click().getWebResponse().getStatusCode());

		// Find the binf password filed and set an invalid password
		HtmlInput bindPasswordField = form.getInputByName("_.bindPassword");
		bindPasswordField.setValueAttribute("small"); // Replace with your password value

		// Expect FailingHttpStatusCodeException
		thrown.expect(FailingHttpStatusCodeException.class);

		// Find the "Submit" button and click it
		getButtonByText(form, "Apply").click();
	}

	/**
	 * Tests the behavior of the "Test Domain" button when a short password is configured.
	 *
	 * <p>For the preconfigured value, the password is "small" in the local data.
	 * When the "Test Domain" button is clicked, the page should display an error message
	 * indicating that the password is too short, along with an "angry Jenkins" error message.</p>
	 *
	 */
	@LocalData
	@Test
	public void testActiveDirectoryDomainTestDomainButtonClickWithShortPassword() throws Exception {
		JenkinsRule.WebClient webClient = jenkins.createWebClient();
		// Navigate to the configuration page
		HtmlPage configPage = webClient.goTo("configureSecurity");

		// Wait for JavaScript to finish loading the page
		webClient.waitForBackgroundJavaScript(2000); // Wait for up to 2 seconds for the page to load
		HtmlForm form = configPage.getFormByName("config");

		//Check that the password is too short message is present
		assertTrue(form.asNormalizedText().contains(Messages.passwordTooShortFIPS()));

		// Click the "Test Domain" button
		HtmlPage resultPage = getButtonByText(form, "Test Domain").click();

		webClient.waitForBackgroundJavaScript(2000); // Wait for up to 5 seconds

		String responseContent = resultPage.asNormalizedText();
		// Assert that the error message is present in the page content
		assertTrue(responseContent.contains("A problem occurred while processing the request"));

		//Check that the password is too short message is present
		assertTrue(responseContent.contains(Messages.passwordTooShortFIPS()));
	}

	private HtmlButton getButtonByText(HtmlForm form, String text) throws Exception {
		for (HtmlElement e : form.getElementsByTagName("button")) {
			if (e.getTextContent().contains(text)) {
				return ((HtmlButton) e);
			}
		}
		throw new AssertionError(String.format("Button [%s] not found", text));
	}

}
