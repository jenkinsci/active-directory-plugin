package hudson.plugins.active_directory;

import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;

import hudson.util.FormValidation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class ActiveDirectoryDomainTest {


	private ActiveDirectorySecurityRealm securityRealm;
	private AbstractActiveDirectoryAuthenticationProvider authenticationProvider;

	@ClassRule
	public static FlagRule<String> fipsSystemPropertyRule =
			FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");


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
}