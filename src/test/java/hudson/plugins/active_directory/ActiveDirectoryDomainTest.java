package hudson.plugins.active_directory;


import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import hudson.util.FormValidation;
import jenkins.security.FIPS140;

import static org.junit.Assert.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

public class ActiveDirectoryDomainTest {

	@AfterEach
	public void tearDown() {
		// Clear all static mocks after each test
		Mockito.clearAllCaches();
	}

	@Test
	public void testPasswordTooShortInFIPSMode() {
		// Set FIPS to compliant algorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		// Create an instance of ActiveDirectoryDomain with a short password and assert exception
		IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
			new ActiveDirectoryDomain("example.com", "server", "site", "bindName", "short", TlsConfiguration.TRUST_ALL_CERTIFICATES);
		});

		// Verify the exception message
		assertEquals(Messages.passwordTooShortFIPS(), exception.getMessage());
	}

	@Test
	public void testPasswordValidInFIPSMode() {
		// Set FIPS to compliant algorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		// Create an instance of ActiveDirectoryDomain with a valid password
		ActiveDirectoryDomain domain = new ActiveDirectoryDomain("example.com", "server", "site", "bindName", "validPassword123", TlsConfiguration.TRUST_ALL_CERTIFICATES);

		// Verify the domain object is created successfully
		assertEquals("example.com", domain.getName());
		assertEquals("server:3268", domain.getServers());
		assertEquals("site", domain.getSite());
		assertEquals("bindName", domain.getBindName());
		assertEquals("validPassword123", domain.getBindPassword().getPlainText());
	}

	@Test
	public void testDoCheckBindPasswordFIPSModeShortPassword() {
		// Mock FIPS140 to return true for useCompliantAlgorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		// Create an instance of the DescriptorImpl class
		ActiveDirectoryDomain.DescriptorImpl descriptor = new ActiveDirectoryDomain.DescriptorImpl();

		// Test with a password less than 14 characters
		FormValidation result = descriptor.doCheckBindPassword("shortPass");
		Assertions.assertEquals(FormValidation.error(Messages.passwordTooShortFIPS()).getMessage(), result.getMessage());
	}

	@Test
	public void testDoCheckBindPasswordFIPSModeValidPassword() {
		// Mock FIPS140 to return true for useCompliantAlgorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		// Create an instance of the DescriptorImpl class
		ActiveDirectoryDomain.DescriptorImpl descriptor = new ActiveDirectoryDomain.DescriptorImpl();

		// Test with a password of 14 characters or more
		FormValidation result = descriptor.doCheckBindPassword("validPassword123");
		Assertions.assertEquals(FormValidation.ok().getMessage(), result.getMessage());
	}
}