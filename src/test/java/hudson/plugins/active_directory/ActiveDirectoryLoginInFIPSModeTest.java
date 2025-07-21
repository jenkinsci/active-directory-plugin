package hudson.plugins.active_directory;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;
import org.jvnet.hudson.test.FlagRule;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

public class ActiveDirectoryLoginInFIPSModeTest {

	private ActiveDirectorySecurityRealm securityRealm;
	private AbstractActiveDirectoryAuthenticationProvider authenticationProvider;

	@ClassRule
	public static FlagRule<String> fipsSystemPropertyRule =
			FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

	@Before
	public void setUp() throws NoSuchFieldException, IllegalAccessException {
		securityRealm = new ActiveDirectorySecurityRealm("domain", Arrays.asList(new ActiveDirectoryDomain("name", "servers", "site", "bindName", "bindPasswordFIPS", TlsConfiguration.JDK_TRUSTSTORE)),
		                                                 "site", "bindName", "bindPassword", "server", GroupLookupStrategy.AUTO, true, true,
		                                                 null, true, null, true);
		// Create a mock instance of AbstractActiveDirectoryAuthenticationProvider
		authenticationProvider = Mockito.mock(AbstractActiveDirectoryAuthenticationProvider.class);

		// Use reflection to set the private field
		Field field = ActiveDirectorySecurityRealm.class.getDeclaredField("authenticationProvider");
		field.setAccessible(true);
		field.set(securityRealm, authenticationProvider);

	}
	
	@Test
	public void testAuthenticateWithShortPassword() {
		String username = "user";
		String password = "short";

		Exception exception = assertThrows(AuthenticationServiceException.class, () -> {
			securityRealm.authenticate2(username, password);
		});

		assertEquals(Messages.passwordTooShortFIPS(),exception.getMessage() );
	}

	@Test
	public void testAuthenticateWithValidPassword() {
        String username = "user";
		String password = "verylongpassword";

		// Mock the retrieveUser method
		UserDetails mockUserDetails = Mockito.mock(UserDetails.class);
		when(mockUserDetails.getUsername()).thenReturn("user");
		when(authenticationProvider.retrieveUser(anyString(), any(UsernamePasswordAuthenticationToken.class)))
				.thenReturn(mockUserDetails);

		UserDetails userDetails = securityRealm.authenticate2(username, password);

		assertEquals("user",userDetails.getUsername() );
	}
}
