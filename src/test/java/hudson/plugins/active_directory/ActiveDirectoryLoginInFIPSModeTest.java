package hudson.plugins.active_directory;

import java.lang.reflect.Field;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

import jenkins.security.FIPS140;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Author: Nevin Sunny
 * Date: 30/09/24
 * Time: 10:13 am
 */
public class ActiveDirectoryLoginInFIPSModeTest {


	private ActiveDirectorySecurityRealm securityRealm;
	private AbstractActiveDirectoryAuthenticationProvider authenticationProvider;

	@Before
	public void setUp() throws NoSuchMethodException, NoSuchFieldException, IllegalAccessException {
		securityRealm = new ActiveDirectorySecurityRealm("domain", "site"
				, "bindName", "bindPassword", "server");

		// Create a mock instance of AbstractActiveDirectoryAuthenticationProvider
		authenticationProvider = Mockito.mock(AbstractActiveDirectoryAuthenticationProvider.class);

		// Use reflection to set the private field
		Field field = ActiveDirectorySecurityRealm.class.getDeclaredField("authenticationProvider");
		field.setAccessible(true);
		field.set(securityRealm, authenticationProvider);

	}

	@Test
	public void testAuthenticateWithShortPassword() {
		// Set FIPS to compliant algorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		String username = "user";
		String password = "short";

		Exception exception = assertThrows(IllegalArgumentException.class, () -> {
			securityRealm.authenticate(username, password);
		});

		assertEquals(Messages.passwordTooShortFIPS(),exception.getMessage() );
	}

	@Test
	public void testAuthenticateWithValidPassword() {
		// Set FIPS to compliant algorithms
		Mockito.mockStatic(FIPS140.class);
		when(FIPS140.useCompliantAlgorithms()).thenReturn(true);

		String username = "user";
		String password = "verylongpassword";

		// Mock the retrieveUser method
		UserDetails mockUserDetails = Mockito.mock(UserDetails.class);
		when(mockUserDetails.getUsername()).thenReturn("user");
		when(authenticationProvider.retrieveUser(anyString(), any(UsernamePasswordAuthenticationToken.class)))
				.thenReturn(mockUserDetails);

		UserDetails userDetails = securityRealm.authenticate(username, password);

		assertEquals("user",userDetails.getUsername() );
	}


}
