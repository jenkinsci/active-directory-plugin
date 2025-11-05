package hudson.plugins.active_directory;

import java.lang.reflect.Field;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

class ActiveDirectoryLoginInFIPSModeTest {

    private ActiveDirectorySecurityRealm securityRealm;
    private AbstractActiveDirectoryAuthenticationProvider authenticationProvider;

    private static String fipsSystemProperty;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
    }

    @BeforeEach
    void beforeEach() throws Exception {
		securityRealm = new ActiveDirectorySecurityRealm("domain", List.of(new ActiveDirectoryDomain("name", "servers", "site", "bindName", "bindPasswordFIPS", TlsConfiguration.JDK_TRUSTSTORE)),
		                                                 "site", "bindName", "bindPassword", "server", GroupLookupStrategy.AUTO, true, true,
		                                                 null, true, null, true);
		// Create a mock instance of AbstractActiveDirectoryAuthenticationProvider
		authenticationProvider = Mockito.mock(AbstractActiveDirectoryAuthenticationProvider.class);

		// Use reflection to set the private field
		Field field = ActiveDirectorySecurityRealm.class.getDeclaredField("authenticationProvider");
		field.setAccessible(true);
		field.set(securityRealm, authenticationProvider);
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
    void testAuthenticateWithShortPassword() {
		String username = "user";
		String password = "short";

		Exception exception = assertThrows(AuthenticationServiceException.class, () ->
			securityRealm.authenticate2(username, password));

		assertEquals(Messages.passwordTooShortFIPS(),exception.getMessage() );
    }

    @Test
    void testAuthenticateWithValidPassword() {
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
