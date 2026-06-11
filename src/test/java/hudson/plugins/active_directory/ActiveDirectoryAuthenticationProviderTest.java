package hudson.plugins.active_directory;

import org.junit.Test;

import static hudson.plugins.active_directory.ActiveDirectoryAuthenticationProvider.*;
import static junit.framework.Assert.*;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryAuthenticationProviderTest {
    @Test
    public void testEscape() {
        assertEquals("LDAP://it\\/ops", dnToLdapUrl("it/ops"));
        assertEquals("LDAP://foo\\#\\,bar", dnToLdapUrl("foo\\#\\,bar"));
    }

    @Test
    public void testEscapeLdapFilterValue() {
        // RFC 4515 metacharacters
        assertEquals("\\2a", escapeLdapFilterValue("*"));
        assertEquals("\\28", escapeLdapFilterValue("("));
        assertEquals("\\29", escapeLdapFilterValue(")"));
        assertEquals("\\5c", escapeLdapFilterValue("\\"));
        assertEquals("\\00", escapeLdapFilterValue("\0"));

        // Combined injection attempts - pipe doesn't need escaping, only parens and wildcard
        assertEquals("admin\\29\\28|\\28sAMAccountName=\\2a",
                     escapeLdapFilterValue("admin)(|(sAMAccountName=*"));
        assertEquals("\\2a", escapeLdapFilterValue("*"));

        // Normal usernames should pass through
        assertEquals("validUser", escapeLdapFilterValue("validUser"));
        assertEquals("user.name", escapeLdapFilterValue("user.name"));
        assertEquals("user@domain", escapeLdapFilterValue("user@domain"));

        // Edge cases
        assertEquals("", escapeLdapFilterValue(null));
        assertEquals("", escapeLdapFilterValue(""));
    }
}
