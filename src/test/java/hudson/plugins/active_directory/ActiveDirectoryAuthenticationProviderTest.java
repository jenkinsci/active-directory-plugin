package hudson.plugins.active_directory;

import org.junit.jupiter.api.Test;

import static hudson.plugins.active_directory.ActiveDirectoryAuthenticationProvider.*;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author Kohsuke Kawaguchi
 */
class ActiveDirectoryAuthenticationProviderTest {

    @Test
    void testEscape() {
        assertEquals("LDAP://it\\/ops", dnToLdapUrl("it/ops"));
        assertEquals("LDAP://foo\\#\\,bar", dnToLdapUrl("foo\\#\\,bar"));
    }
}
