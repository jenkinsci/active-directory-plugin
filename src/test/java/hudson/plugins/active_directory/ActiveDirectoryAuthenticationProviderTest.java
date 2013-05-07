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
}
