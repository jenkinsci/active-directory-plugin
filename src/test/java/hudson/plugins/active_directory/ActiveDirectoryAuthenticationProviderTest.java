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
        assertEquals("it\\/ops", ldapEscape("it/ops"));
        assertEquals("foo\\#\\,bar", ldapEscape("foo#,bar"));
    }
}
