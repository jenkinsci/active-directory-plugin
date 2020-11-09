package hudson.plugins.active_directory;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import java.io.File;
import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;


public class WindowsAdsiModeUserCacheDisabledTest {

    @BeforeClass
    public static void setUp() {
        assumeTrue(isWindows());
    }

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    public void dynamicCacheEnableSetUp() throws Exception {
        CacheConfiguration cacheConfiguration = new CacheConfiguration(500,30);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, null, null, null,
                null, null, null, false, null, cacheConfiguration, null, (ActiveDirectoryInternalUsersDatabase) null);
        j.jenkins.setSecurityRealm(activeDirectorySecurityRealm);
    }


    public void dynamicCacheDisabledSetUp() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, null, null, null,
                null, null, null, false, null, null, null, (ActiveDirectoryInternalUsersDatabase) null);
        j.jenkins.setSecurityRealm(activeDirectorySecurityRealm);
    }

    @Test
    public void actualLogin() throws Exception {
        dynamicCacheDisabledSetUp();
        JenkinsRule.WebClient wc = j.createWebClient().login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
    }

    @Test
    public void testEndtoEndCacheEnabled() throws Exception {
        dynamicCacheEnableSetUp();
        List<String> messages;
        l.record(hudson.plugins.active_directory.ActiveDirectoryAuthenticationProvider.class, Level.FINE).capture(20);
        // Try to login as fred with correct password
        JenkinsRule.WebClient wc = j.createWebClient().login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
        // Move to $JENKINS_URL/user/Fred to perform an internal lookup which will be cached
        wc.goTo("user/fred");
        //Logout
        j.createWebClient().goTo("logout");
        // Try to login as fred with blank password
        try {
            wc.login("fred", "");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Empty password not allowed was tried by user fred")));
        // Try to login as fred with incorrect password
        try {
            wc.login("fred", "fred");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Login failure: Incorrect password for fred")));
        // Try to login as fred with correct password
        wc.login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
    }

    @Test
    public void testEndtoEndCacheDisabled() throws Exception {
        dynamicCacheDisabledSetUp();
        List<String> messages;
        l.record(hudson.plugins.active_directory.ActiveDirectoryAuthenticationProvider.class, Level.FINE).capture(20);
        // Try to login as Fred with correct password
        JenkinsRule.WebClient wc = j.createWebClient().login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
        // Move to $JENKINS_URL/user/fred to perform an internal lookup which will be cached
        wc.goTo("user/fred");
        //Logout
        j.createWebClient().goTo("logout");
        // Try to login as Fred with blank password
        try {
            wc.login("fred", "");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Empty password not allowed was tried by user fred")));
        // Try to login as fred with incorrect password
        try {
            wc.login("fred", "fred");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Login failure: Incorrect password for fred")));
        // Try to login as fred with correct password
        wc.login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));

    }

    /**
     * inline ${@link hudson.Functions#isWindows()} to prevent a transient
     * remote classloader issue
     */
    private static boolean isWindows() {
        return File.pathSeparatorChar == ';';
    }
}
