package hudson.plugins.active_directory;

import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import java.util.List;
import java.util.logging.Level;

import static hudson.Functions.isWindows;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This tests requires a very specific windows environment to run, the windows machine
 * needs to be joined to a function domain that has the user fred with the password ia4uV1EeKait.
 * It is enabled in the WindowsITs profile, but will skip on I as that profile is enabled only on the special Linux environment.
 */
@WithJenkins
class WindowsAdsiModeUserCacheDisabledIT {

    private final LogRecorder l = new LogRecorder();

    private JenkinsRule j;

    @BeforeAll
    static void beforeAll() {
        assumeTrue(isWindows());
    }

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    private void dynamicCacheEnableSetUp() {
        CacheConfiguration cacheConfiguration = new CacheConfiguration(500,30);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, null, null, null,
                null, null, null, false, null, cacheConfiguration, null, null, false);
        j.jenkins.setSecurityRealm(activeDirectorySecurityRealm);
    }


    private void dynamicCacheDisabledSetUp() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, null, null, null,
                null, null, null, false, null, null, null, null, false);
        j.jenkins.setSecurityRealm(activeDirectorySecurityRealm);
    }

    @Test
    void actualLogin() throws Exception {
        dynamicCacheDisabledSetUp();
        JenkinsRule.WebClient wc = j.createWebClient().login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
    }

    @Test
    void testEndtoEndCacheEnabled() throws Exception {
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
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("fred", ""));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Empty password not allowed was tried by user fred")));
        // Try to login as fred with incorrect password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("fred", "fred"));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Login failure: Incorrect password for fred")));
        // Try to login as fred with correct password
        wc.login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
    }

    @Test
    void testEndtoEndCacheDisabled() throws Exception {
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
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("fred", ""));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Empty password not allowed was tried by user fred")));
        // Try to login as fred with incorrect password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("fred", "fred"));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Login failure: Incorrect password for fred")));
        // Try to login as fred with correct password
        wc.login("fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>fred</name>"));
    }

}
