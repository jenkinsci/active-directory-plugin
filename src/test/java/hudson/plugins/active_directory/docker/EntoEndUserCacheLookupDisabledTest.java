package hudson.plugins.active_directory.docker;

import org.htmlunit.FailingHttpStatusCodeException;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectoryInternalUsersDatabase;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.CacheConfiguration;
import hudson.plugins.active_directory.GroupLookupStrategy;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers(disabledWithoutDocker = true)
@WithJenkins
class EntoEndUserCacheLookupDisabledTest {

    @Container
    private final ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withDynamicPorts();

    private JenkinsRule j;

    private final LogRecorder l = new LogRecorder();

    private static final String AD_DOMAIN = "samdom.example.com";
    private static final String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    private static final String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    private static final int MAX_RETRIES = 30;
    private String dockerIp;
    private int dockerPort;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    private void customSingleADSetup(ActiveDirectoryDomain activeDirectoryDomain, String site, String bindName, String bindPassword,
                                    GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain,
                                    CacheConfiguration cache, Boolean startTls, ActiveDirectoryInternalUsersDatabase internalUsersDatabase) throws Exception {
        dockerIp = docker.getHost();
        dockerPort = docker.getMappedPort(3268);

        activeDirectoryDomain.servers = dockerIp + ":" + dockerPort;
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);

        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, site, bindName, bindPassword, null, groupLookupStrategy, removeIrrelevantGroups, customDomain, cache, startTls, internalUsersDatabase, false);
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        UserDetails userDetails = null;
        int i = 0;
        while (i < MAX_RETRIES && userDetails == null) {
            try {
                userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
            } catch (AuthenticationServiceException e) {
                Thread.sleep(1000);
            }
            i ++;
        }
    }

    @Test
    void testEndtoEndManagerDnCacheEnabled() throws Exception {
        List<String> messages;
        l.record(hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.class, Level.FINE).capture(20);
        // Configure AD servers with Manager DN and the Cache enabled
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null);
        CacheConfiguration cacheConfiguration = new CacheConfiguration(500,30);
        customSingleADSetup(activeDirectoryDomain, null, null, null, GroupLookupStrategy.RECURSIVE, false, null, cacheConfiguration, false, null );
        // Try to login as Fred with correct password
        JenkinsRule.WebClient wc = j.createWebClient().login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
        // Move to $JENKINS_URL/user/Fred to perform an internal lookup which will be cached
        wc.goTo("user/Fred");
        //Logout
        j.createWebClient().goTo("logout");
        // Try to login as Fred with blank password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("Fred", ""));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with incorrect password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("Fred", "Fred"));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with correct password
        wc.login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
    }

    @Test
    void testEndtoEndManagerDnCacheDisabled() throws Exception {
        List<String> messages;
        l.record(hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.class, Level.FINE).capture(20);
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null);
        customSingleADSetup(activeDirectoryDomain, null, null, null, GroupLookupStrategy.RECURSIVE, false, null, null, false, null );
        // Try to login as Fred with correct password
        JenkinsRule.WebClient wc = j.createWebClient().login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
        // Move to $JENKINS_URL/user/Fred to perform an internal lookup which will be cached
        wc.goTo("user/Fred");
        //Logout
        j.createWebClient().goTo("logout");
        // Try to login as Fred with blank password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("Fred", ""));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with incorrect password
        assertThrows(FailingHttpStatusCodeException.class, () -> wc.login("Fred", "Fred"));
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with correct password
        wc.login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));

    }
}
