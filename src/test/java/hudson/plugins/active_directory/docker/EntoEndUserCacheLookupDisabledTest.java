package hudson.plugins.active_directory.docker;

import org.htmlunit.FailingHttpStatusCodeException;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectoryInternalUsersDatabase;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.CacheConfiguration;
import hudson.plugins.active_directory.GroupLookupStrategy;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.testcontainers.DockerClientFactory;
import org.testcontainers.containers.GenericContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class EntoEndUserCacheLookupDisabledTest {

    @Rule(order = 0)
    public RequireDockerRule rdr = new RequireDockerRule();

    @Rule(order = 1)
    public ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withDynamicPorts();

    @Rule(order = 2) // start Jenkins after the container so that timeouts do not apply to container building.
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    private final static String AD_DOMAIN = "samdom.example.com";
    private final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    private final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    private final static int MAX_RETRIES = 30;
    private String dockerIp;
    private int dockerPort;

    public void customSingleADSetup(ActiveDirectoryDomain activeDirectoryDomain, String site, String bindName, String bindPassword,
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
    public void testEndtoEndManagerDnCacheEnabled() throws Exception {
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
        try {
            wc.login("Fred", "");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with incorrect password
        try {
            wc.login("Fred", "Fred");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with correct password
        wc.login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
    }

    @Test
    public void testEndtoEndManagerDnCacheDisabled() throws Exception {
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
        try {
            wc.login("Fred", "");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with incorrect password
        try {
            wc.login("Fred", "Fred");
            fail();
        } catch (FailingHttpStatusCodeException ex) {
        }
        messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
        // Try to login as Fred with correct password
        wc.login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));

    }
}
