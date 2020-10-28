package hudson.plugins.active_directory.docker;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectoryInternalUsersDatabase;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.CacheConfiguration;
import hudson.plugins.active_directory.CacheUtil;
import hudson.plugins.active_directory.GroupLookupStrategy;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class EntoEndUserCacheLookupEnabledTest {

    @Rule
    public DockerRule<TheFlintstonesTest.TheFlintstones> docker = new DockerRule<>(TheFlintstonesTest.TheFlintstones.class);

    @Rule
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    private final static String AD_DOMAIN = "samdom.example.com";
    private final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    private final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    private final static int MAX_RETRIES = 30;
    private String dockerIp;
    private int dockerPort;

    private static String CACHE_AUTH;

    @BeforeClass
    public static void enableHealthMetrics() {
        CACHE_AUTH = System.getProperty(CacheUtil.class.getName() + ".cacheAuth");
        System.setProperty(CacheUtil.class.getName() + ".cacheAuth", "true");
    }

    @AfterClass
    public static void disableHealthMetrics() {
        // Put back the previous value before the test was executed
        if (CACHE_AUTH != null) {
            System.setProperty(CacheUtil.class.getName() + ".cacheAuth", CACHE_AUTH);
        } else {
            System.clearProperty(CacheUtil.class.getName() + ".cacheAuth");
        }
    }

    public void customSingleADSetup(ActiveDirectoryDomain activeDirectoryDomain, String site, String bindName, String bindPassword,
                                    GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain,
                                    CacheConfiguration cache, Boolean startTls, ActiveDirectoryInternalUsersDatabase internalUsersDatabase) throws Exception {
        TheFlintstonesTest.TheFlintstones d = docker.get();
        dockerIp = d.ipBound(3268);
        dockerPort = d.port(3268);

        activeDirectoryDomain.servers = dockerIp + ":" + dockerPort;
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);

        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, site, bindName, bindPassword, null, groupLookupStrategy, removeIrrelevantGroups, customDomain, cache, startTls, internalUsersDatabase);
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        while(!FileUtils.readFileToString(d.getLogfile()).contains("custom (exit status 0; expected)")) {
            Thread.sleep(1000);
        }
        UserDetails userDetails = null;
        int i = 0;
        while (i < MAX_RETRIES && userDetails == null) {
            try {
                userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
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

    @DockerFixture(id = "ad-dc", ports= {135, 138, 445, 39, 464, 389, 3268}, udpPorts = {53}, matchHostPorts = true, dockerfileFolder="docker/TheFlintstonesTest/TheFlintstones")
    public static class TheFlintstones extends DockerContainer {

    }
}
