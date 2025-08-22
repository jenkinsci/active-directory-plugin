/*
 * The MIT License
 *
 * Copyright (c) 2017, Felix Belzunce Arcos, CloudBees, Inc., and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package hudson.plugins.active_directory.docker;

import org.htmlunit.FailingHttpStatusCodeException;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.DNSUtils;
import hudson.plugins.active_directory.GroupLookupStrategy;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.naming.CommunicationException;
import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import hudson.security.GroupDetails;
import hudson.util.RingBufferLogHandler;
import org.jvnet.hudson.test.recipes.LocalData;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests with Docker
 */
@Testcontainers(disabledWithoutDocker = true)
@WithJenkins
class TheFlintstonesTest {

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
    void beforeEach(JenkinsRule rule) throws Exception {
        j = rule;
        // see hudson.plugins.active_directory.ActiveDirectoryDomain.createDNSLookupContext()
        // getHost returns a hostname not IP address...
        // use our DNS to resolve that to an IP address.
        String DNS_URLs = new URI("dns", null, InetAddress.getByName(docker.getHost()).getHostAddress(), Integer.parseInt(docker.getDNSPort()), null, null, null).toASCIIString();
        System.setProperty(DNSUtils.OVERRIDE_DNS_PROPERTY, DNS_URLs);
    }

    @AfterEach
    void afterEach() {
        // see hudson.plugins.active_directory.ActiveDirectoryDomain.createDNSLookupContext()
        System.clearProperty(ActiveDirectoryDomain.class.getName()+ ".OVERRIDE_DNS_SERVERS");
    }

    private void dynamicSetUp() throws Exception {
        dockerIp = docker.getHost();
        dockerPort = docker.getMappedPort(3268);
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, dockerIp + ":" +  dockerPort , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, false);
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

    private void manualSetUp() throws Exception {
        dockerIp = docker.getHost();
        dockerPort = docker.getMappedPort(3268);

        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();
        for (ActiveDirectoryDomain activeDirectoryDomain : activeDirectorySecurityRealm.getDomains()) {
            activeDirectoryDomain.bindPassword = Secret.fromString(AD_MANAGER_DN_PASSWORD);
            activeDirectoryDomain.servers = dockerIp + ":" +  dockerPort;
        }

        while(!docker.getLogs().contains("custom (exit status 0; expected)")) {
            Thread.sleep(1000);
        }
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
    void simpleLoginSuccessful() throws Exception {
        dynamicSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @Test
    void actualLogin() throws Exception {
        dynamicSetUp();
        JenkinsRule.WebClient wc = j.createWebClient().login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
        /* For a JENKINS-63737 stress test:
        while (true) {
            j.createWebClient().login("Fred", "ia4uV1EeKait");
        }
        */
    }

    @Issue("SECURITY-2099")
    @Test
    void shouldNotAllowEmptyPassword() throws Exception {
        l.record(hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.class, Level.FINE).capture(20);
        dynamicSetUp();
        assertThrows(FailingHttpStatusCodeException.class, () -> j.createWebClient().login("Fred", ""));
        final List<String> messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
    }

    @Test
    void simpleLoginFails() throws Exception {
        dynamicSetUp();
        UsernameNotFoundException e = assertThrows(UsernameNotFoundException.class, () -> j.jenkins.getSecurityRealm().loadUserByUsername2("Homer"));
        assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
    }

    @Issue("JENKINS-45576")
    @Test
    void loadGroupFromGroupname() throws Exception {
        dynamicSetUp();
        String groupname = "The Rubbles";
        GroupDetails group = j.jenkins.getSecurityRealm().loadGroupByGroupname2(groupname, false);
        assertThat(group.getName(), is("The Rubbles"));
    }

    @Issue("JENKINS-45576")
    @Test
    void loadGroupFromAlias() throws Exception {
        dynamicSetUp();
        // required to monitor the log messages, removing this line the test will fail
        List<String> logMessages = captureLogMessages(20);

        String aliasname = "Rubbles";
        boolean isAlias;
        try {
            j.jenkins.getSecurityRealm().loadGroupByGroupname2(aliasname, false);
        } catch (Exception e) {
            // ignored
        } finally {
            Collection<String> filter = logMessages.stream().
                filter(s -> s.contains( "JENKINS-45576")).
                    toList();
            isAlias = !filter.isEmpty();
        }

        assertTrue(isAlias);
    }

    private List<String> captureLogMessages(int size) {
        final List<String> logMessages = new ArrayList<>(size);
        Logger logger = Logger.getLogger("");
        logger.setLevel(Level.ALL);

        RingBufferLogHandler ringHandler = new RingBufferLogHandler(size) {

            final Formatter f = new SimpleFormatter(); // placeholder instance for what should have been a static method perhaps
            @Override
            public synchronized void publish(LogRecord record) {
                super.publish(record);
                String message = f.formatMessage(record);
                Throwable x = record.getThrown();
                logMessages.add(message == null && x != null ? x.toString() : message);
            }
        };
        logger.addHandler(ringHandler);

        return logMessages;
    }

    // ReadResolve tlsConfiguration migration tests

    @LocalData
    @Test
    void testSimpleLoginSuccessfulAfterReadResolveTlsConfigurationSingleDomain() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    void testSimpleLoginFailsAfterReadResolveTlsConfigurationSingleDomain() throws Exception {
        manualSetUp();
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername2("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    @LocalData
    @Test
    void testSimpleLoginSuccessAfterReadResolveTlsConfigurationMultipleDomainsOneDomain() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    void testSimpleLoginFailsAfterReadResolveTlsConfigurationMultipleDomainsOneDomain() throws Exception {
        manualSetUp();
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername2("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    // TlsConfiguration tests
    @LocalData
    @Test
    void testSimpleLoginSuccessfulTrustingAllCertificates() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    void testSimpleLoginFailsTrustingJDKTrustStore() throws Exception {
        try {
            manualSetUp();
        } catch (CommunicationException e) {
            assertTrue(e.getMessage().contains("simple bind failed"));
        }
    }

    @Issue("SECURITY-2117")
    @Test
    void testNullBytesInPasswordMustFail() throws Exception {
        l.record(hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.class, Level.FINE).capture(20);
        dynamicSetUp();
        assertThrows(FailingHttpStatusCodeException.class, () -> j.createWebClient().login("Fred", "\u0000\u0000\u0000\u0000\u0000\u0000"));
        final List<String> messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
    }

    @Issue("SECURITY-2117")
    @Test
    void testIncorrectPasswordMustFail() throws Exception {
        l.record(hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.class, Level.FINE).capture(20);
        dynamicSetUp();
        assertThrows(FailingHttpStatusCodeException.class, () -> j.createWebClient().login("Fred", "Fred"));
        final List<String> messages = l.getMessages();
        assertTrue(messages.stream().anyMatch(s -> s.contains("Failed to retrieve user Fred")));
    }

    @Issue("JENKINS-36148")
    @Test
    void checkDomainHealth() throws Exception {
        dynamicSetUp();
        ActiveDirectorySecurityRealm securityRealm = (ActiveDirectorySecurityRealm) Jenkins.get().getSecurityRealm();
        ActiveDirectoryDomain domain = securityRealm.getDomain(AD_DOMAIN);
        assertEquals("NS: dc1.samdom.example.com.", domain.getRecordFromDomain().toString().trim());
    }

}
