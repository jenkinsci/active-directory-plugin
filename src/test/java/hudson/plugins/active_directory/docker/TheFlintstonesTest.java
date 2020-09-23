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

import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.GroupLookupStrategy;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import javax.naming.CommunicationException;
import javax.naming.NamingException;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static junit.framework.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertTrue;

import java.util.logging.Formatter;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

import com.google.common.base.Predicates;
import com.google.common.collect.Collections2;

import hudson.security.GroupDetails;
import hudson.util.RingBufferLogHandler;
import org.jvnet.hudson.test.recipes.LocalData;

/**
 * Integration tests with Docker
 */
public class TheFlintstonesTest {

    @Rule
    public DockerRule<TheFlintstones> docker = new DockerRule<>(TheFlintstones.class);

    @Rule
    public JenkinsRule j = new JenkinsRule();

    public final static String AD_DOMAIN = "samdom.example.com";
    public final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    public final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    public final static int MAX_RETRIES = 30;
    public String dockerIp;
    public int dockerPort;

    public void dynamicSetUp() throws Exception {
        TheFlintstones d = docker.get();
        dockerIp = d.ipBound(3268);
        dockerPort = d.port(3268);
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, dockerIp + ":" +  dockerPort , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
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

    public void manualSetUp() throws Exception {
        TheFlintstones d = docker.get();
        dockerIp = d.ipBound(3268);
        dockerPort = d.port(3268);

        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();
        for (ActiveDirectoryDomain activeDirectoryDomain : activeDirectorySecurityRealm.getDomains()) {
            activeDirectoryDomain.bindPassword = Secret.fromString(AD_MANAGER_DN_PASSWORD);
            activeDirectoryDomain.servers = dockerIp + ":" +  dockerPort;
        }

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
    public void simpleLoginSuccessful() throws Exception {
        dynamicSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @Test
    public void actualLogin() throws Exception {
        dynamicSetUp();
        JenkinsRule.WebClient wc = j.createWebClient().login("Fred", "ia4uV1EeKait");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>Fred</name>"));
        /* For a JENKINS-63737 stress test:
        while (true) {
            j.createWebClient().login("Fred", "ia4uV1EeKait");
        }
        */
    }

    @Test
    public void simpleLoginFails() throws Exception {
        dynamicSetUp();
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    @Issue("JENKINS-36148")
    @Test
    public void checkDomainHealth() throws Exception {
        dynamicSetUp();
        ActiveDirectorySecurityRealm securityRealm = (ActiveDirectorySecurityRealm) Jenkins.getInstance().getSecurityRealm();
        ActiveDirectoryDomain domain = securityRealm.getDomain(AD_DOMAIN);
        assertEquals("NS: dc1.samdom.example.com.", domain.getRecordFromDomain().toString().trim());
    }

    @Issue("JENKINS-36148")
    @Test
    public void validateCustomDomainController() throws ServletException, NamingException, IOException, Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" + dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null).toString().trim());
    }

    @Issue("JENKINS-36148")
    @Test
    public void validateDomain() throws ServletException, NamingException, IOException, Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null).toString().trim());

    }

    @Issue("JENKINS-45576")
    @Test
    public void loadGroupFromGroupname() throws Exception {
        dynamicSetUp();
        String groupname = "The Rubbles";
        GroupDetails group = j.jenkins.getSecurityRealm().loadGroupByGroupname(groupname);
        assertThat(group.getName(), is("The Rubbles"));
    }

    @Issue("JENKINS-45576")
    @Test
    public void loadGroupFromAlias() throws Exception {
        dynamicSetUp();
        // required to monitor the log messages, removing this line the test will fail
        List<String> logMessages = captureLogMessages(20);

        String aliasname = "Rubbles";
        boolean isAlias = false;
        try {
            j.jenkins.getSecurityRealm().loadGroupByGroupname(aliasname);
        } catch (Exception e) {
        } finally {
            Collection<String> filter = Collections2.filter(logMessages, Predicates.containsPattern("JENKINS-45576"));
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
    public void testSimpleLoginSuccessfulAfterReadResolveTlsConfigurationSingleDomain() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    public void testSimpleLoginFailsAfterReadResolveTlsConfigurationSingleDomain() throws Exception {
        manualSetUp();
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    @LocalData
    @Test
    public void testSimpleLoginSuccessAfterReadResolveTlsConfigurationMultipleDomainsOneDomain() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    public void testSimpleLoginFailsAfterReadResolveTlsConfigurationMultipleDomainsOneDomain() throws Exception {
        manualSetUp();
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    // TlsConfiguration tests
    @LocalData
    @Test
    public void testSimpleLoginSuccessfulTrustingAllCertificates() throws Exception {
        manualSetUp();
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @LocalData
    @Test
    public void testSimpleLoginFailsTrustingJDKTrustStore() throws Exception {
        try {
            manualSetUp();
        } catch (CommunicationException e) {
            assertTrue(e.getMessage().contains("simple bind failed"));
        }
    }

    @DockerFixture(id = "ad-dc", ports= {135, 138, 445, 39, 464, 389, 3268}, udpPorts = {53}, matchHostPorts = true)
    public static class TheFlintstones extends DockerContainer {

    }

}
