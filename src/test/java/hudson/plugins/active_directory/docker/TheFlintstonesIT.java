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

import static org.junit.Assert.assertEquals;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.naming.NamingException;
import javax.servlet.ServletException;

import hudson.plugins.active_directory.TlsConfiguration;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.burningwave.tools.net.DNSClientHostResolver;
import org.burningwave.tools.net.DefaultHostResolver;
import org.burningwave.tools.net.HostResolutionRequestInterceptor;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.GroupLookupStrategy;

/**
 * Integration tests with Docker and requiring custom DNS in the target env with fixed ports.
 */
public class TheFlintstonesIT {


    @Rule(order = 0)
    public RequireDockerRule rdr = new RequireDockerRule();

    @Rule(order = 1)
    public ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withStaticPorts();

    @Rule(order = 4) // start Jenkins after the container so that timeouts do not apply to container building.
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    @Before
    public void configureDNSServer() {
        // we need to pint the JVMs DNS resolver at the samba server
        // for AD to work correctly it needs to be able to resolve hosts and do SRV lookups on the domain
        HostResolutionRequestInterceptor.INSTANCE.install(
                new DNSClientHostResolver("127.0.0.1"), // The SAMBA Server
                DefaultHostResolver.INSTANCE);
    }

    public final static String AD_DOMAIN = "samdom.example.com";
    public final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    public final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    public final static int MAX_RETRIES = 30;
    public final static int GLOBAL_CATALOG_PLAIN_TEXT = 3268;
    public final static int GLOBAL_CATALOG_TLS = 3269;
    public String dockerIp;
    public int dockerPort;

    public void dynamicSetUp() throws Exception {
        dynamicSetUp(false);
    }

    public void dynamicSetUp(boolean requireTLS) throws Exception {
        dockerIp = requireTLS ? docker.getHost() : "dc1.samdom.example.com";
        dockerPort = docker.getMappedPort(requireTLS ? GLOBAL_CATALOG_TLS : GLOBAL_CATALOG_PLAIN_TEXT);
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, dockerIp + ":" +  dockerPort , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, requireTLS);
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
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

    @Issue("JENKINS-36148")
    @Test
    public void validateCustomDomainController() throws ServletException, NamingException, IOException, Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" + dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("JENKINS-36148")
    @Test
    public void validateDomain() throws ServletException, NamingException, IOException, Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());

    }

    @Issue("JENKINS-69683")
    @Test
    public void validateTestDomainRequireTLSDisabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("JENKINS-69683")
    @Test
    public void validateTestDomainServerRequireTLSDisabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("SECURITY-3059")
    @Test
    public void validateTestDomainServerRequireTLSEnabled() throws Exception {
        dynamicSetUp(true);
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, "dc1.samdom.example.com" + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, TlsConfiguration.TRUST_ALL_CERTIFICATES, GroupLookupStrategy.TOKENGROUPS, false, false, true).toString().trim());
    }

    @Issue("SECURITY-3059")
    @Test
    public void validateTestDomainServerRequireStartTLSEnabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, "dc1.samdom.example.com" + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, TlsConfiguration.TRUST_ALL_CERTIFICATES, GroupLookupStrategy.TOKENGROUPS, false, true, false).toString().trim());
    }

}
