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

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

import hudson.plugins.active_directory.TlsConfiguration;
import org.burningwave.tools.net.DNSClientHostResolver;
import org.burningwave.tools.net.DefaultHostResolver;
import org.burningwave.tools.net.HostResolutionRequestInterceptor;
import org.burningwave.tools.net.MappedHostResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LogRecorder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.userdetails.UserDetails;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.DNSUtils;
import hudson.plugins.active_directory.GroupLookupStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Integration tests with Docker and using samba as a DNS server
 */
@Testcontainers(disabledWithoutDocker = true)
@WithJenkins
class TheFlintstonesIT {

    @Container
    private final ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withStaticPorts();

    private JenkinsRule j;

    @SuppressWarnings("unused")
    private final LogRecorder l = new LogRecorder();

    private static final String AD_DOMAIN = "samdom.example.com";
    private static final String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    private static final String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    private static final int MAX_RETRIES = 30;
    private static final int GLOBAL_CATALOG_PLAIN_TEXT = 3268;
    private static final int GLOBAL_CATALOG_TLS = 3269;

    private String dockerIp;
    private int dockerPort;

    @BeforeEach
    void beforeEach(JenkinsRule rule) throws Exception {
        j = rule;
        // we need to pint the JVMs DNS resolver at the AD (samba) server
        // for AD to work correctly it needs to be able to resolve hosts and do SRV lookups on the domain

        // whilst the `getHost()` is supposed to return an IPAddress in some cases it will return "localhost"
        // we need a resolved address to configure the resolver do a lookup before we change the DNS.
        InetAddress hostInetAddr = InetAddress.getByName(docker.getHost());
        String hostIP = hostInetAddr.getHostAddress();

        // but additionally we need to use the locally bound ports for the catalog and not what AD returns for name resolution
        Map<String, String> hostAliases = new LinkedHashMap<>();
        hostAliases.put("dc1.samdom.example.com", hostIP);
        // this adds the A entry for the PDC, but will leave the discovery of this to the SRV lookup

        HostResolutionRequestInterceptor.INSTANCE.install(
                new MappedHostResolver(hostAliases),
                new DNSClientHostResolver(hostIP, 553),
                DefaultHostResolver.INSTANCE);

        // we also need to set the JNDI default
        // see hudson.plugins.active_directory.ActiveDirectoryDomain.createDNSLookupContext()
        if (hostInetAddr instanceof Inet6Address) {
            System.setProperty(DNSUtils.OVERRIDE_DNS_PROPERTY, "dns://["+hostIP+"]:553");
        } else {
            System.setProperty(DNSUtils.OVERRIDE_DNS_PROPERTY, "dns://"+hostIP+":553");
        }
    }

    @AfterEach
    void afterEach() {
        HostResolutionRequestInterceptor.INSTANCE.install(DefaultHostResolver.INSTANCE);
        System.clearProperty(DNSUtils.OVERRIDE_DNS_PROPERTY);
    }

    private void dynamicSetUp() throws Exception {
        dynamicSetUp(false);
    }

    private void dynamicSetUp(boolean requireTLS) throws Exception {
        dockerIp = "dc1.samdom.example.com";
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
                userDetails = j.jenkins.getSecurityRealm().loadUserByUsername2("Fred");
            } catch (AuthenticationServiceException e) {
                Thread.sleep(1000);
            }
            i ++;
        }
    }

    @Issue("JENKINS-36148")
    @Test
    void validateCustomDomainController() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" + dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("JENKINS-36148")
    @Test
    void validateDomain() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());

    }

    @Issue("JENKINS-69683")
    @Test
    void validateTestDomainRequireTLSDisabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("JENKINS-69683")
    @Test
    void validateTestDomainServerRequireTLSDisabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null, null, false, false, false).toString().trim());
    }

    @Issue("SECURITY-3059")
    @Test
    void validateTestDomainServerRequireTLSEnabled() throws Exception {
        dynamicSetUp(true);
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, "dc1.samdom.example.com" + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, TlsConfiguration.TRUST_ALL_CERTIFICATES, GroupLookupStrategy.TOKENGROUPS, false, false, true).toString().trim());
    }

    @Issue("SECURITY-3059")
    @Test
    void validateTestDomainServerRequireStartTLSEnabled() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, "dc1.samdom.example.com" + ":" +  dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, TlsConfiguration.TRUST_ALL_CERTIFICATES, GroupLookupStrategy.TOKENGROUPS, false, true, false).toString().trim());
    }

}
