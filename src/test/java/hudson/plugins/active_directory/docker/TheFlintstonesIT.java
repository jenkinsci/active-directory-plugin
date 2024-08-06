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
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.naming.NamingException;
import javax.servlet.ServletException;

import hudson.plugins.active_directory.TlsConfiguration;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.burningwave.tools.net.DNSClientHostResolver;
import org.burningwave.tools.net.DefaultHostResolver;
import org.burningwave.tools.net.HostResolutionRequestInterceptor;
import org.burningwave.tools.net.MappedHostResolver;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.DNSUtils;
import hudson.plugins.active_directory.GroupLookupStrategy;

/**
 * Integration tests with Docker and using samba as a DNS server
 */
public class TheFlintstonesIT {


    @Rule(order = 0)
    public RequireDockerRule rdr = new RequireDockerRule();

    // if the rule fails as port 53 is in use (on linux) see hack_systemd_resolve.sh 
    // or https://www.linuxuprising.com/2020/07/ubuntu-how-to-free-up-port-53-used-by.html
    @Rule(order = 1)
    public ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withStaticPorts();

    @Rule(order = 2) // start Jenkins after the container so that timeouts do not apply to container building.
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    @Before
    public void overrideDNSServers() throws UnknownHostException {
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
        // getHost returns a hostname not IPaddress...
        // use our DNS to resolve that to an IP address.
        System.setProperty(DNSUtils.OVERRIDE_DNS_PROPERTY, "dns://"+hostIP+":553");
    }

    @After
    public void restoreDNS() {
        HostResolutionRequestInterceptor.INSTANCE.install(DefaultHostResolver.INSTANCE);
        System.clearProperty(DNSUtils.OVERRIDE_DNS_PROPERTY);
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
