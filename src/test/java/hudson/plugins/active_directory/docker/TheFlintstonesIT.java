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
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;
import org.testcontainers.DockerClientFactory;
import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.GroupLookupStrategy;
import hudson.util.Secret;

/**
 * Integration tests with Docker and requiring custom DNS in the target env with fixed ports.
 */
public class TheFlintstonesIT {

    @Rule(order = 0)
    public RequireDockerRule rdr = new RequireDockerRule();

    @Rule(order = 1)
    public ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withStaticPorts();

    @Rule(order = 2) // start Jenkins after the container so that timeouts do not apply to container building.
    public JenkinsRule j = new JenkinsRule();

    @Rule
    public LoggerRule l = new LoggerRule();

    public final static String AD_DOMAIN = "samdom.example.com";
    public final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    public final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    public final static int MAX_RETRIES = 30;
    public String dockerIp;
    public int dockerPort;

    public void dynamicSetUp() throws Exception {
        dockerIp = docker.getHost();
        dockerPort = docker.getMappedPort(3268);
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, dockerIp + ":" +  dockerPort , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, false);
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        while(!docker.getLogs().contains("custom (exit status 0; expected)")) {
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

    @Issue("JENKINS-36148")
    @Test
    public void validateCustomDomainController() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, dockerIp + ":" + dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null).toString().trim());
    }

    @Issue("JENKINS-36148")
    @Test
    public void validateDomain() throws Exception {
        dynamicSetUp();
        ActiveDirectoryDomain.DescriptorImpl adDescriptor = new ActiveDirectoryDomain.DescriptorImpl();
        assertEquals("OK: Success", adDescriptor.doValidateTest(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD, null).toString().trim());
    }
}
