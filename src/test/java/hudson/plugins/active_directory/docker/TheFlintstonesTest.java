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
import jenkins.model.Jenkins;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.FileUtils;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertTrue;

/**
 * Integration tests with Docker
 */
public class TheFlintstonesTest {

    @Rule
    public DockerRule<TheFlintstones> docker = new DockerRule<TheFlintstones>(TheFlintstones.class);

    @Rule
    public JenkinsRule j = new JenkinsRule();

    public final static String AD_DOMAIN = "samdom.example.com";
    public final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    public final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    public final static int MAX_RETRIES = 30;
    public static String DOCKER_IP;

    @Before
    public void setUp() throws Exception {
        TheFlintstones d = docker.get();
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, d.ipBound(389)+ ":" +  d.port(389) , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<ActiveDirectoryDomain>(1);
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
        DOCKER_IP = d.ipBound(389);
        System.out.println(DOCKER_IP);
    }

    @Test
    public void simpleLoginSuccessful() throws Exception {
        UserDetails userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred2");
        assertThat(userDetails.getUsername(), is("Fred"));
    }

    @Test
    public void simpleLoginFails() throws Exception {
        try {
            j.jenkins.getSecurityRealm().loadUserByUsername("Homer");
        } catch (UsernameNotFoundException e) {
            assertTrue(e.getMessage().contains("Authentication was successful but cannot locate the user information for Homer"));
        }
    }

    @Test
    public void checkDomainHealth() throws Exception {
        System.setProperty("samdom.example.com", DOCKER_IP);
        ActiveDirectorySecurityRealm securityRealm = (ActiveDirectorySecurityRealm) Jenkins.getInstance().getSecurityRealm();
        ActiveDirectoryDomain domain = securityRealm.getDomain(AD_DOMAIN);
        domain.getRecordFromDomain();
        System.out.println(domain.getRecordFromDomain().toString());
    }

    @DockerFixture(id = "ad-dc", ports= {389, 3268})
    public static class TheFlintstones extends DockerContainer {

    }

}
