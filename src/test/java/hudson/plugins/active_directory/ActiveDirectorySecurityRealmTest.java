package hudson.plugins.active_directory;

import hudson.security.SecurityRealm;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;


public class ActiveDirectorySecurityRealmTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @LocalData
    @Test
    public void testReadResolveSingleDomain() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            // JENKINS-39423 Make Site independent of each domain
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        }
    }

    @LocalData
    @Test
    public void testReadResolveSingleDomainSingleServer() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("server.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            // JENKINS-39423 Make Site independent of each domain
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        }
    }

    @LocalData
    @Test
    public void testReadResolveSingleDomainWithTwoServers() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("server-1.example.com:3268,server-2.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            // JENKINS-39423 Make Site independent of each domain
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithoutSpaceAfterComma() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithoutSpaceAfterCommaAndSingleServer() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals("server.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals("server.example.com:3268", activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithoutSpaceAfterCommaAndTwoServers() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals("server-1.example.com:3268,server-2.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals("server-1.example.com:3268,server-2.example.com:3268", activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithSpaceAfterComma() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithSpaceAfterCommaAndSingleServer() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals("server.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals("server.example.com:3268", activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveTwoDomainsWithSpaceAfterCommaAndTwoServers() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals("server-1.example.com:3268,server-2.example.com:3268", activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals("server-1.example.com:3268,server-2.example.com:3268", activeDirectorySecurityRealm.getDomains().get(1).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        }
    }

    @LocalData
    @Test
    public void testReadResolveMultiDomainSingleDomainOneDisplayName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            // JENKINS-39423 Make Site independent of each domain
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        }
    }

    @LocalData
    @Test
    public void testReadResolveMultiDomainTwoDomainsOneDisplayName() throws Exception {
        SecurityRealm securityRealm = jenkinsRule.getInstance().getSecurityRealm();
        assertEquals(true, securityRealm instanceof ActiveDirectorySecurityRealm);

        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
            assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
            assertEquals(null, activeDirectorySecurityRealm.getDomains().get(0).getServers());
            // JENKINS-39375 Support a different bindUser per domain
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
            assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
            assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
            // JENKINS-39423 Make Site independent of each domain
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
            assertEquals("site", activeDirectorySecurityRealm.getDomains().get(1).getSite());
        }
    }
}
