package hudson.plugins.active_directory;

import java.util.ArrayList;
import java.util.List;

import org.htmlunit.html.DomElement;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import hudson.plugins.active_directory.docker.TheFlintstonesTest;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;


public class ActiveDirectorySecurityRealmTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    public final static String AD_DOMAIN = "samdom.example.com";
    public final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=samdom,DC=example,DC=com";

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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 Make tlsConfiguration independent of each domain
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
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
            // SECURITY-859 If there is not tlsConfiguration saved on disk, keep it as null
            assertNull(activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());        }
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
            // SECURITY-859 If there is not tlsConfiguration saved on disk, keep it as null
            assertNull(activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
            assertNull(activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());

        }
    }

    @Issue("JENKINS-46884")
    @Test
    public void testAdvancedOptionsVisibleWithNonNativeAuthentication() throws Exception {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(TheFlintstonesTest.AD_DOMAIN, null, null, TheFlintstonesTest.AD_MANAGER_DN, TheFlintstonesTest.AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
        Jenkins.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        DomElement domElement = jenkinsRule.createWebClient().goTo("configureSecurity").getElementByName("startTls");
        assertTrue(domElement != null);
    }

    @Issue("JENKINS-46884")
    @Test
    public void testCacheOptionAlwaysVisible() throws Exception {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(TheFlintstonesTest.AD_DOMAIN, null, null, TheFlintstonesTest.AD_MANAGER_DN, TheFlintstonesTest.AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
        Jenkins.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        DomElement domElement = jenkinsRule.createWebClient().goTo("configureSecurity").getElementByName("cache");
        assertTrue(domElement != null);
    }

    @Issue("SECURITY-859")
    @LocalData
    @Test
    public void testReadResolveMultipleDomainsOneDomainEndToEnd() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        // Check there is one domain
        assertEquals(activeDirectorySecurityRealm.getDomains().size(), 1);
        // Check domain
        assertEquals(activeDirectorySecurityRealm.getDomains().get(0).getName(), AD_DOMAIN);
        // Check bindName
        assertEquals(activeDirectorySecurityRealm.getDomains().get(0).getBindName(), AD_MANAGER_DN);
        // Check groupLookupStrategy
        assertEquals(activeDirectorySecurityRealm.getGroupLookupStrategy(), GroupLookupStrategy.RECURSIVE);
        // Check removeIrrelevantGroups
        assertEquals(activeDirectorySecurityRealm.removeIrrelevantGroups, true);
        // Check cache Size
        assertEquals(activeDirectorySecurityRealm.getCache().getSize(), 500);
        // Check cache TTLS
        assertEquals(activeDirectorySecurityRealm.getCache().getTtl(), 1800);
        // Check tlsConfiguration
        assertEquals(activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration(),
                     TlsConfiguration.JDK_TRUSTSTORE);
    }

    @LocalData
    @Test
    public void testStartTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, false);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, true);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, false);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, true);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

    }

    @LocalData
    @Test
    public void testRequireTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, false);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, true);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, false);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, true);
        assertEquals("no FIPS mode. So, no impact of TLS configuration", FormValidation.Kind.OK, result.kind);
    }

    @LocalData
    @Test
    public void testFallBackUserDomainController() throws Exception {
        HudsonPrivateSecurityRealm hudsonPrivateSecurityRealm = new HudsonPrivateSecurityRealm(true, true, null);
        hudsonPrivateSecurityRealm.createAccount("admin", "admin");
        JenkinsRule.WebClient wc = jenkinsRule.createWebClient().login("admin", "admin");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>admin</name>"));
    }

    @LocalData
    @Test
    public void testFallBackUserDomain() throws Exception {
        HudsonPrivateSecurityRealm hudsonPrivateSecurityRealm = new HudsonPrivateSecurityRealm(true, true, null);
        hudsonPrivateSecurityRealm.createAccount("admin", "admin");
        JenkinsRule.WebClient wc = jenkinsRule.createWebClient().login("admin", "admin");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>admin</name>"));
    }

}
