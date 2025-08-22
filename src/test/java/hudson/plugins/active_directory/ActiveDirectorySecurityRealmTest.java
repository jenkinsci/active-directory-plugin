package hudson.plugins.active_directory;

import java.util.ArrayList;
import java.util.List;

import org.htmlunit.html.DomElement;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import jenkins.model.Jenkins;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class ActiveDirectorySecurityRealmTest {

    private static final String AD_DOMAIN = "samdom.example.com";
    private static final String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=samdom,DC=example,DC=com";
    private static final String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";

    private static String fipsSystemProperty;

    private JenkinsRule j;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "false");
    }

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    @AfterAll
    static void afterAll() {
        if (fipsSystemProperty != null) {
            System.setProperty("jenkins.security.FIPS140.COMPLIANCE", fipsSystemProperty);
        } else {
            System.clearProperty("jenkins.security.FIPS140.COMPLIANCE");
        }
    }


    @LocalData
    @Test
    void testReadResolveSingleDomain() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

        assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
        assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
        // JENKINS-39375 Support a different bindUser per domain
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
        // JENKINS-39423 Make Site independent of each domain
        assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        // SECURITY-859 Make tlsConfiguration independent of each domain
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
    }

    @LocalData
    @Test
    void testReadResolveSingleDomainSingleServer() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveSingleDomainWithTwoServers() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithoutSpaceAfterComma() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

        assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
        assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
        assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
        assertNull(activeDirectorySecurityRealm.getDomains().get(1).getServers());
        // JENKINS-39375 Support a different bindUser per domain
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        // SECURITY-859 Make tlsConfiguration independent of each domain
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
    }

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithoutSpaceAfterCommaAndSingleServer() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithoutSpaceAfterCommaAndTwoServers() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithSpaceAfterComma() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

        assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
        assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
        assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
        assertNull(activeDirectorySecurityRealm.getDomains().get(1).getServers());
        // JENKINS-39375 Support a different bindUser per domain
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(1).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(1).getBindPassword());
        // SECURITY-859 Make tlsConfiguration independent of each domain
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, activeDirectorySecurityRealm.getDomains().get(1).getTlsConfiguration());
    }

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithSpaceAfterCommaAndSingleServer() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveTwoDomainsWithSpaceAfterCommaAndTwoServers() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

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

    @LocalData
    @Test
    void testReadResolveMultiDomainSingleDomainOneDisplayName() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

        assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
        assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
        // JENKINS-39375 Support a different bindUser per domain
        assertEquals("bindUser", activeDirectorySecurityRealm.getDomains().get(0).getBindName());
        assertNotNull(activeDirectorySecurityRealm.getDomains().get(0).getBindPassword());
        // JENKINS-39423 Make Site independent of each domain
        assertEquals("site", activeDirectorySecurityRealm.getDomains().get(0).getSite());
        // SECURITY-859 If there is not tlsConfiguration saved on disk, keep it as null
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
    }

    @LocalData
    @Test
    void testReadResolveMultiDomainTwoDomainsOneDisplayName() {
        SecurityRealm securityRealm = j.getInstance().getSecurityRealm();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = assertInstanceOf(ActiveDirectorySecurityRealm.class, securityRealm);

        assertEquals(2, activeDirectorySecurityRealm.getDomains().size());
        assertEquals("example.com", activeDirectorySecurityRealm.getDomains().get(0).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
        assertEquals("example-2.com", activeDirectorySecurityRealm.getDomains().get(1).getName());
        assertNull(activeDirectorySecurityRealm.getDomains().get(0).getServers());
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

    @Issue("JENKINS-46884")
    @Test
    void testAdvancedOptionsVisibleWithNonNativeAuthentication() throws Exception {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
        Jenkins.get().setSecurityRealm(activeDirectorySecurityRealm);
        DomElement domElement = j.createWebClient().goTo("configureSecurity").getElementByName("startTls");
        assertNotNull(domElement);
    }

    @Issue("JENKINS-46884")
    @Test
    void testCacheOptionAlwaysVisible() throws Exception {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN, null, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
        Jenkins.get().setSecurityRealm(activeDirectorySecurityRealm);
        DomElement domElement = j.createWebClient().goTo("configureSecurity").getElementByName("cache");
        assertNotNull(domElement);
    }

    @Issue("SECURITY-859")
    @LocalData
    @Test
    void testReadResolveMultipleDomainsOneDomainEndToEnd() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();

        // Check there is one domain
        assertEquals(1, activeDirectorySecurityRealm.getDomains().size());
        // Check domain
        assertEquals(AD_DOMAIN, activeDirectorySecurityRealm.getDomains().get(0).getName());
        // Check bindName
        assertEquals(AD_MANAGER_DN, activeDirectorySecurityRealm.getDomains().get(0).getBindName());
        // Check groupLookupStrategy
        assertEquals(GroupLookupStrategy.RECURSIVE, activeDirectorySecurityRealm.getGroupLookupStrategy());
        // Check removeIrrelevantGroups
        assertTrue(activeDirectorySecurityRealm.removeIrrelevantGroups);
        // Check cache Size
        assertEquals(500, activeDirectorySecurityRealm.getCache().getSize());
        // Check cache TTLS
        assertEquals(1800, activeDirectorySecurityRealm.getCache().getTtl());
        // Check tlsConfiguration
        assertEquals(
                TlsConfiguration.JDK_TRUSTSTORE, activeDirectorySecurityRealm.getDomains().get(0).getTlsConfiguration());
    }

    @LocalData
    @Test
    void testStartTlsForWarnings() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");
    }

    @LocalData
    @Test
    void testRequireTlsForWarnings() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "no FIPS mode. So, no impact of TLS configuration");
    }

    @LocalData
    @Test
    void testFallBackUserDomainController() throws Exception {
        HudsonPrivateSecurityRealm hudsonPrivateSecurityRealm = new HudsonPrivateSecurityRealm(true, true, null);
        hudsonPrivateSecurityRealm.createAccount("admin", "admin");
        JenkinsRule.WebClient wc = j.createWebClient().login("admin", "admin");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>admin</name>"));
    }

    @LocalData
    @Test
    void testFallBackUserDomain() throws Exception {
        HudsonPrivateSecurityRealm hudsonPrivateSecurityRealm = new HudsonPrivateSecurityRealm(true, true, null);
        hudsonPrivateSecurityRealm.createAccount("admin", "admin");
        JenkinsRule.WebClient wc = j.createWebClient().login("admin", "admin");
        assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", ""), containsString("<name>admin</name>"));
    }
}
