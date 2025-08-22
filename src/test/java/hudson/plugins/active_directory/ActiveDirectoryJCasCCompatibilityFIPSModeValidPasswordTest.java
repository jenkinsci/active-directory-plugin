package hudson.plugins.active_directory;

import io.jenkins.plugins.casc.misc.junit.jupiter.AbstractRoundTripTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.jvnet.hudson.test.JenkinsRule;

import jenkins.model.Jenkins;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class ActiveDirectoryJCasCCompatibilityFIPSModeValidPasswordTest extends AbstractRoundTripTest {

    private static String fipsSystemProperty;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
    }

    @AfterAll
    static void afterAll() {
        if (fipsSystemProperty != null) {
            System.setProperty("jenkins.security.FIPS140.COMPLIANCE", fipsSystemProperty);
        } else {
            System.clearProperty("jenkins.security.FIPS140.COMPLIANCE");
        }
    }

    @Override
    protected void assertConfiguredAsExpected(JenkinsRule rule, String s) {
        final Jenkins jenkins = Jenkins.get();
        final ActiveDirectorySecurityRealm realm = (ActiveDirectorySecurityRealm) jenkins.getSecurityRealm();

        assertEquals(1, realm.domains.size());
        ActiveDirectoryDomain domain = realm.domains.get(0);
        assertEquals("acme", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme.com:123,ad2.acme.com:456", domain.servers);
        assertEquals("site", domain.getSite());
        assertEquals("veryLargePassword", domain.getBindPassword().getPlainText());  // check for valid password
        assertEquals(TlsConfiguration.JDK_TRUSTSTORE, domain.getTlsConfiguration());

        assertEquals(2, realm.getEnvironmentProperties().size());
        ActiveDirectorySecurityRealm.EnvironmentProperty prop = realm.getEnvironmentProperties().get(0);
        assertEquals("prop1", prop.getName());
        assertEquals("value1", prop.getValue());
        prop = realm.getEnvironmentProperties().get(1);
        assertEquals("prop2", prop.getName());
        assertEquals("value2", prop.getValue());

        assertTrue(realm.removeIrrelevantGroups);
        assertTrue(realm.startTls);
        assertEquals("jenkins", realm.getJenkinsInternalUser());
        assertEquals(GroupLookupStrategy.RECURSIVE, realm.getGroupLookupStrategy());
        assertNotNull(realm.getCache());
        assertEquals(500, realm.getCache().getSize());
        assertEquals(600, realm.getCache().getTtl());
    }

    @Override
    protected String configResource(){
        return "configuration-as-code-fips-valid-password.yaml";
    }


    @Override
    protected String stringInLogExpected() {
        return "Setting class hudson.plugins.active_directory.ActiveDirectorySecurityRealm.groupLookupStrategy = RECURSIVE";
    }
}
