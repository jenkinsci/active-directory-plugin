package hudson.plugins.active_directory;

import org.junit.ClassRule;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.RestartableJenkinsRule;
import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;

import jenkins.model.Jenkins;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ActiveDirectoryJCasCCompatibilityFIPSModeValidPasswordTest extends RoundTripAbstractTest {

    @ClassRule
    public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @Override
    protected void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        final Jenkins jenkins = Jenkins.getInstance();
        final ActiveDirectorySecurityRealm realm = (ActiveDirectorySecurityRealm) jenkins.getSecurityRealm();

        assertEquals(1, realm.domains.size());
        ActiveDirectoryDomain domain = realm.domains.get(0);
        assertEquals("acme", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme.com:123,ad2.acme.com:456", domain.servers);
        assertEquals("site", domain.getSite());
        assertEquals("S3cur3P@ssw0rd!", domain.getBindPassword().getPlainText());  // check for valid password
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
