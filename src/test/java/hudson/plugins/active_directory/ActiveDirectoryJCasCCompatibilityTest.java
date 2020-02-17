package hudson.plugins.active_directory;

import io.jenkins.plugins.casc.misc.RoundTripAbstractTest;
import jenkins.model.Jenkins;
import org.junit.Before;
import org.junit.Rule;
import org.junit.contrib.java.lang.system.EnvironmentVariables;
import org.junit.rules.RuleChain;
import org.jvnet.hudson.test.RestartableJenkinsRule;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class ActiveDirectoryJCasCCompatibilityTest extends RoundTripAbstractTest {

    @Rule
    public RuleChain chain = RuleChain.outerRule(new EnvironmentVariables()
            .set("BIND_PASSWORD_1", "PASSW1")
            .set("BIND_PASSWORD_2", "PASSW2"));

    @Before
    public void setUp() {
        chain.around(r.j);
    }

    @Override
    protected void assertConfiguredAsExpected(RestartableJenkinsRule restartableJenkinsRule, String s) {
        final Jenkins jenkins = Jenkins.getInstance();
        final ActiveDirectorySecurityRealm realm = (ActiveDirectorySecurityRealm) jenkins.getSecurityRealm();

        assertEquals(2, realm.domains.size());
        // First domain
        ActiveDirectoryDomain domain = realm.domains.get(0);
        assertEquals("acme", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme.com:123,ad2.acme.com:456", domain.servers);
        assertEquals("site", domain.getSite());
        assertEquals("PASSW1", domain.getBindPassword().getPlainText());
        assertEquals(TlsConfiguration.JDK_TRUSTSTORE, domain.getTlsConfiguration());
        // Second domain
        domain = realm.domains.get(1);
        assertEquals("acme2", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme2.com:123,ad2.acme2.com:456", domain.servers);
        assertEquals("site2", domain.getSite());
        assertEquals("PASSW2", domain.getBindPassword().getPlainText());
        assertEquals(TlsConfiguration.TRUST_ALL_CERTIFICATES, domain.getTlsConfiguration());

        assertEquals(2, realm.getEnvironmentProperties().size());
        // First Env Property
        ActiveDirectorySecurityRealm.EnvironmentProperty prop = realm.getEnvironmentProperties().get(0);
        assertEquals("prop1", prop.getName());
        assertEquals("value1", prop.getValue());
        // Second Env Property
        prop = realm.getEnvironmentProperties().get(1);
        assertEquals("prop2", prop.getName());
        assertEquals("value2", prop.getValue());

        // General properties
        assertTrue(realm.removeIrrelevantGroups);
        assertTrue(realm.startTls);
        assertEquals("jenkins", realm.getJenkinsInternalUser());
        assertEquals(GroupLookupStrategy.RECURSIVE, realm.getGroupLookupStrategy());
        assertNotNull(realm.getCache());
        assertEquals(500, realm.getCache().getSize());
        assertEquals(600, realm.getCache().getTtl());
    }

    @Override
    protected String stringInLogExpected() {
        return "Setting class hudson.plugins.active_directory.ActiveDirectorySecurityRealm.groupLookupStrategy = RECURSIVE";
    }
    
}
