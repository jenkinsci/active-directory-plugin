package hudson.plugins.active_directory;

import hudson.Extension;
import io.jenkins.plugins.casc.SecretSource;

import java.util.Optional;

import io.jenkins.plugins.casc.misc.junit.jupiter.AbstractRoundTripTest;
import jenkins.model.Jenkins;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.*;

@WithJenkins
class ActiveDirectoryJCasCCompatibilityTest extends AbstractRoundTripTest {

    @Override
    protected void assertConfiguredAsExpected(JenkinsRule rule, String s) {
        final Jenkins jenkins = Jenkins.get();
        final ActiveDirectorySecurityRealm realm = (ActiveDirectorySecurityRealm) jenkins.getSecurityRealm();

        assertEquals(2, realm.domains.size());
        // First domain
        ActiveDirectoryDomain domain = realm.domains.get(0);
        assertEquals("acme", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme.com:123,ad2.acme.com:456", domain.servers);
        assertEquals("site", domain.getSite());
        assertEquals("VALIDPASSWORD1", domain.getBindPassword().getPlainText());
        assertEquals(TlsConfiguration.JDK_TRUSTSTORE, domain.getTlsConfiguration());
        // Second domain
        domain = realm.domains.get(1);
        assertEquals("acme2", domain.name);
        assertEquals("admin", domain.bindName);
        assertEquals("ad1.acme2.com:123,ad2.acme2.com:456", domain.servers);
        assertEquals("site2", domain.getSite());
        assertEquals("VALIDPASSWORD2", domain.getBindPassword().getPlainText());
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

    @SuppressWarnings("unused")
    @Extension
    public static class TheSource extends SecretSource {
        @Override
        public Optional<String> reveal(String secret) {
            return switch (secret) {
                case "BIND_PASSWORD_1" -> Optional.of("VALIDPASSWORD1");
                case "BIND_PASSWORD_2" -> Optional.of("VALIDPASSWORD2");
                default -> Optional.empty();
            };
        }
    }
}
