package hudson.plugins.active_directory;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;

import hudson.util.FormValidation;

import static org.junit.jupiter.api.Assertions.assertEquals;

/*
Verifies the warning message when Jenkins operates in FIPS mode.
 */
@WithJenkins
class ActiveDirectorySecurityRealmFipsEnabledTest {

    private static String fipsSystemProperty;

    private JenkinsRule j;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
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
    void testStartTlsForWarnings() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, false);
        assertEquals(FormValidation.Kind.ERROR,
                     result.kind,
                     "FIPS mode and no TLS configured, so not compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and one of requireTls/startTls configured. so it's compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and requireTls configured. so it's compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and startTls configured. so it's compliant");
    }

    @LocalData
    @Test
    void testRequireTlsForWarnings() {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) j.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, false);
        assertEquals(FormValidation.Kind.ERROR,
                     result.kind,
                     "FIPS mode and tls not configured, so not compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and one of requireTls/startTls configured. so it's compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and requireTls configured. so it's compliant");

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind, "FIPS mode and startTls configured. so it's compliant");
    }
}
