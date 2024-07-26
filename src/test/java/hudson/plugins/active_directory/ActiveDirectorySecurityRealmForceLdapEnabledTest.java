package hudson.plugins.active_directory;

import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;

import hudson.util.FormValidation;

import static org.junit.Assert.assertEquals;

import static hudson.plugins.active_directory.ActiveDirectorySecurityRealm.LEGACY_FORCE_LDAPS_PROPERTY;

/*
Verifies the warning message when Jenkins operates in non-FIPS and Force LDAP property is enabled.
 */
public class ActiveDirectorySecurityRealmForceLdapEnabledTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @ClassRule
    public static TestRule forceLdapProp = FlagRule.systemProperty(LEGACY_FORCE_LDAPS_PROPERTY, "true");

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
}
