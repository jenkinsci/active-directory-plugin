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
Verifies the warning message when Jenkins operates in FIPS and Force LDAP property is disabled.
 */
public class ActiveDirectorySecurityRealmForceLdapDisabledTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    @ClassRule
    public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "true");

    @LocalData
    @Test
    public void testStartTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, false);
        assertEquals("FIPS mode and no TLS configured. so not compliant", FormValidation.Kind.WARNING, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, true);
        assertEquals("FIPS mode and requireTls/startTls configured. so it's compliant", FormValidation.Kind.OK,
                     result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, false);
        assertEquals("FIPS mode and requireTls configured. so it's compliant", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, true);
        assertEquals("FIPS mode and startTls configured. so it's compliant", FormValidation.Kind.OK, result.kind);
    }

    @LocalData
    @Test
    public void testRequireTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, false);
        assertEquals("FIPS mode and no TLS configured. so not compliant", FormValidation.Kind.WARNING, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, true);
        assertEquals("FIPS mode and requireTls/startTls configured. so it's compliant", FormValidation.Kind.OK,
                     result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, false);
        assertEquals("FIPS mode and requireTls configured. so it's compliant", FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, true);
        assertEquals("FIPS mode and startTls configured. so it's compliant", FormValidation.Kind.OK, result.kind);
    }
}
