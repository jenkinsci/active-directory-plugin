package hudson.plugins.active_directory;

import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
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

    @BeforeClass
    public static void globalSetup() {
        System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "FALSE");
        System.setProperty(LEGACY_FORCE_LDAPS_PROPERTY, "TRUE");
    }

    @LocalData
    @Test
    public void testStartTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, false);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckStartTls(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind);
    }

    @LocalData
    @Test
    public void testRequireTlsForWarnings() throws Exception {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) jenkinsRule.jenkins.getSecurityRealm();

        FormValidation result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, false);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, true);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(true, false);
        assertEquals(FormValidation.Kind.OK, result.kind);

        result = activeDirectorySecurityRealm.getDescriptor().doCheckRequireTLS(false, true);
        assertEquals(FormValidation.Kind.OK, result.kind);
    }
}
