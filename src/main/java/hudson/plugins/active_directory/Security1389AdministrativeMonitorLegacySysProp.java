package hudson.plugins.active_directory;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import hudson.security.SecurityRealm;

import jenkins.model.Jenkins;

@Extension
public class Security1389AdministrativeMonitorLegacySysProp extends AdministrativeMonitor {

    private final boolean SYSTEM_PROPERTY_SET = System.getProperty(ActiveDirectorySecurityRealm.LEGACY_FORCE_LDAPS_PROPERTY) != null;

    @Override
    public boolean isActivated() {
        SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm adRealm = (ActiveDirectorySecurityRealm) securityRealm;
            return SYSTEM_PROPERTY_SET && adRealm.isRequireTLSPersisted();
        }
        return false;
    }

}
