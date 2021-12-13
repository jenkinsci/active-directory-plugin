package hudson.plugins.active_directory;

import hudson.Extension;
import hudson.model.AdministrativeMonitor;
import hudson.security.SecurityRealm;

import jenkins.model.Jenkins;

@Extension
public class Security1389AdministrativeMonitor extends AdministrativeMonitor {

    @Override
    public boolean isActivated() {
        SecurityRealm securityRealm = Jenkins.get().getSecurityRealm();
        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm adRealm = (ActiveDirectorySecurityRealm) securityRealm;
            return !adRealm.isRequireTLSPersisted();
        }
        return false;
    }

}
