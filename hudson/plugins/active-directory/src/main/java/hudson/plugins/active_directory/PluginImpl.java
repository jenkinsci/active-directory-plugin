package hudson.plugins.active_directory;

import hudson.Plugin;
import hudson.security.SecurityRealm;

/**
 * @author Kohsuke Kawaguchi
 */
public class PluginImpl extends Plugin {
    @Override
    public void start() throws Exception {
        SecurityRealm.LIST.add(ActiveDirectorySecurityRealm.DesciprotrImpl.INSTANCE);
    }
}
