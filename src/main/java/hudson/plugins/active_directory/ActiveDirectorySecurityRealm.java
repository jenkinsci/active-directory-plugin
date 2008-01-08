package hudson.plugins.active_directory;

import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.spring.BeanBuilder;
import net.sf.json.JSONObject;
import org.acegisecurity.AuthenticationManager;
import org.kohsuke.stapler.StaplerRequest;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectorySecurityRealm extends SecurityRealm {
    public AuthenticationManager createAuthenticationManager() {

        BeanBuilder builder = new BeanBuilder();
        builder.parse(getClass().getResourceAsStream("ActiveDirectory.groovy"));
        return findBean(AuthenticationManager.class,builder.createApplicationContext());
    }

    public Descriptor<SecurityRealm> getDescriptor() {
        return DesciprotrImpl.INSTANCE;
    }

    public static final class DesciprotrImpl extends Descriptor<SecurityRealm> {
        public static final DesciprotrImpl INSTANCE = new DesciprotrImpl();

        public DesciprotrImpl() {
            super(ActiveDirectorySecurityRealm.class);
        }

        public String getDisplayName() {
            return Messages.DisplayName();
        }

        public ActiveDirectorySecurityRealm newInstance(StaplerRequest req, JSONObject formData) throws FormException {
            return new ActiveDirectorySecurityRealm();
        }

        public String getHelpFile() {
            return "/plugin/active-directory/help/realm.html";
        }
    }
}
