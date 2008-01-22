package hudson.plugins.active_directory;

import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.spring.BeanBuilder;
import net.sf.json.JSONObject;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.userdetails.UserDetailsService;
import org.kohsuke.stapler.StaplerRequest;
import org.springframework.web.context.WebApplicationContext;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectorySecurityRealm extends SecurityRealm {
    public SecurityComponents createSecurityComponents() {
        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
        builder.parse(getClass().getResourceAsStream("ActiveDirectory.groovy"));
        WebApplicationContext context = builder.createApplicationContext();
        return new SecurityComponents(
            findBean(AuthenticationManager.class, context),
            findBean(UserDetailsService.class, context));
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
