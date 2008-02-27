package hudson.plugins.active_directory;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryUserDetail extends User {
    public ActiveDirectoryUserDetail(String username, String password, boolean enabled, boolean accountNonExpired, boolean credentialsNonExpired, boolean accountNonLocked, GrantedAuthority[] authorities) throws IllegalArgumentException {
        // Acegi doesn't like null password, but during remember-me processing we don't know the password.
        // so we need to set some dummy. See #1229
        super(username, password!=null?password:"PASSWORD", enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
    }
}
