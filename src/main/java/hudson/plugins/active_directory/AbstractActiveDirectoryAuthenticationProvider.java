package hudson.plugins.active_directory;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class AbstractActiveDirectoryAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider implements UserDetailsService, GroupDetailsService {
    protected abstract UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // active directory authentication is not by comparing clear text password,
        // so there's nothing to do here.
    }
}
