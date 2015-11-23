/*
 * The MIT License
 *
 * Copyright (c) 2008-2014, Kohsuke Kawaguchi, CloudBees, Inc., and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.active_directory;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.plugins.active_directory.sso.SSOOptions;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class AbstractActiveDirectoryAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider implements UserDetailsService, GroupDetailsService {
    private final ActiveDirectorySecurityRealm realm;
    
    public AbstractActiveDirectoryAuthenticationProvider(ActiveDirectorySecurityRealm realm) {
      setHideUserNotFoundExceptions(SHOW_USER_NOT_FOUND_EXCEPTION);
      this.realm=realm;
    }

    /**
     * Authenticates the user (if {@code authentication!=null}), or retrieve the user name information (otherwise.)
     */
    protected abstract UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException;

    protected abstract GroupDetails retrieveGroup(String groupname);

    /**
     * Returns true if we can retrieve user just from the name without supplying any credential.
     */
    protected abstract boolean canRetrieveUserByName();
    
    /**
     * isSsoCheckedAgainstAD():  Facilitator for making the code more readable in loadGroupByGroupname & loadUserByUsername
     */
    private boolean isSsoNoCheckedAgainstADEnabled() {
      if(this.realm!=null && this.realm.getSsoOptions()!=null &&
            SSOOptions.SSO_MODE_NOCHECK.equalsIgnoreCase(this.realm.getSsoOptions().getCheckMode())) return true;
      return false;
    }

    public GroupDetails loadGroupByGroupname(String groupname) {
      if(this.isSsoNoCheckedAgainstADEnabled() && groupname.equals(this.realm.getSsoOptions().getDefaultGroup()))    
        return new ActiveDirectoryGroupDetails(groupname);
      else return retrieveGroup(groupname);
    }
   
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
      // SSO Enabled in no_check mode, find suffix and return ActiveDirectoryDetails
      if(this.isSsoNoCheckedAgainstADEnabled()) {
        if(this.realm.getSsoOptions().getJenkinsUsernameSuffix()!=null  &&  
              !this.realm.getSsoOptions().getJenkinsUsernameSuffix().isEmpty() && 
              username.endsWith(this.realm.getSsoOptions().getJenkinsUsernameSuffix())) 
          return new ActiveDirectoryUserDetail(username, null,
                true, true,
                true, true,
                new GrantedAuthority[] {
                    SecurityRealm.AUTHENTICATED_AUTHORITY,
                    new GrantedAuthorityImpl(realm.getSsoOptions().getDefaultGroup())
                  },
                username, null, null);
        else if(username.equals(this.realm.getSsoOptions().getDefaultGroup())) throw new UsernameNotFoundException("User is the SSO Default group");
        else return retrieveUser(username,null);                  
      }
      else return retrieveUser(username,null);
    }

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // active directory authentication is not by comparing clear text password,
        // so there's nothing to do here.
    }

    /**
     * Setting this to true might help with diagnosing login problem.
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "Diagnostic fields are left mutable so that groovy console can be used to dynamically turn/off probes.")
    public static boolean SHOW_USER_NOT_FOUND_EXCEPTION = Boolean.getBoolean(AbstractActiveDirectoryAuthenticationProvider.class.getName()+".showUserNotFoundException");
}
