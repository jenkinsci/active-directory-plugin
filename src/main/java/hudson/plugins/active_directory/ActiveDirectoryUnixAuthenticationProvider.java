package hudson.plugins.active_directory;

import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.dao.AbstractUserDetailsAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.springframework.dao.DataAccessException;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;

/**
 * {@link AuthenticationProvider} with Active Directory, through LDAP.
 *
 * @author Kohsuke Kawaguchi
 * @author James Nord
 */
public class ActiveDirectoryUnixAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
    implements UserDetailsService, GroupDetailsService {

    private final String[] domainNames;
    private final String site;
    private final String bindName, bindPassword;
    private final ActiveDirectorySecurityRealm.DesciprotrImpl descriptor;

    public ActiveDirectoryUnixAuthenticationProvider(ActiveDirectorySecurityRealm realm) {
        this.domainNames = realm.domain.split(",");
        this.site = realm.site;
        this.bindName = realm.bindName;
        this.bindPassword = realm.bindPassword==null ? null : realm.bindPassword.toString();
        this.descriptor = realm.getDescriptor();
    }

    /**
     * We'd like to implement {@link UserDetailsService} ideally, but in short of keeping the manager user/password,
     * we can't do so. In Active Directory authentication, we should support SPNEGO/Kerberos and
     * that should eliminate the need for the "remember me" service.
     */
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        throw new UsernameNotFoundException("Active-directory plugin doesn't support user retrieval");
    }

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // active directory authentication is not by comparing clear text password,
        // so there's nothing to do here.
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        UserDetails userDetails = null;
        for (String domainName : domainNames) {
            try {
                userDetails = retrieveUser(username, authentication, domainName);
            }
            catch (BadCredentialsException bce) {
                LOGGER.log(Level.WARNING,"Credential exception tying to authenticate against " + domainName + " domain",bce);
            }
            if (userDetails != null) {
                break;
            }
        }
        if (userDetails == null) {
            LOGGER.log(Level.WARNING,"Exhausted all configured domains and could not authenticat against any.");
            throw new BadCredentialsException("Either no such user '"+username+"' or incorrect password");
        }
        return userDetails;
    }
    
    private UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication, String domainName) throws AuthenticationException {
        // when we use custom socket factory below, every LDAP operations result in a classloading via context classloader,
        // so we need it to resolve.
        ClassLoader ccl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            String password = null;
            if(authentication!=null)
                password = (String) authentication.getCredentials();

            List<SocketInfo> ldapServers;
            try {
                ldapServers = descriptor.obtainLDAPServer(domainName,site);
            } catch (NamingException e) {
                LOGGER.log(Level.WARNING,"Failed to find the LDAP service",e);
                throw new AuthenticationServiceException("Failed to find the LDAP service for the domain "+domainName,e);
            }

            DirContext context;
            String id;
            if (bindName!=null) {
                // two step approach. Use a special credential to obtain DN for the user trying to login,
                // then authenticate.
                try {
                    id = username;
                    context = descriptor.bind(bindName, bindPassword, ldapServers);
                } catch (BadCredentialsException e) {
                    throw new AuthenticationServiceException("Failed to bind to LDAP server with the bind name/password",e);
                }
            } else {
                String principalName = getPrincipalName(username, domainName);
                id = principalName.substring(0, principalName.indexOf('@'));
                context = descriptor.bind(principalName, password, ldapServers);
            }

            try {
                // locate this user's record
                SearchControls controls = new SearchControls();
                controls.setSearchScope(SUBTREE_SCOPE);
                NamingEnumeration<SearchResult> renum = context.search(toDC(domainName),"(& (userPrincipalName={0})(objectClass=user))",
                        new Object[]{id}, controls);
                if(!renum.hasMore()) {
                    // failed to find it. Fall back to sAMAccountName.
                    // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                    LOGGER.fine("Failed to find "+id+" in userPrincipalName. Trying sAMAccountName");
                    renum = context.search(toDC(domainName),"(& (sAMAccountName={0})(objectClass=user))",
                            new Object[]{id},controls);
                    if(!renum.hasMore()) {
                        throw new BadCredentialsException("Authentication was successful but cannot locate the user information for "+username);
                    }
                }
                SearchResult result = renum.next();

                if (bindName!=null) {
                    // if we've used the credential specifically for the bind, we need to verify the provided password.
                    Object dn = result.getAttributes().get("distinguishedName").get();
                    if (dn==null)
                        throw new BadCredentialsException("No distinguished name for "+username);
                    LOGGER.fine("Attempting to validate password for DN="+dn);
                    DirContext test = descriptor.bind(dn.toString(), password, ldapServers);
                    test.close();
                }

                Set<GrantedAuthority> groups = resolveGroups(result.getAttributes(), context);
                groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

                context.close();

                return new ActiveDirectoryUserDetail(
                    id, password,
                    true, true, true, true,
                    groups.toArray(new GrantedAuthority[groups.size()])
                );
            } catch (NamingException e) {
                LOGGER.log(Level.WARNING,"Failed to retrieve user information for "+username,e);
                throw new BadCredentialsException("Failed to retrieve user information for "+username,e);
            }
        } finally {
            Thread.currentThread().setContextClassLoader(ccl);
        }
    }

    /**
     * Returns the full user principal name of the form "joe@europe.contoso.com".
     * 
     * If people type in 'foo@bar' or 'bar\\foo', it should be treated as 'foo@bar.acme.org'
     */
    private String getPrincipalName(String username, String domainName) {
        String principalName;
        int slash = username.indexOf('\\');
        if (slash>0) {
            principalName = username.substring(slash+1)+'@'+username.substring(0,slash)+'.'+domainName;
        } else
        if (username.contains("@"))
            principalName = username + '.' + domainName;
        else
            principalName = username + '@' + domainName;
        return principalName;
    }

    private Set<GrantedAuthority> resolveGroups(Attributes identity, DirContext context) throws NamingException {
        Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
        LinkedList<Attributes> membershipList = new LinkedList<Attributes>();
        membershipList.add(identity);
        while (!membershipList.isEmpty()) {
            identity = membershipList.removeFirst();

            Attribute memberOf = identity.get("memberOf");
            if (memberOf == null)    continue;

            for (int i=0; i < memberOf.size() ; i++) {
                if (LOGGER.isLoggable(Level.FINE))
                    LOGGER.fine(identity.get("CN").get()+" is a member of "+memberOf.get(i));

                Attributes group = context.getAttributes("\"" + memberOf.get(i) + '"',
                                                        new String[] {"CN", "memberOf"});
                Attribute cn = group.get("CN");
                if (groups.add(new GrantedAuthorityImpl(cn.get().toString()))) {
                    membershipList.add(group); // recursively look for groups that this group is a member of.
                }
            }
        }
        return groups;
    }
    
    private static String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if(token.length()==0)   continue;   // defensive check
            if(buf.length()>0)  buf.append(",");
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryUnixAuthenticationProvider.class.getName());

	public GroupDetails loadGroupByGroupname(String groupname) {
		throw new UserMayOrMayNotExistException(groupname);
	}
}
