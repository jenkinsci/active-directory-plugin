package hudson.plugins.active_directory;

import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm.DesciprotrImpl;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;

import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.acegisecurity.AuthenticationException;
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

import com.sun.jndi.ldap.LdapCtxFactory;

/**
 * {@link AuthenticationProvider} with Active Directory, through LDAP.
 *
 * @author Kohsuke Kawaguchi
 * @author James Nord
 */
public class ActiveDirectoryUnixAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
    implements UserDetailsService, GroupDetailsService {

    private final String[] domainNames;

    public ActiveDirectoryUnixAuthenticationProvider(String domainName) {
        this.domainNames = domainName.split(",");
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
        String password = null;
        if(authentication!=null)
            password = (String) authentication.getCredentials();

        // bind by using the specified username/password
        Hashtable props = new Hashtable();
        String principalName = username + '@' + domainName;
        props.put(Context.SECURITY_PRINCIPAL, principalName);
        props.put(Context.SECURITY_CREDENTIALS,password);
        props.put(Context.REFERRAL, "follow");
        DirContext context;
        try {
            context = LdapCtxFactory.getLdapCtxInstance(
                    "ldap://" + DesciprotrImpl.INSTANCE.obtainLDAPServer(domainName) + '/',
                    props);
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING,"Failed to bind to LDAP",e);
            throw new BadCredentialsException("Either no such user '"+principalName+"' or incorrect password",e);
        }

        try {
            // locate this user's record
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> renum = context.search(toDC(domainName),"(& (userPrincipalName="+principalName+")(objectClass=user))", controls);
            if(!renum.hasMore()) {
                // failed to find it. Fall back to sAMAccountName.
                // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                renum = context.search(toDC(domainName),"(& (sAMAccountName="+username+")(objectClass=user))", controls);
                if(!renum.hasMore()) {
                    throw new BadCredentialsException("Authentication was successful but cannot locate the user information for "+username);
                }
            }
            SearchResult result = renum.next();


            Attribute memberOf = result.getAttributes().get("memberOf");
            Set<GrantedAuthority> groups = resolveGroups(memberOf, context);
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
            
            context.close();

            return new ActiveDirectoryUserDetail(
                username, password,
                true, true, true, true,
                groups.toArray(new GrantedAuthority[groups.size()])
            );
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING,"Failed to retrieve user information for "+username,e);
            throw new BadCredentialsException("Failed to retrieve user information for "+username,e);
        }
    }

    private Set<GrantedAuthority> resolveGroups(Attribute memberOf, DirContext context) throws NamingException {
        Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();
        LinkedList<Attribute> membershipList = new LinkedList<Attribute>();
        membershipList.add(memberOf);
        while (!membershipList.isEmpty()) {
            Attribute memberships = membershipList.removeFirst();
            if (memberships != null) {
                for (int i=0; i < memberships.size() ; i++) {
                    Attributes atts = context.getAttributes("\"" + memberships.get(i) + '"', 
                                                            new String[] {"CN", "memberOf"});
                    Attribute cn = atts.get("CN");
                    if (groups.add(new GrantedAuthorityImpl(cn.get().toString()))) {
                        Attribute members = atts.get("memberOf");
                        if (members != null) {
                            membershipList.add(members);
                        }
                    }
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
