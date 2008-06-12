package hudson.plugins.active_directory;

import com.sun.jndi.ldap.LdapCtxFactory;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm.DesciprotrImpl;
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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import static javax.naming.directory.SearchControls.SUBTREE_SCOPE;
import javax.naming.directory.SearchResult;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link AuthenticationProvider} with Active Directory, through LDAP.
 *
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryUnixAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
    implements UserDetailsService {

    private final String domainName;

    public ActiveDirectoryUnixAuthenticationProvider(String domainName) {
        this.domainName = domainName;
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
        String password = null;
        if(authentication!=null)
            password = (String) authentication.getCredentials();

        // bind by using the specified username/password
        Hashtable props = new Hashtable();
        String principalName = username + '@' + domainName;
        props.put(Context.SECURITY_PRINCIPAL, principalName);
        props.put(Context.SECURITY_CREDENTIALS,password);
        DirContext context;
        try {
            context = LdapCtxFactory.getLdapCtxInstance(
                    "ldap://" + DesciprotrImpl.INSTANCE.obtainLDAPServer(domainName) + '/',
                    props);
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING,"Failed to bind to LDAP",e);
            throw new BadCredentialsException("Either no such user '"+username+"' or incorrect password",e);
        }

        try {
            // locate this user's record
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> renum = context.search(toDC(domainName),"(& (userPrincipalName="+principalName+")(objectClass=user))", controls);
            if(!renum.hasMore())
                throw new BadCredentialsException("Authentication was successful but cannot locate the user information for "+username);
            SearchResult result = renum.next();


            List<GrantedAuthority> groups = new ArrayList<GrantedAuthority>();
            Attribute memberOf = result.getAttributes().get("memberOf");
            if(memberOf!=null) {// null if this user belongs to no group at all
                for(int i=0; i<memberOf.size(); i++) {
                    Attributes atts = context.getAttributes(memberOf.get(i).toString(), new String[]{"CN"});
                    Attribute att = atts.get("CN");
                    groups.add(new GrantedAuthorityImpl(att.get().toString()));
                }
            }

            context.close();

            return new ActiveDirectoryUserDetail(
                username, password,
                true, true, true, true,
                groups.toArray(new GrantedAuthority[groups.size()])
            );
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING,"Failed to retrieve user information",e);
            throw new BadCredentialsException("Authentication was successful but more than one users in the directory matches the user name: "+username,e);
        }
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
}
