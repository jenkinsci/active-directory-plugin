package hudson.plugins.active_directory;

import com4j.COM4J;
import com4j.Com4jObject;
import com4j.ComException;
import com4j.Variant;
import com4j.typelibs.activeDirectory.IADs;
import com4j.typelibs.activeDirectory.IADsGroup;
import com4j.typelibs.activeDirectory.IADsOpenDSObject;
import com4j.typelibs.activeDirectory.IADsUser;
import com4j.typelibs.ado20.ClassFactory;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import com4j.typelibs.ado20._Recordset;
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

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * {@link AuthenticationProvider} with Active Directory, plus {@link UserDetailsService}
 *
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryAuthenticationProvider extends AbstractUserDetailsAuthenticationProvider
    implements UserDetailsService {
    private final String defaultNamingContext;
    /**
     * ADO connection for searching Active Directory.
     */
    private final _Connection con;

    public ActiveDirectoryAuthenticationProvider() {
        IADs rootDSE = COM4J.getObject(IADs.class, "LDAP://RootDSE", null);

        defaultNamingContext = (String)rootDSE.get("defaultNamingContext");
        LOGGER.info("Active Directory domain is "+defaultNamingContext);

        con = ClassFactory.createConnection();
        con.provider("ADsDSOObject");
        con.open("Active Directory Provider",""/*default*/,""/*default*/,-1/*default*/);
    }

    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        // active directory authentication is not by comparing clear text password,
        // so there's nothing to do here.
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        return retrieveUser(username,null);
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        String password = null;
        if(authentication!=null)
            password = (String) authentication.getCredentials();


        _Command cmd = ClassFactory.createCommand();
        cmd.activeConnection(con);

        cmd.commandText("<LDAP://"+defaultNamingContext+">;(sAMAccountName="+username+");distinguishedName;subTree");
        _Recordset rs = cmd.execute(null, Variant.MISSING, -1/*default*/);
        if(rs.eof())
            throw new UsernameNotFoundException("No such user: "+username);

        String dn = rs.fields().item("distinguishedName").value().toString();


        // now we got the DN of the user
        IADsOpenDSObject dso = COM4J.getObject(IADsOpenDSObject.class,"LDAP:",null);

        // turns out we don't need DN for authentication
        // we can bind with the user name
        // dso.openDSObject("LDAP://"+context,args[0],args[1],1);

        // to do bind with DN as the user name, the flag must be 0
        IADsUser usr;
        try {
            usr = (authentication==null
                ? dso.openDSObject("LDAP://"+dn, null, null, 0)
                : dso.openDSObject("LDAP://"+dn, dn, password, 0))
                    .queryInterface(IADsUser.class);
        } catch (ComException e) {
            throw new BadCredentialsException("Incorrect password for "+username);
        }

        List<GrantedAuthority> groups = new ArrayList<GrantedAuthority>();
        for( Com4jObject g : usr.groups() ) {
            IADsGroup grp = g.queryInterface(IADsGroup.class);
            // cut "CN=" and make that the role name
            groups.add(new GrantedAuthorityImpl(grp.name().substring(3)));
        }

        return new ActiveDirectoryUserDetail(
            username, password,
            !usr.accountDisabled(),
            true, true, true,
            groups.toArray(new GrantedAuthority[groups.size()])
        );
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryAuthenticationProvider.class.getName());
}
