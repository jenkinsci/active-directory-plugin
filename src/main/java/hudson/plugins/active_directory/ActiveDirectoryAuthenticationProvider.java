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
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 * {@link AuthenticationProvider} with Active Directory, plus {@link UserDetailsService}
 *
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryAuthenticationProvider extends AbstractActiveDirectoryAuthenticationProvider {
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

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        String password = null;
        if(authentication!=null)
            password = (String) authentication.getCredentials();


        String dn = getDnOfUserOrGroup(username);


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
        if (usr == null)    // the user name was in fact a group
        	throw new UsernameNotFoundException("User not found: "+username);

        List<GrantedAuthority> groups = new ArrayList<GrantedAuthority>();
        for( Com4jObject g : usr.groups() ) {
            IADsGroup grp = g.queryInterface(IADsGroup.class);
            // cut "CN=" and make that the role name
            groups.add(new GrantedAuthorityImpl(grp.name().substring(3)));
        }
        groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);
        
        return new ActiveDirectoryUserDetail(
            username, password,
            !isAccountDisabled(usr),
            true, true, true,
            groups.toArray(new GrantedAuthority[groups.size()]),
                getFullName(usr), getEmailAddress(usr), getTelehoneNumber(usr)
        ).updateUserInfo();
    }

    @Override
    protected boolean canRetrieveUserByName() {
        return true;
    }

    private String getTelehoneNumber(IADsUser usr) {
        try {
            Object t = usr.telephoneNumber();
            return t==null ? null : t.toString();
        } catch (ComException e) {
            if (e.getHRESULT()==0x8000500D) // see http://support.microsoft.com/kb/243440
                return null;
            throw e;
        }
    }

    private String getEmailAddress(IADsUser usr) {
        try {
            return usr.emailAddress();
        } catch (ComException e) {
            if (e.getHRESULT()==0x8000500D) // see http://support.microsoft.com/kb/243440
                return null;
            throw e;
        }
    }

    private String getFullName(IADsUser usr) {
        try {
            return usr.fullName();
        } catch (ComException e) {
            if (e.getHRESULT()==0x8000500D) // see http://support.microsoft.com/kb/243440
                return null;
            throw e;
        }
    }

    private boolean isAccountDisabled(IADsUser usr) {
        try {
            return usr.accountDisabled();
        } catch (ComException e) {
            if (e.getHRESULT()==0x8000500D)
                /*
                    See http://support.microsoft.com/kb/243440 and JENKINS-10086
                    We suspect this to be caused by old directory items that do not have this value,
                    so assume this account is enabled.
                 */
                return false;
            throw e;
        }
    }

    private String getDnOfUserOrGroup(String userOrGroupname) throws UsernameNotFoundException {
		_Command cmd = ClassFactory.createCommand();
        cmd.activeConnection(con);

        cmd.commandText("<LDAP://"+defaultNamingContext+">;(sAMAccountName="+userOrGroupname+");distinguishedName;subTree");
        _Recordset rs = cmd.execute(null, Variant.MISSING, -1/*default*/);
        if(rs.eof())
            throw new UsernameNotFoundException("No such user or group: "+userOrGroupname);

        String dn = rs.fields().item("distinguishedName").value().toString();
		return dn;
	}

	public GroupDetails loadGroupByGroupname(String groupname) {
        ActiveDirectoryGroupDetails details = groupCache.get(groupname);
        if (details!=null)      return details;
        throw new UsernameNotFoundException("Group not found: " + groupname);
	}

    /**
     * {@link ActiveDirectoryGroupDetails} cache.
     */
    private final Cache<String,ActiveDirectoryGroupDetails,UsernameNotFoundException> groupCache = new Cache<String,ActiveDirectoryGroupDetails,UsernameNotFoundException>() {
        @Override
        protected ActiveDirectoryGroupDetails compute(String groupname) {
            // First get the distinguishedName
            try {
                String dn = getDnOfUserOrGroup(groupname);
                IADsOpenDSObject dso = COM4J.getObject(IADsOpenDSObject.class, "LDAP:", null);
                IADsGroup group = dso.openDSObject("LDAP://" + dn, null, null, 0)
                        .queryInterface(IADsGroup.class);

                // If not a group will return null
                if (group == null)  return null;
                return new ActiveDirectoryGroupDetails(groupname);
            } catch (UsernameNotFoundException e) {
                return null; // failed to convert group name to DN
            }
        }
    };

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryAuthenticationProvider.class.getName());
}
