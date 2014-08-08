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

import com4j.COM4J;
import com4j.Com4jObject;
import com4j.ComException;
import com4j.ExecutionException;
import com4j.Variant;
import com4j.typelibs.activeDirectory.IADs;
import com4j.typelibs.activeDirectory.IADsGroup;
import com4j.typelibs.activeDirectory.IADsOpenDSObject;
import com4j.typelibs.activeDirectory.IADsUser;
import com4j.typelibs.ado20.ClassFactory;
import com4j.typelibs.ado20._Command;
import com4j.typelibs.ado20._Connection;
import com4j.typelibs.ado20._Recordset;
import com4j.util.ComObjectCollector;
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
import org.kohsuke.stapler.framework.io.IOException2;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
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

    public ActiveDirectoryAuthenticationProvider() throws IOException {
        try {
            IADs rootDSE = COM4J.getObject(IADs.class, "LDAP://RootDSE", null);

            defaultNamingContext = (String)rootDSE.get("defaultNamingContext");
            LOGGER.info("Active Directory domain is "+defaultNamingContext);

            con = ClassFactory.createConnection();
            con.provider("ADsDSOObject");
            con.open("Active Directory Provider",""/*default*/,""/*default*/,-1/*default*/);
        } catch (ExecutionException e) {
            throw new IOException2("Failed to connect to Active Directory. Does this machine belong to Active Directory?",e);
        }
    }

    /**
     * Converts a value of the "distinguished name" attribute of some AD object
     * and returns the "LDAP://..." URL to connect to it vis {@link IADsOpenDSObject#openDSObject(String, String, String, int)}
     *
     * AFAICT, MSDN doesn't document exactly describe how a value of the DN attribute is escaped,
     * but in my experiment with Windows 2008, it escapes <tt>,+\#<>;"=</tt> but not <tt>/</tt>
     *
     * This method must escape '/' since it needs to be escaped in LDAP:// URL, but we also need
     * to avoid double-escaping what's already escaped.
     *
     * @see <a href="http://www.rlmueller.net/CharactersEscaped.htm">source</a>
     */
    static String dnToLdapUrl(String dn) {
        return "LDAP://"+dn.replace("/","\\/");
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        String password = null;
        if(authentication!=null)
            password = (String) authentication.getCredentials();

        String dn = getDnOfUserOrGroup(username);

        ComObjectCollector col = new ComObjectCollector();
        COM4J.addListener(col);
        try {
            // now we got the DN of the user
            IADsOpenDSObject dso = COM4J.getObject(IADsOpenDSObject.class,"LDAP:",null);

            // turns out we don't need DN for authentication
            // we can bind with the user name
            // dso.openDSObject("LDAP://"+context,args[0],args[1],1);

            // to do bind with DN as the user name, the flag must be 0
            IADsUser usr;
            try {
                usr = (authentication==null
                    ? dso.openDSObject(dnToLdapUrl(dn), null, null, ADS_READONLY_SERVER)
                    : dso.openDSObject(dnToLdapUrl(dn), dn, password, ADS_READONLY_SERVER))
                        .queryInterface(IADsUser.class);
            } catch (ComException e) {
                // this is failing
                String msg = String.format("Incorrect password for %s DN=%s: error=%08X", username, dn, e.getHRESULT());
                LOGGER.log(Level.FINE, "Login failure: "+msg,e);
                throw (BadCredentialsException)new BadCredentialsException(msg).initCause(e);
            }
            if (usr == null)    // the user name was in fact a group
                throw new UsernameNotFoundException("User not found: "+username);

            List<GrantedAuthority> groups = new ArrayList<GrantedAuthority>();
            for( Com4jObject g : usr.groups() ) {
                if (g==null)        continue;   // according to JENKINS-17357 in some environment the collection contains null
                IADsGroup grp = g.queryInterface(IADsGroup.class);
                // cut "CN=" and make that the role name
                groups.add(new GrantedAuthorityImpl(grp.name().substring(3)));
            }
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

            LOGGER.log(Level.FINER, "Login successful: "+username+" dn="+dn);

            return new ActiveDirectoryUserDetail(
                username, password,
                !isAccountDisabled(usr),
                true, true, true,
                groups.toArray(new GrantedAuthority[groups.size()]),
                    getFullName(usr), getEmailAddress(usr), getTelephoneNumber(usr)
            ).updateUserInfo();
        } catch (AuthenticationException e) {
            LOGGER.log(Level.FINE, "Failed toretrieve user "+username, e);
            throw e;
        } finally {
            col.disposeAll();
            COM4J.removeListener(col);
        }
    }

    @Override
    protected boolean canRetrieveUserByName() {
        return true;
    }

    private String getTelephoneNumber(IADsUser usr) {
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
        _Recordset rs = cmd.execute(null, Variant.getMissing(), -1/*default*/);
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
            ComObjectCollector col = new ComObjectCollector();
            COM4J.addListener(col);
            try {
                // First get the distinguishedName
                String dn = getDnOfUserOrGroup(groupname);
                IADsOpenDSObject dso = COM4J.getObject(IADsOpenDSObject.class, "LDAP:", null);
                IADsGroup group = dso.openDSObject(dnToLdapUrl(dn), null, null, ADS_READONLY_SERVER)
                        .queryInterface(IADsGroup.class);

                // If not a group will return null
                if (group == null)  return null;
                return new ActiveDirectoryGroupDetails(groupname);
            } catch (UsernameNotFoundException e) {
                return null; // failed to convert group name to DN
            } catch (ComException e) {
                // recover gracefully since AD might behave in a way we haven't anticipated
                LOGGER.log(Level.WARNING, "Failed to figure out details of AD group: "+groupname,e);
                return null;
            } finally {
                col.disposeAll();
                COM4J.removeListener(col);
            }
        }
    };

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryAuthenticationProvider.class.getName());

    /**
     * Signify that we can connect to a read-only mirror.
     *
     * See http://msdn.microsoft.com/en-us/library/windows/desktop/aa772247(v=vs.85).aspx
     */
    private static final int ADS_READONLY_SERVER = 0x4;

}
