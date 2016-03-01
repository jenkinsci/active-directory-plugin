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
import hudson.Util;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.Secret;
import javax.naming.NameNotFoundException;

import hudson.util.TimeUnit2;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.providers.AuthenticationProvider;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.lang.StringUtils;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.TimeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.Stack;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link AuthenticationProvider} with Active Directory, through LDAP.
 * 
 * @author Kohsuke Kawaguchi
 * @author James Nord
 */
public class ActiveDirectoryUnixAuthenticationProvider extends AbstractActiveDirectoryAuthenticationProvider {

    private final String[] domainNames;

    private final String site;

    /**
     * The LDAP server that we should talk to first, regardless of the LDAP server discovery result.
     * Conceptually there should be one per domain, but for historical reason we only support one here.
     */
    private final String server;

    private final String bindName, bindPassword;

    private final ActiveDirectorySecurityRealm.DescriptorImpl descriptor;

    private GroupLookupStrategy groupLookupStrategy;

    /**
     * {@link ActiveDirectoryGroupDetails} cache.
     */
    private final Cache<String,ActiveDirectoryGroupDetails,UsernameNotFoundException> groupCache = new Cache<String,ActiveDirectoryGroupDetails,UsernameNotFoundException>() {
        @Override
        protected ActiveDirectoryGroupDetails compute(String groupname) {
            boolean problem = false;
            for (String domainName : domainNames) {
                // when we use custom socket factory below, every LDAP operations result
                // in a classloading via context classloader, so we need it to resolve.
                ClassLoader ccl = Thread.currentThread().getContextClassLoader();
                Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
                try {
                    DirContext context = descriptor.bind(bindName, bindPassword, obtainLDAPServers(domainName));

                    try {
                        final String domainDN = toDC(domainName);

                        Attributes group = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (cn={0})(objectCategory=group))",groupname);
                        if (group==null) {
                            // failed to find it. Fall back to sAMAccountName.
                            // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                            LOGGER.fine("Failed to find "+groupname+" in cn. Trying sAMAccountName");
                            group = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (sAMAccountName={0})(objectCategory=group))",groupname);
                            if (group==null) {
                                // Group not found in this domain, try next
                                continue;
                            }
                        }
                        LOGGER.fine("Found group " + groupname + " : " + group);
                        return new ActiveDirectoryGroupDetails(groupname);
                    } catch (NamingException e) {
                        LOGGER.log(Level.WARNING, "Failed to retrieve user information for "+groupname, e);
                        throw new BadCredentialsException("Failed to retrieve user information for "+groupname, e);
                    } finally {
                        closeQuietly(context);
                    }
                } catch (UsernameNotFoundException e) {
                    // everything worked OK but we just didn't find it. This could be just a typo in group name.
                    LOGGER.log(Level.FINE, "Failed to find the group "+groupname+" in "+domainName+" domain", e);
                } catch (AuthenticationException e) {
                    // something went wrong talking to the server. This should be reported
                    LOGGER.log(Level.WARNING, "Failed to find the group "+groupname+" in "+domainName+" domain", e);
                    problem = true;
                } finally {
                    Thread.currentThread().setContextClassLoader(ccl);
                }
            }

            if (!problem) {
                return null; // group not found anywhere. cache this result
            } else {
                LOGGER.log(Level.WARNING, "Exhausted all configured domains and could not authenticate against any.");
                throw new UserMayOrMayNotExistException(groupname);
            }
        }
    };
    
    public ActiveDirectoryUnixAuthenticationProvider(ActiveDirectorySecurityRealm realm) {
        if (realm.domain==null) throw new IllegalArgumentException("Active Directory domain name is required but it is not set");
        this.domainNames = realm.domain.split(",");
        this.site = realm.site;
        this.bindName = realm.bindName;
        this.server = realm.server;
        this.bindPassword = Secret.toString(realm.bindPassword);
        this.groupLookupStrategy = realm.getGroupLookupStrategy();
        this.descriptor = realm.getDescriptor();
    }

    protected UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        try {
            // this is more seriously error, indicating a failure to search
            List<BadCredentialsException> errors = new ArrayList<BadCredentialsException>();

            // this is lesser error, in that we searched and the user was not found
            List<UsernameNotFoundException> notFound = new ArrayList<UsernameNotFoundException>();

            for (String domainName : domainNames) {
                try {
                    return retrieveUser(username, authentication, domainName);
                } catch (UsernameNotFoundException e) {
                    notFound.add(e);
                } catch (BadCredentialsException bce) {
                    LOGGER.log(Level.WARNING, "Credential exception trying to authenticate against "+domainName+" domain", bce);
                    errors.add(bce);
                }
            }

            switch (errors.size()) {
            case 0:
                break;  // fall through
            case 1:
                throw errors.get(0); // preserve the original exception
            default:
                throw new MultiCauseBadCredentialsException("Either no such user '"+username+"' or incorrect password",errors);
            }

            if (notFound.size()==1)
                throw notFound.get(0);  // preserve the original exception

            if (!Util.filter(notFound,UserMayOrMayNotExistException.class).isEmpty())
                // if one domain responds with UserMayOrMayNotExistException, then it might actually exist there,
                // so our response will be "can't tell"
                throw new MultiCauseUserMayOrMayNotExistException("We can't tell if the user exists or not: "+username,notFound);

            if (!notFound.isEmpty())
                throw new MultiCauseUserNotFoundException("No such user: "+username,notFound);

            throw new AssertionError("no domain is configured");
        } catch (AuthenticationException e) {
            LOGGER.log(Level.FINE, "Failed to retrieve user "+username, e);
            throw e;
        }
    }

    @Override
    protected boolean canRetrieveUserByName() {
        return bindName!=null;
    }

    /**
     *
     * @param authentication
     *      null if we are just retrieving the said user, instead of trying to authenticate.
     */
    private UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication, String domainName) throws AuthenticationException {
        // when we use custom socket factory below, every LDAP operations result
        // in a classloading via context classloader, so we need it to resolve.
        ClassLoader ccl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            String password = NO_AUTHENTICATION;
            if (authentication!=null)
                password = (String) authentication.getCredentials();

            return retrieveUser(username, password, domainName, obtainLDAPServers(domainName));
        } finally {
            Thread.currentThread().setContextClassLoader(ccl);
        }
    }

    /**
     * Obtains the list of the LDAP servers in the order we should talk to, given how this
     * {@link ActiveDirectoryUnixAuthenticationProvider} is configured.
     */
    private List<SocketInfo> obtainLDAPServers(String domainName) throws AuthenticationServiceException {
        try {
            return descriptor.obtainLDAPServer(domainName, site, server);
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING, "Failed to find the LDAP service", e);
            throw new AuthenticationServiceException("Failed to find the LDAP service for the domain "+domainName, e);
        }
    }

    /**
     * Authenticates and retrieves the user by using the given list of available AD LDAP servers.
     * 
     * @param password
     *      If this is {@link #NO_AUTHENTICATION}, the authentication is not performed, and just the retrieval
     *      would happen.
     * @throws UsernameNotFoundException
     *      The user didn't exist.
     * @return never null
     */
    @SuppressFBWarnings(value = "ES_COMPARING_PARAMETER_STRING_WITH_EQ", justification = "Intentional instance check.")
    public UserDetails retrieveUser(String username, String password, String domainName, List<SocketInfo> ldapServers) {
        DirContext context;
        boolean anonymousBind;    // did we bind anonymously?

        // LDAP treats empty password as anonymous bind, so we need to reject it
        if (StringUtils.isEmpty(password))
            throw new BadCredentialsException("Empty password");

        String userPrincipalName = getPrincipalName(username, domainName);
        String samAccountName = userPrincipalName.substring(0, userPrincipalName.indexOf('@'));

        if (bindName!=null) {
            // two step approach. Use a special credential to obtain DN for the
            // user trying to login, then authenticate.
            try {
                context = descriptor.bind(bindName, bindPassword, ldapServers);
                anonymousBind = false;
            } catch (BadCredentialsException e) {
                throw new AuthenticationServiceException("Failed to bind to LDAP server with the bind name/password", e);
            }
        } else {
            anonymousBind = password == NO_AUTHENTICATION;
            try {
                // if we are just retrieving the user, try using anonymous bind by empty password (see RFC 2829 5.1)
                // but if that fails, that's not BadCredentialException but UserMayOrMayNotExistException
                context = descriptor.bind(userPrincipalName, anonymousBind ? "" : password, ldapServers);
            } catch (BadCredentialsException e) {
                if (anonymousBind)
                    // in my observation, if we attempt an anonymous bind and AD doesn't allow it, it still passes the bind method
                    // and only fail later when we actually do a query. So perhaps this is a dead path, but I'm leaving it here
                    // anyway as a precaution.
                    throw new UserMayOrMayNotExistException("Unable to retrieve the user information without bind DN/password configured");
                throw e;
            }
        }

        try {
            // locate this user's record
            final String domainDN = toDC(domainName);

            Attributes user = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (userPrincipalName={0})(objectCategory=user))",userPrincipalName);
            if (user==null) {
                // failed to find it. Fall back to sAMAccountName.
                // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                LOGGER.fine("Failed to find "+userPrincipalName+" in userPrincipalName. Trying sAMAccountName");
                user = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (sAMAccountName={0})(objectCategory=user))",samAccountName);
                if (user==null) {
                    throw new UsernameNotFoundException("Authentication was successful but cannot locate the user information for "+username);
                }
            }
            LOGGER.fine("Found user "+username+" : "+user);

            Object dn = user.get("distinguishedName").get();
            if (dn==null)
                throw new AuthenticationServiceException("No distinguished name for "+username);

            if (bindName!=null && password!=NO_AUTHENTICATION) {
                // if we've used the credential specifically for the bind, we
                // need to verify the provided password to do authentication
                LOGGER.fine("Attempting to validate password for DN="+dn);
                DirContext test = descriptor.bind(dn.toString(), password, ldapServers);
                // Binding alone is not enough to test the credential. Need to actually perform some query operation.
                // but if the authentication fails this throws an exception
                try {
                    new LDAPSearchBuilder(test,domainDN).searchOne("(& (userPrincipalName={0})(objectCategory=user))",userPrincipalName);
                } finally {
                    closeQuietly(test);
                }
            }

            Set<GrantedAuthority> groups = resolveGroups(domainDN, dn.toString(), context);
            groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY);

            return new ActiveDirectoryUserDetail(username, password, true, true, true, true, groups.toArray(new GrantedAuthority[groups.size()]),
                    getStringAttribute(user, "displayName"),
                    getStringAttribute(user, "mail"),
                    getStringAttribute(user, "telephoneNumber")
                    ).updateUserInfo();
        } catch (NamingException e) {
            if (anonymousBind && e.getMessage().contains("successful bind must be completed") && e.getMessage().contains("000004DC")) {
                // sometimes (or always?) anonymous bind itself will succeed but the actual query will fail.
                // see JENKINS-12619. On my AD the error code is DSID-0C0906DC
                throw new UserMayOrMayNotExistException("Unable to retrieve the user information without bind DN/password configured");
            }

            LOGGER.log(Level.WARNING, "Failed to retrieve user information for "+username, e);
            throw new BadCredentialsException("Failed to retrieve user information for "+username, e);
        } finally {
            closeQuietly(context);
        }
    }

    public GroupDetails loadGroupByGroupname(String groupname) {
        if (bindName==null)
            throw new UserMayOrMayNotExistException("Unable to retrieve group information without bind DN/password configured");

        ActiveDirectoryGroupDetails details = groupCache.get(groupname);
        if (details==null)  throw new UsernameNotFoundException(groupname);
        else                return details;
    }

    private void closeQuietly(DirContext context) {
        try {
            if (context!=null)
                context.close();
        } catch (NamingException e) {
            LOGGER.log(Level.INFO,"Failed to close DirContext: "+context,e);
        }
    }


    private String getStringAttribute(Attributes user, String name) throws NamingException {
        Attribute a = user.get(name);
        if (a==null)    return null;
        Object v = a.get();
        if (v==null)    return null;
        return v.toString();
    }

    /**
     * Returns the full user principal name of the form "joe@europe.contoso.com".
     * 
     * If people type in 'foo@bar' or 'bar\\foo', it should be treated as
     * 'foo@bar.acme.org' (where 'acme.org' part comes from the given domain name)
     */
    private String getPrincipalName(String username, String domainName) {
        String principalName;
        int slash = username.indexOf('\\');
        if (slash>0) {
            principalName = username.substring(slash+1)+'@'+username.substring(0, slash)+'.'+domainName;
        } else if (username.contains("@"))
            principalName = username+'.'+domainName;
        else
            principalName = username+'@'+domainName;
        return principalName;
    }

    /**
     * Resolves all the groups that the user is in.
     *
     * We now use <a href="http://msdn.microsoft.com/en-us/library/windows/desktop/ms680275(v=vs.85).aspx">tokenGroups</a>
     * attribute, which is a computed attribute that lists all the SIDs of the groups that the user is directly/indirectly in.
     * We then use that to retrieve all the groups in one query and resolve their canonical names.
     *
     * @param userDN
     *      User's distinguished name.
     * @param context Used for making queries.
     */
    private Set<GrantedAuthority> resolveGroups(String domainDN, String userDN, DirContext context) throws NamingException {
        LOGGER.finer("Looking up group of "+userDN);
        Attributes id = context.getAttributes(userDN,new String[]{"tokenGroups","memberOf","CN"});
        Attribute tga = id.get("tokenGroups");
        if (tga==null) {// see JENKINS-11644. still trying to figure out when this happens
            LOGGER.warning("Failed to retrieve tokenGroups for "+userDN);
            HashSet<GrantedAuthority> r = new HashSet<GrantedAuthority>();
            r.add(new GrantedAuthorityImpl("unable-to-retrieve-tokenGroups"));
            return r;
        }

        // build up the query to retrieve all the groups
        StringBuilder query = new StringBuilder("(|");
        List<byte[]> sids = new ArrayList<byte[]>();

        NamingEnumeration<?> tokenGroups = tga.getAll();
        while (tokenGroups.hasMore()) {
            byte[] gsid = (byte[])tokenGroups.next();
            query.append("(objectSid={"+sids.size()+"})");
            sids.add(gsid);
        }
        tokenGroups.close();

        query.append(")");

        Set<GrantedAuthority> groups = new HashSet<GrantedAuthority>();

        NamingEnumeration<SearchResult> renum = new LDAPSearchBuilder(context,domainDN).subTreeScope().returns("cn").search(query.toString(), sids.toArray());
        parseMembers(userDN, groups, renum);
        renum.close();

        {/*
            stage 2: use memberOf to find groups that aren't picked up by tokenGroups.
            This includes distribution groups
        */
            LOGGER.fine("Stage 2: looking up via memberOf");

            while (true) {
                switch (groupLookupStrategy) {
                case AUTO:
                    // try the accurate one first, and if it's too slow fall back to recursive in the hope that it's faster
                    long start = System.nanoTime();
                    boolean found = false;
                    long duration = 0;
                    try {
                        found = chainGroupLookup(domainDN, userDN, context, groups);
                        duration = TimeUnit2.NANOSECONDS.toSeconds(System.nanoTime() - start);
                    } catch (TimeLimitExceededException e) {
                        LOGGER.log(Level.WARNING, "The LDAP request did not terminate within the specified time limit. AD will fall back to recursive lookup", e);
                    } catch (NamingException e) {
                        if (e.getMessage().contains("LDAP response read timed out")) {
                            LOGGER.log(Level.WARNING, "LDAP response read time out. AD will fall back to recursive lookup", e);
                        } else {
                            throw e;
                        }
                    }
                    if (!found || duration >= 10) {
                        LOGGER.warning(String.format("AD chain lookup is taking too long (%dms). Falling back to recursive lookup", duration));
                        groupLookupStrategy = GroupLookupStrategy.RECURSIVE;
                        continue;
                    } else {
                        // it run fast enough, so let's stick to it
                        groupLookupStrategy = GroupLookupStrategy.CHAIN;
                        return groups;
                    }
                case RECURSIVE:
                    recursiveGroupLookup(context, id, groups);
                    return groups;
                case CHAIN:
                    chainGroupLookup(domainDN, userDN, context, groups);
                    return groups;
                }
            }
        }
    }

    /**
     * Performs AD-extension to LDAP query that performs recursive group lookup.
     * This Microsoft extension is explained in http://msdn.microsoft.com/en-us/library/aa746475(v=vs.85).aspx
     *
     * @return
     *      false if it appears that this search failed.
     * @see
     */
    private boolean chainGroupLookup(String domainDN, String userDN, DirContext context, Set<GrantedAuthority> groups) throws NamingException {
        NamingEnumeration<SearchResult> renum = new LDAPSearchBuilder(context, domainDN).subTreeScope().returns("cn").search(
                "(member:1.2.840.113556.1.4.1941:={0})", userDN);
        try {
            if (renum.hasMore()) {
                // http://ldapwiki.willeke.com/wiki/Active%20Directory%20Group%20Related%20Searches cites that
                // this filter search extension requires at least Win2K3 SP2. So if this didn't find anything,
                // fall back to the recursive search

                // TODO: this search alone might be producing the super set of the tokenGroups/objectSid based search in the stage 1.
                parseMembers(userDN, groups, renum);
                return true;
            } else {
                return false;
            }
        } finally {
            renum.close();
        }
    }

    /**
     * Performs recursive group membership lookup.
     *
     * This was how we did the lookup traditionally until we discovered 1.2.840.113556.1.4.1941.
     * But various people reported that it slows down the execution tremendously to the point that it is unusable,
     * while others seem to report that it runs faster than recursive search (http://social.technet.microsoft.com/Forums/fr-FR/f238d2b0-a1d7-48e8-8a60-542e7ccfa2e8/recursive-retrieval-of-all-ad-group-memberships-of-a-user?forum=ITCG)
     *
     * This implementation is kept for Windows 2003 that doesn't support 1.2.840.113556.1.4.1941, but it can be also
     * enabled for those who are seeing the performance problem.
     *
     * See JENKINS-22830
     */
    private void recursiveGroupLookup(DirContext context, Attributes id, Set<GrantedAuthority> groups) throws NamingException {
        Stack<Attributes> q = new Stack<Attributes>();
        q.push(id);
        while (!q.isEmpty()) {
            Attributes identity = q.pop();
            LOGGER.finer("Looking up group of " + identity);

            Attribute memberOf = identity.get("memberOf");
            if (memberOf == null)
                continue;

            for (int i = 0; i < memberOf.size(); i++) {
                try {
                    Attributes group = context.getAttributes(new LdapName(memberOf.get(i).toString()), new String[]{"CN", "memberOf"});
                    Attribute cn = group.get("CN");
                    if (cn == null) {
                        LOGGER.fine("Failed to obtain CN of " + memberOf.get(i));
                        continue;
                    }
                    if (LOGGER.isLoggable(Level.FINE))
                        LOGGER.fine(cn.get() + " is a member of " + memberOf.get(i));

                    if (groups.add(new GrantedAuthorityImpl(cn.get().toString()))) {
                        q.add(group); // recursively look for groups that this group is a member of.
                    }
                } catch (NameNotFoundException e) {
                    LOGGER.fine("Failed to obtain CN of " + memberOf.get(i));
                }
            }
        }
    }

    private void parseMembers(String userDN, Set<GrantedAuthority> groups, NamingEnumeration<SearchResult> renum) throws NamingException {
        while (renum.hasMore()) {
            Attributes a = renum.next().getAttributes();
            Attribute cn = a.get("cn");
            if (LOGGER.isLoggable(Level.FINE))
                LOGGER.fine(userDN+" is a member of "+cn);
            groups.add(new GrantedAuthorityImpl(cn.get().toString()));
        }
    }

    /*package*/ static String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if (token.length()==0)
                continue; // defensive check
            if (buf.length()>0)
                buf.append(",");
            buf.append("DC=").append(token);
        }
        return buf.toString();
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryUnixAuthenticationProvider.class.getName());

    /**
     * We use this as the password value if we are calling retrieveUser to retrieve the user information
     * without authentication.
     */
    private static final String NO_AUTHENTICATION = "\u0000\u0000\u0000\u0000\u0000\u0000";
}
