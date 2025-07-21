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

import com.github.benmanes.caffeine.cache.Cache;
import hudson.Util;
import hudson.model.User;
import hudson.security.GroupDetails;
import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.security.UserMayOrMayNotExistException2;
import hudson.util.DaemonThreadFactory;
import hudson.util.NamingThreadFactory;
import hudson.util.Secret;

import javax.naming.NameNotFoundException;

import org.apache.commons.lang.StringUtils;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
import javax.naming.TimeLimitExceededException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.Stack;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * {@link AuthenticationProvider} with Active Directory, through LDAP.
 * 
 * @author Kohsuke Kawaguchi
 * @author James Nord
 */
public class ActiveDirectoryUnixAuthenticationProvider extends AbstractActiveDirectoryAuthenticationProvider {

    private final List<ActiveDirectoryDomain> domains;

    private final String site;

    private final ActiveDirectorySecurityRealm.DescriptorImpl descriptor;

    private GroupLookupStrategy groupLookupStrategy;

    /**
     * The internal {@link User} to fall back when {@link NamingException} happens
     */
    private final ActiveDirectoryInternalUsersDatabase activeDirectoryInternalUser;

    protected static final String DN_FORMATTED = "distinguishedNameFormatted";

    /**
     * To specify the TTL and Size used for caching users and groups
     */
    private CacheConfiguration cache;

    /**
     * The {@link UserDetails} cache.
     */
    private final Cache<CacheKey, UserDetails> userCache;

    /**
     * The {@link ActiveDirectoryGroupDetails} cache.
     */
    private final Cache<String, ActiveDirectoryGroupDetails> groupCache;

    /**
     * The threadPool to update the cache on background
     */
    private final ExecutorService threadPoolExecutor;

    /**
     * Properties to be passed to the current LDAP context
     */
    private Hashtable<String, String> props = new Hashtable<>();

    /**
     * Timeout if no connection after 30 seconds
     */
    private final static String DEFAULT_LDAP_CONNECTION_TIMEOUT = "30000";

    /**
     * Timeout if no response after 60 seconds
     */
    private final static String DEFAULT_LDAP_READ_TIMEOUT = "60000";

    /**
     * Represents com.sun.jndi.ldap.connect.timeout
     */
    private final static String LDAP_CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";

    /**
     * Represents com.sun.jndi.ldap.read.timeout
     */
    private final static String LDAP_READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";

    /**
     * Selects the SSL strategy to follow on the TLS connections
     *
     * <p>
     *     Even if we are not using any of the TLS ports (3269/636) the plugin will try to establish a TLS channel
     *     using startTLS. Because of this, we need to be able to specify the SSL strategy on the plugin
     *
     * <p>
     *     For the moment there are two possible values: trustAllCertificates and trustStore.
     */
    @Deprecated
    protected TlsConfiguration tlsConfiguration;

    /**
     * The core pool size for the {@link ExecutorService}
     */
    private static final int corePoolSize = Integer.parseInt(System.getProperty("hudson.plugins.active_directory.threadPoolExecutor.corePoolSize", "4"));

    /**
     * The max pool size for the {@link ExecutorService}
     */
    private static final int maxPoolSize = Integer.parseInt(System.getProperty("hudson.plugins.active_directory.threadPoolExecutor.maxPoolSize", "8"));

    /**
     * The keep alive time for the {@link ExecutorService}
     */
    private static final long keepAliveTime = Long.parseLong(System.getProperty("hudson.plugins.active_directory.threadPoolExecutor.keepAliveTime", "10000"));

    /**
     * The queue size for the {@link ExecutorService}
     */
    private static final int queueSize = Integer.parseInt(System.getProperty("hudson.plugins.active_directory.threadPoolExecutor.queueSize", "25"));


    public ActiveDirectoryUnixAuthenticationProvider(ActiveDirectorySecurityRealm realm) {
        this.site = realm.site;
        this.domains = realm.domains;
        this.groupLookupStrategy = realm.getGroupLookupStrategy();
        this.activeDirectoryInternalUser = realm.internalUsersDatabase;
        this.descriptor = realm.getDescriptor();
        this.cache = realm.cache;

        if (cache == null) {
            this.cache = new CacheConfiguration(0, 0);
        }

        // On startup userCache and groupCache are not created and cache is different from null
        if (cache.getUserCache() == null || cache.getGroupCache() == null) {
            this.cache = new CacheConfiguration(cache.getSize(), cache.getTtl());
        }
        this.userCache = cache.getUserCache();
        this.groupCache = cache.getGroupCache();
        this.threadPoolExecutor = new ThreadPoolExecutor(
                corePoolSize,
                maxPoolSize,
                keepAliveTime,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<Runnable>(queueSize),
                new NamingThreadFactory(new DaemonThreadFactory(), "ActiveDirectory.updateUserCache"),
                new ThreadPoolExecutor.DiscardPolicy()
        );
        Map<String, String> extraEnvVarsMap = ActiveDirectorySecurityRealm.EnvironmentProperty.toMap(realm.environmentProperties);
        props.put(LDAP_CONNECT_TIMEOUT, System.getProperty(LDAP_CONNECT_TIMEOUT, DEFAULT_LDAP_CONNECTION_TIMEOUT));
        props.put(LDAP_READ_TIMEOUT, System.getProperty(LDAP_READ_TIMEOUT, DEFAULT_LDAP_READ_TIMEOUT));
        // put all the user defined properties into our context environment replacing any mappings that already exist.
        props.putAll(extraEnvVarsMap);
    }

    protected UserDetails retrieveUser(final String username, final UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        try {
            // this is more seriously error, indicating a failure to search
            List<AuthenticationException> errors = new ArrayList<>();

            // this is lesser error, in that we searched and the user was not found
            List<UsernameNotFoundException> notFound = new ArrayList<>();

            for (ActiveDirectoryDomain domain : domains) {
                try {
                    return retrieveUser(username, authentication, domain);
                } catch (NamingException ne) {
                    if (userMatchesInternalDatabaseUser(username)) {
                        LOGGER.log(Level.WARNING, String.format("Looking into Jenkins Internal Users Database for user %s", username));
                        User internalUser = hudson.model.User.get(username);
                        HudsonPrivateSecurityRealm.Details hudsonPrivateSecurityRealm = internalUser.getProperty(HudsonPrivateSecurityRealm.Details.class);
                        String password = "";
                        if (authentication.getCredentials() instanceof String) {
                            password = (String) authentication.getCredentials();
                        }
                        if (hudsonPrivateSecurityRealm.isPasswordCorrect(password)) {
                            LOGGER.log(Level.INFO, String.format("Falling back into the internal user %s", username));
                            return new ActiveDirectoryUserDetail(username, "redacted", true, true, true, true, hudsonPrivateSecurityRealm.getAuthorities2(), internalUser.getDisplayName(), "", "");
                        } else {
                            LOGGER.log(Level.WARNING, String.format("Credential exception trying to authenticate against %s domain", domain.getName()), ne);
                            errors.add(new MultiCauseUserMayOrMayNotExistException("We can't tell if the user exists or not: " + username, notFound));
                        }
                    } else {
                        LOGGER.log(Level.WARNING, String.format("Communications issues when trying to authenticate against %s domain for user %s", domain.getName(), (username == null ? "<null>" : username)), ne);
                        errors.add(new MultiCauseUserMayOrMayNotExistException("We can't tell if the user exists or not: " + username, notFound));
                    }
                } catch (UsernameNotFoundException e) {
                    notFound.add(e);
                } catch (BadCredentialsException bce) {
                    LOGGER.log(Level.WARNING, String.format("Credential exception trying to authenticate against %s domain", domain.getName()), bce);
                    errors.add(bce);
                }
            }

            switch (errors.size()) {
                case 0:
                    break;  // fall through
                case 1:
                    throw errors.get(0); // preserve the original exception
                default:
                    throw new MultiCauseBadCredentialsException("Either no such user '" + username + "' or incorrect password", errors);
            }

            if (notFound.size()==1) {
                throw notFound.get(0);  // preserve the original exception
            }

            if (!Util.filter(notFound, UserMayOrMayNotExistException2.class).isEmpty()) {
                // if one domain responds with UserMayOrMayNotExistException, then it might actually exist there,
                // so our response will be "can't tell"
                throw new MultiCauseUserMayOrMayNotExistException("We can't tell if the user exists or not: " + username, notFound);
            }
            if (!notFound.isEmpty()) {
                throw new MultiCauseUserNotFoundException("No such user: " + username, notFound);
            }

            throw new AssertionError("No domain is configured");
        } catch (AuthenticationException e) {
            LOGGER.log(Level.FINE, String.format("Failed to retrieve user %s", username), e);
            throw e;
        }
    }


    /**
     *
     * @param authentication
     *      null if we are just retrieving the said user, instead of trying to authenticate.
     */
    private UserDetails retrieveUser(String username, UsernamePasswordAuthenticationToken authentication, ActiveDirectoryDomain domain) throws AuthenticationException, NamingException {
        // when we use custom socket factory below, every LDAP operations result
        // in a classloading via context classloader, so we need it to resolve.
        ClassLoader ccl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            Password password = NoAuthentication.INSTANCE;
            if (authentication!=null)
                password = new UserPassword((String) authentication.getCredentials());

            return retrieveUser(username, password, domain, obtainLDAPServers(domain));
        } finally {
            Thread.currentThread().setContextClassLoader(ccl);
        }
    }

    /**
     * Obtains the list of the LDAP servers in the order we should talk to, given how this
     * {@link ActiveDirectoryUnixAuthenticationProvider} is configured.
     */
    private List<SocketInfo> obtainLDAPServers(ActiveDirectoryDomain domain) throws AuthenticationServiceException, NamingException {
        try {
            return descriptor.obtainLDAPServer(domain);
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING, "Failed to find the LDAP service for the domain {0}", domain.getName());
            throw  e;
        }
    }

    /**
     * Authenticates and retrieves the user by using the given list of available AD LDAP servers.
     * 
     * @param password
     *      If this is {@link AbstractActiveDirectoryAuthenticationProvider.NoAuthentication}, the authentication is not performed, and just the retrieval
     *      would happen.
     * @throws UsernameNotFoundException
     *      The user didn't exist.
     * @return never null
     */
    public UserDetails retrieveUser(final String username, final Password password, final ActiveDirectoryDomain domain, final List<SocketInfo> ldapServers) throws NamingException {
        Objects.requireNonNull(password);
        UserDetails userDetails;
        final CacheKey cacheKey = CacheUtil.computeCacheKey(username, password, userCache.asMap().keySet());

        final String bindName = domain.getBindName();
        final String bindPassword = Secret.toString(domain.getBindPassword());

        try {
            final ActiveDirectoryUserDetail[] cacheMiss = new ActiveDirectoryUserDetail[1];
            final Function<CacheKey, UserDetails> cacheKeyUserDetailsFunction = cacheKey1 ->
                {
                    DirContext context;
                    boolean anonymousBind = false;    // did we bind anonymously?

                    // LDAP treats empty password as anonymous bind, so we need to reject it
                    if (password instanceof UserPassword && StringUtils.isEmpty(((UserPassword) password).getPassword())) {
                        throw new BadCredentialsException("Empty password");
                    }

                    String userPrincipalName = getPrincipalName(username, domain.getName());
                    String samAccountName = userPrincipalName.substring(0, userPrincipalName.indexOf('@'));

                    if (bindName != null) {
                        // two step approach. Use a special credential to obtain DN for the
                        // user trying to login, then authenticate.
                        try {
                            context = descriptor.bind(bindName, bindPassword, ldapServers, props, domain.getTlsConfiguration());
                            anonymousBind = false;
                        } catch (NamingException e) {
                            if (activeDirectoryInternalUser != null) {
                                throw new RuntimeException(e);
                            }
                            throw new AuthenticationServiceException("Failed to bind to LDAP server with the bind name/password", e);
                        }
                    } else {
                        anonymousBind = password instanceof NoAuthentication;

                        try {
                            // if we are just retrieving the user, try using anonymous bind by empty password (see RFC 2829 5.1)
                            // but if that fails, that's not BadCredentialException but UserMayOrMayNotExistException
                            context = descriptor.bind( userPrincipalName,
                                                       anonymousBind ? "" : ((UserPassword) password).getPassword(),
                                                       ldapServers, props, domain.getTlsConfiguration() );
                        } catch (NamingException e) {
                            throw new RuntimeException(e);
                        } catch (BadCredentialsException e) {
                            if (anonymousBind)
                                // in my observation, if we attempt an anonymous bind and AD doesn't allow it, it still passes the bind method
                                // and only fail later when we actually do a query. So perhaps this is a dead path, but I'm leaving it here
                                // anyway as a precaution.
                                throw new UserMayOrMayNotExistException2("Unable to retrieve the user information without bind DN/password configured");
                            throw e;
                        }
                    }

                    try {
                        // locate this user's record
                        final String domainDN = toDC(domain.getName());

                        Attributes user = new LDAPSearchBuilder(context, domainDN).subTreeScope().searchOne("(& (userPrincipalName={0})(objectCategory=user))", userPrincipalName);
                        if (user == null) {
                            // failed to find it. Fall back to sAMAccountName.
                            // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                            LOGGER.log(Level.FINE, "Failed to find {0} in userPrincipalName. Trying sAMAccountName", userPrincipalName);
                            user = new LDAPSearchBuilder(context, domainDN).subTreeScope().searchOne("(& (sAMAccountName={0})(objectCategory=user))", samAccountName);
                            if (user == null) {
                                throw new UsernameNotFoundException("Authentication was successful but cannot locate the user information for " + username);
                            }
                        }
                        LOGGER.fine("Found user " + username + " : " + user);

                        Object dnObject = user.get(DN_FORMATTED).get();
                        if (dnObject == null) {
                            throw new AuthenticationServiceException("No distinguished name for " + username);
                        }

                        String dn = dnObject.toString();
                        LdapName ldapName = new LdapName(dn);
                        String dnFormatted = ldapName.toString();

                        if (bindName != null && password instanceof UserPassword) {
                            // if we've used the credential specifically for the bind, we
                            // need to verify the provided password to do authentication
                            LOGGER.log(Level.FINE, "Attempting to validate password for DN={0}", dn);
                            DirContext test = descriptor.bind(dnFormatted, ((UserPassword) password).getPassword(), ldapServers, props, domain.getTlsConfiguration());
                            // Binding alone is not enough to test the credential. Need to actually perform some query operation.
                            // but if the authentication fails this throws an exception
                            try {
                                new LDAPSearchBuilder(test, domainDN).searchOne("(& (userPrincipalName={0})(objectCategory=user))", userPrincipalName);
                            } finally {
                                closeQuietly(test);
                            }
                        }

                        Set<GrantedAuthority> groups = resolveGroups(domainDN, dnFormatted, context);
                        groups.add(SecurityRealm.AUTHENTICATED_AUTHORITY2);

                        cacheMiss[0] = new ActiveDirectoryUserDetail(username, "redacted", true, true, true, true, groups,
                                getStringAttribute(user, "displayName"),
                                getStringAttribute(user, "mail"),
                                getStringAttribute(user, "telephoneNumber")
                        );
                        return cacheMiss[0];
                    } catch (NamingException e) {
                        if (activeDirectoryInternalUser != null) {
                            throw new RuntimeException(e);
                        }
                        if (anonymousBind && e.getMessage().contains("successful bind must be completed") && e.getMessage().contains("000004DC")) {
                            // sometimes (or always?) anonymous bind itself will succeed but the actual query will fail.
                            // see JENKINS-12619. On my AD the error code is DSID-0C0906DC
                            throw new UserMayOrMayNotExistException2("Unable to retrieve the user information without bind DN/password configured");
                        }
                        if (anonymousBind && e.getMessage().contains("Operation unavailable without authentication") && e.getMessage().contains("00002020")) {
                            // sometimes (or always?) anonymous bind itself will succeed but the actual query will fail.
                            // see JENKINS-47133
                            String msg = String.format("Server doesn't allow to retrieve the information for user `%s` without bind DN/password configured", username);
                            LOGGER.log(Level.WARNING, msg);
                            throw new UserMayOrMayNotExistException2(msg);
                        }

                        LOGGER.log(Level.WARNING, String.format("Failed to retrieve user information for %s", username), e);
                        throw new BadCredentialsException("Failed to retrieve user information for " + username, e);
                    } finally {
                        closeQuietly(context);
                    }
            };
            userDetails = cacheKey == null ? cacheKeyUserDetailsFunction.apply(null) : userCache.get(cacheKey, cacheKeyUserDetailsFunction);
            if (cacheMiss[0] != null || cacheKey == null) { // If a lookup was performed
                threadPoolExecutor.execute(() -> {
                    final String threadName = Thread.currentThread().getName();
                    Thread.currentThread().setName(threadName + " updating-cache-for-user-" + cacheMiss[0].getUsername());
                    LOGGER.log(Level.FINEST, "Starting the cache update {0}", new Date());
                    try {
                        long t0 = System.currentTimeMillis();
                        cacheMiss[0].updateUserInfo();
                        LOGGER.log(Level.FINEST, "Finished the cache update {0}", new Date());
                        long t1 = System.currentTimeMillis();
                        LOGGER.log(Level.FINE, "The cache for user {0} took {1} msec", new Object[]{cacheMiss[0].getUsername(), String.valueOf(t1-t0)});
                    } finally {
                        Thread.currentThread().setName(threadName);
                    }
                });
                if (userMatchesInternalDatabaseUser(username) && password instanceof UserPassword) {
                    threadPoolExecutor.execute(() -> {
                        final String threadName = Thread.currentThread().getName();
                        Thread.currentThread().setName(threadName + " updating-internal-jenkins-database-for-user" + cacheMiss[0].getUsername());
                        LOGGER.log(Level.FINEST, "Starting the Jenkins Internal Database update {0}", new Date());
                        try {
                            long t0 = System.currentTimeMillis();
                            cacheMiss[0].updatePasswordInJenkinsInternalDatabase(username, ((UserPassword)password).getPassword());
                            LOGGER.log(Level.FINEST, "Finished the password update {0}", new Date());
                            long t1 = System.currentTimeMillis();
                            LOGGER.log(Level.FINE, "The password update for user {0} took {1} msec", new Object[]{cacheMiss[0].getUsername(), String.valueOf(t1-t0)});
                        } finally {
                            Thread.currentThread().setName(threadName);
                        }
                    });
                }

            }
        } catch (Exception e) {
            if (e instanceof AuthenticationException) {
                throw (AuthenticationException)e;
            }
            if (e instanceof NamingException) {
                throw (NamingException)e;
            }
            Throwable t = e.getCause();
            if (t instanceof AuthenticationException) {
                throw (AuthenticationException)t;
            }
            if (e.getCause() instanceof NamingException) {
                throw (NamingException)e.getCause();
            }
            LOGGER.log(Level.SEVERE, "There was a problem caching user "+ username, e);
            throw new CacheAuthenticationException("Authentication failed because there was a problem caching user " +  username, e);
        }
        return userDetails;
    }

    private boolean userMatchesInternalDatabaseUser(String username) {
        return activeDirectoryInternalUser != null && activeDirectoryInternalUser.getJenkinsInternalUser() != null && username.equals(activeDirectoryInternalUser.getJenkinsInternalUser());
    }

    public GroupDetails loadGroupByGroupname(final String groupname) {
        try {
            return groupCache.get(groupname, s ->  {
                            for (ActiveDirectoryDomain domain : domains) {
                                if (domain==null) {
                                    throw new UserMayOrMayNotExistException2("Unable to retrieve group information without bind DN/password configured");
                                }
                                // when we use custom socket factory below, every LDAP operations result
                                // in a classloading via context classloader, so we need it to resolve.
                                ClassLoader ccl = Thread.currentThread().getContextClassLoader();
                                Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
                                try {
                                    DirContext context = descriptor.bind(domain.getBindName(), domain.getBindPassword().getPlainText(),
                                                                         obtainLDAPServers(domain), props, domain.getTlsConfiguration());

                                    try {
                                        final String domainDN = toDC(domain.getName());

                                        Attributes group = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (cn={0})(objectCategory=group))", groupname);
                                        if (group==null) {
                                            // failed to find it. Fall back to sAMAccountName.
                                            // see http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                                            // new link: https://web.archive.org/web/20090321130122/http://www.nabble.com/Re%3A-Hudson-AD-plug-in-td21428668.html
                                            LOGGER.log(Level.FINE, "Failed to find {0} in cn. Trying sAMAccountName", groupname);
                                            group = new LDAPSearchBuilder(context,domainDN).subTreeScope().searchOne("(& (sAMAccountName={0})(objectCategory=group))", groupname);

                                            // https://issues.jenkins-ci.org/browse/JENKINS-45576
                                            // Fall back to sAMAccountName for groups is causing issues with AD exchange alias.
                                            //   -> see https://technet.microsoft.com/en-us/library/cc539081.aspx
                                            // When a user login Jenkins, their groups are resolved from the CN (not the sAMAccountName). 
                                            // If one AD group have different values for CN and sAMAccountName then Jenkins will consider that group as different depending
                                            // on if you used the CN or the sAMAccountName to get the group. 
                                            // Ignoring the sAMAccountName search seems to be the best option to avoid confusion
                                            if (group!=null) {
                                                String cn = group.get("CN").get().toString();
                                                LOGGER.log(Level.WARNING, String.format("JENKINS-45576: `%s` is an Exchange alias and aliases are not currently supported. Please use the group common name `%s` instead", groupname, cn));
                                                group = null;
                                            }
                                            continue;
                                        }
                                        LOGGER.log(Level.FINE, "Found group {0} : {1}", new Object[] {groupname, group});
                                        return new ActiveDirectoryGroupDetails(groupname);
                                    } catch (NamingException e) {
                                        LOGGER.log(Level.WARNING, String.format("Failed to retrieve user information for %s", groupname), e);
                                        throw new BadCredentialsException("Failed to retrieve user information for "+ groupname, e);
                                    } finally {
                                        closeQuietly(context);
                                    }
                                } catch (NamingException e) {
                                    throw new RuntimeException(e);
                                } catch (AuthenticationException e) {
                                    // something went wrong talking to the server. This should be reported
                                    LOGGER.log(Level.WARNING, String.format("Failed to find the group %s in %s domain", groupname, domain.getName()), e);
                                } finally {
                                    Thread.currentThread().setContextClassLoader(ccl);
                                }
                            }
                            LOGGER.log(Level.WARNING, "Exhausted all configured domains and could not authenticate against any");
                            throw new UserMayOrMayNotExistException2(groupname);
                    });
        } catch (Exception e) {
            if (e instanceof AuthenticationException) {
                throw e;
            }
            LOGGER.log(Level.SEVERE, String.format("There was a problem caching group %s", groupname), e);
            throw new CacheAuthenticationException("Authentication failed because there was a problem caching group " +  groupname, e);
        }
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
     * If people type in 'foo@bar' or 'bar\foo' or just 'foo', it should be treated as
     * 'foo@bar' (where 'bar' represents the given domain name)
     */
    private String getPrincipalName(String username, String domainName) {
        String principalName;
        int slash = username.indexOf('\\');
        if (slash>0) {
            principalName = username.substring(slash+1)+'@'+domainName;
        } else if (username.contains("@"))
            principalName = username;
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
        if (userDN.contains("/")) {
            userDN = userDN.replace("/","\\/");
        }
        Set<GrantedAuthority> groups = new HashSet<>();

        LOGGER.log(Level.FINER, "Looking up group of {0}", userDN);
        Attributes id = context.getAttributes(userDN,new String[]{"tokenGroups","memberOf","CN"});
        Attribute tga = id.get("tokenGroups");

        if (tga==null) {
            // tga will be null if you are not using a global catalogue
            // or if the user is not actually a member of any security groups.
            LOGGER.log(Level.FINE, "Failed to retrieve tokenGroups for {0}", userDN);
            // keep on trucking as we can still use memberOf for Distribution Groups.
        }
        else {
            // build up the query to retrieve all the groups
            StringBuilder query = new StringBuilder("(|");
            List<byte[]> sids = new ArrayList<>();
    
            NamingEnumeration<?> tokenGroups = tga.getAll();
            while (tokenGroups.hasMore()) {
                byte[] gsid = (byte[])tokenGroups.next();
                query.append("(objectSid={"+sids.size()+"})");
                sids.add(gsid);
            }
            tokenGroups.close();
    
            query.append(")");
    
            NamingEnumeration<SearchResult> renum = new LDAPSearchBuilder(context,domainDN).subTreeScope().returns("cn").search(query.toString(), sids.toArray());
            parseMembers(userDN, groups, renum);
            renum.close();
        }
        
        {/*
                stage 2: use memberOf to find groups that aren't picked up by tokenGroups.
                This includes distribution groups
            */
            LOGGER.fine("Stage 2: looking up via memberOf");

            while (true) {
                switch (groupLookupStrategy) {
                case TOKENGROUPS:
                    // no extra lookup - ever.
                    return groups;
                case AUTO:
                    // try the accurate one first, and if it's too slow fall back to recursive in the hope that it's faster
                    long start = System.nanoTime();
                    boolean found = false;
                    long duration = 0;
                    try {
                        found = chainGroupLookup(domainDN, userDN, context, groups);
                        duration = TimeUnit.NANOSECONDS.toSeconds(System.nanoTime() - start);
                    } catch (TimeLimitExceededException e) {
                        LOGGER.log(Level.WARNING, "The LDAP request did not terminate within the specified time limit. AD will fall back to recursive lookup", e);
                    } catch (NamingException e) {
                        if (e.getMessage().contains("LDAP response read timed out")) {
                            LOGGER.log(Level.WARNING, "LDAP response read time out. AD will fall back to recursive lookup", e);
                        } else {
                            throw e;
                        }
                    }
                    if (!found && duration >= 10) {
                        LOGGER.log(Level.WARNING, "Group lookup via Active Directory's 'LDAP_MATCHING_RULE_IN_CHAIN' extension timed out after {0} seconds. Falling back to recursive group lookup strategy for this and future queries", duration);
                        groupLookupStrategy = GroupLookupStrategy.RECURSIVE;
                        continue;
                    } else if (found && duration >= 10) {
                        LOGGER.log(Level.WARNING, "Group lookup via Active Directory's 'LDAP_MATCHING_RULE_IN_CHAIN' extension matched user's groups but took {0} seconds to run. Switching to recursive lookup for future group lookup queries", duration);
                        groupLookupStrategy = GroupLookupStrategy.RECURSIVE;
                        return groups;
                    } else if (!found) {
                        LOGGER.log(Level.WARNING, "Group lookup via Active Directory's 'LDAP_MATCHING_RULE_IN_CHAIN' extension failed. Falling back to recursive group lookup strategy for this and future queries");
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
        Stack<Attributes> q = new Stack<>();
        q.push(id);
        while (!q.isEmpty()) {
            Attributes identity = q.pop();
            LOGGER.finer("Looking up group of " + identity);

            Attribute memberOf = identity.get("memberOf");
            if (memberOf == null)
                continue;

            for (int i = 0; i < memberOf.size(); i++) {
                try {
                    LOGGER.log(Level.FINE, "Trying to get the CN of {0}", memberOf.get(i));
                    Attributes group = context.getAttributes(new LdapName(memberOf.get(i).toString()), new String[]{"CN", "memberOf"});
                    Attribute cn = group.get("CN");
                    if (cn == null) {
                        LOGGER.fine("Failed to obtain CN of " + memberOf.get(i));
                        continue;
                    }
                    if (LOGGER.isLoggable(Level.FINE))
                        LOGGER.fine(cn.get() + " is a member of " + memberOf.get(i));

                    if (groups.add(new SimpleGrantedAuthority(cn.get().toString()))) {
                        q.add(group); // recursively look for groups that this group is a member of.
                    }
                } catch (NameNotFoundException e) {
                    LOGGER.fine("Failed to obtain CN of " + memberOf.get(i));
                }
            }
        }
    }

    private void parseMembers(String userDN, Set<GrantedAuthority> groups, NamingEnumeration<SearchResult> renum) throws NamingException {
        try {
            while (renum.hasMore()) {
                Attributes a = renum.next().getAttributes();
                Attribute cn = a.get("cn");
                if (LOGGER.isLoggable(Level.FINE))
                    LOGGER.fine(userDN + " is a member of " + cn);
                groups.add(new SimpleGrantedAuthority(cn.get().toString()));
            }
        } catch (PartialResultException e) {
            // See JENKINS-42687. Just log the exception. Sometimes all the groups are correctly
            // retrieved but this Exception is launched as a last element of the NamingEnumeration
            // Even if it is really a PartialResultException, I don't see why this should be a blocker
            // I think a better approach is to log the Exception and continue
            LOGGER.log(Level.WARNING, String.format("JENKINS-42687 Might be more members for user  %s", userDN), e);
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
}
