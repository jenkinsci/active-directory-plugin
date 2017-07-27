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

import com.google.common.collect.Lists;
import com.sun.jndi.ldap.LdapCtxFactory;
import com4j.typelibs.ado20.ClassFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.Functions;
import hudson.init.Terminator;
import hudson.model.AbstractDescribableImpl;
import hudson.model.AdministrativeMonitor;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.AbstractPasswordBasedSecurityRealm;
import hudson.security.AuthorizationStrategy;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.security.TokenBasedRememberMeServices2;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import hudson.util.Secret;
import hudson.util.spring.BeanBuilder;
import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.IOUtils;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.DoNotUse;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLSocketFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectStreamException;
import java.io.PrintWriter;
import java.io.Serializable;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.Util.*;
import static hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.*;

/**
 * {@link SecurityRealm} that talks to Active Directory.
 * 
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectorySecurityRealm extends AbstractPasswordBasedSecurityRealm {
    /**
     * Represent the old Active Directory Domain
     *
     * <p>
     * We need to keep this as transient in order to be able to use readResolve
     * to migrate the old descriptor to the newone.
     *
     * <p>
     * This has been deprecated since {@link ActiveDirectoryDomain}
     */
    public transient String domain;

    /**
     * Represent the old Active Directory Domain Controllers
     *
     * <p>
     * We need to keep this as transient in order to be able to use readResolve
     * to migrate the old descriptor to the newone.
     *
     * <p>
     * This has been deprecated since {@link ActiveDirectoryDomain}
     */
    public transient String server;

    /**
     * List of {@link ActiveDirectoryDomain}
     *
     */
    public List<ActiveDirectoryDomain> domains;

    /**
     * Active directory site (which specifies the physical concentration of the
     * servers), if any. If the value is non-null, we'll only contact servers in
     * this site.
     * 
     * <p>
     * On Windows, I'm assuming ADSI takes care of everything automatically.
     *
     * <p>
     * We need to keep this as transient in order to be able to use readResolve
     * to migrate the old descriptor to the newone.
     */
    public transient final String site;

    /**
     * Represent the old bindName
     *
     * <p>
     * We need to keep this as transient in order to be able to use readResolve
     * to migrate the old descriptor to the new one.
     *
     * <p>
     * This has been deprecated @since Jenkins 2.1
     */
    public transient String bindName;

    /**
     * Represent the old bindPassword
     *
     * <p>
     * We need to keep this as transient in order to be able to use readResolve
     * to migrate the old descriptor to the new one.
     *
     * <p>
     * This has been deprecated @since Jenkins 2.1
     */
    public transient Secret bindPassword;

    /**
     * If true enable startTls in case plain communication is used. In case the plugin
     * is configured to use TLS then this option will not have any impact.
     */
    public Boolean startTls;

    private GroupLookupStrategy groupLookupStrategy;

    /**
     * If true, Jenkins ignores Active Directory groups that are not being used by the active Authorization Strategy.
     * This can significantly improve performance in environments with a large number of groups
     * but a small number of corresponding rules defined by the Authorization Strategy.
     * Groups are considered as used if they are returned by {@link AuthorizationStrategy#getGroups()}.
     */
    public final boolean removeIrrelevantGroups;

    /**
     *  Cache of the Active Directory plugin
     */
    protected CacheConfiguration cache;

    /**
     *  Ldap extra properties
     */
    protected List<EnvironmentProperty> environmentProperties;

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
    protected TlsConfiguration tlsConfiguration;

    /**
     *  The Jenkins internal user to fall back in case f {@link NamingException}
     */
    protected ActiveDirectoryInternalUsersDatabase internalUsersDatabase;

    /**
     * The threadPool to update the cache on background
     */
    protected transient ExecutorService threadPoolExecutor;

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName, String bindPassword, String server) {
        this(domain, site, bindName, bindPassword, server, GroupLookupStrategy.AUTO, false);
    }

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName, String bindPassword, String server, GroupLookupStrategy groupLookupStrategy) {
        this(domain,site,bindName,bindPassword,server,groupLookupStrategy,false);
    }

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups) {
        this(domain, site, bindName, bindPassword, server, groupLookupStrategy, removeIrrelevantGroups, null);
    }

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, CacheConfiguration cache) {
        this(domain, Lists.newArrayList(new ActiveDirectoryDomain(domain, server)), site, bindName, bindPassword, server, groupLookupStrategy, removeIrrelevantGroups, domain!=null, cache, true);
    }

    public ActiveDirectorySecurityRealm(String domain, List<ActiveDirectoryDomain> domains, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain, CacheConfiguration cache, Boolean startTls) {
        this(domain, domains, site, bindName, bindPassword, server, groupLookupStrategy, removeIrrelevantGroups, customDomain, cache, startTls, TlsConfiguration.TRUST_ALL_CERTIFICATES);
    }

    public ActiveDirectorySecurityRealm(String domain, List<ActiveDirectoryDomain> domains, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain, CacheConfiguration cache, Boolean startTls, TlsConfiguration tlsConfiguration) {
        this(domain, domains, site, bindName, bindPassword, server, groupLookupStrategy, removeIrrelevantGroups, customDomain, cache, startTls, tlsConfiguration, null);
    }

    @DataBoundConstructor
    // as Java signature, this binding doesn't make sense, so please don't use this constructor
    public ActiveDirectorySecurityRealm(String domain, List<ActiveDirectoryDomain> domains, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain, CacheConfiguration cache, Boolean startTls, TlsConfiguration tlsConfiguration, ActiveDirectoryInternalUsersDatabase internalUsersDatabase) {
        if (customDomain!=null && !customDomain)
            domains = null;
        this.domain = fixEmpty(domain);
        this.server = fixEmpty(server);
        this.domains = domains;
        this.site = fixEmpty(site);
        this.bindName = fixEmpty(bindName);
        this.bindPassword = Secret.fromString(fixEmpty(bindPassword));
        this.groupLookupStrategy = groupLookupStrategy;
        this.removeIrrelevantGroups = removeIrrelevantGroups;
        this.cache = cache;
        this.tlsConfiguration = tlsConfiguration;
        this.startTls = startTls;
        this.internalUsersDatabase = internalUsersDatabase;
    }

    @DataBoundSetter
    public void setEnvironmentProperties(List<EnvironmentProperty> environmentProperties) {
        this.environmentProperties = environmentProperties;
    }

    @Restricted(NoExternalUse.class)
    public CacheConfiguration getCache() {
        if (cache != null && (cache.getSize() == 0 || cache.getTtl() == 0)) {
            return null;
        }
        return cache;
    }

    @Restricted(NoExternalUse.class)
    public String getJenkinsInternalUser() {
        return internalUsersDatabase == null ? null : internalUsersDatabase.getJenkinsInternalUser();
    }

    @Restricted(NoExternalUse.class)
    public ActiveDirectoryInternalUsersDatabase getInternalUsersDatabase() {
        return internalUsersDatabase != null && internalUsersDatabase.getJenkinsInternalUser() != null && internalUsersDatabase.getJenkinsInternalUser().isEmpty() ? null : internalUsersDatabase;
    }

    @Restricted(NoExternalUse.class)
    public Boolean isStartTls() {
        return startTls;
    }

    public Integer getSize() {
        return cache == null ? null : cache.getSize();
    }

    public Integer getTtl() {
        return cache == null ? null : cache.getTtl();
    }

    // for jelly use only
    @Restricted(NoExternalUse.class)
    public List<EnvironmentProperty> getEnvironmentProperties() {
        return environmentProperties;
    }

    public GroupLookupStrategy getGroupLookupStrategy() {
        if (groupLookupStrategy==null)      return GroupLookupStrategy.AUTO;
        return groupLookupStrategy;
    }

    // for jelly use only
    @Restricted(NoExternalUse.class)
    public TlsConfiguration getTlsConfiguration() {
        return tlsConfiguration;
    }

    public SecurityComponents createSecurityComponents() {
        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
        Binding binding = new Binding();
        binding.setVariable("realm", this);
        InputStream i = getClass().getResourceAsStream("ActiveDirectory.groovy");
        try {
            builder.parse(i, binding);
        } finally {
            IOUtils.closeQuietly(i);
        }
        WebApplicationContext context = builder.createApplicationContext();

        //final AbstractActiveDirectoryAuthenticationProvider adp = findBean(AbstractActiveDirectoryAuthenticationProvider.class, context);
        findBean(AbstractActiveDirectoryAuthenticationProvider.class, context); //Keeping the call because there might be side effects?
        final UserDetailsService uds = findBean(UserDetailsService.class, context);

        TokenBasedRememberMeServices2 rms = new TokenBasedRememberMeServices2() {
            public Authentication autoLogin(HttpServletRequest request, HttpServletResponse response) {
                try {
                    return super.autoLogin(request, response);
                } catch (Exception e) {// TODO: this check is made redundant with 1.556, but needed with earlier versions
                    cancelCookie(request, response, "Failed to handle remember-me cookie: "+Functions.printThrowable(e));
                    return null;
                }
            }
        };
        rms.setUserDetailsService(uds);
        rms.setKey(Hudson.getInstance().getSecretKey());
        rms.setParameter("remember_me"); // this is the form field name in login.jelly

        return new SecurityComponents( findBean(AuthenticationManager.class, context), uds, rms);
    }

    @Restricted(NoExternalUse.class)
    public List<ActiveDirectoryDomain> getDomains() {
        return domains;
    }

    public Object readResolve() throws ObjectStreamException {
        if (domain != null) {
            this.domains = new ArrayList<ActiveDirectoryDomain>();
            domain = domain.trim();
            String[] oldDomains = domain.split(",");
            for (String oldDomain : oldDomains) {
                oldDomain = oldDomain.trim();
                this.domains.add(new ActiveDirectoryDomain(oldDomain, server));
            }
        }
        List <ActiveDirectoryDomain> activeDirectoryDomains = this.getDomains();
        // JENKINS-14281 On Windows domain can be indeed null
        if (activeDirectoryDomains!= null) {
            // JENKINS-39375 Support a different bindUser per domain
            if (bindName != null && bindPassword != null) {
                for (ActiveDirectoryDomain activeDirectoryDomain : activeDirectoryDomains) {
                    activeDirectoryDomain.bindName = bindName;
                    activeDirectoryDomain.bindPassword = bindPassword;
                }
            }
            // JENKINS-39423 Make site independent of each domain
            if (site != null) {
                for (ActiveDirectoryDomain activeDirectoryDomain : activeDirectoryDomains) {
                    activeDirectoryDomain.site = site;
                }
            }
        }
        if (startTls == null) {
            this.startTls = true;
        }

        return this;
    }

    @Override
    public DescriptorImpl getDescriptor() {
        return (DescriptorImpl) super.getDescriptor();
    }

    /**
     * Authentication test.
     */
    public void doAuthTest(StaplerRequest req, StaplerResponse rsp, @QueryParameter String username, @QueryParameter String password) throws IOException, ServletException {
        // require the administrator permission since this is full of debug info.
        Hudson.getInstance().checkPermission(Hudson.ADMINISTER);

        StringWriter out = new StringWriter();
        PrintWriter pw = new PrintWriter(out);

        ClassLoader ccl = Thread.currentThread().getContextClassLoader();
        Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
        try {
            UserDetailsService uds = getAuthenticationProvider();
            if (uds instanceof ActiveDirectoryUnixAuthenticationProvider) {
                ActiveDirectoryUnixAuthenticationProvider p = (ActiveDirectoryUnixAuthenticationProvider) uds;
                DescriptorImpl descriptor = getDescriptor();

                for (ActiveDirectoryDomain domain : domains) {
	                try {
	                    pw.println("Domain= " + domain.getName() + " site= "+ domain.getSite());
	                    List<SocketInfo> ldapServers = descriptor.obtainLDAPServer(domain);
	                    pw.println("List of domain controllers: "+ldapServers);
	                    
	                    for (SocketInfo ldapServer : ldapServers) {
	                        pw.println("Trying a domain controller at "+ldapServer);
	                        try {
	                            UserDetails d = p.retrieveUser(username, password, domain, Collections.singletonList(ldapServer));
	                            pw.println("Authenticated as "+d);
	                        } catch (AuthenticationException e) {
	                            e.printStackTrace(pw);
	                        }
	                    }
	                } catch (NamingException e) {
	                    pw.println("Failing to resolve domain controllers");
	                    e.printStackTrace(pw);
	                }
                }
            } else {
                pw.println("Using Windows ADSI. No diagnostics available.");
            }
        } catch (Exception e) {
            e.printStackTrace(pw);
        } finally {
            Thread.currentThread().setContextClassLoader(ccl);
        }

        req.setAttribute("output", out.toString());
        req.getView(this, "test.jelly").forward(req, rsp);
    }

    @Restricted(DoNotUse.class)
    public void shutDownthreadPoolExecutors() {
        threadPoolExecutor.shutdown();
    }

    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return Messages.DisplayName();
        }

        @Override
        public String getHelpFile() {
            return "/plugin/active-directory/help/realm.html";
        }

        /**
         * If true, we can do ADSI/COM based look up that's far more reliable.
         * False if we need to do the authentication in pure Java via
         * {@link ActiveDirectoryUnixAuthenticationProvider}
         */
        public boolean canDoNativeAuth() {
            if (!Functions.isWindows())     return false;

            try {
                ClassFactory.createConnection().dispose();
                return true;
            } catch (Throwable t) {
                if (!WARNED) {
                    LOGGER.log(Level.INFO,"COM4J isn't working. Falling back to non-native authentication",t);
                    WARNED = true;
                }
                return false;
            }
        }

        public ListBoxModel doFillSizeItems() {
            ListBoxModel listBoxModel = new ListBoxModel();
            listBoxModel.add("10 elements", "10");
            listBoxModel.add("20 elements", "20");
            listBoxModel.add("50 elements", "50");
            listBoxModel.add("100 elements", "100");
            listBoxModel.add("200 elements", "200");
            listBoxModel.add("256 elements", "256");
            listBoxModel.add("500 elements", "500");
            listBoxModel.add("1000 elements", "1000");
            return listBoxModel;
        }

        public ListBoxModel doFillTtlItems() {
            ListBoxModel listBoxModel = new ListBoxModel();
            listBoxModel.add("30 sec", "30");
            listBoxModel.add("1 min", "60");
            listBoxModel.add("5 min", "300");
            listBoxModel.add("10 min", "600");
            listBoxModel.add("15 min", "900");
            listBoxModel.add("30 min", "1800");
            listBoxModel.add("1 hour", "3600");

            return listBoxModel;
        }

        public ListBoxModel doFillGroupLookupStrategyItems() {
            ListBoxModel model = new ListBoxModel();
            for (GroupLookupStrategy e : GroupLookupStrategy.values()) {
                model.add(e.getDisplayName(),e.name());
            }
            return model;
        }

        public ListBoxModel doFillTlsConfigurationItems() {
            ListBoxModel model = new ListBoxModel();
            for (TlsConfiguration tlsConfiguration : TlsConfiguration.values()) {
                model.add(tlsConfiguration.getDisplayName(),tlsConfiguration.name());
            }
            return model;
        }

        private boolean isTrustAllCertificatesEnabled(TlsConfiguration tlsConfiguration) {
            return (tlsConfiguration == null || TlsConfiguration.TRUST_ALL_CERTIFICATES.equals(tlsConfiguration));
        }

        private static boolean WARNED = false;

        @Deprecated
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers, Hashtable<String, String> props) throws NamingException {
            return bind(principalName, password, ldapServers, props, null);
        }

        /**
         * Binds to the server using the specified username/password.
         * <p>
         * In a real deployment, often there are servers that don't respond or
         * otherwise broken, so try all the servers.
         */
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers, Hashtable<String, String> props, TlsConfiguration tlsConfiguration) throws NamingException {
            // in a AD forest, it'd be mighty nice to be able to login as "joe"
            // as opposed to "joe@europe",
            // but the bind operation doesn't appear to allow me to do so.
            Hashtable<String, String> newProps = new Hashtable<String, String>();

            // Sometimes might be useful to ignore referral. Use this System property is under the user risk
            Boolean ignoreReferrals = Boolean.valueOf(System.getProperty("hudson.plugins.active_directory.referral.ignore", "false"));

            if (!ignoreReferrals) {
                newProps.put(Context.REFERRAL, "follow");
            } else {
                newProps.put(Context.REFERRAL, "ignore");
            }

            newProps.put("java.naming.ldap.attributes.binary","tokenGroups objectSid");

            if (FORCE_LDAPS && isTrustAllCertificatesEnabled(tlsConfiguration)) {
                newProps.put("java.naming.ldap.factory.socket", TrustAllSocketFactory.class.getName());
            }

            newProps.putAll(props);
            NamingException namingException = null;

            for (SocketInfo ldapServer : ldapServers) {
                try {
                    LdapContext context = bind(principalName, password, ldapServer, newProps);
                    LOGGER.fine("Bound to " + ldapServer);
                    return context;
                } catch (javax.naming.AuthenticationException e) {
                    // if the authentication failed (as opposed to a communication problem with the server),
                    // don't retry, because if this is because of a wrong password, we can end up locking
                    // the user out by causing multiple failed attempts.
                    // error code 49 (LdapClient.LDAP_INVALID_CREDENTIALS) maps to this exception in LdapCtx.mapErrorCode
                    // see http://confluence.atlassian.com/display/CONFKB/LDAP+Error+Code+49 and http://www-01.ibm.com/support/docview.wss?uid=swg21290631
                    // for subcodes within this error.
                    // it seems like we can be clever about checking subcode to decide if we retry or not,
                    // but I'm erring on the safe side as I'm not sure how reliable the code is, and maybe
                    // servers can be configured to hide the distinction between "no such user" and "bad password"
                    // to reveal what user names are available.
                    LOGGER.log(Level.WARNING, "Failed to authenticate while binding to "+ldapServer, e);
                    throw new BadCredentialsException("Either no such user '" + principalName + "' or incorrect password", namingException);
                } catch (NamingException e) {
                    LOGGER.log(Level.WARNING, "Failed to bind to "+ldapServer, e);
                    namingException = e; // retry
                }
            }
            // if all the attempts failed
            LOGGER.log(Level.WARNING, "All attempts to login failed for user {0}", principalName);
            throw namingException;
        }

        /**
         * Binds to the server using the specified username/password.
         * <p>
         * In a real deployment, often there are servers that don't respond or
         * otherwise broken, so try all the servers.
         */
        @Deprecated
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers) throws NamingException {
            return bind(principalName, password, ldapServers, new Hashtable<String, String>());
        }

        private void customizeLdapProperty(Hashtable<String, String> props, String propName) {
            String prop = System.getProperty(propName, null);
            if (prop != null) {
                props.put(propName, prop);
            }
        }
        
        /** Lookups for hardcoded LDAP properties if they are specified as System properties and uses them */
        private void customizeLdapProperties(Hashtable<String, String> props) {
             customizeLdapProperty(props, "com.sun.jndi.ldap.connect.timeout");
             customizeLdapProperty(props, "com.sun.jndi.ldap.read.timeout");
        }

        @IgnoreJRERequirement
        @Deprecated
        private LdapContext bind(String principalName, String password, SocketInfo server, Hashtable<String, String> props) throws NamingException {
            return bind(principalName, password, server, props, null);
        }

        @IgnoreJRERequirement
        private LdapContext bind(String principalName, String password, SocketInfo server, Hashtable<String, String> props, TlsConfiguration tlsConfiguration) throws NamingException {
            String ldapUrl = (FORCE_LDAPS?"ldaps://":"ldap://") + server + '/';
            String oldName = Thread.currentThread().getName();
            Thread.currentThread().setName("Connecting to "+ldapUrl+" : "+oldName);
            LOGGER.fine("Connecting to " + ldapUrl);
            try {
                props.put(Context.PROVIDER_URL, ldapUrl);
                props.put("java.naming.ldap.version", "3");
                
                customizeLdapProperties(props);
                
                LdapContext context = (LdapContext)LdapCtxFactory.getLdapCtxInstance(ldapUrl, props);

                boolean isStartTls = true;
                SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
                if (securityRealm instanceof ActiveDirectorySecurityRealm) {
                    ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
                     isStartTls= activeDirectorySecurityRealm.isStartTls();
                }

                if (!FORCE_LDAPS && isStartTls) {
                    // try to upgrade to TLS if we can, but failing to do so isn't fatal
                    // see http://download.oracle.com/javase/jndi/tutorial/ldap/ext/starttls.html
                    try {
                        StartTlsResponse rsp = (StartTlsResponse)context.extendedOperation(new StartTlsRequest());
                        if (isTrustAllCertificatesEnabled(tlsConfiguration)) {
                            rsp.negotiate((SSLSocketFactory)TrustAllSocketFactory.getDefault());
                        } else {
                            rsp.negotiate();
                        }
                        LOGGER.fine("Connection upgraded to TLS");
                    } catch (NamingException e) {
                        LOGGER.log(Level.FINE, "Failed to start TLS. Authentication will be done via plain-text LDAP", e);
                    } catch (IOException e) {
                        LOGGER.log(Level.FINE, "Failed to start TLS. Authentication will be done via plain-text LDAP", e);
                    }
                }

                if (principalName==null || password==null || password.equals("")) {
                    // anonymous bind. LDAP uses empty password as a signal to anonymous bind (RFC 2829 5.1),
                    // which means it can never be the actual user password.
                    context.addToEnvironment(Context.SECURITY_AUTHENTICATION, "none");
                    LOGGER.fine("Binding anonymously to "+ldapUrl);
                } else {
                    // authenticate after upgrading to TLS, so that the credential won't go in clear text
                    context.addToEnvironment(Context.SECURITY_PRINCIPAL, principalName);
                    context.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
                    LOGGER.fine("Binding as "+principalName+" to "+ldapUrl);
                }

                // this is supposed to cause the LDAP bind operation with the server,
                // but I notice that AD may still accept this and yet fail to search later,
                // when I tried anonymous bind.
                // if I do specify a wrong credential, this seems to fail.
                context.reconnect(null);

                return context; // worked
            } finally {
                Thread.currentThread().setName(oldName);
            }
        }

        /**
         * Creates {@link DirContext} for accesssing DNS.
         */
        public DirContext createDNSLookupContext() throws NamingException {
            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            env.put("java.naming.provider.url", "dns:");
            return new InitialDirContext(env);
        }

        @Deprecated
        public List<SocketInfo> obtainLDAPServer(String domainName, String site, String preferredServer) throws NamingException {
            return obtainLDAPServer(createDNSLookupContext(), domainName, site, preferredServer);
        }

        public List<SocketInfo> obtainLDAPServer(ActiveDirectoryDomain activeDirectoryDomain) throws NamingException {
            return obtainLDAPServer(createDNSLookupContext(), activeDirectoryDomain.getName(), activeDirectoryDomain.getSite(), activeDirectoryDomain.getServers());
        }

        /**
         * Use DNS and obtains the LDAP servers that we should try.
         *
         * @param preferredServers
         *      If non-null, these servers are reported instead of doing the discovery.
         *      In previous versions, this was simply added on top of the auto-discovered list, but this option
         *      is useful when you have many domain controllers (because a single mistyped password can cause
         *      an authentication attempt with every listed server, which can lock the user out!) This also
         *      puts this feature in alignment with {@link #DOMAIN_CONTROLLERS}, which seems to indicate that
         *      there are users who prefer this behaviour.
         *
         * @return A list with at least one item.
         */
        public List<SocketInfo> obtainLDAPServer(DirContext ictx, String domainName, String site, String preferredServers) throws NamingException {
            List<SocketInfo> result = new ArrayList<SocketInfo>();
            if (preferredServers==null || preferredServers.isEmpty())
                preferredServers = DOMAIN_CONTROLLERS;

            if (preferredServers!=null) {
                for (String token : preferredServers.split(",")) {
                    result.add(new SocketInfo(token.trim()));
                }
                return result;
            }


            String ldapServer = null;
            Attribute a = null;
            NamingException failure = null;

            // try global catalog if it exists first, then the particular domain
            for (ActiveDirectoryDomain.Catalog catalog : ActiveDirectoryDomain.Catalog.values()) {
                ldapServer = catalog + (site!=null ? site + "._sites." : "") + domainName;
                LOGGER.fine("Attempting to resolve " + ldapServer + " to SRV record");
                try {
                    Attributes attributes = ictx.getAttributes(ldapServer, new String[] { "SRV" });
                    a = attributes.get("SRV");
                    if (a!=null)
                        break;
                } catch (NamingException e) {
                    // failed retrieval. try next option.
                    failure = e;
                } catch (NumberFormatException x) {
                    failure = (NamingException) new NamingException("JDK IPv6 bug encountered").initCause(x);
                }
            }

            if (a!=null) {
                // discover servers
                class PrioritizedSocketInfo implements Comparable<PrioritizedSocketInfo> {
                    SocketInfo socket;
                    int priority;

                    PrioritizedSocketInfo(SocketInfo socket, int priority) {
                        this.socket = socket;
                        this.priority = priority;
                    }

                    @SuppressFBWarnings(value = "EQ_COMPARETO_USE_OBJECT_EQUALS", justification = "Weird and unpredictable behaviour intentional for load balancing.")
                    public int compareTo(PrioritizedSocketInfo that) {
                        return that.priority - this.priority; // sort them so that bigger priority comes first
                    }
                }
                List<PrioritizedSocketInfo> plist = new ArrayList<PrioritizedSocketInfo>();
                for (NamingEnumeration ne = a.getAll(); ne.hasMoreElements();) {
                    String record = ne.next().toString();
                    LOGGER.fine("SRV record found: "+record);
                    String[] fields = record.split(" ");
                    // fields[1]: weight
                    // fields[2]: port
                    // fields[3]: target host name

                    String hostName = fields[3];
                    // cut off trailing ".". JENKINS-2647
                    if (hostName.endsWith("."))
                        hostName = hostName.substring(0, hostName.length()-1);
                    int port = Integer.parseInt(fields[2]);
                    if (FORCE_LDAPS) {
                        // map to LDAPS ports. I don't think there's any SRV records specifically for LDAPS.
                        // I think Microsoft considers LDAP+TLS the way to go, or else there should have been
                        // separate SRV entries.
                        if (port==389)  port=636;
                        if (port==3268) port=3269;
                    }
                    int p = Integer.parseInt(fields[0]);
                    plist.add(new PrioritizedSocketInfo(new SocketInfo(hostName, port),p));
                }
                Collections.sort(plist);
                for (PrioritizedSocketInfo psi : plist)
                    result.add(psi.socket);
            }

            if (result.isEmpty()) {
                NamingException x = new NamingException("No SRV record found for " + ldapServer);
                if (failure!=null)  x.initCause(failure);
                throw x;
            }

            LOGGER.fine(ldapServer + " resolved to " + result);
            return result;
        }
    }

    @Override
    public GroupDetails loadGroupByGroupname(String groupname) throws UsernameNotFoundException, DataAccessException {
        return getAuthenticationProvider().loadGroupByGroupname(groupname);
    }

    /**
     * Interface that actually talks to Active Directory.
     */
    public AbstractActiveDirectoryAuthenticationProvider getAuthenticationProvider() {
        return (AbstractActiveDirectoryAuthenticationProvider)getSecurityComponents().userDetails;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        // delegate to one of our ActiveDirectory(Unix)?AuthenticationProvider
        return getAuthenticationProvider().loadUserByUsername(username);
    }

    @Override
    protected UserDetails authenticate(String username, String password) throws AuthenticationException {
        return getAuthenticationProvider().retrieveUser(username,new UsernamePasswordAuthenticationToken(username,password));
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectorySecurityRealm.class.getName());

    /**
     * If non-null, this value specifies the domain controllers and overrides all the lookups.
     *
     * The format is "host:port,host:port,..."
     *
     * @deprecated as of 1.28
     *      Use the UI field.
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "Diagnostic fields are left mutable so that groovy console can be used to dynamically turn/off probes.")
    public static String DOMAIN_CONTROLLERS = System.getProperty(ActiveDirectorySecurityRealm.class.getName()+".domainControllers");

    /**
     * Instead of LDAP+TLS upgrade, start right away with LDAPS.
     * For the time being I'm trying not to expose this to users. I don't see why any AD shouldn't support
     * TLS upgrade if it's got the certificate.
     *
     * One legitimate use case is when the domain controller is Windows 2000, which doesn't support TLS
     * (according to http://support.microsoft.com/kb/321051).
     */
    @SuppressFBWarnings(value = "MS_SHOULD_BE_FINAL", justification = "Diagnostic fields are left mutable so that groovy console can be used to dynamically turn/off probes.")
    public static boolean FORCE_LDAPS = Boolean.getBoolean(ActiveDirectorySecurityRealm.class.getName()+".forceLdaps");

    /**
     * Store all the extra environment variable to be used on the LDAP Context
     */
    public static class EnvironmentProperty extends AbstractDescribableImpl<EnvironmentProperty> implements Serializable {
        private final String name;
        private final String value;

        @DataBoundConstructor
        public EnvironmentProperty(String name, String value) {
            this.name = name;
            this.value = value;
        }

        public String getName() {
            return name;
        }

        public String getValue() {
            return value;
        }

        public static Map<String,String> toMap(List<EnvironmentProperty> properties) {
            final Map<String, String> result = new LinkedHashMap<String, String>();
            if (properties != null) {
                for (EnvironmentProperty property:properties) {
                    result.put(property.getName(), property.getValue());
                }
                return result;
            }
            return result;
        }

        @Extension
        public static class DescriptorImpl extends Descriptor<EnvironmentProperty> {

            @Override
            public String getDisplayName() {
                return null;
            }
        }
    }

    @Extension
    public final static TlsConfigurationAdministrativeMonitor NOTICE = new TlsConfigurationAdministrativeMonitor();

    /**
     * Administrative Monitor for changing TLS certificates management
     */
    public static final class TlsConfigurationAdministrativeMonitor extends AdministrativeMonitor {

        public boolean isActivated() {
                SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
                if (securityRealm instanceof ActiveDirectorySecurityRealm) {
                    ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
                    if (activeDirectorySecurityRealm.tlsConfiguration == null) {
                        return true;
                    }
                }

            return false;
        }

        /**
         * Depending on whether the user said "dismiss" or "correct", send him to the right place.
         */
        public void doAct(StaplerRequest req, StaplerResponse rsp) throws IOException {
            if(req.hasParameter("correct")) {
                rsp.sendRedirect(req.getRootPath()+"/configureSecurity");

            }
        }

        public static TlsConfigurationAdministrativeMonitor get() {
            return AdministrativeMonitor.all().get(TlsConfigurationAdministrativeMonitor.class);
        }
    }

}
