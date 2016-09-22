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

import com.sun.jndi.ldap.LdapCtxFactory;
import com4j.typelibs.ado20.ClassFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.Functions;
import hudson.Util;
import hudson.model.AbstractDescribableImpl;
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
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.codehaus.mojo.animal_sniffer.IgnoreJRERequirement;
import org.kohsuke.accmod.Restricted;
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
     * Active directory domain name to authenticate against.
     * 
     * <p>
     * When this plugin is used on Windows, this field is null, and we use ADSI
     * and ADO through com4j to perform authentication.
     * 
     * <p>
     * OTOH, when this plugin runs on non-Windows, this field must be non-null,
     * and we'll use LDAP for authentication.
     */
    public final String domain;

    /**
     * Active directory site (which specifies the physical concentration of the
     * servers), if any. If the value is non-null, we'll only contact servers in
     * this site.
     * 
     * <p>
     * On Windows, I'm assuming ADSI takes care of everything automatically.
     */
    public final String site;

    /**
     * If non-null, use this name and password to bind to LDAP to obtain the DN
     * of the user trying to login. This is unnecessary in a single-domain mode,
     * where we can just bind with the user name and password provided during
     * the login, but in a forest mode, without some known credential, we cannot
     * figure out which domain in the forest the user belongs to.
     */
    public final String bindName;

    public final Secret bindPassword;

    /**
     * If non-null, Jenkins will try to connect at this server at the first priority, before falling back to
     * discovered DNS servers.
     */
    public final String server;

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

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName, String bindPassword, String server) {
        this(domain, site, bindName, bindPassword, server, GroupLookupStrategy.AUTO, false);
    }

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName, String bindPassword, String server, GroupLookupStrategy groupLookupStrategy) {
        this(domain,site,bindName,bindPassword,server,groupLookupStrategy,false);
    }

    public ActiveDirectorySecurityRealm(String domain, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups) {
        this(domain,site,bindName,bindPassword,server,groupLookupStrategy,removeIrrelevantGroups,domain!=null, null);
    }
    
    @DataBoundConstructor
    // as Java signature, this binding doesn't make sense, so please don't use this constructor
    public ActiveDirectorySecurityRealm(String domain, String site, String bindName,
                                        String bindPassword, String server, GroupLookupStrategy groupLookupStrategy, boolean removeIrrelevantGroups, Boolean customDomain, CacheConfiguration cache) {
        if (customDomain!=null && !customDomain)
            domain = null;
        this.domain = fixEmpty(domain);
        this.site = fixEmpty(site);
        this.bindName = fixEmpty(bindName);
        this.bindPassword = Secret.fromString(fixEmpty(bindPassword));
        this.groupLookupStrategy = groupLookupStrategy;
        this.removeIrrelevantGroups = removeIrrelevantGroups;

        // append default port if not specified
        server = fixEmpty(server);
        if (server != null) {
            String[] servers = server.split(",");
            for (int i = 0; i < servers.length; i++) {
                if (!servers[i].contains(":")) {
                    servers[i] += ":3268";
                }
            }
            server = StringUtils.join(servers, ",");
        }

        this.server = server;
        this.cache = cache;
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

                for (String domainName : domain.split(",")) {
	                try {
	                    pw.println("Domain="+domainName+" site="+site);
	                    List<SocketInfo> ldapServers = descriptor.obtainLDAPServer(domainName, site, server);
	                    pw.println("List of domain controllers: "+ldapServers);
	                    
	                    for (SocketInfo ldapServer : ldapServers) {
	                        pw.println("Trying a domain controller at "+ldapServer);
	                        try {
	                            UserDetails d = p.retrieveUser(username, password, domainName, Collections.singletonList(ldapServer));
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

        private static boolean WARNED = false;

        public FormValidation doValidate(@QueryParameter(fixEmpty = true) String domain, @QueryParameter(fixEmpty = true) String site, @QueryParameter(fixEmpty = true) String bindName,
                @QueryParameter(fixEmpty = true) String bindPassword, @QueryParameter(fixEmpty = true) String server) throws IOException, ServletException, NamingException {
            String [] domains = domain.split(",");
            String[] DnItems = {"CN=", "DC=", "OU="};
            if (domains.length > 1 ) {
                for (String dnItem : DnItems) {
                    if (bindName.contains(dnItem)) {
                        return FormValidation.error("Use multiple domains require the bindName to be expressed with the displayName");
                    }
                }
            }
            ClassLoader ccl = Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            try {
                Functions.checkPermission(Hudson.ADMINISTER);
                domain = Util.fixEmptyAndTrim(domain);

                if (canDoNativeAuth() && domain==null) {
                    // this check must be identical to that of ActiveDirectory.groovy
                    try {
                        // make sure we can connect via ADSI
                        new ActiveDirectoryAuthenticationProvider();
                        return FormValidation.ok("OK");
                    } catch (Exception e) {
                        return FormValidation.error(e, "Failed to contact Active Directory");
                    }
                }

                if (domain==null) {// no value given yet
                    return FormValidation.error("No domain name set");
                }

                Secret password = Secret.fromString(bindPassword);
                if (bindName!=null && password==null)
                    return FormValidation.error("DN is specified but not password");

                String[] names = domain.split(",");
                for (String name : names) {
                    name = name.trim();
                    if (!name.endsWith("."))
                        name += '.';

                    DirContext ictx;

                    // first test the sanity of the domain name itself
                    try {
                        LOGGER.fine("Attempting to resolve "+name+" to NS record");
                        ictx = createDNSLookupContext();
                        Attributes attributes = ictx.getAttributes(name, new String[] { "NS" });
                        Attribute ns = attributes.get("NS");
                        if (ns==null) {
                            LOGGER.fine("Attempting to resolve "+name+" to A record");
                            attributes = ictx.getAttributes(name, new String[] { "A" });
                            Attribute a = attributes.get("A");
                            if (a==null)
                                throw new NamingException(name+" doesn't look like a domain name");
                        }
                        LOGGER.log(Level.FINE, "{0} resolved to {1}", new Object[] {name, ns});
                    } catch (NamingException e) {
                        LOGGER.log(Level.WARNING, "Failed to resolve "+name+" to A record", e);
                        return FormValidation.error(e, name+" doesn't look like a valid domain name");
                    }

                    // then look for the LDAP server
                    List<SocketInfo> servers;
                    try {
                        servers = obtainLDAPServer(ictx, name, site, server);
                    } catch (NamingException e) {
                        String msg = site==null ? "No LDAP server was found in "+name : "No LDAP server was found in the "+site+" site of "+name;
                        LOGGER.log(Level.WARNING, msg, e);
                        return FormValidation.error(e, msg);
                    }

                    if (bindName!=null) {
                        // make sure the bind actually works
                        try {
                            DirContext context = bind(bindName, Secret.toString(password), servers);
                            try {
                                // actually do a search to make sure the credential is valid
                                Attributes userAttributes = new LDAPSearchBuilder(context, toDC(name)).subTreeScope().searchOne("(objectClass=user)");
                                if (userAttributes == null) {
                                    return FormValidation.error(Messages.ActiveDirectorySecurityRealm_NoUsers());
                                }
                            } finally {
                                context.close();
                            }
                        } catch (BadCredentialsException e) {
                            return FormValidation.error(e, "Bad bind username or password");
                        } catch (javax.naming.AuthenticationException e) {
                            return FormValidation.error(e, "Bad bind username or password");
                        } catch (Exception e) {
                            return FormValidation.error(e, e.getMessage());
                        }
                    } else {
                        // just some connection test
                        // try to connect to LDAP port to make sure this machine has LDAP service
                        IOException error = null;
                        for (SocketInfo si : servers) {
                            try {
                                si.connect().close();
                                break; // looks good
                            } catch (IOException e) {
                                LOGGER.log(Level.FINE, "Failed to connect to "+si, e);
                                error = e;
                                // try the next server in the list
                            }
                        }
                        if (error!=null) {
                            LOGGER.log(Level.WARNING, "Failed to connect to "+servers, error);
                            return FormValidation.error(error, "Failed to connect to "+servers);
                        }
                    }
                }

                // looks good
                return FormValidation.ok("Success");
            } finally {
                Thread.currentThread().setContextClassLoader(ccl);
            }
        }

        public FormValidation doCheckBindName(@QueryParameter String domain, @QueryParameter String bindName) {
            String [] domains = domain.split(",");
            String[] DnItems = {"CN=", "DC=", "OU="};
            if (domains.length > 1 ) {
                for (String dnItem : DnItems) {
                    if (bindName.contains(dnItem)) {
                        return FormValidation.warning("Please, use the displayName");
                    }
                }
            }
            return FormValidation.ok();
        }

        @Deprecated
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers, Hashtable<String, String> props) {
        return bind(principalName, password, false, ldapServers, props);
        }

            /**
             * Binds to the server using the specified username/password.
             * <p>
             * In a real deployment, often there are servers that don't respond or
             * otherwise broken, so try all the servers.
             */
        public DirContext bind(String principalName, String password, boolean hasDefinedLdapServers, List<SocketInfo> ldapServers, Hashtable<String, String> props) {
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
            newProps.put("java.naming.ldap.factory.socket",TrustAllSocketFactory.class.getName());
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
                    if (!hasDefinedLdapServers) {
                        throw new BadCredentialsException("Either no such user '" + principalName + "' or incorrect password", namingException);
                    } else {
                        namingException = e; // retry
                    }
                } catch (NamingException e) {
                    LOGGER.log(Level.WARNING, "Failed to bind to "+ldapServer, e);
                    namingException = e; // retry
                }
            }
            // if all the attempts failed
            throw new BadCredentialsException("Either no such user '" + principalName + "' or incorrect password", namingException);
        }

        /**
         * Binds to the server using the specified username/password.
         * <p>
         * In a real deployment, often there are servers that don't respond or
         * otherwise broken, so try all the servers.
         */
        @Deprecated
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers) {
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
        private LdapContext bind(String principalName, String password, SocketInfo server, Hashtable<String, String> props) throws NamingException {
            String ldapUrl = (FORCE_LDAPS?"ldaps://":"ldap://") + server + '/';
            String oldName = Thread.currentThread().getName();
            Thread.currentThread().setName("Connecting to "+ldapUrl+" : "+oldName);
            LOGGER.fine("Connecting to " + ldapUrl);
            try {
                props.put(Context.PROVIDER_URL, ldapUrl);
                props.put("java.naming.ldap.version", "3");
                
                customizeLdapProperties(props);
                
                LdapContext context = (LdapContext)LdapCtxFactory.getLdapCtxInstance(ldapUrl, props);

                if (!FORCE_LDAPS) {
                    // try to upgrade to TLS if we can, but failing to do so isn't fatal
                    // see http://download.oracle.com/javase/jndi/tutorial/ldap/ext/starttls.html
                    try {
                        StartTlsResponse rsp = (StartTlsResponse)context.extendedOperation(new StartTlsRequest());
                        rsp.negotiate((SSLSocketFactory)TrustAllSocketFactory.getDefault());
                        LOGGER.fine("Connection upgraded to TLS");
                    } catch (NamingException e) {
                        LOGGER.log(Level.FINE, "Failed to start TLS. Authentication will be done via plain-text LDAP", e);
                        context.removeFromEnvironment("java.naming.ldap.factory.socket");
                    } catch (IOException e) {
                        LOGGER.log(Level.FINE, "Failed to start TLS. Authentication will be done via plain-text LDAP", e);
                        context.removeFromEnvironment("java.naming.ldap.factory.socket");
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

        public List<SocketInfo> obtainLDAPServer(String domainName, String site, String preferredServer) throws NamingException {
            return obtainLDAPServer(createDNSLookupContext(), domainName, site, preferredServer);
        }

        // domain name prefixes
        // see http://technet.microsoft.com/en-us/library/cc759550(WS.10).aspx
        private static final List<String> CANDIDATES = Arrays.asList("_gc._tcp.", "_ldap._tcp.");

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
            if (preferredServers==null)
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
            for (String candidate : CANDIDATES) {
                ldapServer = candidate+(site!=null ? site+"._sites." : "")+domainName;
                LOGGER.fine("Attempting to resolve "+ldapServer+" to SRV record");
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

}
