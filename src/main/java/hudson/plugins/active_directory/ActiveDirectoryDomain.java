package hudson.plugins.active_directory;

/*
 * The MIT License
 *
 * Copyright (c) 2016, Felix Belzunce Arcos, CloudBees, Inc., and contributors
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

import hudson.Extension;
import hudson.Functions;
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.util.FormValidation;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.BadCredentialsException;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.naming.CommunicationException;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import java.io.IOException;
import java.io.Serializable;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider.toDC;

/**
 * Represents an Active Directory domain with its Domain Controllers
 *
 * Easily allows you to match Domains with Domains Controllers
 *
 * @since 2.0
 */
public class ActiveDirectoryDomain extends AbstractDescribableImpl<ActiveDirectoryDomain> implements Serializable {

    /**
     * Domain name
     *
     * <p>
     * When this plugin is used on Windows, this field is null, and we use ADSI
     * and ADO through com4j to perform authentication.
     *
     * <p>
     * OTOH, when this plugin runs on non-Windows, this field must be non-null,
     * and we'll use LDAP for authentication.
     */
    public String name;

    /**
     * If non-null, Jenkins will try to connect at this server at the first priority, before falling back to
     * discovered DNS servers.
     */
    public String servers;

    /**
     * Active directory site (which specifies the physical concentration of the
     * servers), if any. If the value is non-null, we'll only contact servers in
     * this site.
     *
     * <p>
     * On Windows, I'm assuming ADSI takes care of everything automatically.
     */
    public String site;

    /**
     * If non-null, use this name and password to bind to LDAP to obtain the DN
     * of the user trying to login. This is unnecessary in a single-domain mode,
     * where we can just bind with the user name and password provided during
     * the login, but in a forest mode, without some known credential, we cannot
     * figure out which domain in the forest the user belongs to.
     */
    public String bindName;

    public Secret bindPassword;

    public ActiveDirectoryDomain(String name, String servers) {
        this(name, servers, null, null, null);
    }

    @DataBoundConstructor
    public ActiveDirectoryDomain(String name, String servers, String site, String bindName, String bindPassword) {
        this.name = name;
        // Append default port if not specified
        servers = fixEmpty(servers);
        if (servers != null) {
            String[] serversArray = servers.split(",");
            for (int i = 0; i < serversArray.length; i++) {
                if (!serversArray[i].contains(":")) {
                    serversArray[i] += ":3268";
                }
            }
            servers = StringUtils.join(serversArray, ",");
        }
        this.servers = servers;
        this.site = fixEmpty(site);
        this.bindName = fixEmpty(bindName);
        this.bindPassword = Secret.fromString(fixEmpty(bindPassword));
    }

    @Restricted(NoExternalUse.class)
    public String getName() {
        return name;
    }

    @Restricted(NoExternalUse.class)
    public String getServers() {
        return servers;
    }

    @Restricted(NoExternalUse.class)
    public String getBindName() {
        return bindName;
    }

    @Restricted(NoExternalUse.class)
    public Secret getBindPassword() {
        return bindPassword;
    }

    @Restricted(NoExternalUse.class)
    public String getSite() {
        return site;
    }


    public List<SocketInfo> getServerList(){
        /*List<SocketInfo> result = new ArrayList<SocketInfo>();
        if (servers!=null) {
            for (String token : servers.split(",")) {
                result.add(new SocketInfo(token.trim()));
            }
            return result;
        }*/

        // Create a fake ActiveDirectorySecurityRealm
        List<SocketInfo> result = new ArrayList<SocketInfo>();
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(name, site, "", "", servers);
        try {
            result = activeDirectorySecurityRealm.getDescriptor().obtainLDAPServer(this);
        } catch (NamingException e) {
            e.printStackTrace();
        }

        return result;
    }


    /**
     * Get the list the servers which are using the LDAP catalog
     * @return
     */
    public List<SocketInfo> getServersUsingLdapCatalog(){
        List<SocketInfo> result = new ArrayList<SocketInfo>();
        if (servers!=null) {
            for (String token : servers.split(",")) {
                SocketInfo socketInfo = new SocketInfo(token.trim());
                if(socketInfo.getPort() == 686 || socketInfo.getPort() == 389) {
                    result.add(new SocketInfo(token.trim()));
                }
            }
            return result;
        }
        return null;
    }

    /**
     * Get the list the servers which are using the LDAP catalog
     * @return
     */
    public boolean isDomanDnsSane(){
        // Create a fake ActiveDirectorySecurityRealm
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(name, site, "", "", servers);
        DirContext ictx;
        // First test the sanity of the domain name itself
        try {
            LOGGER.log(Level.FINE, "Attempting to resolve {0} to NS record", name);
            ictx = activeDirectorySecurityRealm.getDescriptor().createDNSLookupContext();
            Attributes attributes = ictx.getAttributes(name, new String[]{"NS"});
            Attribute ns = attributes.get("NS");
            if (ns == null) {
                LOGGER.log(Level.FINE, "Attempting to resolve {0} to A record", name);
                attributes = ictx.getAttributes(name, new String[]{"A"});
                Attribute a = attributes.get("A");
                if (a == null) {
                    throw new NamingException(name + " doesn't look like a domain name");
                }
            }
            LOGGER.log(Level.FINE, "{0} resolved to {1}", new Object[]{name, ns});
            return true;
        } catch (NamingException e) {
            LOGGER.log(Level.WARNING, String.format("Failed to resolve %s to A record", name), e);
            return false;
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

    public boolean isDomainExposingGc() {
        // try global catalog if it exists first, then the particular domain
        String candidate = "_gc._tcp.";
        Attribute a;
        String ldapServer;
        ldapServer = candidate+(site!=null ? site+"._sites." : "")+this.name;
        LOGGER.fine("Attempting to resolve "+ldapServer+" to SRV record");
        try {
            Attributes attributes = createDNSLookupContext().getAttributes(ldapServer, new String[] { "SRV" });
            a = attributes.get("SRV");
            if (a!=null) {
                return true;
            } else {
                return false;
            }
        } catch (NamingException e) {
            // failed retrieval. try next option.
        } catch (NumberFormatException x) {
            //
        }
        return false;
    }

    public boolean isDomainExposingLdapCatalog() {
        // try global catalog if it exists first, then the particular domain
        String candidate = "_ldap._tcp.";
        Attribute a;
        String ldapServer;
        ldapServer = candidate+(site!=null ? site+"._sites." : "")+this.name;
        LOGGER.fine("Attempting to resolve "+ldapServer+" to SRV record");
        try {
            Attributes attributes = createDNSLookupContext().getAttributes(ldapServer, new String[] { "SRV" });
            a = attributes.get("SRV");
            if (a!=null) {
                return true;
            } else {
                return false;
            }
        } catch (NamingException e) {
            // failed retrieval. try next option.
        } catch (NumberFormatException x) {
            //
        }
        return false;
    }

    public boolean isLoginSuccessful(SocketInfo socketInfo) {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(name, site, "", "", servers);
        List<SocketInfo> servertest = new ArrayList<SocketInfo>(1);
        servertest.add(socketInfo);

        if (bindName != null) {
            // Make sure the bind actually works
            try {
                DirContext context = activeDirectorySecurityRealm.getDescriptor().bind(bindName, Secret.toString(bindPassword), servertest);
                try {
                    // Actually do a search to make sure the credential is valid
                    Attributes userAttributes = new LDAPSearchBuilder(context, toDC(name)).subTreeScope().searchOne("(objectClass=user)");
                    if (userAttributes == null) {
                    }
                } finally {
                    context.close();
                    return true;
                }
            }  catch (Exception e) {
                return false;
            }
        } else {
            // just some connection test
            // try to connect to LDAP port to make sure this machine has LDAP service
            IOException error = null;
            for (SocketInfo si : servertest) {
                try {
                    si.connect().close();
                    return true; // looks good
                } catch (IOException e) {
                    return false;
                }
            }
            return false;
        }
    }


    /**
     * Convert empty string to null.
     */
    public static String fixEmpty(String s) {
        if(s==null || s.length()==0)    return null;
        return s;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<ActiveDirectoryDomain> {
        @Override
        public String getDisplayName() { return ""; }
        
        public FormValidation doValidateTest(@QueryParameter(fixEmpty = true) String name, @QueryParameter(fixEmpty = true) String servers, @QueryParameter(fixEmpty = true) String site, @QueryParameter(fixEmpty = true) String bindName,
                                             @QueryParameter(fixEmpty = true) String bindPassword) throws IOException, ServletException, NamingException {

            // Create a fake ActiveDirectorySecurityRealm
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(name, site, bindName, bindPassword, servers);

            ClassLoader ccl = Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            try {
                Functions.checkPermission(Hudson.ADMINISTER);

                // In case we can do native authentication
                if (activeDirectorySecurityRealm.getDescriptor().canDoNativeAuth() && name==null) {
                    // this check must be identical to that of ActiveDirectory.groovy
                    try {
                        // make sure we can connect via ADSI
                        new ActiveDirectoryAuthenticationProvider();
                        return FormValidation.ok("Success");
                    } catch (Exception e) {
                        return FormValidation.error(e, "Failed to contact Active Directory");
                    }
                }

                // If non nativate authentication then check there is at least one Domain created in the UI
                if (name==null || name.isEmpty()) {
                    return FormValidation.error("No domain was set");
                }

                Secret password = Secret.fromString(bindPassword);
                if (bindName!=null && password==null)
                    return FormValidation.error("Bind DN is specified but not the password");

                DirContext ictx;
                // First test the sanity of the domain name itself
                try {
                    LOGGER.log(Level.FINE, "Attempting to resolve {0} to NS record", name);
                    ictx = activeDirectorySecurityRealm.getDescriptor().createDNSLookupContext();
                    Attributes attributes = ictx.getAttributes(name, new String[]{"NS"});
                    Attribute ns = attributes.get("NS");
                    if (ns == null) {
                        LOGGER.log(Level.FINE, "Attempting to resolve {0} to A record", name);
                        attributes = ictx.getAttributes(name, new String[]{"A"});
                        Attribute a = attributes.get("A");
                        if (a == null) {
                            throw new NamingException(name + " doesn't look like a domain name");
                        }
                    }
                    LOGGER.log(Level.FINE, "{0} resolved to {1}", new Object[]{name, ns});
                } catch (NamingException e) {
                    LOGGER.log(Level.WARNING, String.format("Failed to resolve %s to A record", name), e);
                    return FormValidation.error(e, name + " doesn't look like a valid domain name");
                }
                // Then look for the LDAP server
                List<SocketInfo> obtainerServers;
                try {
                    obtainerServers = activeDirectorySecurityRealm.getDescriptor().obtainLDAPServer(ictx, name, site, servers);
                } catch (NamingException e) {
                    String msg = site == null ? "No LDAP server was found in " + name : "No LDAP server was found in the " + site + " site of " + name;
                    LOGGER.log(Level.WARNING, msg, e);
                    return FormValidation.error(e, msg);
                }

                if (bindName != null) {
                    // Make sure the bind actually works
                    try {
                        DirContext context = activeDirectorySecurityRealm.getDescriptor().bind(bindName, Secret.toString(password), obtainerServers);
                        try {
                            // Actually do a search to make sure the credential is valid
                            Attributes userAttributes = new LDAPSearchBuilder(context, toDC(name)).subTreeScope().searchOne("(objectClass=user)");
                            if (userAttributes == null) {
                                return FormValidation.error(Messages.ActiveDirectorySecurityRealm_NoUsers());
                            }
                        } finally {
                            context.close();
                        }
                    } catch (BadCredentialsException e) {
                        Throwable t = e.getCause();
                        if (t instanceof CommunicationException) {
                            return FormValidation.error(e, "Any Domain Controller is reachable");
                        }
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
                    for (SocketInfo si : obtainerServers) {
                        try {
                            si.connect().close();
                            break; // looks good
                        } catch (IOException e) {
                            LOGGER.log(Level.FINE, String.format("Failed to connect to %s", si), e);
                            error = e;
                            // try the next server in the list
                        }
                    }
                    if (error != null) {
                        LOGGER.log(Level.WARNING, String.format("Failed to connect to %s", servers), error);
                        return FormValidation.error(error, "Failed to connect to " + servers);
                    }
                }
                // looks good
                return FormValidation.ok("Success");
            } finally {
                Thread.currentThread().setContextClassLoader(ccl);
            }
        }
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryUnixAuthenticationProvider.class.getName());

}
