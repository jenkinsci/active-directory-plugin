package hudson.plugins.active_directory;

import com.sun.jndi.ldap.LdapCtxFactory;
import groovy.lang.Binding;
import hudson.Extension;
import hudson.Functions;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.security.GroupDetails;
import hudson.security.SecurityRealm;
import hudson.util.FormValidation;
import hudson.util.Secret;
import hudson.util.spring.BeanBuilder;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.BadCredentialsException;
import org.acegisecurity.userdetails.UserDetailsService;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.springframework.dao.DataAccessException;
import org.springframework.web.context.WebApplicationContext;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import static hudson.Util.fixEmpty;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectorySecurityRealm extends SecurityRealm {
    /**
     * Active directory domain name to authenticate against.
     *
     * <p>
     * When this plugin is used on Windows, this field is null,
     * and we use ADSI and ADO through com4j to perform authentication.
     *
     * <p>
     * OTOH, when this plugin runs on non-Windows, this field
     * must be non-null, and we'll use LDAP for authentication.
     */
    public final String domain;

    /**
     * Active directory site (which specifies the physical concentration of the servers),
     * if any. If the value is non-null, we'll only contact servers in this site.
     *
     * <p>
     * On Windows, I'm assuming ADSI takes care of everything automatically.
     */
    public final String site;

    /**
     * If non-null, use this name and password to bind to LDAP to obtain the DN of the user trying to login.
     * This is unnecessary in a sigle-domain mode, where we can just bind with the user name and password
     * provided during the login, but in a forest mode, without some known credential, we cannot figure out
     * which domain in the forest the user belongs to.
     */
    public final String bindName;
    public final Secret bindPassword;

    @DataBoundConstructor
    public ActiveDirectorySecurityRealm(String domain, String site, String bindName, String bindPassword) {
        this.domain = fixEmpty(domain);
        this.site = fixEmpty(site);
        this.bindName = fixEmpty(bindName);
        this.bindPassword = Secret.fromString(fixEmpty(bindPassword));
    }

    public SecurityComponents createSecurityComponents() {
        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
        Binding binding = new Binding();
        binding.setVariable("realm",this);
        builder.parse(getClass().getResourceAsStream("ActiveDirectory.groovy"),binding);
        WebApplicationContext context = builder.createApplicationContext();
        return new SecurityComponents(
            findBean(AuthenticationManager.class, context),
            findBean(UserDetailsService.class, context));
    }

    @Override
    public DesciprotrImpl getDescriptor() {
        return (DesciprotrImpl)super.getDescriptor();
    }

    @Extension
    public static final class DesciprotrImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return Messages.DisplayName();
        }
        
        @Override
        public String getHelpFile() {
            return "/plugin/active-directory/help/realm.html";
        }

        /**
         * If true, we can do ADSI/COM based look up that's far more reliable.
         * False if we need to do the authentication in pure Java via {@link ActiveDirectoryUnixAuthenticationProvider}
         */
        public boolean canDoNativeAuth() {
            return Hudson.isWindows() && "32".equals(System.getProperty("sun.arch.data.model"));
        }

        public FormValidation doValidate(
                @QueryParameter(fixEmpty=true) String domain,
                @QueryParameter(fixEmpty=true) String site,
                @QueryParameter(fixEmpty=true) String bindName,
                @QueryParameter(fixEmpty=true) String bindPassword) throws IOException, ServletException, NamingException {
            ClassLoader ccl = Thread.currentThread().getContextClassLoader();
            Thread.currentThread().setContextClassLoader(getClass().getClassLoader());
            try {
                Functions.checkPermission(Hudson.ADMINISTER);
                String n = Util.fixEmptyAndTrim(domain);
                if(n==null) {// no value given yet
                    return FormValidation.error("No domain name set");
                }

                Secret password = Secret.fromString(bindPassword);
                if (bindName!=null && password==null)
                    return FormValidation.error("DN is specified but not password");

                String[] names = n.split(",");
                for (String name : names) {

                    if(!name.endsWith(".")) name+='.';

                    DirContext ictx;

                    // first test the sanity of the domain name itself
                    try {
                        LOGGER.fine("Attempting to resolve "+name+" to A record");
                        ictx = createDNSLookupContext();
                        Attributes attributes = ictx.getAttributes(name, new String[]{"A"});
                        Attribute a = attributes.get("A");
                        if(a==null) throw new NamingException();
                        LOGGER.fine(name+" resolved to "+ a.get());
                    } catch (NamingException e) {
                        LOGGER.log(Level.WARNING,"Failed to resolve "+name+" to A record",e);
                        return FormValidation.error(e,name+" doesn't look like a valid domain name");
                    }

                    // then look for the LDAP server
                    List<SocketInfo> servers;
                    try {
                        servers = obtainLDAPServer(ictx,name,site);
                    } catch (NamingException e) {
                        String msg = site==null ? "No LDAP server was found in " + name : "No LDAP server was found in the "+site+" site of "+name;
                        LOGGER.log(Level.WARNING, msg,e);
                        return FormValidation.error(e,msg);
                    }

                    if (bindName!=null) {
                        // make sure the bind actually works
                        try {
                            bind(bindName,password.toString(),servers).close();
                        } catch (BadCredentialsException e) {
                            return FormValidation.error(e,"Bad bind username or password");
                        } catch (Exception e) {
                            return FormValidation.error(e,e.getMessage());
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
                                LOGGER.log(Level.FINE,"Failed to connect to "+si,e);
                                error = e;
                                // try the next server in the list
                            }
                        }
                        if (error!=null) {
                            LOGGER.log(Level.WARNING,"Failed to connect to "+servers,error);
                            return FormValidation.error(error,"Failed to connect to "+servers);
                        }
                    }
                }

                // looks good
                return FormValidation.ok("Success");
            } finally {
                Thread.currentThread().setContextClassLoader(ccl);
            }
        }

        /**
         * Binds to the server using the specified username/password.
         * <p>
         * In a real deployment, often there are servers that don't respond or otherwise broken,
         * so try all the servers.
         */
        public DirContext bind(String principalName, String password, List<SocketInfo> ldapServers) {
            // in a AD forest, it'd be mighty nice to be able to login as "joe" as opposed to "joe@europe",
            // but the bind operation doesn't appear to allow me to do so.
            Hashtable<String,String> props = new Hashtable<String,String>();
            props.put(Context.SECURITY_PRINCIPAL, principalName);
            props.put(Context.SECURITY_CREDENTIALS,password);
            props.put(Context.REFERRAL, "follow");
            // specifying custom socket factory requires a custom classloader.
            props.put("java.naming.ldap.factory.socket", TrustAllSocketFactory.class.getName());


            NamingException error = null;
            for (SocketInfo ldapServer : ldapServers) {
                try {
                    return LdapCtxFactory.getLdapCtxInstance("ldaps://" + ldapServer + '/', props); // worked
                } catch (NamingException e) {
                    LOGGER.log(Level.WARNING,"Failed to bind to "+ldapServer,e);
                    error = e; // retry
                }
            }

            // if all the attempts failed
            throw new BadCredentialsException("Either no such user '"+principalName+"' or incorrect password",error);
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

        public List<SocketInfo> obtainLDAPServer(String domainName, String site) throws NamingException {
            return obtainLDAPServer(createDNSLookupContext(),domainName,site);
        }

        private static final List<SocketInfo> CANDIDATES = Arrays.asList(
                new SocketInfo("_gc._tcp.",3269),
                new SocketInfo("_ldap._tcp.",636)  // LDAPS
            );

        /**
         * Use DNS and obtains the LDAP servers that we should try.
         *
         * @return
         *      A list with at least one item.
         */
        public List<SocketInfo> obtainLDAPServer(DirContext ictx, String domainName, String site) throws NamingException {
            String ldapServer=null;
            Attribute a=null;
            SocketInfo mode = null;
            NamingException failure=null;

            // try global catalog if it exists first, then the particular domain
            for (SocketInfo candidate : CANDIDATES) {
                mode = candidate;
                ldapServer = candidate.host/*used as a prefix*/+(site!=null?site+"._sites.":"")+domainName;
                LOGGER.fine("Attempting to resolve "+ldapServer+" to SRV record");
                try {
                    Attributes attributes = ictx.getAttributes(ldapServer, new String[]{"SRV"});
                    a = attributes.get("SRV");
                    if (a!=null)    break;
                } catch (NamingException e) {
                    // failed retrieval. try next option.
                    failure = e;
                }
            }

            if(a==null) {// all options failed
                if (failure!=null)  throw failure;
                throw new NamingException();
            }

            int priority = -1;
            List<SocketInfo> result = new ArrayList<SocketInfo>();
            for (NamingEnumeration ne = a.getAll(); ne.hasMoreElements(); ) {
                String[] fields = ne.next().toString().split(" ");
                int p = Integer.parseInt(fields[0]);
                // fields[1]: weight
                // fields[2]: port
                // fields[3]: target host name
                if (priority == -1 || p < priority) {
                    priority = p;
                    result.clear();
                }
                if (priority==p) {
                    String hostName = fields[3];
                    // cut off trailing ".". HUDSON-2647
                    if (hostName.endsWith("."))   hostName = hostName.substring(0,hostName.length()-1);
                    result.add(new SocketInfo(hostName,mode.port));
                }
            }
            if (result.isEmpty())
                throw new NamingException("No SRV record found for "+ldapServer);
            
            LOGGER.fine(ldapServer+" resolved to "+ result);
            return result;
        }
    }
    
    @Override
    public GroupDetails loadGroupByGroupname(String groupname)
    		throws UsernameNotFoundException, DataAccessException {
    	GroupDetailsService groupDetailsService = (GroupDetailsService) getSecurityComponents().userDetails;
    	return groupDetailsService.loadGroupByGroupname(groupname);
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectorySecurityRealm.class.getName());
}
