package hudson.plugins.active_directory;

import groovy.lang.Binding;
import hudson.Util;
import hudson.model.Descriptor;
import hudson.security.SecurityRealm;
import hudson.util.FormFieldValidator;
import hudson.util.spring.BeanBuilder;
import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.userdetails.UserDetailsService;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.StaplerResponse;
import org.springframework.web.context.WebApplicationContext;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.servlet.ServletException;
import java.io.IOException;
import java.net.Socket;
import java.util.Hashtable;
import java.util.logging.Level;
import java.util.logging.Logger;

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

    @DataBoundConstructor
    public ActiveDirectorySecurityRealm(String domain) {
        this.domain = domain;
    }

    public SecurityComponents createSecurityComponents() {
        BeanBuilder builder = new BeanBuilder(getClass().getClassLoader());
        Binding binding = new Binding();
        binding.setVariable("domain",domain);
        builder.parse(getClass().getResourceAsStream("ActiveDirectory.groovy"),binding);
        WebApplicationContext context = builder.createApplicationContext();
        return new SecurityComponents(
            findBean(AuthenticationManager.class, context),
            findBean(UserDetailsService.class, context));
    }

    public Descriptor<SecurityRealm> getDescriptor() {
        return DesciprotrImpl.INSTANCE;
    }

    public static final class DesciprotrImpl extends Descriptor<SecurityRealm> {
        public static final DesciprotrImpl INSTANCE = new DesciprotrImpl();

        public DesciprotrImpl() {
            super(ActiveDirectorySecurityRealm.class);
        }

        public String getDisplayName() {
            return Messages.DisplayName();
        }
        
        public String getHelpFile() {
            return "/plugin/active-directory/help/realm.html";
        }

        public void doDomainCheck(StaplerRequest req, StaplerResponse rsp, @QueryParameter("value") final String value) throws IOException, ServletException {
            new FormFieldValidator(req,rsp,true) {
                protected void check() throws IOException, ServletException {
                    String name = Util.fixEmptyAndTrim(value);
                    if(name==null) {// no value given yet
                        ok();
                        return;
                    }
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
                        error(name+" doesn't look like a valid domain name");
                        return;
                    }

                    // then look for the LDAP server
                    final String ldapServer = "_ldap._tcp."+name;
                    String serverHostName;
                    try {
                        serverHostName = obtainLDAPServer(ictx,name);
                    } catch (NamingException e) {
                        LOGGER.log(Level.WARNING,"Failed to resolve "+ldapServer+" to SRV record",e);
                        error("No LDAP server was found in "+name);
                        return;
                    }

                    // try to connect to LDAP port to make sure this machine has LDAP service
                    // TODO: honor the port number in SRV record
                    try {
                        new Socket(serverHostName,389).close();
                    } catch (IOException e) {
                        LOGGER.log(Level.WARNING,"Failed to connect to LDAP port",e);
                        error("Failed to connect to the LDAP port (389) of "+serverHostName);
                        return;
                    }

                    // looks good
                    ok();
                }
            }.process();
        }

        /**
         * Creates {@link DirContext} for accesssing DNS.
         */
        public DirContext createDNSLookupContext() throws NamingException {
            Hashtable env = new Hashtable();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
            return new InitialDirContext(env);
        }

        public String obtainLDAPServer(String domainName) throws NamingException {
            return obtainLDAPServer(createDNSLookupContext(),domainName);
        }

        /**
         * Use DNS and obtains the LDAP server's host name.
         */
        public String obtainLDAPServer(DirContext ictx, String domainName) throws NamingException {
            final String ldapServer = "_ldap._tcp."+domainName;

            LOGGER.fine("Attempting to resolve "+ldapServer+" to SRV record");
            Attributes attributes = ictx.getAttributes(ldapServer, new String[]{"SRV"});
            Attribute a = attributes.get("SRV");
            if(a==null) throw new NamingException();
            LOGGER.fine(ldapServer+" resolved to "+ a.get());

            return a.get().toString().split(" ")[3];
        }
    }

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectorySecurityRealm.class.getName());
}
