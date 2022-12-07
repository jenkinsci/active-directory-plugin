package hudson.plugins.active_directory;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

@Restricted(NoExternalUse.class) // visible for testing.
public class DNSUtils {

    public static final String OVERRIDE_DNS_PROPERTY = DNSUtils.class.getName() + ".OVERRIDE_DNS_SERVERS";

    /**
     * Creates {@link DirContext} for accessing DNS. This code allows for easier testing by allowing unit tets to
     * overide the DNS server, in production this should have no effects.
     */
    static DirContext createDNSLookupContext() throws NamingException {
        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.dns.DnsContextFactory");
        String dns = System.getProperty(OVERRIDE_DNS_PROPERTY);
        if (dns != null) {
            env.put("java.naming.provider.url", dns);
            System.out.println("Overriding DNS to: " + dns);
        } else {
            env.put("java.naming.provider.url", "dns:");
        }
        return new InitialDirContext(env);
    }

}
