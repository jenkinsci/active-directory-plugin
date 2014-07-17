package hudson.plugins.active_directory;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

/**
 * Fluent API for building LDAP queries.
 *
 * @author Kohsuke Kawaguchi
 */
class LDAPSearchBuilder {

    private static final Logger LOG = Logger.getLogger(LDAPSearchBuilder.class.getName());

    private final DirContext context;
    private final String baseDN;

    private final SearchControls controls = new SearchControls();

    public LDAPSearchBuilder(DirContext context, String baseDN) {
        this.context = context;
        this.baseDN = baseDN;
    }

    public LDAPSearchBuilder objectScope() {
        controls.setSearchScope(SearchControls.OBJECT_SCOPE);
        return this;
    }

    public LDAPSearchBuilder subTreeScope() {
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        return this;
    }

    public LDAPSearchBuilder returns(String... attributes) {
        controls.setReturningAttributes(attributes);
        return this;
    }

    public Attributes searchOne(String filter, Object... args) throws NamingException {
        NamingEnumeration<SearchResult> r = search(filter,args);
        try {
            if (r.hasMore()) {
                Attributes attrs = r.next().getAttributes();
                LOG.log(Level.FINER, "found {0}", attrs);
                return attrs;
            } else {
                LOG.finer("no result");
            }
            return null;
        } finally {
            r.close();
        }
    }

    public NamingEnumeration<SearchResult> search(String filter, Object... args) throws NamingException {
        if (LOG.isLoggable(Level.FINER)) {
            Map<Object,Object> env = new HashMap<Object,Object>(context.getEnvironment());
            if (env.containsKey(Context.SECURITY_CREDENTIALS)) {
                env.put(Context.SECURITY_CREDENTIALS, "…");
            }
            LOG.log(Level.FINER, "searching {0}{1} in {2} using {3} with scope {4} returning {5}", new Object[] {filter, Arrays.toString(args), baseDN, env, controls.getSearchScope(), Arrays.toString(controls.getReturningAttributes())});
        }
        return context.search(baseDN, filter,args,controls);
    }
}
