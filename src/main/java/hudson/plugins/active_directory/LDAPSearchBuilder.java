package hudson.plugins.active_directory;

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
            if (r.hasMore())        return r.next().getAttributes();
            return null;
        } finally {
            r.close();
        }
    }

    public NamingEnumeration<SearchResult> search(String filter, Object... args) throws NamingException {
        return context.search(baseDN, filter,args,controls);
    }
}
