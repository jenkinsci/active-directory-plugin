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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.PartialResultException;
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

    /**
     * Add all the attributes returned by the search
     *
     * @param filter
     *      The filter to be used for the search
     * @param args
     *      Arguments to be used for the search
     *
     * @return Return all the attributes of the search and adds the DN correctly formatted per RFC 2253
     */
    public Attributes searchOne(String filter, Object... args) throws NamingException {
        NamingEnumeration<SearchResult> r = search(filter,args);
        try {
            if (r.hasMore()) {
                SearchResult searchResult = r.next();
                Attributes attrs = searchResult.getAttributes();
                //We need to use getNameInNamespace in order to correctly format everything
                //to be able to use LdapName later and get the DN correctly formatted with escaped
                //characters like slash
                attrs.put(ActiveDirectoryUnixAuthenticationProvider.DN_FORMATTED, searchResult.getNameInNamespace());
                LOG.log(Level.FINER, "found {0}", attrs);
                return attrs;
            } else {
                LOG.finer("no result");
            }
            return null;
        } catch (PartialResultException e) {
            // See JENKINS-42687. On this case might happen that the search instead of returning an empty
            // NamingEnumeration is returning a PartialResultException. Again, In my opinion this should
            // not be a blocker. We should just log the Exception and return null like on the case where
            // any user was found.
            LOG.log(Level.WARNING, String.format("JENKINS-42687 The user we are looking for might exist"), e);
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
