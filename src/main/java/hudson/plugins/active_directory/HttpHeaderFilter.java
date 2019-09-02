package hudson.plugins.active_directory;

import jenkins.model.Jenkins;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

class HttpHeaderFilter implements Filter {
    private static final Logger LOGGER = Logger.getLogger(HttpHeaderFilter.class.getName());

    private ActiveDirectorySecurityRealm activeDirectorySecurityRealm;

    HttpHeaderFilter(ActiveDirectorySecurityRealm activeDirectorySecurityRealm) {
        this.activeDirectorySecurityRealm = activeDirectorySecurityRealm;
    }

    public void doFilter(ServletRequest request,
                         ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest r = (HttpServletRequest) request;

        String userFromHeader;
        Authentication auth = Jenkins.ANONYMOUS;
        if ((getUserHeader() != null && (userFromHeader = r.getHeader(getUserHeader())) != null)) {
            LOGGER.log(Level.FINE, "User from HTTP Header: {0}", userFromHeader);

            try {
                UserDetails userDetails = activeDirectorySecurityRealm.getAuthenticationProvider().loadUserByUsername(userFromHeader);

                GrantedAuthority[] authorities = userDetails.getAuthorities();

                auth = new UsernamePasswordAuthenticationToken(userFromHeader, "", authorities);
            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.FINE, "User from HTTP Header {0} not found in LDAP", userFromHeader);
            }
        }
        SecurityContextHolder.getContext().setAuthentication(auth);
        chain.doFilter(r, response);
    }

    private String getUserHeader() {
        return activeDirectorySecurityRealm.userFromHTTPHeader;
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        /* No need to initialize or destroy */
    }

    @Override
    public void destroy() {
        /* No need to initialize or destroy */
    }
}
