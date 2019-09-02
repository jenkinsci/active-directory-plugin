package hudson.plugins.active_directory;

import hudson.model.User;
import hudson.util.Scrambler;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
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

    public void doFilter(ServletRequest servletRequest,
                         ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        Authentication auth = Jenkins.ANONYMOUS;
        String authenticatedUserFromApiToken = getUserFromAuthorizationHeader(request);

        String userName = authenticatedUserFromApiToken == null ? getUserFromReverseProxyHeader(request) : authenticatedUserFromApiToken;
        if (userName != null) {
            try {
                UserDetails userDetails = activeDirectorySecurityRealm.getAuthenticationProvider().loadUserByUsername(userName);

                GrantedAuthority[] authorities = userDetails.getAuthorities();

                auth = new UsernamePasswordAuthenticationToken(userName, "", authorities);
            } catch (UsernameNotFoundException e) {
                LOGGER.log(Level.FINE, "User from HTTP Header {0} not found in LDAP", userName);
            }
        }

        SecurityContextHolder.getContext().setAuthentication(auth);
        chain.doFilter(request, response);
    }

    private String getUserFromAuthorizationHeader(HttpServletRequest request) {
        String authorization;
        if ((authorization = request.getHeader("Authorization")) != null && authorization.toLowerCase().startsWith("basic ")) {
            String uidpassword = Scrambler.descramble(authorization.substring(6));
            int idx = uidpassword.indexOf(':');
            if (idx >= 0) {
                String username = uidpassword.substring(0, idx);
                String password = uidpassword.substring(idx + 1);

                // attempt to authenticate as API token
                User u = User.get(username, false);
                if (u != null) {
                    ApiTokenProperty t = u.getProperty(ApiTokenProperty.class);
                    if (t != null && t.matchesPassword(password)) { // Authenticate API-Token
                        return username;
                    } else { // Authenticate against LDAP
                        UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, password);
                        UserDetails details = activeDirectorySecurityRealm.getAuthenticationProvider().retrieveUser(username, auth);
                        if (details != null)
                            return username;
                    }
                }
            }
        }
        return null;
    }

    private String getUserFromReverseProxyHeader(HttpServletRequest request) {
        String userFromHeader;
        if ((getUserHeader() != null && (userFromHeader = request.getHeader(getUserHeader())) != null)) {
            LOGGER.log(Level.FINE, "User from HTTP Header: {0}", userFromHeader);
            return userFromHeader;
        }
        return null;
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
