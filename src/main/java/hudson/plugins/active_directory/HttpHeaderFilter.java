package hudson.plugins.active_directory;

import hudson.model.User;
import hudson.security.ACL;
import hudson.security.ACLContext;
import hudson.util.Scrambler;
import jenkins.model.Jenkins;
import jenkins.security.ApiTokenProperty;
import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

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

        if (Jenkins.getAuthentication() instanceof AnonymousAuthenticationToken) {
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

            try (ACLContext _ = ACL.as(auth)) {
                chain.doFilter(request, response);
            }
        } else {
            chain.doFilter(request, response);
        }
    }

    String getUserFromAuthorizationHeader(HttpServletRequest request) {
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

    String getUserFromReverseProxyHeader(HttpServletRequest request) {
        String userFromHeader;
        if ((getUserHeader() != null && (userFromHeader = request.getHeader(getUserHeader())) != null)) {
            LOGGER.log(Level.FINE, "User from HTTP Header: {0}", userFromHeader);
            if (getUsernameExtractionExpression() != null && !getUsernameExtractionExpression().equals("")) {
                try {
                    Pattern pattern = Pattern.compile(getUsernameExtractionExpression(), Pattern.CASE_INSENSITIVE);
                    Matcher m = pattern.matcher(userFromHeader);
                    if (m.find()) {
                        return m.group(1);
                    } else
                        return userFromHeader;
                } catch (PatternSyntaxException ex) {
                    LOGGER.log(Level.WARNING, "Error in username extraction expression: {0}", ex);
                    return userFromHeader;
                }
            } else
                return userFromHeader;
        }
        return null;
    }

    private String getUserHeader() {
        return activeDirectorySecurityRealm.userFromHttpHeader;
    }

    private String getUsernameExtractionExpression() {
        return activeDirectorySecurityRealm.usernameExtractionExpression;
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
