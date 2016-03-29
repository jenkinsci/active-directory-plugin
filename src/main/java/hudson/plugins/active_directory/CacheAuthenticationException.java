package hudson.plugins.active_directory;

import org.acegisecurity.AuthenticationException;

/**
 * To throw AuthenticationException when the login failed due a cache issue
 */
public class CacheAuthenticationException extends AuthenticationException {

    public CacheAuthenticationException(String msg, Exception e) {
        super(msg, e);
    }

}
