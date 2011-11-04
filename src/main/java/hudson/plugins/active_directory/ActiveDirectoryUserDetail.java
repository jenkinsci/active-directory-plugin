package hudson.plugins.active_directory;

import java.util.HashMap;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryUserDetail extends User {
    // additional attributes from Active Directory
    private final String givenName, sn, mail, telephoneNumber;

	public ActiveDirectoryUserDetail(String username, String password,
			boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			GrantedAuthority[] authorities,
			String givenName, String sn, String mail, String telephoneNumber)
			throws IllegalArgumentException {
		// Acegi doesn't like null password, but during remember-me processing
		// we don't know the password so we need to set some dummy. See #1229
		super(username, password != null ? password : "PASSWORD", enabled,
				accountNonExpired, credentialsNonExpired, accountNonLocked,
				authorities);

        this.givenName = givenName;
        this.sn = sn;
        this.mail = mail;
        this.telephoneNumber = telephoneNumber;
	}

    public String getGivenName() {
        return givenName;
    }

    /**
     * Surname, AKA last name.
     * LDAP "sn" attribute.
     */
    public String getLastName() {
        return sn;
    }

    public String getMail() {
        return mail;
    }

    public String getTelephoneNumber() {
        return telephoneNumber;
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    private static final long serialVersionUID = 1L;
}