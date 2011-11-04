package hudson.plugins.active_directory;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryUserDetail extends User {
    // additional attributes from Active Directory
    private final String displayName, mail, telephoneNumber;

	public ActiveDirectoryUserDetail(String username, String password,
			boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			GrantedAuthority[] authorities,
			String displayName, String mail, String telephoneNumber)
			throws IllegalArgumentException {
		// Acegi doesn't like null password, but during remember-me processing
		// we don't know the password so we need to set some dummy. See #1229
		super(username, password != null ? password : "PASSWORD", enabled,
				accountNonExpired, credentialsNonExpired, accountNonLocked,
				authorities);

        this.displayName = displayName;
        this.mail = mail;
        this.telephoneNumber = telephoneNumber;
	}

    public String getDisplayName() {
        return displayName;
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

    /**
     * Gets the corresponding {@link hudson.model.User} object.
     */
    public hudson.model.User getJenkinsUser() {
        return hudson.model.User.get(getUsername());
    }

    /**
     * Use the information to update the {@link hudson.model.User} object.
     *
     * @return this
     */
    public UserDetails updateUserInfo() {
        hudson.model.User u = getJenkinsUser();
        if (getDisplayName()!=null)
            u.setFullName(getDisplayName());

        if (getMail()!=null)
            try {
                u.addProperty(new Mailer.UserProperty(getMail()));
            } catch (IOException e) {
                LOGGER.log(Level.WARNING,"Failed to associate the e-mail address",e);
            }

        return this;
    }

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryUserDetail.class.getName());
}