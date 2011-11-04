package hudson.plugins.active_directory;

import hudson.Extension;
import hudson.model.Hudson;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.MailAddressResolver;
import org.acegisecurity.AcegiSecurityException;
import org.springframework.dao.DataAccessException;

import java.util.logging.Logger;

import static java.util.logging.Level.*;

/**
 * If the security realm is Active Directory, try to pick up e-mail
 * address from it.
 *
 * @author Animesh Banerjee
 * 
 */
@Extension
public class ActiveDirectoryMailAddressResolverImpl extends
		MailAddressResolver {
	public String findMailAddressFor(User u) {
		SecurityRealm realm = Hudson.getInstance().getSecurityRealm();
		if(!(realm instanceof ActiveDirectorySecurityRealm)){
			return null;
		}   
		try {
			ActiveDirectoryUserDetail details = (ActiveDirectoryUserDetail) realm
					.getSecurityComponents().userDetails.loadUserByUsername(u
					.getId());
			LOGGER.log(FINE, "Email address = '"+ details.getMail() + "'");
				return details.getMail();
		} catch (DataAccessException e) {
			LOGGER.log(FINE, "Failed to look Active Directory for e-mail address", e);
			return null;
		} catch (AcegiSecurityException e) {
			LOGGER.log(FINE, "Failed to look up Active Directory for e-mail address", e);
			return null;
		}
	}

	private static final Logger LOGGER = Logger
			.getLogger(ActiveDirectoryMailAddressResolverImpl.class.getName());
}