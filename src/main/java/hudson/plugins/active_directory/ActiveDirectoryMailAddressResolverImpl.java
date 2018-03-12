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

import hudson.Extension;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.MailAddressResolver;
import jenkins.model.Jenkins;
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
		SecurityRealm realm = Jenkins.getActiveInstance().getSecurityRealm();
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