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

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import hudson.security.HudsonPrivateSecurityRealm;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.tasks.Mailer.UserProperty;
import jenkins.model.Jenkins;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;
import org.apache.commons.collections.CollectionUtils;

import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;

/**
 * @author Kohsuke Kawaguchi
 */
public class ActiveDirectoryUserDetail extends User {
    // additional attributes from Active Directory
    private final String displayName, mail, telephoneNumber;

    private String toStringValue;

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

    @Override
    public String toString() {
        return toStringValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ActiveDirectoryUserDetail)) return false;
        if (!super.equals(o)) return false;

        ActiveDirectoryUserDetail that = (ActiveDirectoryUserDetail)o;

        if (displayName != null ? !displayName.equals(that.displayName) : that.displayName != null) {
            return false;
        }
        if (mail != null ? !mail.equals(that.mail) : that.mail != null) {
            return false;
        }
        if (telephoneNumber != null ? !telephoneNumber.equals(that.telephoneNumber) : that.telephoneNumber != null) {
            return false;
        }
        return !(toStringValue != null ? !toStringValue.equals(that.toStringValue) : that.toStringValue != null);

    }

    @Override
    public int hashCode() {
        int result = super.hashCode();
        result = 31 * result + (displayName != null ? displayName.hashCode() : 0);
        result = 31 * result + (mail != null ? mail.hashCode() : 0);
        result = 31 * result + (telephoneNumber != null ? telephoneNumber.hashCode() : 0);
        result = 31 * result + (toStringValue != null ? toStringValue.hashCode() : 0);
        return result;
    }

    @Override 
    @SuppressFBWarnings(value="NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE", justification="https://github.com/jenkinsci/jenkins/pull/2094")
    protected void setAuthorities(GrantedAuthority[] authorities) {
        SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
        if ((realm instanceof ActiveDirectorySecurityRealm)) {
            ActiveDirectorySecurityRealm activeDirectoryRealm = (ActiveDirectorySecurityRealm)realm;
            if (activeDirectoryRealm.removeIrrelevantGroups) {
                Set<String> referencedGroups = new HashSet<String>();
                for (String group : Jenkins.getInstance().getAuthorizationStrategy().getGroups()) {
                    referencedGroups.add(group.toLowerCase());
                }
                // We remove irrelevant groups only if the active AuthorizationStrategy has any referenced groups:
                if (!referencedGroups.isEmpty()) {
                    List<GrantedAuthority> relevantGroups = new ArrayList<GrantedAuthority>();

                    for (GrantedAuthority group : authorities) {
                        String groupName = group.getAuthority();
                        if (groupName != null && referencedGroups.contains(groupName.toLowerCase())) {
                            relevantGroups.add(group);
                        }
                    }
                    authorities = relevantGroups.toArray(new GrantedAuthority[relevantGroups.size()]);
                }
            }
        }

        super.setAuthorities(authorities);
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString()).append(": ");
        sb.append("Username: ").append(getUsername()).append("; ");
        sb.append("Password: [PROTECTED]; ");
        sb.append("Enabled: ").append(isEnabled()).append("; ");
        sb.append("AccountNonExpired: ").append(isAccountNonExpired()).append("; ");
        sb.append("credentialsNonExpired: ").append(isCredentialsNonExpired()).append("; ");
        sb.append("AccountNonLocked: ").append(isAccountNonLocked()).append("; ");

        if (this.getAuthorities() != null) {
            sb.append("Granted Authorities: ");

            for (int i = 0; i < this.getAuthorities().length; i++) {
                if (i > 0) {
                    sb.append(", ");
                }

                sb.append(this.getAuthorities()[i].toString());
            }
        } else {
            sb.append("Not granted any authorities");
        }
        toStringValue = sb.toString();
    }

    public static long getSerialVersionUID() {
        return serialVersionUID;
    }

    /**
     * Gets the corresponding {@link hudson.model.User} object.
     */
    public hudson.model.User getJenkinsUser() {
        try { // TODO 1.651.2+ remove reflection
            return (hudson.model.User) hudson.model.User.class.getMethod("getById", String.class, boolean.class).invoke(null, getUsername(), true);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException)e.getCause();
            }
            // Only RuntimeException is expected
            LOGGER.log(Level.WARNING, String.format("There was a problem obtaining the Jenkins user %s by Id", getUsername()), e);
        } catch (NoSuchMethodException e) {
            // fine, older baseline
        } catch (Exception e) { // unexpected
            LOGGER.log(Level.WARNING, String.format("There was a problem obtaining the Jenkins user %s by Id", getUsername()), e);
        }
        return hudson.model.User.get(getUsername());
    }

    /**
     * Use the information to update the {@link hudson.model.User} object.
     *
     * @return this
     */
    public UserDetails updateUserInfo() {
        // the challenge here is to set the name if it's not set, but if the user overrides that
        //
        hudson.model.User u = getJenkinsUser();
        if (getDisplayName()!=null && u.getId().equals(u.getFullName()))
            u.setFullName(getDisplayName());

        UserProperty existing = u.getProperty(UserProperty.class);
        if (existing==null || !existing.hasExplicitlyConfiguredAddress()) {
            try {
                u.addProperty(new Mailer.UserProperty(getMail()));
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to associate the e-mail address", e);
            }
        }

        return this;
    }

    /**
     * Update the the password for the specified {@link hudson.model.User} in the Jenkins
     * Internal User Database
     *
     *
     */
    protected void updatePasswordInJenkinsInternalDatabase(String username, String password) {
        LOGGER.log(Level.FINEST, String.format("Looking in Jenkins Internal Database for user %s", username));
        hudson.model.User internalUser = hudson.model.User.get(username);
        HudsonPrivateSecurityRealm.Details details = internalUser.getProperty(HudsonPrivateSecurityRealm.Details.class);
        try {
            Class[] paramString = new Class[1];
            paramString[0] = String.class;
            Class cls = Class.forName("hudson.security.HudsonPrivateSecurityRealm$Details");
            Method method = cls.getDeclaredMethod("fromPlainPassword", paramString);
            method.setAccessible(true);
            method.invoke(details, password);
        } catch (ClassNotFoundException e) {
            LOGGER.log(Level.WARNING, String.format("Failed to update the password for user %s in the Jenkins Internal Database", username), e);
        } catch (NoSuchMethodException e) {
            LOGGER.log(Level.WARNING, String.format("Failed to update the password for user %s in the Jenkins Internal Database", username), e);
        } catch (InvocationTargetException e) {
            LOGGER.log(Level.WARNING, String.format("Failed to update the password for user %s in the Jenkins Internal Database", username), e);
        } catch (IllegalAccessException e) {
            LOGGER.log(Level.WARNING, String.format("Failed to update the password for user %s in the Jenkins Internal Database", username), e);
        }
    }

    private static final long serialVersionUID = 1L;

    private static final Logger LOGGER = Logger.getLogger(ActiveDirectoryUserDetail.class.getName());
}