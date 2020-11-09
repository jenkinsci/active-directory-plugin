/*
 * The MIT License
 *
 * Copyright (c) 2020, CloudBees, Inc.
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

import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;

import javax.annotation.CheckForNull;
import javax.annotation.Nonnull;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.concurrent.TimeUnit;

/**
 * Ease all the computations required to determine the user account optional attributes for creating
 * the UserDetails that will be used by the SecurityRealm. These attribute checks can be disabled by setting the
 * system property {@code hudson.plugins.active_directory.ActiveDirectorySecurityRealm.disableUserPolicyEnforcement} to
 * {@code true} (or setting the value of {@link ActiveDirectorySecurityRealm#DISABLE_USER_POLICY_ENFORCEMENT} in the
 * script console).
 *
 * @see <a href="https://issues.jenkins.io/browse/JENKINS-55813">JENKINS-55813</a>
 */
@Restricted(NoExternalUse.class)
public class UserAttributesHelper {
    // https://support.microsoft.com/en-us/help/305144/how-to-use-the-useraccountcontrol-flags-to-manipulate-user-account-pro
    // https://docs.microsoft.com/en-us/windows/win32/adschema/a-useraccountcontrol
    private static final String ATTR_USER_ACCOUNT_CONTROL = "userAccountControl";
    // https://docs.microsoft.com/en-us/windows/win32/adschema/a-accountexpires
    private static final String ATTR_ACCOUNT_EXPIRES = "accountExpires";
    // for Windows Server 2003-based domain
    // https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-user-account-control-computed
    private static final String ATTR_USER_ACCOUNT_CONTROL_COMPUTED = "msDS-User-Account-Control-Computed";
    // for ADAM (Active Directory Application Mode), replace the ADS_UF_DISABLED
    // https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-useraccountdisabled
    private static final String ATTR_USER_ACCOUNT_DISABLED = "msDS-UserAccountDisabled";
    // for ADAM, replace the ADS_UF_PASSWORD_EXPIRED
    // https://docs.microsoft.com/en-us/windows/win32/adschema/a-msds-userpasswordexpired
    private static final String ATTR_USER_PASSWORD_EXPIRED = "msDS-UserPasswordExpired";

    // https://docs.microsoft.com/en-us/windows/desktop/adschema/a-accountexpires
    // constant names follow the code in Iads.h
    private static final long ACCOUNT_NO_EXPIRATION = 0x7FFF_FFFF_FFFF_FFFFL;
    private static final int ADS_UF_DISABLED = 0x0002;
    private static final int ADS_UF_LOCK_OUT = 0x0010;
    private static final int ADS_DONT_EXPIRE_PASSWORD = 0x1_0000;
    private static final int ADS_UF_PASSWORD_EXPIRED = 0x80_0000;

    public static boolean checkIfUserIsEnabled(@Nonnull Attributes user) {
        if (ActiveDirectorySecurityRealm.DISABLE_USER_POLICY_ENFORCEMENT) {
            return true;
        }

        Integer uac = getUserAccountControl(user);
        if (uac != null && (uac & ADS_UF_DISABLED) == ADS_UF_DISABLED) {
            return false;
        }

        String disabled = getStringAttribute(user, ATTR_USER_ACCOUNT_DISABLED);
        return !"true".equalsIgnoreCase(disabled);
    }

    public static boolean checkIfAccountNonExpired(@Nonnull Attributes user) {
        if (ActiveDirectorySecurityRealm.DISABLE_USER_POLICY_ENFORCEMENT) {
            return true;
        }

        String accountExpirationDate = getStringAttribute(user, ATTR_ACCOUNT_EXPIRES);
        if (accountExpirationDate != null) {
            long expirationAsLong = Long.parseLong(accountExpirationDate);
            if (expirationAsLong == 0L || expirationAsLong == ACCOUNT_NO_EXPIRATION) {
                return true;
            }

            long nowIn100NsFromJan1601 = getWin32EpochHundredNanos();
            boolean expired = expirationAsLong < nowIn100NsFromJan1601;
            return !expired;
        }

        return true;
    }

    // documentation: https://docs.microsoft.com/en-us/windows/desktop/adschema/a-accountexpires
    // code inspired by https://community.oracle.com/thread/1157460
    private static long getWin32EpochHundredNanos() {
        GregorianCalendar win32Epoch = new GregorianCalendar(1601, Calendar.JANUARY, 1);
        Date win32EpochDate = win32Epoch.getTime();
        // note that 1/1/1601 will be returned as a negative value by Java
        GregorianCalendar today = new GregorianCalendar();
        Date todayDate = today.getTime();
        long timeSinceWin32EpochInMs = todayDate.getTime() - win32EpochDate.getTime();
        // milliseconds to microseconds => x1000
        long timeSinceWin32EpochInNs = TimeUnit.NANOSECONDS.convert(timeSinceWin32EpochInMs, TimeUnit.MILLISECONDS);
        // but we need in 100 ns, as 1000 ns = 1 micro, add a x10 factor
        return timeSinceWin32EpochInNs * 100;
    }

    public static boolean checkIfCredentialsAreNonExpired(@Nonnull Attributes user) {
        if (ActiveDirectorySecurityRealm.DISABLE_USER_POLICY_ENFORCEMENT) {
            return true;
        }

        Integer uac = getUserAccountControl(user);
        if (uac != null) {
            if ((uac & ADS_DONT_EXPIRE_PASSWORD) == ADS_DONT_EXPIRE_PASSWORD) {
                return true;
            }
            if ((uac & ADS_UF_PASSWORD_EXPIRED) == ADS_UF_PASSWORD_EXPIRED) {
                return false;
            }
        }

        String expired = getStringAttribute(user, ATTR_USER_PASSWORD_EXPIRED);
        return !"true".equalsIgnoreCase(expired);
    }

    public static boolean checkIfAccountNonLocked(@Nonnull Attributes user) {
        if (ActiveDirectorySecurityRealm.DISABLE_USER_POLICY_ENFORCEMENT) {
            return true;
        }

        Integer uac = getUserAccountControl(user);
        if (uac != null) {
            return (uac & ADS_UF_LOCK_OUT) != ADS_UF_LOCK_OUT;
        }

        return true;
    }

    private static @CheckForNull Integer getUserAccountControl(@Nonnull Attributes user) {
        String uac = getStringAttribute(user, ATTR_USER_ACCOUNT_CONTROL);
        String computedUac = getStringAttribute(user, ATTR_USER_ACCOUNT_CONTROL_COMPUTED);
        if (uac == null) {
            return computedUac == null ? null : Integer.parseInt(computedUac);
        } else if (computedUac == null) {
            return Integer.parseInt(uac);
        } else {
            return Integer.parseInt(uac) | Integer.parseInt(computedUac);
        }
    }

    static @CheckForNull String getStringAttribute(@Nonnull Attributes user, @Nonnull String name) {
        Attribute a = user.get(name);
        if (a == null || a.size() == 0) {
            return null;
        }
        try {
            Object v = a.get();
            return v == null ? null : v.toString();
        } catch (NamingException e) {
            return null;
        }
    }
}
