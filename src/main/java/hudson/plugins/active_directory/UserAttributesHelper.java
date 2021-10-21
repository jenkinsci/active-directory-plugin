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

import org.acegisecurity.AccountExpiredException;
import org.acegisecurity.CredentialsExpiredException;
import org.acegisecurity.DisabledException;
import org.acegisecurity.LockedException;

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
 * the UserDetails that will be used by the SecurityRealm.
 *
 * @see <a href="https://issues.jenkins.io/browse/JENKINS-55813">JENKINS-55813</a>
 */
class UserAttributesHelper {
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

    public static void checkIfUserIsEnabled(@Nonnull Attributes user) {
        Integer uac = getUserAccountControl(user);
        if (uac != null && (uac & ADS_UF_DISABLED) == ADS_UF_DISABLED) {
            throw new DisabledException(Messages.UserDetails_Disabled(user.get("dn")));
        }

        String disabled = getStringAttribute(user, ATTR_USER_ACCOUNT_DISABLED);
        if ("true".equalsIgnoreCase(disabled)) {
            throw new DisabledException(Messages.UserDetails_Disabled(user.get("dn")));
        }
    }

    public static void checkIfAccountNonExpired(@Nonnull Attributes user) {
        String accountExpirationDate = getStringAttribute(user, ATTR_ACCOUNT_EXPIRES);
        if (accountExpirationDate != null) {
            long expirationAsLong = Long.parseLong(accountExpirationDate);
            if (expirationAsLong == 0L || expirationAsLong == ACCOUNT_NO_EXPIRATION) {
                return;
            }

            long nowIn100NsFromJan1601 = getWin32EpochHundredNanos();
            boolean expired = expirationAsLong < nowIn100NsFromJan1601;
            if (expired) {
                throw new AccountExpiredException(Messages.UserDetails_Expired(user.get("dn"), accountExpirationDate));
            }
        }
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

    public static void checkIfCredentialsAreNonExpired(@Nonnull Attributes user) {
        Integer uac = getUserAccountControl(user);
        if (uac != null) {
            if ((uac & ADS_DONT_EXPIRE_PASSWORD) == ADS_DONT_EXPIRE_PASSWORD) {
                return;
            }
            if ((uac & ADS_UF_PASSWORD_EXPIRED) == ADS_UF_PASSWORD_EXPIRED) {
                throw new CredentialsExpiredException(Messages.UserDetails_CredentialsExpired(user.get("dn")));
            }
        }

        String expired = getStringAttribute(user, ATTR_USER_PASSWORD_EXPIRED);
        if ("true".equalsIgnoreCase(expired)) {
            throw new CredentialsExpiredException(Messages.UserDetails_CredentialsExpired(user.get("dn")));
        }
    }

    public static void checkIfAccountNonLocked(@Nonnull Attributes user) {
        Integer uac = getUserAccountControl(user);
        if (uac != null && (uac & ADS_UF_LOCK_OUT) == ADS_UF_LOCK_OUT) {
            throw new LockedException(Messages.UserDetails_Locked(user.get("dn")));
        }
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
