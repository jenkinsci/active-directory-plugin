package hudson.plugins.active_directory;

/*
 * The MIT License
 *
 * Copyright (c) 2016, Felix Belzunce Arcos, CloudBees, Inc., and contributors
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

import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.SecurityRealm;
import jenkins.model.Jenkins;

import java.util.List;

/**
 * Jenkins ManagementLink to provide the Active Directory status
 *
 * Intend to provide useful information about the current set-up
 * and if might be anyway to improve it.
 *
 * @since 2.1
 */
@Extension
public class ActiveDirectoryStatus extends ManagementLink {

    @Override
    public String getIconFileName() {
        return "/plugin/active-directory/images/icon.png";
    }

    @Override
    public String getDisplayName() {
        return "Active Directory Status";
    }

    @Override
    public String getUrlName() {
        return "ad";
    }

    /**
     * Gets the singleton of the {@link ActiveDirectorySecurityRealm}.
     *
     * @return the singleton of the {@link ActiveDirectorySecurityRealm}.
     */
    public static List<ActiveDirectoryDomain> getDomains() {
        SecurityRealm securityRealm = Jenkins.getInstance().getSecurityRealm();
        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
            return activeDirectorySecurityRealm.getDomains();
        }
        return null;
    }
}
