package hudson.plugins.active_directory;

/*
 * The MIT License
 *
 * Copyright (c) 2017, Felix Belzunce Arcos, CloudBees, Inc., and contributors
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

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.ManagementLink;
import hudson.security.Permission;
import hudson.security.SecurityRealm;
import hudson.util.ListBoxModel;
import jenkins.model.Jenkins;
import jenkins.util.ProgressiveRendering;
import net.sf.json.JSON;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.acegisecurity.userdetails.UserDetails;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.StaplerProxy;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

/**
 * ManagementLink to provide an Active Directory health status
 *
 * Intend to report a health status of the Active Directory Domain through
 * a ManagementLink on Jenkins.
 *  - Check if there is any broken Domain Controller on the farm
 *  - Report the connection time
 *  - Provides the User lookup time
 *
 * @since 2.1
 */
@Extension
public class ActiveDirectoryStatus extends ManagementLink implements StaplerProxy {

    @Override
    public String getIconFileName() {
        return "symbol-medkit-outline plugin-ionicons-api";
    }

    @Override
    public String getDisplayName() {
        return Messages._ActiveDirectoryStatus_ActiveDirectoryHealthStatus().toString();
    }

    @Override
    public String getUrlName() {
        return "ad-health";
    }

    @NonNull
    @Override
    public Permission getRequiredPermission() {
        return Jenkins.ADMINISTER;
    }

    /**
     * Get the list of domains configured on the Security Realm
     *
     * @return the Active Directory domains {@link ActiveDirectoryDomain}.
     */
    @Restricted(NoExternalUse.class)
    public static List<ActiveDirectoryDomain> getDomains() {
    SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
    if (securityRealm instanceof ActiveDirectorySecurityRealm) {
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
        return activeDirectorySecurityRealm.getDomains();
    }
    return Collections.emptyList();
    }

    /**
     * Start the Domain Controller Health checks against a specific domain
     *
     * @param domain to check the health
     * @return {@link ProgressiveRendering}
     */
    @Restricted(NoExternalUse.class)
    public ProgressiveRendering startDomainHealthChecks(final String domain) {
        return new ProgressiveRendering() {
            final List<ServerHealth> domainHealth = new LinkedList<>();
            @Override protected void compute() throws Exception {
                for (ActiveDirectoryDomain domainItem : getDomains()) {
                    if (canceled()) {
                        return;
                    }
                    if (domainItem.getName().equals(domain)) {
                        SecurityRealm securityRealm = Jenkins.getActiveInstance().getSecurityRealm();
                        if (securityRealm instanceof ActiveDirectorySecurityRealm) {
                            ActiveDirectorySecurityRealm activeDirectorySecurityRealm = (ActiveDirectorySecurityRealm) securityRealm;
                            List<SocketInfo> servers = activeDirectorySecurityRealm.getDescriptor().obtainLDAPServer(domainItem);
                            for (SocketInfo socketInfo : servers) {
                                ServerHealth serverHealth = new ServerHealth(socketInfo);
                                domainHealth.add(serverHealth);
                            }
                        }
                    }
                }
            }
            @Override protected synchronized JSON data() {
                JSONArray r = new JSONArray();
                for (ServerHealth serverHealth : domainHealth) {
                    r.add(serverHealth);
                }
                domainHealth.clear();
                return new JSONObject().accumulate("domainHealth", r);
            }
        };
    }

    @Restricted(NoExternalUse.class)
    public ListBoxModel doFillDomainsItems() {
        ListBoxModel model = new ListBoxModel();
        for (ActiveDirectoryDomain domain : getDomains()) {
            model.add(domain.getName());
        }
        return model;
    }

    @Override
    public Object getTarget() {
        Jenkins.get().checkPermission(getRequiredPermission());
        return this;
    }

    @NonNull
    @Override
    public Category getCategory() {
        return Category.STATUS; // AD would be SECURITY, but here it's more a "health status" indeed.
    }

    /**
     * ServerHealth of a SocketInfo
     */
    @SuppressFBWarnings("UUF_UNUSED_FIELD")
    public static class ServerHealth extends SocketInfo {
        /**
         * true if able to retrieve the user details from Jenkins
         */
        private boolean canLogin;

        /**
         * Time for a Socket to reach out the target server
         */
        private long pingExecutionTime;

        /**
         * Total amount of time for Jenkins to perform SecurityRealm.loadUserByUsername
         */
        private long loginExecutionTime;

        public ServerHealth(SocketInfo socketInfo) {
            super(socketInfo.getHost(), socketInfo.getPort());
            this.pingExecutionTime = this.computePingExecutionTime();
            this.loginExecutionTime = this.computeLoginExecutionTime();
        }

        @Restricted(NoExternalUse.class)
        public boolean isCanLogin() {
            return true ? loginExecutionTime != -1 : false;
        }

        @Restricted(NoExternalUse.class)
        public long getPingExecutionTime() {
            return pingExecutionTime;
        }

        @Restricted(NoExternalUse.class)
        public long getLoginExecutionTime() {
            return loginExecutionTime;
        }

        /**
         * Retrieve the time for Jenkins to perform SecurityRealm.loadUserByUsername
         *
         * @return -1 in case the user could not be retrieved
         */
        private long computeLoginExecutionTime() {
            String username = Jenkins.getAuthentication().getName();
            long t0 = System.currentTimeMillis();
            UserDetails userDetails = Jenkins.getActiveInstance().getSecurityRealm().loadUserByUsername(username);
            long t1 = System.currentTimeMillis();
            return  (userDetails!=null) ? (t1 - t0) : -1;
        }

        /**
         * Retrieve the time to to establish a Socket connection with the AD server
         *
         * @return -1 in case the connection failed
         */
        private long computePingExecutionTime() {
            try {
                long t0 = System.currentTimeMillis();
                super.connect().close();
                long t1 = System.currentTimeMillis();
                return t1-t0;
            } catch (IOException e) {
            }
            return -1;
        }
    }

}
