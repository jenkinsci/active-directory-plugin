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
import hudson.model.AbstractDescribableImpl;
import hudson.model.Descriptor;
import org.apache.commons.lang.StringUtils;
import org.kohsuke.accmod.Restricted;
import org.kohsuke.accmod.restrictions.NoExternalUse;
import org.kohsuke.stapler.DataBoundConstructor;

import java.io.Serializable;

/**
 * Represents an Active Directory domain with its Domain Controllers
 *
 * Easily allows you to match Domains with Domains Controllers
 *
 * @since 2.0
 */
public class ActiveDirectoryDomain extends AbstractDescribableImpl<ActiveDirectoryDomain> implements Serializable {

    /**
     * Domain name
     *
     * <p>
     * When this plugin is used on Windows, this field is null, and we use ADSI
     * and ADO through com4j to perform authentication.
     *
     * <p>
     * OTOH, when this plugin runs on non-Windows, this field must be non-null,
     * and we'll use LDAP for authentication.
     */
    public String name;

    /**
     * If non-null, Jenkins will try to connect at this server at the first priority, before falling back to
     * discovered DNS servers.
     */
    public String servers;

    @DataBoundConstructor
    public ActiveDirectoryDomain(String name, String servers) {
        this.name = name;
        // Append default port if not specified
        servers = fixEmpty(servers);
        if (servers != null) {
            String[] serversArray = servers.split(",");
            for (int i = 0; i < serversArray.length; i++) {
                if (!serversArray[i].contains(":")) {
                    serversArray[i] += ":3268";
                }
            }
            servers = StringUtils.join(serversArray, ",");
        }
        this.servers = servers;
    }

    @Restricted(NoExternalUse.class)
    public String getName() {
        return name;
    }

    @Restricted(NoExternalUse.class)
    public String getServers() {
        return servers;
    }

    /**
     * Convert empty string to null.
     */
    public static String fixEmpty(String s) {
        if(s==null || s.length()==0)    return null;
        return s;
    }

    @Extension
    public static class DescriptorImpl extends Descriptor<ActiveDirectoryDomain> {
        @Override
        public String getDisplayName() { return ""; }
    }
}
