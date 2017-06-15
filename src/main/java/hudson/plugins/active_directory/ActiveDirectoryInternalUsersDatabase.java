package hudson.plugins.active_directory;

/*
 * The MIT License
 *
 * Copyright (c) 2017-2018, Félix Belzunce Arcos, CloudBees, Inc., and contributors
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

import org.kohsuke.stapler.DataBoundConstructor;

/**
 * Class to fall back into the Jenkins Internal Database inc ase of any {@link javax.naming.CommunicationException}
 */
public class ActiveDirectoryInternalUsersDatabase {

    /**
     * The Jenkins internal user you would like to fall back in order to access Jenkins
     * in case of a {@link javax.naming.NamingException}
     */
    private final String jenkinsInternalUser;

    @DataBoundConstructor
    public ActiveDirectoryInternalUsersDatabase(String jenkinsInternalUser) {
        this.jenkinsInternalUser = jenkinsInternalUser;
    }

    public String getJenkinsInternalUser() {
        return jenkinsInternalUser;
    }
}
