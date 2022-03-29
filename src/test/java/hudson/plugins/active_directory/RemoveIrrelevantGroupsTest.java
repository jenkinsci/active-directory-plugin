/*
 * The MIT License
 *
 * Copyright (c) 2014 Sony Mobile Communications Inc. All rights reserved.
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

import hudson.security.AuthorizationStrategy;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.jvnet.hudson.test.JenkinsRule;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for the "Remove Irrelevant Groups" feature.
 *
 * @author Fredrik Persson &lt;fredrik6.persson@sonymobile.com&gt;
 */
public class RemoveIrrelevantGroupsTest {

    @Rule
    public JenkinsRule jenkinsRule = new JenkinsRule();

    /**
     * Sets up Jenkins with an {@link ActiveDirectorySecurityRealm}.
     */
    @Before
    public void setUp() {
        ActiveDirectorySecurityRealm securityRealm = new ActiveDirectorySecurityRealm("domain.com", null, null,
                null, null, GroupLookupStrategy.AUTO, true);
        jenkinsRule.getInstance().setSecurityRealm(securityRealm);
    }

    /**
     * Makes Jenkins.getInstance().getAuthorizationStrategy.getGroups()
     * return argument groups.
     */
    private void setUpJenkinsUsedGroups(String... groups) {
        Set<String> usedGroups = new HashSet<>();
        for (String group : groups) {
            usedGroups.add(group);
        }

        AuthorizationStrategy authorizationStrategy = mock(AuthorizationStrategy.class);
        when(authorizationStrategy.getGroups()).thenReturn(usedGroups);
        jenkinsRule.getInstance().setAuthorizationStrategy(authorizationStrategy);
    }

    /**
     * Verifies that only the relevant user groups are set when calling the
     * constructor for {@link ActiveDirectoryUserDetail} and there are
     * some relevant groups.
     */
    @Test
    public void testSomeGroupsAreRelevant() {
        setUpJenkinsUsedGroups("UsedGroup-1", "UsedGroup-2");

        GrantedAuthority[] userGroups = {
                new GrantedAuthorityImpl("UsedGroup-1"),
                new GrantedAuthorityImpl("UsedGroup-2"),
                new GrantedAuthorityImpl("UnusedGroup")};

        ActiveDirectoryUserDetail user = new ActiveDirectoryUserDetail("Username", null,
        true, true, true, true, userGroups, null, null, null);

        GrantedAuthority[] relevantUserGroups = Arrays.copyOf(userGroups, 2); //The first two are relevant
        assertArrayEquals(relevantUserGroups, user.getAuthorities());
    }

    /**
     * Verifies that no user groups are set when calling the
     * constructor for {@link ActiveDirectoryUserDetail} and there are no
     * relevant groups.
     */
    @Test
    public void testNoGroupsAreRelevant() {
        setUpJenkinsUsedGroups("UsedGroup-1", "UsedGroup-2");

        GrantedAuthority[] userGroups = {
                new GrantedAuthorityImpl("UnusedGroup")};

        ActiveDirectoryUserDetail user = new ActiveDirectoryUserDetail("Username", null,
                true, true, true, true, userGroups, null, null, null);

        assertEquals(0, user.getAuthorities().length);
    }

    /**
     * Verifies that all argument groups are set when {@link AuthorizationStrategy#getGroups()}
     * returns an empty list.
     */
    @Test
    public void testNoGroupsAreRegistered() {
        setUpJenkinsUsedGroups(); //No registered groups by the AuthorizationStrategy.

        GrantedAuthority[] userGroups = {
                new GrantedAuthorityImpl("UnusedGroup")};

        ActiveDirectoryUserDetail user = new ActiveDirectoryUserDetail("Username", null,
                true, true, true, true, userGroups, null, null, null);

        assertArrayEquals(userGroups, user.getAuthorities());
    }

}
