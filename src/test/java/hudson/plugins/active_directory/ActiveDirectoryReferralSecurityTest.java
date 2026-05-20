package hudson.plugins.active_directory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.Hashtable;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;


@WithJenkins
class ActiveDirectoryReferralSecurityTest {

    private boolean originalIgnoreReferrals;

    private JenkinsRule j;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
        originalIgnoreReferrals = ActiveDirectorySecurityRealm.DescriptorImpl.IGNORE_REFERRALS;
    }

    @AfterEach
    void afterEach() {
        ActiveDirectorySecurityRealm.DescriptorImpl.IGNORE_REFERRALS = originalIgnoreReferrals;
    }

    @Test
    @Issue("SECURITY-3659")
    void referralFollowingDisabledByDefault() throws Exception {
        // Do not override the field — assert that the compiled default is safe
        assertRogueServerNotContacted();
    }

    @Test
    @Issue("SECURITY-3659")
    void referralFollowingEnabledWhenEscapeHatchSet() throws Exception {
        ActiveDirectorySecurityRealm.DescriptorImpl.IGNORE_REFERRALS = false;
        assertRogueServerContacted();
    }

    private void assertRogueServerNotContacted() throws Exception {
        AtomicBoolean rogueConnectionAttempted = performReferralTest();
        assertFalse(rogueConnectionAttempted.get(),
                "Rogue server must not receive a connection when referral following is disabled");
    }

    private void assertRogueServerContacted() throws Exception {
        AtomicBoolean rogueConnectionAttempted = performReferralTest();
        assertTrue(rogueConnectionAttempted.get(),
                "Rogue server should receive a connection when referral following is enabled");
    }

    private AtomicBoolean performReferralTest() throws Exception {
        try (ServerSocket rogueServer = new ServerSocket(0)) {
            rogueServer.setSoTimeout(10000);
            int roguePort = rogueServer.getLocalPort();

            AtomicBoolean rogueConnectionAttempted = new AtomicBoolean(false);
            Thread rogueAcceptor = new Thread(() -> {
                try (Socket s = rogueServer.accept()) {
                    rogueConnectionAttempted.set(true);
                } catch (IOException ignored) {
                }
            });
            rogueAcceptor.setDaemon(true);
            rogueAcceptor.start();

            try (ServerSocket ldapServer = new ServerSocket(0)) {
                int ldapPort = ldapServer.getLocalPort();

                Thread ldapHandler = new Thread(() -> {
                    try (Socket client = ldapServer.accept()) {
                        byte[] buf = new byte[1024];
                        client.getInputStream().read(buf);
                        OutputStream out = client.getOutputStream();
                        out.write(buildLdapBindResponse());
                        out.flush();
                        client.getInputStream().read(buf);
                        out.write(buildLdapSearchResultReference(roguePort));
                        out.write(buildLdapSearchResultDone());
                        out.flush();
                        Thread.sleep(5000);
                    } catch (Exception ignored) {
                    }
                });
                ldapHandler.setDaemon(true);
                ldapHandler.start();

                ActiveDirectoryDomain domain = new ActiveDirectoryDomain(
                        "test.local", "localhost:" + ldapPort, null, "CN=admin,DC=test,DC=local", "password");
                ActiveDirectorySecurityRealm realm = new ActiveDirectorySecurityRealm(
                        null, Collections.singletonList(domain), null, null, null, null,
                        GroupLookupStrategy.RECURSIVE, false, true, null, false, null, null);
                j.jenkins.setSecurityRealm(realm);

                try {
                    DirContext ctx = realm.getDescriptor().bind(
                            "CN=admin,DC=test,DC=local", "password",
                            Collections.singletonList(new SocketInfo("localhost", ldapPort)),
                            new Hashtable<>(),
                            TlsConfiguration.TRUST_ALL_CERTIFICATES, false, false);
                    SearchControls controls = new SearchControls();
                    controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
                    NamingEnumeration<?> results = ctx.search("DC=test,DC=local", "(uid=testuser)", controls);
                    while (results.hasMore()) {
                        results.next();
                    }
                    ctx.close();
                } catch (Exception e) {
                    // Expected — fake LDAP server doesn't fully implement the protocol
                }

                rogueAcceptor.join(10000);

                return rogueConnectionAttempted;
            }
        }
    }

    private static byte[] buildLdapBindResponse() {
        return new byte[]{
                0x30, 0x0c,
                0x02, 0x01, 0x01,
                0x61, 0x07,
                0x0a, 0x01, 0x00,
                0x04, 0x00,
                0x04, 0x00
        };
    }

    private static byte[] buildLdapSearchResultReference(int roguePort) {
        String referralUrl = "ldap://localhost:" + roguePort + "/dc=evil,dc=com";
        byte[] urlBytes = referralUrl.getBytes();
        int innerLen = 2 + urlBytes.length;
        int outerLen = 2 + 1 + 2 + innerLen;
        ByteBuffer buf = ByteBuffer.allocate(2 + outerLen);
        buf.put((byte) 0x30);
        buf.put((byte) outerLen);
        buf.put((byte) 0x02); buf.put((byte) 0x01); buf.put((byte) 0x02);
        buf.put((byte) 0x73);
        buf.put((byte) innerLen);
        buf.put((byte) 0x04);
        buf.put((byte) urlBytes.length);
        buf.put(urlBytes);
        return buf.array();
    }

    private static byte[] buildLdapSearchResultDone() {
        return new byte[]{
                0x30, 0x0c,
                0x02, 0x01, 0x02,
                0x65, 0x07,
                0x0a, 0x01, 0x00,
                0x04, 0x00,
                0x04, 0x00
        };
    }
}
