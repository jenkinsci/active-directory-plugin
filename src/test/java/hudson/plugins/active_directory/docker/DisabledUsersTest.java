package hudson.plugins.active_directory.docker;

import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.GroupLookupStrategy;
import hudson.security.SecurityRealm;
import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.DisabledException;
import org.apache.commons.io.input.Tailer;
import org.apache.commons.io.input.TailerListenerAdapter;
import org.jenkinsci.test.acceptance.docker.DockerContainer;
import org.jenkinsci.test.acceptance.docker.DockerFixture;
import org.jenkinsci.test.acceptance.docker.DockerRule;
import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.Issue;
import org.jvnet.hudson.test.JenkinsRule;

import java.io.IOException;
import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

@Issue("JENKINS-55813")
public class DisabledUsersTest {

    @Rule
    public DockerRule<Image> docker = new DockerRule<>(Image.class);

    @Rule
    public JenkinsRule j = new JenkinsRule();

    private final static String AD_DOMAIN = "samdom.example.com";
    private final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
    private final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
    private final static int MAX_RETRIES = 30;

    private void setup() throws IOException, InterruptedException {
        Image image = docker.get();
        String dockerIp = image.ipBound(3268);
        int dockerPort = image.port(3268);
        ActiveDirectoryDomain domain = new ActiveDirectoryDomain(AD_DOMAIN, dockerIp + ':' + dockerPort, null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
        j.jenkins.setSecurityRealm(new ActiveDirectorySecurityRealm(
                null, Collections.singletonList(domain), null, null, null, null, GroupLookupStrategy.RECURSIVE, false, true, null, false));
        CountDownLatch exitStatusZero = new CountDownLatch(1);
        Tailer.create(image.getLogfile(), new TailerListenerAdapter() {
            @Override
            public void handle(String line) {
                if (line.contains("custom (exit status 0; expected)")) {
                    exitStatusZero.countDown();
                }
            }
        });
        assertTrue(exitStatusZero.await(5, TimeUnit.MINUTES));
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        for (int i = 0; i < MAX_RETRIES; i++) {
            try {
                if (securityRealm.loadUserByUsername("Fred") != null) {
                    return;
                }
            } catch (AuthenticationServiceException ignored) {
                TimeUnit.SECONDS.sleep(1);
            }
        }
    }

    @Test
    public void verifyBamBamAccountDisabled() throws IOException, InterruptedException {
        setup();
        // make sure other users are still valid
        SecurityRealm securityRealm = j.jenkins.getSecurityRealm();
        assertNotNull(securityRealm.loadUserByUsername("Fred"));
        assertNotNull(securityRealm.loadUserByUsername("Wilma"));
        assertNotNull(securityRealm.loadUserByUsername("Barney"));
        assertNotNull(securityRealm.loadUserByUsername("Betty"));
        assertThrows(DisabledException.class, () -> securityRealm.loadUserByUsername("Bam Bam"));
    }

    @DockerFixture(id = "ad-dc", ports = {135, 138, 445, 39, 464, 389, 3268}, udpPorts = {53}, matchHostPorts = true)
    public static class Image extends DockerContainer {
    }
}
