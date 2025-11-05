package hudson.plugins.active_directory;

import java.util.ArrayList;
import java.util.List;

import org.htmlunit.FailingHttpStatusCodeException;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class ActiveDirectoryLoginInFIPSModeIntegrationTest {

    private static String fipsSystemProperty;

    private JenkinsRule j;

    @BeforeAll
    static void beforeAll() {
        fipsSystemProperty = System.setProperty("jenkins.security.FIPS140.COMPLIANCE", "true");
    }

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    @AfterAll
    static void afterAll() {
        if (fipsSystemProperty != null) {
            System.setProperty("jenkins.security.FIPS140.COMPLIANCE", fipsSystemProperty);
        } else {
            System.clearProperty("jenkins.security.FIPS140.COMPLIANCE");
        }
    }

    @Test
    void testLoginFailureWithShortPasswordInFIPSmode() {
        ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain("samdom.example.com", "localhost:3268"
            , "site", "Administrator", "verlargebindpassword", TlsConfiguration.JDK_TRUSTSTORE);
        List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
        domains.add(activeDirectoryDomain);
        ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null
            , null, GroupLookupStrategy.RECURSIVE, false, true, null, true, null, true);
        j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
        assertThrows(FailingHttpStatusCodeException.class, () ->
            // Try to login as Fred with a short password, it will throw an exception
            j.createWebClient().login("Fred", "ia4uV1EeKait"));
    }

}
