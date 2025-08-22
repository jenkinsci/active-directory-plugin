package hudson.plugins.active_directory;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;
import org.jvnet.hudson.test.recipes.LocalData;
import hudson.ExtensionList;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


@WithJenkins
class Security1389AdministrativeMonitorTest {

    private JenkinsRule j;

    @BeforeEach
    void beforeEach(JenkinsRule rule) {
        j = rule;
    }

    @Test
    @LocalData
    void testMonitorIsShownForExistingInstalls() throws Exception {
        assertThat(j.jenkins.getSecurityRealm().getClass(), is(ActiveDirectorySecurityRealm.class));
        Security1389AdministrativeMonitor adminMontor = ExtensionList.lookupSingleton(Security1389AdministrativeMonitor.class);
        assertTrue(adminMontor.isActivated(), "Admin monitor should be activated");
        j.submit(j.createWebClient().goTo("configureSecurity").getFormByName("config"));
        assertFalse(adminMontor.isActivated(), "Admin monitor should be activated");
    }

}
