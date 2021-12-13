package hudson.plugins.active_directory;

import org.junit.Rule;
import org.junit.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.recipes.LocalData;
import hudson.ExtensionList;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.MatcherAssert.assertThat;


public class Security1389AdministrativeMonitorTest {

    @Rule
    public JenkinsRule jr = new JenkinsRule();

    @Test
    @LocalData
    public void testMonitorIsShownForExistingInstalls() throws Exception {
        assertThat(jr.jenkins.getSecurityRealm().getClass(), is(ActiveDirectorySecurityRealm.class));
        Security1389AdministrativeMonitor adminMontor = ExtensionList.lookupSingleton(Security1389AdministrativeMonitor.class);
        assertTrue("Admin monitor should be activated", adminMontor.isActivated());
        jr.submit(jr.createWebClient().goTo("configureSecurity").getFormByName("config"));
        assertFalse("Admin monitor should be activated", adminMontor.isActivated());
    }

}
