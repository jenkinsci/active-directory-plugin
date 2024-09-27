package hudson.plugins.active_directory.docker;

import java.net.InetAddress;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.acegisecurity.AuthenticationServiceException;
import org.acegisecurity.userdetails.UserDetails;
import org.hamcrest.MatcherAssert;
import org.hamcrest.Matchers;
import org.htmlunit.FailingHttpStatusCodeException;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.jvnet.hudson.test.FlagRule;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.LoggerRule;

import hudson.plugins.active_directory.ActiveDirectoryDomain;
import hudson.plugins.active_directory.ActiveDirectoryInternalUsersDatabase;
import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.CacheConfiguration;
import hudson.plugins.active_directory.DNSUtils;
import hudson.plugins.active_directory.GroupLookupStrategy;

import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.matchers.JUnitMatchers.containsString;

/**
 * Author: Nevin Sunny
 * Date: 26/09/24
 * Time: 7:25 pm
 */
public class FIPSActiveDirectoryLoginTest {

	@Rule(order = 0)
	public RequireDockerRule rdr = new RequireDockerRule();

	@Rule(order = 1)
	public ActiveDirectoryGenericContainer<?> docker = new ActiveDirectoryGenericContainer<>().withDynamicPorts();

	@Rule(order = 2) // start Jenkins after the container so that timeouts do not apply to container building.
	public JenkinsRule j = new JenkinsRule();

	@Rule
	public LoggerRule l = new LoggerRule();

	@ClassRule
	public static TestRule fip140Prop = FlagRule.systemProperty("jenkins.security.FIPS140.COMPLIANCE", "false");

	private final static String AD_DOMAIN = "samdom.example.com";
	private final static String AD_MANAGER_DN = "CN=Administrator,CN=Users,DC=SAMDOM,DC=EXAMPLE,DC=COM";
	private final static String AD_MANAGER_DN_PASSWORD = "ia4uV1EeKait";
	private final static int MAX_RETRIES = 30;
	private String dockerIp;
	private int dockerPort;

	@Before
	public void setup() throws Exception {
		String DNS_URLs = new URI("dns", null, InetAddress.getByName(docker.getHost()).getHostAddress(), Integer.parseInt(docker.getDNSPort()), null, null, null).toASCIIString();
		System.setProperty(DNSUtils.OVERRIDE_DNS_PROPERTY, DNS_URLs);

		dockerIp = docker.getHost();
		dockerPort = docker.getMappedPort(3268);
		ActiveDirectoryDomain activeDirectoryDomain = new ActiveDirectoryDomain(AD_DOMAIN,
		                                                                        dockerIp + ":" +  dockerPort , null, AD_MANAGER_DN, AD_MANAGER_DN_PASSWORD);
		List<ActiveDirectoryDomain> domains = new ArrayList<>(1);
		domains.add(activeDirectoryDomain);
		ActiveDirectorySecurityRealm activeDirectorySecurityRealm = new ActiveDirectorySecurityRealm(null, domains, null, null, null
				, null, GroupLookupStrategy.RECURSIVE, false, true, null, false, null, true);
		j.getInstance().setSecurityRealm(activeDirectorySecurityRealm);
		UserDetails userDetails = null;
		int i = 0;
		while (i < MAX_RETRIES && userDetails == null) {
			try {
				userDetails = j.jenkins.getSecurityRealm().loadUserByUsername("Fred");
			} catch (AuthenticationServiceException e) {
				Thread.sleep(1000);
			}
			i ++;
		}
	}

	@Test(expected = FailingHttpStatusCodeException.class)
	public void testLoginFailureWithShortPasswordInFIPSmode() throws Exception {
		// Try to login as Fred with a short password
		j.createWebClient().login("Fred", "ia4uV1EeKait");
	}

	@Test
	public void simpleLoginSuccessful() throws Exception {
		JenkinsRule.WebClient wc = j.createWebClient().login("Dino", "p1bfdrMsqyHhbAm");
		MatcherAssert.assertThat(wc.goToXml("whoAmI/api/xml").asXml().replaceAll("\\s+", "")
				, Matchers.containsString("<name>Dino</name>"));
	}
}
