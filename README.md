Active Directory plugin for Jenkins
===================================

[![Build Status](https://ci.jenkins.io/job/Plugins/job/active-directory-plugin/job/master/badge/icon)](https://ci.jenkins.io/job/Plugins/job/active-directory-plugin/job/master/)
[![Jenkins Plugin](https://img.shields.io/jenkins/plugin/v/active-directory.svg)](https://plugins.jenkins.io/active-directory/)
[![GitHub release](https://img.shields.io/github/release/jenkinsci/active-directory.svg?label=changelog)](https://github.com/jenkinsci/active-directory-plugin/releases/latest/)
[![Jenkins Plugin Installs](https://img.shields.io/jenkins/plugin/i/active-directory.svg?color=blue)](https://plugins.jenkins.io/active-directory/)

| Plugin Information                                                                                            |
|---------------------------------------------------------------------------------------------------------------|
| View Active Directory [on the plugin site](https://plugins.jenkins.io/active-directory) for more information. |

Older versions of this plugin may not be safe to use. Please review the following warnings before using an older version:

-   [Improper certificate validation](https://jenkins.io/security/advisory/2019-01-28/#SECURITY-859)
-   [Man-in-the-middle vulnerability due to missing certificate check](https://jenkins.io/security/advisory/2017-03-20/)

With this plugin, you can configure Jenkins to authenticate the username and the password through Active Directory.This plugin internally uses two very different implementations, depending on whether Jenkins is running on Windows or non-Windows and if you specify a domain.

-   If Jenkins is running on a Windows machine and you do not specify a domain, that machine must be a member of the domain you wish to authenticate against. Jenkins uses ADSI to figure out all the details, so no additional configuration is required.
-   If Jenkins is running on a non-Windows machine (or you specify one or more domains), then you need to tell Jenkins the name of Active Directory domain(s) to authenticate with. Jenkins then uses DNS SRV records and LDAP service of Active Directory to authenticate users.

Jenkins recognizes all the groups in Active Directory that the user belongs to, so you can use those to make authorization decisions (for example you can choose the matrix-based security as the authorization strategy and perhaps allow "Domain Admins" to administer Jenkins).

#### Active Directory Health Status

Since the version 2.5 the AD plugin adds a ManagementLink to report a Health Status about the Domain and Domain controllers. In order to correctly use this feature, you should be logged-in into the instance and the cache should be disabled. Then, you will get:

-   The Domain health
    -   DNS resolution
    -   Global Catalog
    -   Ldap Catalog
-   The Domain Controller Health
    -   If the user can login into the DC
    -   The Connection time
    -   The total time in the lookup process

![](docs/images/ad-managementLink-view.png)

#### Fall-back user

Since the version 2.5 of the AD plugin, you can define a user to fall back in case there is a communication issue between Jenkins and the AD server. On this way, this admin user can be used to continue administering Jenkins in case of communication issues, where usually you were following the link [Disable security](https://wiki.jenkins.io/display/JA/Disable+security). The password of this user is automatically synced with the Jenkins Internal Database by this feature. In order to configure this new feature you should enable \*Use Jenkins Internal Database\* in the AD configuration under Manage Jenkins → Configure Global Security and specify a SINGLE user by its username.

  
![](docs/images/ad-internalJenkinsUser.png)

#### [SECURITY-251](https://wiki.jenkins.io/display/JENKINS/SECURITY-251) Active Directory Plugin did not verify certificate of AD server

From versions \< 2.3 the Active Directory Plugin did not verify certificates of the Active Directory server, thereby enabling Man-in-the-Middle attacks. From version 2.3 the plugin allows to choose between a secured option and continue trusting all the certificates.

In case there was an Active Directory configured previously on the instance after upgrading the plugin the following Administrative Monitor will appear.

![](docs/images/ad-tls-administrative-monitor.png)

To avoid this message to appear again in case you would like to continue trusting all the certificates, the only thing you need to do is to go to Manage Jenkins -\> Configure Global Security and hit the button saved. Then, the Administrative Monitor should not appear anymore as you acknowledge that you are fine by continuing on this TrustAllCertificates mode.

However, for security reasons the recommendation is to move to the secured option. This can be done on the Active Directory configuration under the Advanced button by selecting TLS configuration: JDK TrustStore. When this option is enabled notice that then in case your Active Directory server is using a self sign certificate, which usually is the case, you must then:

![](docs/images/ad-tls-selector.png)

1\. Export the certificate from your AD server  
2\. Create a custom keystore from the JVM keystore

For Unix:

    CUSTOM_KEYSTORE=$JENKINS_HOME/.keystore/
    mkdir -p $CUSTOM_KEYSTORE
    cp $JAVA_HOME/jre/lib/security/cacerts $CUSTOM_KEYSTORE

For Windows:

    CUSTOM_KEYSTORE=%JENKINS_HOME%\.keystore\
    md %CUSTOM_KEYSTORE%
    copy %JAVA_HOME%\jre\lib\security\cacerts %CUSTOM_KEYSTORE%

3\. Import your certificate

For Unix:

    $JAVA_HOME/bin/keytool -keystore $JENKINS_HOME/.keystore/cacerts \
      -import -alias <YOUR_ALIAS_HERE> -file <YOUR_CA_FILE>

For Windows:

    %JAVA_HOME%\bin\keytool -keystore %JENKINS_HOME%\.keystore\cacerts -import -alias <YOUR_ALIAS_HERE> -file <YOUR_CA_FILE>

4\. Add the certificate to the Jenkins startup parameters:

The following JAVA properties should be added depending on your OS:

For Unix:

    -Djavax.net.ssl.trustStore=$JENKINS_HOME/.keystore/cacerts \
    -Djavax.net.ssl.trustStorePassword=changeit

For Windows:

    -Djavax.net.ssl.trustStore=%JENKINS_HOME%\.keystore\cacerts
    -Djavax.net.ssl.trustStorePassword=changeit

5\. Follow section Securing access to Active Directory servers to enable LDAPS

Disaster recovery: In case that after all of this you cannot login anymore, you should enable the logging on the plugin to understand why it is failing. In case that after you enable the secured option you cannot login on the instance anymore, you might want to quickly fallback to the previous status specially on production environments. You can easily do this by going to $JENKINS\_HOME/config.xml and under the section \<securityRealm class="hudson.plugins.active\_directory ActiveDirectorySecurityRealm" revert the tlsConfiguration to the previous status. A restart is needed.

    <tlsConfiguration>TRUST_ALL_CERTIFICATES</tlsConfiguration>

#### IMPORTANT Active Directory 2.0 - Better multi-domains support

The latest release of the Active Directory plugin provides you a better multi-domains support.

![](docs/images/ad-multi-domains.png)

Users running Active Directory plugin 1.49 might be locked in case they were using Multiple Domains with Multiple Domains Controllers - this is the side effect of fixing the possibility of locking an account when not using Domain Controllers by a simple password mistake. The problematic
[PR is here](https://github.com/jenkinsci/active-directory-plugin/pull/41).

In case this is the case and you are locked, you just need to go to $JENKINS\_HOME/config.xml and modify the \<servers\> section deleting the ones which are not a member of the corresponding domain.

    <securityRealm class="hudson.plugins.active_directory.ActiveDirectorySecurityRealm" plugin="active-directory@2.0">
        <domains>
          <hudson.plugins.active__directory.ActiveDirectoryDomain>
            <name>support-cloudbees-2.com</name>
            <servers>192.168.1.32:3268,192.168.1.33:3268</servers>
          </hudson.plugins.active__directory.ActiveDirectoryDomain>
          <hudson.plugins.active__directory.ActiveDirectoryDomain>
            <name>support-cloudbees.com</name>
            <servers>192.168.1.16:3268,192.168.1.17:3268</servers>
          </hudson.plugins.active__directory.ActiveDirectoryDomain>
        </domains>
        <bindName>bindUser</bindName>
        <bindPassword>dk5ISc2eOWTrub9YFUkfFzSsUvy061yV4/Udna+0Wa0=</bindPassword>
        <groupLookupStrategy>RECURSIVE</groupLookupStrategy>
        <removeIrrelevantGroups>false</removeIrrelevantGroups>
      </securityRealm>

A restart of the instance is needed after this.

#### Securing access to Active Directory servers

There are two possible options for securing access to Active Directory:

##### A.- LDAP + StartTLS (by default) 

Active Directory plugin performs [TLS upgrade](http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol#StartTLS) (StartTLS), it connects to domain controllers through insecure LDAP, then from within the LDAP protocol it "upgrades" the connection to use [TLS](https://en.wikipedia.org/wiki/Transport_Layer_Security), achieving the same degree of confidentiality and server authentication as LDAPS does.

As the server needs to have a valid X509 certificate for this to function, if the server fails to do TLS upgrade, the communication continues to happen over insecure LDAP. In other words, in the environment that the server supports this, it'll automatically use a properly secure connection. See [TechNet article](http://social.technet.microsoft.com/wiki/contents/articles/2980.ldap-over-ssl-ldaps-certificate.aspx) for how to install a certificate on your AD domain controllers to enable this feature.

To verify if the connection is upgraded or not, see [Logging](https://wiki.jenkins.io/display/JENKINS/Logging) and adds a logger to `hudson.plugins.active_directory.ActiveDirectorySecurityRealm` for FINE or above. Search for "TLS" in the log messages. 

##### B.- LDAPS

On the other hand, if you wish on using LDAPS, you should set:

-   System property `-Dhudson.plugins.active\_directory.ActiveDirectorySecurityRealm.forceLdaps=true` as a startup parameter to force Jenkins to start a connection with LDAPS. 
-   Use secured port is defined 636 or 3269
    (`your.hostname.com\[\|:636\|:3269\]`)

 Note that
`-Dhudson.plugins.active\_directory.ActiveDirectorySecurityRealm.forceLdaps=true` skips the default LDAP + TLS upgrade.

#### Override domain controllers

This plugin follows the standard lookup procedure to determine the list of candidate Active Directory domain controllers, and this should be sufficient for the normal circumstances. But if for some reasons it isn't, you can manually override and provide the list of domain controllers by specifying the "Domain controller" field in the advanced section with the value of the format "host:port,host:port,...". The port should normally be 3269 (for global catalog over SSL), 636 (LDAP over SSL), 3268 (for global catalog), or 389 (LDAP).

For historical reasons, the system property "hudson.plugins.active\_directory.ActiveDirectorySecurityRealm.domainControllers" for this purpose is still supported, but starting with 1.28, the configuration in the UI is preferred.

If you have multiple AD domains federated into a forest, be sure to use a [global catalog](https://technet.microsoft.com/en-us/library/cc728188%28v=ws.10%29.aspx), or else you will fail to find group memberships that are defined in other domains.

#### Group Names

If you have added a group and it appears in the list with a red stop sign, Jenkins cannot find it. Remove it and investigate why.

If you are not sure what the notation for a group name is, try the following procedure:

1.  Grant full access to anonymous user (in case you have to reconfigure security having logged out)
2.  Configure the AD server, test it, and save the configuration
3.  Log in using the AD user. Click your name to see a page listing the groups you were found in
4.  Add the relevant groups found to the security matrix with appropriate permissions
5.  Do not forget to withdraw permissions from the anonymous user, taking into consideration the Overall:Read permission (hover over the column header for detail)

## Troubleshooting

#### Create/Update a dedicated Logs Recorder

If you think you've configured everything correctly but still not being able to login (or any other problems), please enable [Logging](https://wiki.jenkins.io/display/JENKINS/Logging) and configure logging level for "hudson.plugins.active\_directory" to ALL. Attempt a login and then file a ticket with the log output.

Also, it might be useful to enable:

    hudson.security = ALL
    jenkins.security = ALL
    org.acegisecurity.ldap = ALL
    org.acegisecurity.providers.ldap = ALL

#### Use a tool like 'ldapsearch' to validate credentials and authentication settings

Take care to escape special character with \`\\\` in case it is necessary.

For TLS end-points:

    ldapsearch -LLL -H ldaps://<DOMAIN_NAME_> -M -b "<searchbase>" -D "<binddn>" -w "<passwd>" "(<userid>)"

For non-TLS end-points:

    ldapsearch -LLL -H ldap://<DOMAIN_NAME> -M -b "<searchbase>" -D "<binddn>" -w "<passwd>" "(<userid>)"

In case you don't want to show your password, you might want to use the command below instead - to be prompted for it.

    ldapsearch -LLL -H ldap://<DOMAIN_NAME> -M -b "<searchbase>" -D "<binddn>" -W "(<userid>)"

All these fields should match with the following fields in the AD plugin configuration:

![](docs/images/ad-simple-configuration.png)

-   \<DOMAIN\_NAME\> -\> Domain Name: support-cloudbees.com
-   \<searchbase\> -\> Organization Unit we want to look into. In the example, it is OU=Support, DC=support-cloudbees, DC=com
-   \<binddn\> -\> Bind DN. In the exaple, CN=felix, OU=Support, DC=support-cloudbees, DC=com
-   \<passwd\> -\> Bind Password
-   \<userid\> -\> User we want to look for. We can look for the managerDN itself or for a different user on the tree. In the example, this can be set-up for example to CN=felix, OU=Support, DC=support-cloudbees, DC=com.

#### If using Domain controller check that all servers on the farm are working correctly

In case, we are using a Domain Controller like in the example below we might want to list all the AD servers in the farm by using:

    nslookup <DOMAIN_CONTROLLER>

![](docs/images/ad-domain-controller-configuration.png){width="600"}

It might happen that one of the servers in the farm is incorrectly replicated and the ad-plugin is sticky with this one, so we might want to check with ldapsearch command or the Test button in the GUI that all the servers are working correctly trying to look for an user on the tree.

#### If using Domain controller check that all servers on the farm are working correctly

You can check this by using:

    nslookup -q=SRV _ldap._tcp.<DOMAIN_NAME>

    nslookup -q=SRV _gc._tcp.<DOMAIN_NAME>

## Warning for 1.37

Be careful if you intend to install version 1.37. It has been known to cause excessive load on Active Directory authentication servers. If you install this version you should carefully monitor traffic on relevant ports, e.g.: `tcpdump port 389 or 3268`.

## Changelog

  

#### Version 2.16 (2019/05/23)

-   Reverts 2.15 since it breaks all the installations on Windows Server [JENKINS-55813](https://issues.jenkins-ci.org/browse/JENKINS-55813) - Getting issue details... STATUS

#### Version 2.15 (2019/05/20)

-   Improve AD/LDAP attribute analysis for locked accounts [JENKINS-55813](https://issues.jenkins-ci.org/browse/JENKINS-55813) - Getting issue details... STATUS

#### Version 2.14 (2019/05/06)

-   Some Exceptions launched by startTLS might break the log-in [JENKINS-44787](https://issues.jenkins-ci.org/browse/JENKINS-44787) - Getting issue details... STATUS

#### Version 2.13 (2019/04/01)

-   Java 11 readiness: also build recommended configurations

#### Version 2.12 (2019/02/08)

-   Remove the problematic Administrative Monitor [JENKINS-56047](https://issues.jenkins-ci.org/browse/JENKINS-56047) - Getting issue details... STATUS  [JENKINS-55852](https://issues.jenkins-ci.org/browse/JENKINS-55852) - Getting issue details... STATUS

#### Version 2.11 (2019/01/28)

-   [Fix security issue](https://jenkins.io/security/advisory/2019-01-28/)

#### Version 2.10 (2018/11/5)

-   TlsConfigurationAdministrativeMonitor is missing its name -  [JENKINS-54267](https://issues.jenkins-ci.org/browse/JENKINS-54267) - Getting issue details... STATUS

#### Version 2.9 (2018/10/19)

-   Configuration-as-Code compatibility -   [JENKINS-53576](https://issues.jenkins-ci.org/browse/JENKINS-53576) - Getting issue details... STATUS

#### Version 2.8 (2017/06/23) FIXING REGRESSION IN 2.7

-   Advanced configuration missing on Configure Global Security (The plugin did not work correctly on Windows Servers) [JENKINS-52045](https://issues.jenkins-ci.org/browse/JENKINS-52045) - Getting issue details... STATUS  

#### Version 2.7 (2017/06/18)

-   AD recognizes groups by CN and sAMAccount when authorities only works with CN [JENKINS-45576](https://issues.jenkins-ci.org/browse/JENKINS-45576) - Getting issue details... STATUS
-   ActiveDirectorySecurityRealm constructor ignores TlsConfiguration  [JENKINS-45816](https://issues.jenkins-ci.org/browse/JENKINS-45816) - Getting issue details... STATUS

-   The help button for Domain does not correctly explain how to add multiple-domains  [JENKINS-46228](https://issues.jenkins-ci.org/browse/JENKINS-46228) - Getting issue details... STATUS

  

#### Version 2.6 (2017/06/22)

-   If getRecordFromDomain returns null report the problems -  [JENKINS-45009](https://issues.jenkins-ci.org/browse/JENKINS-45009) - Getting issue details... STATUS

#### Version 2.5 (2017/06/20)

-   Fail-over user to fallback when there are authentication issues -  [JENKINS-39065](https://issues.jenkins-ci.org/browse/JENKINS-39065) - Getting issue details... STATUS
-   ManagementLink to improve the supportability of the AD plugin -  [JENKINS-41744](https://issues.jenkins-ci.org/browse/JENKINS-41744) - Getting issue details... STATUS

#### Version 2.4 (2017/03/24)

-   Guice failing on terminating ActiveDirectorySecurityRealm.shutDownthreadPoolExecutors -
    ([JENKINS-43091](https://issues.jenkins-ci.org/browse/JENKINS-43091))

#### Version 2.3 (2017/03/20)

-   Enable StartTls is always TRUE in the UI -
    ([JENKINS-42831](https://issues.jenkins-ci.org/browse/JENKINS-42831))

#### Version 2.2 (2017/03/15)

-   NPE thrown at login when after AD Plugin update -
    ([JENKINS-42739](https://issues.jenkins-ci.org/browse/JENKINS-42739))
-   Fix for version 2.1 on Windows Environments, where the plugin was broken due not keeping on mind [domains can be null on Windows environments](https://github.com/jenkinsci/active-directory-plugin/commit/2711542bf4ef59552b66ad5ead3802cdeb317348).

#### Version 2.1 (2017/03/13)

-   Support different bindUser per domain -
    ([JENKINS-39375](https://issues.jenkins-ci.org/browse/JENKINS-39375))
-   Make site independent of each domain -
    ([JENKINS-39423](https://issues.jenkins-ci.org/browse/JENKINS-39423))
-   Cannot populate servers via groovy script -
    ([JENKINS-39676](https://issues.jenkins-ci.org/browse/JENKINS-39676))
-   Add a test per domain -
    ([JENKINS-39776](https://issues.jenkins-ci.org/browse/JENKINS-39776))
-   Not throw any Exception in case there is not any domain -
    ([JENKINS-40599](https://issues.jenkins-ci.org/browse/JENKINS-40599))
    [This was making not to start and show a page with the Exception](https://wiki.jenkins.io/display/JENKINS/Active+Directory+Plugin#)
-   Add description according to Wiki -
    ([JENKINS-42245](https://issues.jenkins-ci.org/browse/JENKINS-42245))
-   Update ActiveDirectoryUserDetail on a different -
    ([JENKINS-38784](https://issues.jenkins-ci.org/browse/JENKINS-38784))
-   Enable com.sun.jndi.ldap.connect.timeout -
    ([JENKINS-36041](https://issues.jenkins-ci.org/browse/JENKINS-36041))
-   Configure startTls on the UI -
    ([JENKINS-42641](https://issues.jenkins-ci.org/browse/JENKINS-42641))
-   Better handle of PartialResultException -
    ([JENKINS-42686](https://issues.jenkins-ci.org/browse/JENKINS-42686))
    This was producing intermittent login failures when using the LDAP catalog.
-   Fix StartTLS
    ([JENKINS-25269](https://issues.jenkins-ci.org/browse/JENKINS-25269))

#### Version 2.0 (2016/10/03)

-   Much better support for multiple domain controllers -
    ([JENKINS-32033](https://issues.jenkins-ci.org/browse/JENKINS-32033)).
    This version might lock the access to your instance, although this will only happen in a very small quantity of cases. See **IMPORTANT Active Directory 2.0 - Better multi-domains support** section for more information.

#### Version 1.49 (2016/09/17)

-   Add a warning when displayed name is not used with several domains -
    ([JENKINS-38294](https://issues.jenkins-ci.org/browse/JENKINS-38294))
-   Trim the domains so a space after comma does not get introduced -
    ([JENKINS-38294](https://issues.jenkins-ci.org/browse/JENKINS-38294))
-   System Property to be able to ignore referrals -
    ([JENKINS-38290](https://issues.jenkins-ci.org/browse/JENKINS-38290))
-   Support for multiple domain controllers -
    ([JENKINS-32033](https://issues.jenkins-ci.org/browse/JENKINS-32033))
-   Not return null inside the cache -
    ([JENKINS-37582](https://issues.jenkins-ci.org/browse/JENKINS-37582))

#### Version 1.48 (2016/09/09)

-   Provide an ultimate speed option based on Security Groups -
    ([JENKINS-36248](https://issues.jenkins-ci.org/browse/JENKINS-36248))
-   Not serialize userCache, neither groupCache -
    ([JENKINS-36212](https://issues.jenkins-ci.org/browse/JENKINS-36212))
-   Return null inside the cache block is not allowed -
    ([JENKINS-37582](https://issues.jenkins-ci.org/browse/JENKINS-37582))

#### Version 1.47 (2016/06/06)

-   <https://issues.jenkins-ci.org/browse/JENKINS-35031>
    ([JENKINS-35031](https://issues.jenkins-ci.org/browse/JENKINS-35031))

#### Version 1.46 (2016/05/19)

-   LDAP users and groups cannot be verified anymore because of [SECURITY-243](https://github.com/jenkinsci/active-directory-plugin/pull/34)
    -([JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426))

#### Version 1.45 (2016/04/27)

-   LDAP users and groups cannot be verified anymore
    ([JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426))
-   Test button is reporting managerDN binding is successful but was not able to find any user on the tree
    ([JENKINS-34444](https://issues.jenkins-ci.org/browse/JENKINS-34444))

#### Version 1.44 (2016/04/20) This version is broken by [JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426) - which is fixed in 1.45

-   Test Active Directory connection button reports success if the search operation doesn't have any result
    ([JENKINS-34143](https://issues.jenkins-ci.org/browse/JENKINS-34143))
-   Optional cache for users and groups
    ([JENKINS-21297](https://issues.jenkins-ci.org/browse/JENKINS-21297))

#### Version 1.43 (2016/04/07)

-   [Added support for multiple servers without assigned ports](https://github.com/jenkinsci/active-directory-plugin/pull/19)
-   AD can not log on with email address
    ([JENKINS-26737](https://issues.jenkins-ci.org/browse/JENKINS-26737))
-   [Update help for irrelevantGroups](https://github.com/jenkinsci/active-directory-plugin/pull/26)

#### Version 1.42 (2016/03/02)

-   [Correct FindBugs issues](https://github.com/jenkinsci/active-directory-plugin/commit/67ca117207fe98e15749f4bd5ed375c5efd92b3d)
-   Chrome browser username autofill adds username as bindName in LDAP
    ([JENKINS-29280](https://issues.jenkins-ci.org/browse/JENKINS-29280))
-   "Automatic" group lookup strategy is not so automatic
    ([JENKINS-28857](https://issues.jenkins-ci.org/browse/JENKINS-28857))
-   TimeLimitExceededException produces "Automatic" group lookup strategy not to work correctly
    ([JENKINS-33213](https://issues.jenkins-ci.org/browse/JENKINS-33213))
-   Active Directory Plugin - Credential exception tying to authenticate with special characters like / or \#
    ([JENKINS-16257](https://issues.jenkins-ci.org/browse/JENKINS-16257))

#### Version 1.40 (2015/04/06)

-   De-emphasize custom domain setting in the ADSI mode, but once that's selected, expose a full set of options
    ([JENKINS-27763](https://issues.jenkins-ci.org/browse/JENKINS-27763))

#### Version 1.39 (2014/11/17)

-   A hack-ish switch to enable faster group lookup
    ([JENKINS-24195](https://issues.jenkins-ci.org/browse/JENKINS-24195))
-   Login based on `userPrincipalName` (which looks like an email address) was not working

#### Version 1.38 (2014/06/03)

-   Apparently the "improvement" in 1.37 backfired for some users. Providing an option for them to select the algorithm as a fallback
    ([JENKINS-22830](https://issues.jenkins-ci.org/browse/JENKINS-22830))

#### Version 1.37 (2014/04/15)

-   Drastically speed up the recursive group membership search through the use of a Microsoft extension in the LDAP filter expression.

#### Version 1.36 (2014/03/27)

-   Fixed a thread leak problem when running on Windows
    ([JENKINS-16429](https://issues.jenkins-ci.org/browse/JENKINS-16429))

#### Version 1.35 (2014/03/11)

-   Implemented "remember me" support in conjunction with upcoming Jenkins 1.556.
    ([JENKINS-9258](https://issues.jenkins-ci.org/browse/JENKINS-9258))

#### Version 1.34 (2014/03/10)

-   Make test-button work for multi-domain configurations ([Pull request \#7](https://github.com/jenkinsci/active-directory-plugin/pull/7))
-   Fix forceLDAPs system property and fix ports when using the system property
    ([JENKINS-21073](https://issues.jenkins-ci.org/browse/JENKINS-21073))
-   Added form validation check to the ADSI codepath
    ([JENKINS-17923](https://issues.jenkins-ci.org/browse/JENKINS-17923))

#### Version 1.33 (2013/05/06)

-   Fixed a show-stopper that broke most ADSI deployments
    ([JENKINS-17676](https://issues.jenkins-ci.org/browse/JENKINS-17676))

#### Version 1.32 (2013/05/01)

-   Fixed a regression in 1.31 that caused encoding problems with ADSI
    ([JENKINS-17692](https://issues.jenkins-ci.org/browse/JENKINS-17692))

#### Version 1.31 (2013/04/18)

-   Performance improvement.
-   Fixed a bug in handling OU that contains tricky characters like '/'.
-   Ignore the lookup failure for the memberOf group as it's possible that the authenticating user doesn't have permissions to access the group
    ([JENKINS-16205](https://issues.jenkins-ci.org/browse/JENKINS-16205))

#### Version 1.30 (2012/11/06)

-   NullPointerException encountered while testing connection.

#### Version 1.29 (2012/06/06)

-   Added additional logging statements for diagnosis.

#### Version 1.28 (2012/05/07)

-   Fixed a regression in 1.27
    [JENKINS-13650](https://issues.jenkins-ci.org/browse/JENKINS-13650)
-   If an authentication fails (as opposed to a communication problem), don't fallback to other domain controllers to prevent a cascade of login failures, which can result in an account lock out.

#### Version 1.27 (2012/04/26)

-   Started caching group definitions to reduce the traffic to domain controllers
-   ADSI implementation now more eagerly releases COM objects without waiting for GC
-   Removed bogus error message when an user wasn't found
    ([JENKINS-12619](https://issues.jenkins-ci.org/browse/JENKINS-12619))
-   When attempting anonymous bind, don't pass in the user name to prevent it from counted as a failure in case anonymous bind is disabled
    ([JENKINS-13595](https://issues.jenkins-ci.org/browse/JENKINS-13595))
-   Fixed a bug that broke the handling of exotic group names
    ([JENKINS-12907](https://issues.jenkins-ci.org/browse/JENKINS-12907))
-   Canonicalize the user name as per writtein AD, instead of using what the user gave us
    ([JENKINS-12607](https://issues.jenkins-ci.org/browse/JENKINS-12607))
-   Updated com4j to use ADSI even on 64bit Windows JVMs
    ([JENKINS-11719](https://issues.jenkins-ci.org/browse/JENKINS-11719))

#### Version 1.26 (2012/01/27)

-   Improved caching on group information ([pull \#3](https://github.com/jenkinsci/active-directory-plugin/pull/3))
-   The "Test" button in the config page now supports multi-domain test. ([pull \#2](https://github.com/jenkinsci/active-directory-plugin/pull/2))
-   Honor LDAP timeout setting when talking to domain controllers ([pull \#1](https://github.com/jenkinsci/active-directory-plugin/pull/1))

#### Version 1.25 (2012/01/24)

-   Fixed a security vulnerability that affects AD with anonymous binding enabled.

#### Version 1.24 (2012/01/05)

-   Fixed a bug in server lookup. We should still consider lower-priority servers if higher priority ones are unreachable
-   Supported group lookup by name
-   Report all attempted authentication when trying to authenticate against multiple domains
    ([JENKINS-11948](https://issues.jenkins-ci.org/browse/JENKINS-11948))

#### Version 1.23 (2011/11/29)

-   Fixed a poor interaction with the matrix security form check
    ([JENKINS-11720](https://issues.jenkins-ci.org/browse/JENKINS-11720))
-   Fixed a regression in 1.22 that broke the distribution group lookup
    ([JENKINS-11668](https://issues.jenkins-ci.org/browse/JENKINS-11668))

#### Version 1.22 (2011/11/8)

-   "remember me" causes exception
    ([JENKINS-11643](https://issues.jenkins-ci.org/browse/JENKINS-11643))
-   Avoid NPE if we fail to retrieve tokenGroups
    ([JENKINS-11644](https://issues.jenkins-ci.org/browse/JENKINS-11644))
-   Fixed 8000500d COM error on Windows platform
    ([JENKINS-11660](https://issues.jenkins-ci.org/browse/JENKINS-11660))

#### Version 1.21 (2011/11/4)

-   Plugin shouldn't require a record on the domain
-   Fixed a bug in the TLS upgrade
    ([JENKINS-8132](https://issues.jenkins-ci.org/browse/JENKINS-8132))
-   Plugin was not recognizing the user's primary group ("Domain Users" most typically)
-   E-mail and full name are now propagated to Jenkins
    ([JENKINS-6648](https://issues.jenkins-ci.org/browse/JENKINS-6648))
-   Made to correctly work with CLI username/password authentication
    ([JENKINS-7995](https://issues.jenkins-ci.org/browse/JENKINS-7995))

#### Version 1.20 (2011/10/19)

-   Fixed a security vulnerability (SECURITY-18)

#### Version 1.19

-   If we fail to check the account disabled flag, assume it's enabled
    ([JENKINS-10086](https://issues.jenkins-ci.org/browse/JENKINS-10086))
-   If/when the socket factory is given, JRE appears to automatically
    try to connect via SSL, so we can only do so during StartTLS call.
-   Error only if there's no server (either configured or discovered.)
-   Added the preferred Server functionality back

#### Version 1.18 (2011/03/20)

-   Add a preferred server in configuration options
-   Update for Jenkins

#### Version 1.17 (2010/11/16)

-   Look up is now done via LDAPS instead of LDAP (although there's no certificate check done now.)
-   The plugin now talks to the global catalog for efficiency, as opposed to a domain, if that's available.
-   Some DNS returns '.' at the end of the host name. Handle it correctly
    ([JENKINS-2647](https://issues.jenkins-ci.org/browse/JENKINS-2647))
-   Fixed a possible LDAP injection problem
    ([JENKINS-3118](https://issues.jenkins-ci.org/browse/JENKINS-3118))
-   Try all the available servers before giving up. Useful when some of your domain controllers aren't working properly.
    ([JENKINS-4268](https://issues.jenkins-ci.org/browse/JENKINS-4268))
-   Added the site support
    ([JENKINS-4203](https://issues.jenkins-ci.org/browse/JENKINS-4203))
-   Cleaned up the help text that incorrectly stated that this doesn't work on Unix. It works.
    ([JENKINS-2500](https://issues.jenkins-ci.org/browse/JENKINS-2500))

#### Version 1.16 (2009/12/8)

-   Added a workaround for WebSphere in doing DNS lookup via JNDI
    ([JENKINS-5045](https://issues.jenkins-ci.org/browse/JENKINS-5045))

#### Version 1.15 (2009/06/10)

-   Fix bug introduced with 1.14 where an AD setup with circular group references would cause a stack overflow.

#### Version 1.14 (2009/06/02)

-   Support nested groups (via the Unix provider)
    ([JENKINS-3071](https://issues.jenkins-ci.org/browse/JENKINS-3071))
-   Fixed a bug that prevented the "authenticated" role being honoured
    ([JENKINS-3735](https://issues.jenkins-ci.org/browse/JENKINS-3735))
-   Support authenticting against multiple domains
    ([JENKINS-3576](https://issues.jenkins-ci.org/browse/JENKINS-3576))

#### Version 1.13 (2009/05/19)

-   Fixed a bug that degraded Windows support (which forces you to enter the domain name.)
-   Implementation of group recognition (for displaying group icon in matrix for instance.)

#### Version 1.12 (2009/04/08)

-   Some DNS returns '.' at the end of the host name. Handle it correctly
    ([JENKINS-2647](https://issues.jenkins-ci.org/browse/JENKINS-2647)) 
    (not correctly fixed until 1.17)
-   Fixed NPE in the form field validation when a group name was added
    ([JENKINS-3344](https://issues.jenkins-ci.org/browse/JENKINS-3344))
-   Lookup fails for members of groups with special characters in the name (like '/')
    ([JENKINS-3249](https://issues.jenkins-ci.org/browse/JENKINS-3249))

#### Version 1.11 (2009/03/25)

-   No change. This is a re-release since 1.10 didn't hit the update center.

#### Version 1.10 (2009/03/20)

-   On Windows, specifying the domain name in the "advanced" section wasn't taking effect.

#### Version 1.9 (2009/02/17)

-   Modified to work with 64bit Windows

#### Version 1.8 (2009/02/13)

-   Hudson honors the priority in the SRV entries

#### Version 1.7 (2009/01/15)

-   Fixed a bug in handling alternative UPN suffix.

#### Version 1.6 (2009/01/12)

-   Fixed a bug in handling "referrals" (which I believe happens when you run AD forest.)

#### Version 1.5 (2008/06/24)

-   Windows users can now also use the LDAP-based AD authentication (the same code used on Unix.) This is apparently necessary when Hudson runs as a local user instead of a domain user

#### Version 1.4 (2008/06/11)

-   Fixed a bug where the configuration page doesn't show the configured AD domain name
-   Fixed a bug that prevented this from working with user-defined containers

#### Version 1.3 (2008/06/09)

-   Supported authentication from Hudson running on non-Windows machines

#### Version 1.2 (2008/02/27)

-   Fixed IllegalArgumentException in remember-me implementation
    ([JENKINS-1229](https://issues.jenkins-ci.org/browse/JENKINS-1229))

#### Version 1.0 (2007/01/09)

-   Initial version


