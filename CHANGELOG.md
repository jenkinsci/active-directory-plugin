# Changelog


## Warning for 1.37

Be careful if you intend to install version 1.37. It has been known to cause excessive load on Active Directory authentication servers. If you install this version you should carefully monitor traffic on relevant ports, e.g.: `tcpdump port 389 or 3268`.

## Version 2.20 (2020/11/04)

* [Important security fixes](https://www.jenkins.io/security/advisory/2020-11-04/)
* User passwords are no longer stored in memory as part of the authentication cache.
  Instead, BCrypt is used.
  The Java system property `hudson.plugins.active_directory.CacheUtil.bcryptLogRounds` can be used to configure the cost parameter; the default is 10 (for 1024 rounds).
  Additionally, the caching of successful authentications can be disabled by setting the system property `hudson.plugins.active_directory.CacheUtil.noCacheAuth` to `true`.
* When a local fallback security realm is configured, the plugin would sometimes reset the password of the specified user to a fixed value.

## Version 2.16 (2019/05/23)

-   Reverts 2.15 since it breaks all the installations on Windows Server [JENKINS-55813](https://issues.jenkins-ci.org/browse/JENKINS-55813) 

## Version 2.15 (2019/05/20)

-   Improve AD/LDAP attribute analysis for locked accounts [JENKINS-55813](https://issues.jenkins-ci.org/browse/JENKINS-55813) 

## Version 2.14 (2019/05/06)

-   Some Exceptions launched by startTLS might break the log-in [JENKINS-44787](https://issues.jenkins-ci.org/browse/JENKINS-44787) 

## Version 2.13 (2019/04/01)

-   Java 11 readiness: also build recommended configurations

## Version 2.12 (2019/02/08)

-   Remove the problematic Administrative Monitor [JENKINS-56047](https://issues.jenkins-ci.org/browse/JENKINS-56047) [JENKINS-55852](https://issues.jenkins-ci.org/browse/JENKINS-55852) 

## Version 2.11 (2019/01/28)

-   [Fix security issue](https://jenkins.io/security/advisory/2019-01-28/)

## Version 2.10 (2018/11/5)

-   TlsConfigurationAdministrativeMonitor is missing its name -  [JENKINS-54267](https://issues.jenkins-ci.org/browse/JENKINS-54267) 

## Version 2.9 (2018/10/19)

-   Configuration-as-Code compatibility -   [JENKINS-53576](https://issues.jenkins-ci.org/browse/JENKINS-53576) 

## Version 2.8 (2017/06/23) FIXING REGRESSION IN 2.7

-   Advanced configuration missing on Configure Global Security (The plugin did not work correctly on Windows Servers) [JENKINS-52045](https://issues.jenkins-ci.org/browse/JENKINS-52045) 

## Version 2.7 (2017/06/18)

-   AD recognizes groups by CN and sAMAccount when authorities only works with CN [JENKINS-45576](https://issues.jenkins-ci.org/browse/JENKINS-45576) 
-   ActiveDirectorySecurityRealm constructor ignores TlsConfiguration  [JENKINS-45816](https://issues.jenkins-ci.org/browse/JENKINS-45816) 

-   The help button for Domain does not correctly explain how to add multiple-domains  [JENKINS-46228](https://issues.jenkins-ci.org/browse/JENKINS-46228) 

  

## Version 2.6 (2017/06/22)

-   If getRecordFromDomain returns null report the problems -  [JENKINS-45009](https://issues.jenkins-ci.org/browse/JENKINS-45009) 

## Version 2.5 (2017/06/20)

-   Fail-over user to fallback when there are authentication issues -  [JENKINS-39065](https://issues.jenkins-ci.org/browse/JENKINS-39065) 
-   ManagementLink to improve the supportability of the AD plugin -  [JENKINS-41744](https://issues.jenkins-ci.org/browse/JENKINS-41744) 

## Version 2.4 (2017/03/24)

-   Guice failing on terminating ActiveDirectorySecurityRealm.shutDownthreadPoolExecutors -
    ([JENKINS-43091](https://issues.jenkins-ci.org/browse/JENKINS-43091))

## Version 2.3 (2017/03/20)

-   Enable StartTls is always TRUE in the UI -
    ([JENKINS-42831](https://issues.jenkins-ci.org/browse/JENKINS-42831))

## Version 2.2 (2017/03/15)

-   NPE thrown at login when after AD Plugin update -
    ([JENKINS-42739](https://issues.jenkins-ci.org/browse/JENKINS-42739))
-   Fix for version 2.1 on Windows Environments, where the plugin was broken due not keeping on mind [domains can be null on Windows environments](https://github.com/jenkinsci/active-directory-plugin/commit/2711542bf4ef59552b66ad5ead3802cdeb317348).

## Version 2.1 (2017/03/13)

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

## Version 2.0 (2016/10/03)

-   Much better support for multiple domain controllers -
    ([JENKINS-32033](https://issues.jenkins-ci.org/browse/JENKINS-32033)).
    This version might lock the access to your instance, although this will only happen in a very small quantity of cases. See **IMPORTANT Active Directory 2.0 - Better multi-domains support** section for more information.

## Version 1.49 (2016/09/17)

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

## Version 1.48 (2016/09/09)

-   Provide an ultimate speed option based on Security Groups -
    ([JENKINS-36248](https://issues.jenkins-ci.org/browse/JENKINS-36248))
-   Not serialize userCache, neither groupCache -
    ([JENKINS-36212](https://issues.jenkins-ci.org/browse/JENKINS-36212))
-   Return null inside the cache block is not allowed -
    ([JENKINS-37582](https://issues.jenkins-ci.org/browse/JENKINS-37582))

## Version 1.47 (2016/06/06)

-   <https://issues.jenkins-ci.org/browse/JENKINS-35031>
    ([JENKINS-35031](https://issues.jenkins-ci.org/browse/JENKINS-35031))

## Version 1.46 (2016/05/19)

-   LDAP users and groups cannot be verified anymore because of [SECURITY-243](https://github.com/jenkinsci/active-directory-plugin/pull/34)
    -([JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426))

## Version 1.45 (2016/04/27)

-   LDAP users and groups cannot be verified anymore
    ([JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426))
-   Test button is reporting managerDN binding is successful but was not able to find any user on the tree
    ([JENKINS-34444](https://issues.jenkins-ci.org/browse/JENKINS-34444))

## Version 1.44 (2016/04/20) This version is broken by [JENKINS-34426](https://issues.jenkins-ci.org/browse/JENKINS-34426) - which is fixed in 1.45

-   Test Active Directory connection button reports success if the search operation doesn't have any result
    ([JENKINS-34143](https://issues.jenkins-ci.org/browse/JENKINS-34143))
-   Optional cache for users and groups
    ([JENKINS-21297](https://issues.jenkins-ci.org/browse/JENKINS-21297))

## Version 1.43 (2016/04/07)

-   [Added support for multiple servers without assigned ports](https://github.com/jenkinsci/active-directory-plugin/pull/19)
-   AD can not log on with email address
    ([JENKINS-26737](https://issues.jenkins-ci.org/browse/JENKINS-26737))
-   [Update help for irrelevantGroups](https://github.com/jenkinsci/active-directory-plugin/pull/26)

## Version 1.42 (2016/03/02)

-   [Correct FindBugs issues](https://github.com/jenkinsci/active-directory-plugin/commit/67ca117207fe98e15749f4bd5ed375c5efd92b3d)
-   Chrome browser username autofill adds username as bindName in LDAP
    ([JENKINS-29280](https://issues.jenkins-ci.org/browse/JENKINS-29280))
-   "Automatic" group lookup strategy is not so automatic
    ([JENKINS-28857](https://issues.jenkins-ci.org/browse/JENKINS-28857))
-   TimeLimitExceededException produces "Automatic" group lookup strategy not to work correctly
    ([JENKINS-33213](https://issues.jenkins-ci.org/browse/JENKINS-33213))
-   Active Directory Plugin - Credential exception tying to authenticate with special characters like / or \#
    ([JENKINS-16257](https://issues.jenkins-ci.org/browse/JENKINS-16257))

## Version 1.40 (2015/04/06)

-   De-emphasize custom domain setting in the ADSI mode, but once that's selected, expose a full set of options
    ([JENKINS-27763](https://issues.jenkins-ci.org/browse/JENKINS-27763))

## Version 1.39 (2014/11/17)

-   A hack-ish switch to enable faster group lookup
    ([JENKINS-24195](https://issues.jenkins-ci.org/browse/JENKINS-24195))
-   Login based on `userPrincipalName` (which looks like an email address) was not working

## Version 1.38 (2014/06/03)

-   Apparently the "improvement" in 1.37 backfired for some users. Providing an option for them to select the algorithm as a fallback
    ([JENKINS-22830](https://issues.jenkins-ci.org/browse/JENKINS-22830))

## Version 1.37 (2014/04/15)

-   Drastically speed up the recursive group membership search through the use of a Microsoft extension in the LDAP filter expression.

## Version 1.36 (2014/03/27)

-   Fixed a thread leak problem when running on Windows
    ([JENKINS-16429](https://issues.jenkins-ci.org/browse/JENKINS-16429))

## Version 1.35 (2014/03/11)

-   Implemented "remember me" support in conjunction with upcoming Jenkins 1.556.
    ([JENKINS-9258](https://issues.jenkins-ci.org/browse/JENKINS-9258))

## Version 1.34 (2014/03/10)

-   Make test-button work for multi-domain configurations ([Pull request \#7](https://github.com/jenkinsci/active-directory-plugin/pull/7))
-   Fix forceLDAPs system property and fix ports when using the system property
    ([JENKINS-21073](https://issues.jenkins-ci.org/browse/JENKINS-21073))
-   Added form validation check to the ADSI codepath
    ([JENKINS-17923](https://issues.jenkins-ci.org/browse/JENKINS-17923))

## Version 1.33 (2013/05/06)

-   Fixed a show-stopper that broke most ADSI deployments
    ([JENKINS-17676](https://issues.jenkins-ci.org/browse/JENKINS-17676))

## Version 1.32 (2013/05/01)

-   Fixed a regression in 1.31 that caused encoding problems with ADSI
    ([JENKINS-17692](https://issues.jenkins-ci.org/browse/JENKINS-17692))

## Version 1.31 (2013/04/18)

-   Performance improvement.
-   Fixed a bug in handling OU that contains tricky characters like '/'.
-   Ignore the lookup failure for the memberOf group as it's possible that the authenticating user doesn't have permissions to access the group
    ([JENKINS-16205](https://issues.jenkins-ci.org/browse/JENKINS-16205))

## Version 1.30 (2012/11/06)

-   NullPointerException encountered while testing connection.

## Version 1.29 (2012/06/06)

-   Added additional logging statements for diagnosis.

## Version 1.28 (2012/05/07)

-   Fixed a regression in 1.27
    [JENKINS-13650](https://issues.jenkins-ci.org/browse/JENKINS-13650)
-   If an authentication fails (as opposed to a communication problem), don't fallback to other domain controllers to prevent a cascade of login failures, which can result in an account lock out.

## Version 1.27 (2012/04/26)

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

## Version 1.26 (2012/01/27)

-   Improved caching on group information ([pull \#3](https://github.com/jenkinsci/active-directory-plugin/pull/3))
-   The "Test" button in the config page now supports multi-domain test. ([pull \#2](https://github.com/jenkinsci/active-directory-plugin/pull/2))
-   Honor LDAP timeout setting when talking to domain controllers ([pull \#1](https://github.com/jenkinsci/active-directory-plugin/pull/1))

## Version 1.25 (2012/01/24)

-   Fixed a security vulnerability that affects AD with anonymous binding enabled.

## Version 1.24 (2012/01/05)

-   Fixed a bug in server lookup. We should still consider lower-priority servers if higher priority ones are unreachable
-   Supported group lookup by name
-   Report all attempted authentication when trying to authenticate against multiple domains
    ([JENKINS-11948](https://issues.jenkins-ci.org/browse/JENKINS-11948))

## Version 1.23 (2011/11/29)

-   Fixed a poor interaction with the matrix security form check
    ([JENKINS-11720](https://issues.jenkins-ci.org/browse/JENKINS-11720))
-   Fixed a regression in 1.22 that broke the distribution group lookup
    ([JENKINS-11668](https://issues.jenkins-ci.org/browse/JENKINS-11668))

## Version 1.22 (2011/11/8)

-   "remember me" causes exception
    ([JENKINS-11643](https://issues.jenkins-ci.org/browse/JENKINS-11643))
-   Avoid NPE if we fail to retrieve tokenGroups
    ([JENKINS-11644](https://issues.jenkins-ci.org/browse/JENKINS-11644))
-   Fixed 8000500d COM error on Windows platform
    ([JENKINS-11660](https://issues.jenkins-ci.org/browse/JENKINS-11660))

## Version 1.21 (2011/11/4)

-   Plugin shouldn't require a record on the domain
-   Fixed a bug in the TLS upgrade
    ([JENKINS-8132](https://issues.jenkins-ci.org/browse/JENKINS-8132))
-   Plugin was not recognizing the user's primary group ("Domain Users" most typically)
-   E-mail and full name are now propagated to Jenkins
    ([JENKINS-6648](https://issues.jenkins-ci.org/browse/JENKINS-6648))
-   Made to correctly work with CLI username/password authentication
    ([JENKINS-7995](https://issues.jenkins-ci.org/browse/JENKINS-7995))

## Version 1.20 (2011/10/19)

-   Fixed a security vulnerability (SECURITY-18)

## Version 1.19

-   If we fail to check the account disabled flag, assume it's enabled
    ([JENKINS-10086](https://issues.jenkins-ci.org/browse/JENKINS-10086))
-   If/when the socket factory is given, JRE appears to automatically
    try to connect via SSL, so we can only do so during StartTLS call.
-   Error only if there's no server (either configured or discovered.)
-   Added the preferred Server functionality back

## Version 1.18 (2011/03/20)

-   Add a preferred server in configuration options
-   Update for Jenkins

## Version 1.17 (2010/11/16)

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

## Version 1.16 (2009/12/8)

-   Added a workaround for WebSphere in doing DNS lookup via JNDI
    ([JENKINS-5045](https://issues.jenkins-ci.org/browse/JENKINS-5045))

## Version 1.15 (2009/06/10)

-   Fix bug introduced with 1.14 where an AD setup with circular group references would cause a stack overflow.

## Version 1.14 (2009/06/02)

-   Support nested groups (via the Unix provider)
    ([JENKINS-3071](https://issues.jenkins-ci.org/browse/JENKINS-3071))
-   Fixed a bug that prevented the "authenticated" role being honoured
    ([JENKINS-3735](https://issues.jenkins-ci.org/browse/JENKINS-3735))
-   Support authenticting against multiple domains
    ([JENKINS-3576](https://issues.jenkins-ci.org/browse/JENKINS-3576))

## Version 1.13 (2009/05/19)

-   Fixed a bug that degraded Windows support (which forces you to enter the domain name.)
-   Implementation of group recognition (for displaying group icon in matrix for instance.)

## Version 1.12 (2009/04/08)

-   Some DNS returns '.' at the end of the host name. Handle it correctly
    ([JENKINS-2647](https://issues.jenkins-ci.org/browse/JENKINS-2647)) 
    (not correctly fixed until 1.17)
-   Fixed NPE in the form field validation when a group name was added
    ([JENKINS-3344](https://issues.jenkins-ci.org/browse/JENKINS-3344))
-   Lookup fails for members of groups with special characters in the name (like '/')
    ([JENKINS-3249](https://issues.jenkins-ci.org/browse/JENKINS-3249))

## Version 1.11 (2009/03/25)

-   No change. This is a re-release since 1.10 didn't hit the update center.

## Version 1.10 (2009/03/20)

-   On Windows, specifying the domain name in the "advanced" section wasn't taking effect.

## Version 1.9 (2009/02/17)

-   Modified to work with 64bit Windows

## Version 1.8 (2009/02/13)

-   Hudson honors the priority in the SRV entries

## Version 1.7 (2009/01/15)

-   Fixed a bug in handling alternative UPN suffix.

## Version 1.6 (2009/01/12)

-   Fixed a bug in handling "referrals" (which I believe happens when you run AD forest.)

## Version 1.5 (2008/06/24)

-   Windows users can now also use the LDAP-based AD authentication (the same code used on Unix.) This is apparently necessary when Hudson runs as a local user instead of a domain user

## Version 1.4 (2008/06/11)

-   Fixed a bug where the configuration page doesn't show the configured AD domain name
-   Fixed a bug that prevented this from working with user-defined containers

## Version 1.3 (2008/06/09)

-   Supported authentication from Hudson running on non-Windows machines

## Version 1.2 (2008/02/27)

-   Fixed IllegalArgumentException in remember-me implementation
    ([JENKINS-1229](https://issues.jenkins-ci.org/browse/JENKINS-1229))

## Version 1.0 (2007/01/09)

-   Initial version


