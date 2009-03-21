/*
    Configure Active Directory as the authentication realm.
*/
import org.acegisecurity.providers.ProviderManager
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider
import hudson.plugins.active_directory.ActiveDirectoryAuthenticationProvider
import hudson.plugins.active_directory.ActiveDirectoryUnixAuthenticationProvider
import org.acegisecurity.providers.rememberme.RememberMeAuthenticationProvider
import hudson.model.Hudson

// global so that this bean can be retrieved as UserDetailsService
if(Hudson.isWindows() && "32".equals(System.getProperty("sun.arch.data.model") && domain==null))
    // Windows path requires com4j, which is currently only supported on Win32
    activeDirectory(ActiveDirectoryAuthenticationProvider)
else
    activeDirectory(ActiveDirectoryUnixAuthenticationProvider,domain) {}

authenticationManager(ProviderManager) {
    providers = [
        activeDirectory,

    // these providers apply everywhere
        bean(RememberMeAuthenticationProvider) {
            key = Hudson.getInstance().getSecretKey();
        },
        // this doesn't mean we allow anonymous access.
        // we just authenticate anonymous users as such,
        // so that later authorization can reject them if so configured
        bean(AnonymousAuthenticationProvider) {
            key = "anonymous"
        }
    ]
}