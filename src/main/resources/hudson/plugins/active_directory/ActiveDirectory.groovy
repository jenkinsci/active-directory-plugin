/*
    Configure Active Directory as the authentication realm.
*/
import org.acegisecurity.providers.ProviderManager
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationProvider

authenticationManager(ProviderManager) {
    providers = [
        bean(ActiveDirectoryAuthenticationProvider),
        // this doesn't mean we allow anonymous access.
        // we just authenticate anonymous users as such,
        // so that later authorization can reject them if so configured
        bean(AnonymousAuthenticationProvider) {
            key = "anonymous"
        }
    ]
}