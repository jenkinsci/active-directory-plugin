package hudson.plugins.active_directory;

import org.jvnet.localizer.Localizable;

/**
 * Classification of all possible TLS configurations
 *
 */
public enum TlsConfiguration {
    JDK_TRUSTSTORE          (Messages._TlsConfiguration_JdkTrustStore()),
    TRUST_ALL_CERTIFICATES  (Messages._TlsConfiguration_TrustAllCertificates())
    ;

    public final Localizable msg;

    TlsConfiguration(Localizable msg) {
        this.msg = msg;
    }

    public String getDisplayName() {
        return msg.toString();
    }
}
