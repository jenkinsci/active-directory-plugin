package hudson.plugins.active_directory;

import javax.net.SocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.logging.Logger;

import static java.util.logging.Level.FINE;

/**
 * @author Kohsuke Kawaguchi
 */
public abstract class TrustAllSocketFactory extends SocketFactory {
    public static SocketFactory getDefault() {
        try {
            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] x509Certificates, String authType) throws CertificateException {
                    if (LOGGER.isLoggable(FINE))
                        LOGGER.fine("Got the certificate: "+Arrays.asList(x509Certificates));
// TODO: define a mechanism for users to accept a certificate from UI
//                    try {
//                        CertificateUtil.validatePath(Arrays.asList(x509Certificates));
//                    } catch (GeneralSecurityException e) {
//                        e.printStackTrace();
//                    }
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new SecureRandom());
            return context.getSocketFactory();
        } catch (NoSuchAlgorithmException e) {
            throw new Error(e);
        } catch (KeyManagementException e) {
            throw new Error(e);
        }
    }

    private static final Logger LOGGER = Logger.getLogger(TrustAllSocketFactory.class.getName());
}
