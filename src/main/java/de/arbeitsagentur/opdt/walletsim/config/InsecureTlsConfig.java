package de.arbeitsagentur.opdt.walletsim.config;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.http.client.JdkClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.autoconfigure.ClientHttpRequestFactoryBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * {@code app.insecure-tls} drops certificate validation for the calls the simulator makes itself,
 * so a test deployment can reach a verifier behind a self-signed certificate or a TLS rewriting
 * proxy. It never affects the connections the simulator serves.
 */
@Configuration
public class InsecureTlsConfig {

    private static final Logger LOG = LoggerFactory.getLogger(InsecureTlsConfig.class);

    /**
     * The request object fetch, the authorization response submission and the trust list retrieval
     * all build on the auto-configured {@code RestClient.Builder}, so customizing the shared
     * request factory covers every outgoing call at once.
     */
    @Bean
    public ClientHttpRequestFactoryBuilderCustomizer<JdkClientHttpRequestFactoryBuilder> insecureTlsCustomizer(
            AppProperties properties) {
        if (!properties.insecureTls()) {
            return builder -> builder;
        }
        LOG.warn("app.insecure-tls is on: outgoing https calls accept any certificate for any host");
        return builder -> builder.withHttpClientCustomizer(httpClient -> httpClient.sslContext(trustEverything()));
    }

    // JSSE leaves the identity check to the trust manager once endpoint identification is on, so a
    // trust manager that checks nothing drops host name verification along with chain validation
    private static SSLContext trustEverything() {
        try {
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, new TrustManager[] {new TrustEverything()}, null);
            return sslContext;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Could not build the insecure TLS context", e);
        }
    }

    private static final class TrustEverything extends X509ExtendedTrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) {}

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) {}

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
