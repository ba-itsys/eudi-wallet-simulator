package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

/**
 * app.insecure-tls drops certificate validation for the calls the simulator makes itself, so a
 * test deployment can talk to a verifier behind a self-signed certificate or a TLS rewriting
 * proxy. The verifier here fails both halves of validation at once: its certificate is untrusted
 * and it is issued for a host the endpoint is not reached under.
 */
class InsecureTlsTest {

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
    class Default {

        @LocalServerPort
        private int port;

        @Test
        void anUntrustedHttpsRequestUriIsRefused() throws Exception {
            try (TestVerifier verifier = TestVerifier.pidVerifier();
                    UntrustedHttpsEndpoint endpoint = new UntrustedHttpsEndpoint(verifier.requestUri())) {
                String page = openWallet(port, verifier, endpoint);

                assertThat(page)
                        .as("the flow stops on the error page instead of opening the picker")
                        .contains("Failed to fetch request object")
                        .doesNotContain("data-credential-id=\"pid-jan-hart\"");
            }
        }
    }

    @Nested
    @SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "app.insecure-tls=true")
    class InsecureTlsEnabled {

        @LocalServerPort
        private int port;

        @Test
        void anUntrustedHttpsRequestUriIsAccepted() throws Exception {
            try (TestVerifier verifier = TestVerifier.pidVerifier();
                    UntrustedHttpsEndpoint endpoint = new UntrustedHttpsEndpoint(verifier.requestUri())) {
                String page = openWallet(port, verifier, endpoint);

                assertThat(page)
                        .as("neither the untrusted issuer nor the wrong host name stops the fetch")
                        .contains("data-credential-id=\"pid-jan-hart\"");
            }
        }
    }

    private static String openWallet(int port, TestVerifier verifier, UntrustedHttpsEndpoint endpoint) {
        URI authorizeUri = URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(endpoint.requestUri(), StandardCharsets.UTF_8));
        return client(port).get().uri(authorizeUri).retrieve().body(String.class);
    }
}
