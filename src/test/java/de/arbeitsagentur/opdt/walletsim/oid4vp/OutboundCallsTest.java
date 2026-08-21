package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;

/**
 * How the simulator reaches the verifier. It fetches the request object and posts the
 * authorization response from the server side, so those calls take the JVM proxy settings of the
 * deployment and follow the redirects an ingress in front of the verifier answers with.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class OutboundCallsTest {

    @LocalServerPort
    private int port;

    private final Map<String, String> replacedProperties = new LinkedHashMap<>();

    @AfterEach
    void restoreProxyProperties() {
        replacedProperties.forEach((name, value) -> {
            if (value == null) {
                System.clearProperty(name);
            } else {
                System.setProperty(name, value);
            }
        });
        replacedProperties.clear();
    }

    @Test
    void verifierCallsGoThroughTheConfiguredProxy() throws Exception {
        try (TestForwardProxy proxy = new TestForwardProxy();
                TestVerifier verifier = TestVerifier.pidVerifier()) {
            useProxy(proxy);

            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&flowState="
                            + URLEncoder.encode(hiddenField(picker, "flowState"), StandardCharsets.UTF_8))
                    .retrieve()
                    .toBodilessEntity();

            assertThat(verifier.awaitResponse().formParameters())
                    .as("the presentation still arrives at the verifier")
                    .containsKey("vp_token");
            assertThat(proxy.requestLines())
                    .as("the request object fetch and the direct_post are the calls the simulator "
                            + "makes itself, and both take the proxy")
                    .hasSize(2)
                    .anySatisfy(line -> assertThat(line).startsWith("GET " + verifier.requestUri()))
                    .anySatisfy(line -> assertThat(line).startsWith("POST " + verifier.responseUri()));
        }
    }

    /**
     * An ingress in front of the verifier can move the request_uri, for example from http to
     * https. The simulator follows that redirect instead of failing on a request object it never
     * received.
     */
    @Test
    void aRedirectedRequestUriStillOpensThePicker() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            HttpServer ingress = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
            ingress.createContext("/moved", exchange -> {
                exchange.getResponseHeaders().add("Location", verifier.requestUri());
                exchange.sendResponseHeaders(302, -1);
                exchange.close();
            });
            ingress.start();
            try {
                String movedRequestUri =
                        "http://localhost:" + ingress.getAddress().getPort() + "/moved";
                URI authorizeUri = URI.create("http://localhost:" + port + "/authorize?client_id="
                        + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                        + "&request_uri="
                        + URLEncoder.encode(movedRequestUri, StandardCharsets.UTF_8));
                String picker = client(port).get().uri(authorizeUri).retrieve().body(String.class);

                assertThat(picker).contains("data-credential-id=\"pid-jan-hart\"");
            } finally {
                ingress.stop(0);
            }
        }
    }

    // localhost is exempt from proxying by default, so the test verifier needs an empty exemption list
    private void useProxy(TestForwardProxy proxy) {
        setProperty("http.proxyHost", "localhost");
        setProperty("http.proxyPort", String.valueOf(proxy.port()));
        setProperty("http.nonProxyHosts", "");
    }

    private void setProperty(String name, String value) {
        replacedProperties.putIfAbsent(name, System.getProperty(name));
        System.setProperty(name, value);
    }
}
