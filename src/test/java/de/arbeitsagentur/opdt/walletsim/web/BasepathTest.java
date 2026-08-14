package de.arbeitsagentur.opdt.walletsim.web;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;

/**
 * Behind a path rewriting ingress every generated URL needs the configured basepath, including
 * the form targets of the edit page that is reached from a presentation flow.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = "app.basepath=/wallet")
class BasepathTest {

    @LocalServerPort
    private int port;

    @Test
    void formTargetsCarryTheBasepathOnBothEditPaths() throws Exception {
        String startPageEdit = client(port)
                .post()
                .uri("/credentials/edit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("credentialId=pid-maria-neumann")
                .retrieve()
                .body(String.class);
        assertThat(startPageEdit).contains("action=\"/wallet/credentials/save\"");

        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).contains("action=\"/wallet/authorize/submit\"");
            String flowState = hiddenField(picker, "flowState");

            String flowEdit = client(port)
                    .post()
                    .uri("/authorize/edit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("editQueryId=pid&selection%5Bpid%5D=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .body(String.class);
            assertThat(flowEdit).contains("action=\"/wallet/authorize/edit/save\"");
        }
    }

    // error pages come from an exception handler, which sees no controller model attributes
    @Test
    void errorPagesCarryTheBasepathToo() {
        String page = client(port)
                .post()
                .uri("/credentials/edit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("credentialId=does-not-exist")
                .retrieve()
                .body(String.class);

        assertThat(page).contains("href=\"/wallet/css/layout.css\"");
        assertThat(page).contains("href=\"/wallet/\"");
        assertThat(page).doesNotContain("null/");
    }
}
