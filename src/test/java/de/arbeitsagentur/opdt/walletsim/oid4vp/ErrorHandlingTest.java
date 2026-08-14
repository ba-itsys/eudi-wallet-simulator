package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * Wallet error handling per OID4VP 1.0 §8.5: for direct_post.jwt the error response is
 * encrypted like any other authorization response. Strict mode rejection is covered in
 * StrictModeTest.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorHandlingTest {

    @LocalServerPort
    private int port;

    @Test
    void cancelOnEncryptedFlowSendsAccessDeniedAsJwe() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withEncryptedResponses()) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            String flowState = hiddenField(picker, "flowState");

            ResponseEntity<String> cancel = client(port)
                    .post()
                    .uri("/authorize/cancel")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(cancel.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            String jwe = response.formParameters().get("response");
            assertThat(jwe)
                    .as("error response is encrypted for direct_post.jwt")
                    .isNotNull();

            EncryptedJWT encrypted = EncryptedJWT.parse(jwe);
            encrypted.decrypt(new ECDHDecrypter(verifier.responseEncryptionKey().toECPrivateKey()));
            assertThat(encrypted.getJWTClaimsSet().getClaim("error")).isEqualTo("access_denied");
            assertThat(encrypted.getJWTClaimsSet().getClaim("state")).isEqualTo(verifier.state());
        }
    }

    @Test
    void requestForAnUnsupportedFormatIsAnsweredWithVpFormatsNotSupported() throws Exception {
        String mdocOnlyQuery =
                """
                {"credentials": [{
                    "id": "pid",
                    "format": "mso_mdoc",
                    "meta": {"doctype_value": "eu.europa.ec.eudi.pid.1"}
                }]}
                """;
        try (TestVerifier verifier = new TestVerifier(mdocOnlyQuery)) {
            ResponseEntity<String> page = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(page.getBody())
                    .as("the wallet explains the refusal instead of offering credentials")
                    .doesNotContain("data-credential-id");

            ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("vp_formats_not_supported");
            assertThat(response.formParameters().get("error_description")).contains("dc+sd-jwt");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }
}
