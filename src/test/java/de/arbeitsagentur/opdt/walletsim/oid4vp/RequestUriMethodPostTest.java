package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * request_uri_method=post per OID4VP 1.0 §5.10: the wallet retrieves the request object with a
 * form-encoded POST carrying wallet_nonce and wallet_metadata, the verifier encrypts the request
 * object to the wallet's advertised key and echoes the wallet_nonce, and the wallet decrypts and
 * validates the echo. The test verifier mirrors keycloak-extension-oid4vp 0.11.1.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RequestUriMethodPostTest {

    @LocalServerPort
    private int port;

    @Test
    void postedFetchSendsMetadataAndCompletesFlowWithEncryptedRequestObject() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withRequestUriMethodPost()) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("data-credential-id=\"pid-jan-hart\"");
            assertThat(verifier.lastRequestObjectMethod()).isEqualTo("POST");
            assertThat(verifier.servedEncryptedRequestObject())
                    .as("the wallet's metadata asked for an encrypted request object")
                    .isTrue();
            assertThat(verifier.receivedWalletNonce()).isNotBlank();

            JsonNode metadata = new ObjectMapper().readValue(verifier.receivedWalletMetadata(), JsonNode.class);
            assertThat(metadata.get("vp_formats_supported").has("dc+sd-jwt")).isTrue();
            JsonNode key = metadata.get("jwks").get("keys").get(0);
            assertThat(key.get("kty").asText()).isEqualTo("EC");
            assertThat(key.get("alg").asText()).isEqualTo("ECDH-ES");
            assertThat(key.has("d")).as("only the public key leaves the wallet").isFalse();
            assertThat(metadata.get("request_object_encryption_enc_values_supported")
                            .valueStream()
                            .map(JsonNode::asText))
                    .contains("A128GCM");

            String flowState = hiddenField(picker.getBody(), "flowState");
            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();
            ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
            assertThat(response.formParameters().get("vp_token")).contains("pid");
        }
    }

    @Test
    void missingWalletNonceEchoIsAConformanceFinding() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestUriMethodPost().withoutWalletNonceEcho()) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("wallet_nonce");
        }
    }

    @Test
    void unencryptedAnswerToAnEncryptionRequestIsAConformanceFinding() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestUriMethodPost().withoutRequestObjectEncryption()) {
            ResponseEntity<String> picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("encrypted request object");
            assertThat(picker.getBody())
                    .as("flow continues in debug mode")
                    .contains("data-credential-id=\"pid-jan-hart\"");
        }
    }

    @Test
    void unknownRequestUriMethodFallsBackToGetWithAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            URI url = URI.create(authorizeUri(port, verifier) + "&request_uri_method=put");
            ResponseEntity<String> picker =
                    client(port).get().uri(url).retrieve().toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(verifier.lastRequestObjectMethod()).isEqualTo("GET");
            assertThat(picker.getBody()).contains("conformance-warnings");
            assertThat(picker.getBody()).contains("request_uri_method");
            assertThat(picker.getBody()).contains("data-credential-id=\"pid-jan-hart\"");
        }
    }
}
