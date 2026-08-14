package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * direct_post.jwt: the authorization response is a JWE encrypted to the verifier's ephemeral key
 * from client_metadata.jwks, echoing that key's kid so the verifier can resolve the flow without
 * a state form field.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EncryptedResponseTest {

    @LocalServerPort
    private int port;

    @Test
    void directPostJwtEncryptsResponseToVerifierKey() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withEncryptedResponses()) {
            URI authorizeUri = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));

            ResponseEntity<String> picker =
                    client(port).get().uri(authorizeUri).retrieve().toEntity(String.class);
            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            String flowState = hiddenField(picker.getBody(), "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse received = verifier.awaitResponse();
            String jwe = received.formParameters().get("response");
            assertThat(jwe)
                    .as("encrypted mode posts a single 'response' JWE parameter")
                    .isNotNull();

            EncryptedJWT encrypted = EncryptedJWT.parse(jwe);
            assertThat(encrypted.getHeader().getKeyID())
                    .as("JWE echoes the verifier encryption key kid")
                    .isEqualTo(verifier.responseEncryptionKey().getKeyID());

            assertThat(encrypted.getHeader().getEncryptionMethod())
                    .as("HAIP prefers A256GCM when the verifier supports it")
                    .isEqualTo(EncryptionMethod.A256GCM);
            encrypted.decrypt(new ECDHDecrypter(verifier.responseEncryptionKey().toECPrivateKey()));
            Map<String, Object> payload = encrypted.getJWTClaimsSet().getClaims();
            assertThat(payload.get("state")).isEqualTo(verifier.state());

            assertThat(payload.get("vp_token"))
                    .as("vp_token is a top-level JSON object inside the JWE (OID4VP 1.0 §8.3)")
                    .isInstanceOf(Map.class);
            JsonNode vpToken = new ObjectMapper()
                    .readValue(new ObjectMapper().writeValueAsString(payload.get("vp_token")), JsonNode.class);
            assertThat(vpToken.get("pid").get(0).asText()).contains("~");
        }
    }
}
