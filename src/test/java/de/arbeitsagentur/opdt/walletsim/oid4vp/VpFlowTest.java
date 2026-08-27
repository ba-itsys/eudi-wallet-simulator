package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.disclosures;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.keyBindingJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Same-device OID4VP happy flow against an in-JVM test verifier: entry via web /authorize link,
 * credential picker, SD-JWT VP with KB-JWT posted via direct_post, browser redirected to the
 * verifier's redirect_uri. The returned presentation is verified with independent test-side crypto.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VpFlowTest {

    private static final String DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]
            }]}
            """;

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    @Test
    void sameDeviceFlowProducesVerifiablePresentationAndRedirects() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));

            ResponseEntity<String> picker =
                    client(port).get().uri(authorizeUrl).retrieve().toEntity(String.class);
            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("data-credential-id=\"pid-jan-hart\"");
            assertThat(picker.getBody()).contains("name=\"flowState\"");

            String flowState = hiddenField(picker.getBody(), "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(submit.getStatusCode().is3xxRedirection())
                    .as("same-device flow redirects the browser to the verifier redirect_uri")
                    .isTrue();
            assertThat(submit.getHeaders().getLocation().toString()).isEqualTo(verifier.redirectUri());

            ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());

            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            String presentation = vpToken.get("pid").get(0).asText();
            verifyPresentation(presentation, verifier);
        }
    }

    @Test
    void cancelPostsAccessDeniedAndFollowsRedirect() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String flowState =
                    hiddenField(client(port).get().uri(authorizeUrl).retrieve().body(String.class), "flowState");

            ResponseEntity<String> cancel = client(port)
                    .post()
                    .uri("/authorize/cancel")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(cancel.getStatusCode().is3xxRedirection()).isTrue();
            ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("access_denied");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }

    @Test
    void pickerShowsTheSentDcqlQueryInACollapsibleDebugPane() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));

            String picker = client(port).get().uri(authorizeUrl).retrieve().body(String.class);

            assertThat(picker).contains("<details id=\"dcql-debug\"");
            assertThat(picker).contains("&quot;vct_values&quot;");
            assertThat(picker).contains("urn:eudi:pid:1");
        }
    }

    @Test
    void crossDeviceCompletionRendersWhenNoRedirectUriIsReturned() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY).withoutRedirectUri()) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String flowState =
                    hiddenField(client(port).get().uri(authorizeUrl).retrieve().body(String.class), "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(submit.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(submit.getBody()).contains("Presentation sent");
        }
    }

    private void verifyPresentation(String presentation, TestVerifier verifier) throws Exception {
        SignedJWT issuerJwt = issuerJwt(presentation);
        assertThat(issuerJwt.verify(
                        new ECDSAVerifier((ECPublicKey) pki.issuerCertificate().getPublicKey())))
                .isTrue();

        List<String> disclosedNames =
                disclosures(presentation).stream().map(Disclosure::getClaimName).toList();
        assertThat(disclosedNames).contains("family_name", "given_name");
        assertThat(disclosedNames).as("only requested claims are disclosed").doesNotContain("birthdate");

        SignedJWT kbJwt = keyBindingJwt(presentation);
        assertThat(kbJwt.getHeader().getType().toString()).isEqualTo("kb+jwt");
        Map<String, Object> cnf = asMap(issuerJwt.getJWTClaimsSet().getClaim("cnf"));
        ECKey holderKey = ECKey.parse(new ObjectMapper().writeValueAsString(cnf.get("jwk")));
        assertThat(kbJwt.verify(new ECDSAVerifier(holderKey.toECPublicKey()))).isTrue();

        Map<String, Object> kbClaims = kbJwt.getJWTClaimsSet().getClaims();
        assertThat(kbJwt.getJWTClaimsSet().getAudience()).containsExactly(verifier.clientId());
        assertThat(kbClaims.get("nonce")).isEqualTo(verifier.nonce());

        // recomputed here the way a verifier does it, rather than asking the library again
        String presented = presentation.substring(0, presentation.lastIndexOf('~') + 1);
        String expectedSdHash = Base64URL.encode(
                        MessageDigest.getInstance("SHA-256").digest(presented.getBytes(StandardCharsets.US_ASCII)))
                .toString();
        assertThat(kbClaims.get("sd_hash")).isEqualTo(expectedSdHash);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }
}
