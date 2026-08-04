package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Same-device OID4VP happy flow against an in-JVM test verifier: entry via web /authorize link,
 * credential picker, SD-JWT VP with KB-JWT posted via direct_post, browser redirected to the
 * verifier's redirect_uri. The returned presentation is verified with independent test-side
 * crypto, mirroring keycloak-extension-oid4vp's checks.
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

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void sameDeviceFlowProducesVerifiablePresentationAndRedirects() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            java.net.URI authorizeUrl = java.net.URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));

            ResponseEntity<String> picker =
                    client().get().uri(authorizeUrl).retrieve().toEntity(String.class);
            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(picker.getBody()).contains("data-credential-id=\"pid-maria-neumann\"");
            assertThat(picker.getBody()).contains("name=\"flowState\"");

            String flowState = extractHiddenField(picker.getBody(), "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("credentialId=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(submit.getStatusCode().is3xxRedirection())
                    .as("same-device flow redirects the browser to the verifier redirect_uri")
                    .isTrue();
            assertThat(submit.getHeaders().getLocation().toString()).isEqualTo(verifier.redirectUri());

            TestVerifier.ReceivedResponse response = verifier.awaitResponse();
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
            java.net.URI authorizeUrl = java.net.URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String flowState = extractHiddenField(
                    client().get().uri(authorizeUrl).retrieve().body(String.class), "flowState");

            ResponseEntity<String> cancel = client().post()
                    .uri("/authorize/cancel")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(cancel.getStatusCode().is3xxRedirection()).isTrue();
            TestVerifier.ReceivedResponse response = verifier.awaitResponse();
            assertThat(response.formParameters().get("error")).isEqualTo("access_denied");
            assertThat(response.formParameters().get("state")).isEqualTo(verifier.state());
        }
    }

    private void verifyPresentation(String presentation, TestVerifier verifier) throws Exception {
        String[] parts = presentation.split("~");
        assertThat(parts.length).as("issuer JWT, disclosures, KB-JWT").isGreaterThanOrEqualTo(3);

        SignedJWT issuerJwt = SignedJWT.parse(parts[0]);
        assertThat(issuerJwt.verify(
                        new ECDSAVerifier((ECPublicKey) pki.issuerCertificate().getPublicKey())))
                .isTrue();

        List<String> disclosedNames = List.of(parts).subList(1, parts.length - 1).stream()
                .map(part -> new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8))
                .toList();
        assertThat(disclosedNames).anyMatch(d -> d.contains("\"family_name\""));
        assertThat(disclosedNames).anyMatch(d -> d.contains("\"given_name\""));
        assertThat(disclosedNames)
                .as("only requested claims are disclosed")
                .noneMatch(d -> d.contains("\"birthdate\""));

        SignedJWT kbJwt = SignedJWT.parse(parts[parts.length - 1]);
        assertThat(kbJwt.getHeader().getType().toString()).isEqualTo("kb+jwt");
        Map<String, Object> cnf = asMap(issuerJwt.getJWTClaimsSet().getClaim("cnf"));
        ECKey holderKey = ECKey.parse(new ObjectMapper().writeValueAsString(cnf.get("jwk")));
        assertThat(kbJwt.verify(new ECDSAVerifier(holderKey.toECPublicKey()))).isTrue();

        Map<String, Object> kbClaims = kbJwt.getJWTClaimsSet().getClaims();
        assertThat(kbJwt.getJWTClaimsSet().getAudience()).containsExactly(verifier.clientId());
        assertThat(kbClaims.get("nonce")).isEqualTo(verifier.nonce());

        String presented = presentation.substring(0, presentation.lastIndexOf('~') + 1);
        String expectedSdHash = Base64URL.encode(
                        MessageDigest.getInstance("SHA-256").digest(presented.getBytes(StandardCharsets.US_ASCII)))
                .toString();
        assertThat(kbClaims.get("sd_hash")).isEqualTo(expectedSdHash);
    }

    private static String extractHiddenField(String html, String name) {
        String marker = "name=\"" + name + "\" value=\"";
        int start = html.indexOf(marker);
        assertThat(start).as("hidden field '%s' present", name).isNotNegative();
        start += marker.length();
        return html.substring(start, html.indexOf('"', start));
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }
}
