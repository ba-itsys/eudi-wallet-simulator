package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Nested disclosures: requesting a nested claim path discloses only that branch. The verifier
 * side decode sees address.locality but not the sibling street_address.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class NestedDisclosureTest {

    private static final String DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["address", "locality"]}]
            }]}
            """;

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void nestedClaimPathDisclosesOnlyTheRequestedBranch() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String picker = client().get().uri(authorizeUrl).retrieve().body(String.class);
            assertThat(picker).contains("address.locality");
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            String vpToken = verifier.awaitResponse().formParameters().get("vp_token");
            String presentation = new ObjectMapper()
                    .readValue(vpToken, JsonNode.class)
                    .get("pid")
                    .get(0)
                    .asText();
            String[] parts = presentation.split("~");
            SignedJWT issuerJwt = SignedJWT.parse(parts[0]);
            List<Disclosure> disclosures = new ArrayList<>();
            for (int i = 1; i < parts.length - 1; i++) {
                disclosures.add(Disclosure.parse(parts[i]));
            }

            Map<String, Object> decoded =
                    new SDObjectDecoder().decode(issuerJwt.getJWTClaimsSet().getClaims(), disclosures);
            assertThat(decoded.get("family_name")).isEqualTo("Neumann");
            @SuppressWarnings("unchecked")
            Map<String, Object> address = (Map<String, Object>) decoded.get("address");
            assertThat(address.get("locality")).isEqualTo("Berlin");
            assertThat(address)
                    .as("sibling claims of the requested nested path stay undisclosed")
                    .doesNotContainKeys("street_address", "postal_code");
            assertThat(decoded).doesNotContainKey("birthdate");
            assertThat((List<?>) decoded.get("nationalities"))
                    .as("array values stay undisclosed, only the structure is visible")
                    .isEmpty();
        }
    }

    private static String extractHiddenField(String html, String name) {
        String marker = "name=\"" + name + "\" value=\"";
        int start = html.indexOf(marker);
        assertThat(start).as("hidden field '%s' present", name).isNotNegative();
        start += marker.length();
        return html.substring(start, html.indexOf('"', start));
    }
}
