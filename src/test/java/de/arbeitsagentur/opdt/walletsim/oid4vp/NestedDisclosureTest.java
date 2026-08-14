package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.disclosures;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.SDObjectDecoder;
import com.nimbusds.jwt.SignedJWT;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
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

    @Test
    void nestedClaimPathDisclosesOnlyTheRequestedBranch() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).contains("address.locality");
            String flowState = hiddenField(picker, "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
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
            SignedJWT issuerJwt = issuerJwt(presentation);
            Map<String, Object> decoded =
                    new SDObjectDecoder().decode(issuerJwt.getJWTClaimsSet().getClaims(), disclosures(presentation));
            assertThat(decoded.get("family_name")).isEqualTo("Neumann");
            @SuppressWarnings("unchecked")
            Map<String, Object> address = (Map<String, Object>) decoded.get("address");
            assertThat(address.get("locality")).isEqualTo("Berlin");
            assertThat(address)
                    .as("sibling claims of the requested nested path stay undisclosed")
                    .doesNotContainKeys("street_address", "postal_code");
            assertThat(decoded)
                    .as("rulebook credentials disclose nothing beyond the requested claims")
                    .doesNotContainKeys("birthdate", "nationalities", "issuing_country", "issuing_authority");
        }
    }
}
