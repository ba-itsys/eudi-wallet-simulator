package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * claim_sets pick the first satisfiable option in preference order (OID4VP 1.0 §6.4.2) and
 * credential_sets request combinations of credential queries answered as one multi entry
 * vp_token (OID4VP 1.0 §6.3.1).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CredentialAndClaimSetsTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void claimSetsFallBackToTheFirstSatisfiableOption() throws Exception {
        String dcql =
                """
                {"credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["urn:eudi:pid:1"]},
                    "claims": [
                        {"id": "fam", "path": ["family_name"]},
                        {"id": "giv", "path": ["given_name"]},
                        {"id": "nick", "path": ["nickname"]}
                    ],
                    "claim_sets": [["fam", "nick"], ["fam", "giv"]]
                }]}
                """;
        try (TestVerifier verifier = new TestVerifier(dcql)) {
            String picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().body(String.class);
            assertThat(picker).contains("data-credential-id=\"pid-maria-neumann\"");
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            List<String> disclosedNames = disclosedClaimNames(
                    presentation(verifier.awaitResponse().formParameters().get("vp_token"), "pid"));
            assertThat(disclosedNames).anyMatch(d -> d.contains("\"family_name\""));
            assertThat(disclosedNames).anyMatch(d -> d.contains("\"given_name\""));
            assertThat(disclosedNames)
                    .as("only the satisfied claim set option is disclosed")
                    .noneMatch(d -> d.contains("\"birthdate\""));
        }
    }

    @Test
    void credentialSetsProduceAMultiEntryVpToken() throws Exception {
        String dcql =
                """
                {"credentials": [
                    {"id": "pid1", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                     "claims": [{"path": ["family_name"]}]},
                    {"id": "pid2", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                     "claims": [{"path": ["given_name"]}]},
                    {"id": "bank", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:bank:1"]},
                     "claims": [{"path": ["iban"]}]}
                ],
                "credential_sets": [
                    {"options": [["pid1", "pid2"]]},
                    {"options": [["bank"]], "required": false}
                ]}
                """;
        try (TestVerifier verifier = new TestVerifier(dcql)) {
            String picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().body(String.class);
            assertThat(picker).contains("id=\"select-pid1-pid-maria-neumann\"");
            assertThat(picker).contains("id=\"select-pid2-pid-thomas-bauer\"");
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid1%5D=pid-maria-neumann"
                            + "&selection%5Bpid2%5D=pid-thomas-bauer"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            String vpToken = verifier.awaitResponse().formParameters().get("vp_token");
            assertThat(disclosedClaimNames(presentation(vpToken, "pid1"))).anyMatch(d -> d.contains("Neumann"));
            assertThat(disclosedClaimNames(presentation(vpToken, "pid2"))).anyMatch(d -> d.contains("Thomas"));
            assertThat(new ObjectMapper().readValue(vpToken, JsonNode.class).has("bank"))
                    .as("the unsatisfiable optional set is omitted")
                    .isFalse();
        }
    }

    private static final String ALTERNATIVES_DCQL =
            """
            {"credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]},
                 "claims": [{"path": ["family_name"]}]},
                {"id": "extra", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
                 "claims": [{"path": ["given_name"]}]}
            ],
            "credential_sets": [
                {"options": [["pid", "extra"], ["pid"]]}
            ]}
            """;

    @Test
    void alternativeSetOptionsAreUserSelectable() throws Exception {
        try (TestVerifier verifier = new TestVerifier(ALTERNATIVES_DCQL)) {
            String picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().body(String.class);
            assertThat(picker)
                    .as("both alternatives are offered as a choice")
                    .contains("id=\"set-option-0-0\"")
                    .contains("id=\"set-option-0-1\"");
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("setOption%5B0%5D=1"
                            + "&selection%5Bpid%5D=pid-maria-neumann"
                            + "&selection%5Bextra%5D=pid-thomas-bauer"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            String vpToken = verifier.awaitResponse().formParameters().get("vp_token");
            JsonNode json = new ObjectMapper().readValue(vpToken, JsonNode.class);
            assertThat(json.has("pid")).isTrue();
            assertThat(json.has("extra"))
                    .as("the chosen option requests only the pid credential")
                    .isFalse();
        }
    }

    @Test
    void alternativeSetDefaultsToTheFirstOption() throws Exception {
        try (TestVerifier verifier = new TestVerifier(ALTERNATIVES_DCQL)) {
            String picker =
                    client().get().uri(authorizeUri(verifier)).retrieve().body(String.class);
            String flowState = extractHiddenField(picker, "flowState");

            ResponseEntity<String> submit = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("setOption%5B0%5D=0"
                            + "&selection%5Bpid%5D=pid-maria-neumann"
                            + "&selection%5Bextra%5D=pid-thomas-bauer"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            String vpToken = verifier.awaitResponse().formParameters().get("vp_token");
            JsonNode json = new ObjectMapper().readValue(vpToken, JsonNode.class);
            assertThat(json.has("pid")).isTrue();
            assertThat(json.has("extra"))
                    .as("the first option requests both credentials")
                    .isTrue();
        }
    }

    private static String presentation(String vpToken, String queryId) {
        JsonNode json = new ObjectMapper().readValue(vpToken, JsonNode.class);
        assertThat(json.has(queryId))
                .as("vp_token contains entry '%s'", queryId)
                .isTrue();
        return json.get(queryId).get(0).asText();
    }

    private static List<String> disclosedClaimNames(String presentation) {
        String[] parts = presentation.split("~");
        return List.of(parts).subList(1, parts.length - 1).stream()
                .map(part -> new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8))
                .toList();
    }

    private static String extractHiddenField(String html, String name) {
        String marker = "name=\"" + name + "\" value=\"";
        int start = html.indexOf(marker);
        assertThat(start).as("hidden field '%s' present", name).isNotNegative();
        start += marker.length();
        return html.substring(start, html.indexOf('"', start));
    }

    private URI authorizeUri(TestVerifier verifier) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }
}
