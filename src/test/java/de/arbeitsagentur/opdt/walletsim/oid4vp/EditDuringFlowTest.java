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
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The bundid-simulator mechanic inside the presentation flow: pick a credential, edit it as a
 * template while the flow state is carried along, and saving issues a fresh ad-hoc credential
 * that is immediately presented to the verifier.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class EditDuringFlowTest {

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

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void editedCredentialIsIssuedAndPreselectedForPresentation() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String picker = client().get().uri(authorizeUrl).retrieve().body(String.class);
            String flowState = extractHiddenField(picker, "flowState");
            assertThat(picker).contains("/authorize/edit");

            ResponseEntity<String> editForm = client().post()
                    .uri("/authorize/edit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("credentialId=pid-maria-neumann&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(editForm.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(editForm.getBody()).contains("id=\"claim-family_name\"");
            assertThat(editForm.getBody()).contains("Neumann");
            assertThat(editForm.getBody()).contains("name=\"flowState\"");

            ResponseEntity<String> save = client().post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-maria-edited&name=" + URLEncoder.encode("PID Maria (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Neumann"
                            + "&claimValues%5Bgiven_name%5D=Maria"
                            + "&claimValues%5Bbirthdate%5D=1964-08-12"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(save.getStatusCode())
                    .as("issuing returns to the selection instead of presenting")
                    .isEqualTo(HttpStatus.OK);
            assertThat(save.getBody()).contains("data-credential-id=\"pid-maria-edited\"");
            int radioStart = save.getBody().indexOf("select-pid-pid-maria-edited");
            assertThat(save.getBody().substring(radioStart, radioStart + 120))
                    .as("the new credential is preselected")
                    .contains("checked");
            assertThat(save.getBody()).contains("this presentation only");

            ResponseEntity<String> stored = client().get()
                    .uri("/api/credentials/pid-maria-edited")
                    .retrieve()
                    .toEntity(String.class);
            assertThat(stored.getStatusCode())
                    .as("editing during a flow does not change the wallet content")
                    .isEqualTo(HttpStatus.NOT_FOUND);

            String carried = extractHiddenField(save.getBody(), "singlePresentationCredential");
            ResponseEntity<String> present = client().post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-maria-edited&singlePresentationCredential="
                            + URLEncoder.encode(carried, StandardCharsets.UTF_8) + "&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            String presentation = vpToken.get("pid").get(0).asText();
            List<String> disclosures = List.of(presentation.split("~")).stream()
                    .skip(1)
                    .limit(presentation.split("~").length - 2L)
                    .map(part -> new String(Base64.getUrlDecoder().decode(part), StandardCharsets.UTF_8))
                    .toList();
            assertThat(disclosures).anyMatch(d -> d.contains("Edited-Neumann"));
        }
    }

    @Test
    void editedCredentialNotMatchingTheQueryRedisplaysFormWithError() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String flowState = extractHiddenField(
                    client().get().uri(authorizeUrl).retrieve().body(String.class), "flowState");

            ResponseEntity<String> save = client().post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-no-family-name&name=Broken&vct=urn:eudi:pid:1&validityDays=30"
                            + "&claimValues%5Bgiven_name%5D=OnlyGivenName"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(save.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(save.getBody()).contains("does not match the verifier");
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
