package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.disclosures;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.WalletTestSupport;
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

    @Test
    void editedCredentialIsIssuedAndPreselectedForPresentation() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String picker = client(port).get().uri(authorizeUrl).retrieve().body(String.class);
            String flowState = hiddenField(picker, "flowState");
            assertThat(picker).contains("/authorize/edit");

            ResponseEntity<String> editForm = client(port)
                    .post()
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
            assertThat(editForm.getBody())
                    .as("the credential keeps its id and status list slot")
                    .contains("value=\"pid-maria-neumann\"")
                    .contains("name=\"statusIndex\"");

            ResponseEntity<String> save = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-maria-neumann&statusIndex=0&name="
                            + URLEncoder.encode("PID Maria (edited)", StandardCharsets.UTF_8)
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
            assertThat(save.getBody()).contains("data-credential-id=\"pid-maria-neumann\"");
            assertThat(save.getBody())
                    .as("the wallet credential is replaced for this flow, not duplicated")
                    .containsOnlyOnce("data-credential-id=\"pid-maria-neumann\"");
            int radioStart = save.getBody().indexOf("select-pid-pid-maria-neumann");
            assertThat(save.getBody().substring(radioStart, radioStart + 120))
                    .as("the new credential is preselected")
                    .contains("checked");
            assertThat(save.getBody()).contains("modified for this presentation");

            JsonNode stored = client(port)
                    .get()
                    .uri("/api/credentials/pid-maria-neumann")
                    .retrieve()
                    .body(JsonNode.class);
            assertThat(stored.get("claims").get("family_name").asText())
                    .as("editing during a flow does not change the wallet content")
                    .isEqualTo("Neumann");

            String carried = hiddenField(save.getBody(), "singlePresentationCredential");
            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-maria-neumann&singlePresentationCredential="
                            + URLEncoder.encode(carried, StandardCharsets.UTF_8) + "&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            String presentation = vpToken.get("pid").get(0).asText();
            assertThat(disclosures(presentation))
                    .anyMatch(disclosure -> "Edited-Neumann".equals(disclosure.getClaimValue()));

            SignedJWT issuerJwt = issuerJwt(presentation);
            @SuppressWarnings("unchecked")
            Map<String, Object> status =
                    (Map<String, Object>) issuerJwt.getJWTClaimsSet().getClaim("status");
            @SuppressWarnings("unchecked")
            Map<String, Object> statusList = (Map<String, Object>) status.get("status_list");
            assertThat(((Number) statusList.get("idx")).intValue())
                    .as("the status list slot of the wallet credential is inherited")
                    .isEqualTo(0);
        }
    }

    private static final String SET_DCQL_QUERY =
            """
            {"credentials": [
                {"id": "pid", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
                 "claims": [{"path": ["family_name"]}]},
                {"id": "ehic", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:ehic:1"]},
                 "claims": [{"path": ["family_name"]}]}
            ],
            "credential_sets": [{"options": [["pid"], ["pid", "ehic"]]}]}
            """;

    // the picker state the user leaves behind when opening the editor for the ehic query
    private static final String CARRIED_PICKER_STATE = "&editQueryId=ehic"
            + "&setOption%5B0%5D=1"
            + "&selection%5Bpid%5D=pid-erika-mustermann"
            + "&selection%5Behic%5D=ehic-maria-neumann";

    @Test
    void editingKeepsTheChosenAlternativeAndTheSelectionsOfEveryOtherQuery() throws Exception {
        try (TestVerifier verifier = new TestVerifier(SET_DCQL_QUERY)) {
            String picker = client(port)
                    .get()
                    .uri(WalletTestSupport.authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            String flowState = hiddenField(picker, "flowState");
            assertThat(tagAt(picker, "data-query-ids=\"pid\""))
                    .as("a fresh picker starts on the first alternative")
                    .contains("selected");

            ResponseEntity<String> editForm = client(port)
                    .post()
                    .uri("/authorize/edit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8) + CARRIED_PICKER_STATE)
                    .retrieve()
                    .toEntity(String.class);
            assertThat(editForm.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(editForm.getBody())
                    .as("the editor carries the picker state as hidden fields")
                    .contains("name=\"selection[pid]\" value=\"pid-erika-mustermann\"")
                    .contains("name=\"setOption[0]\" value=\"1\"")
                    .contains("name=\"editQueryId\"");

            ResponseEntity<String> save = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=ehic-maria-neumann&name="
                            + URLEncoder.encode("EHIC Maria (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:ehic:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Neumann"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                            + CARRIED_PICKER_STATE)
                    .retrieve()
                    .toEntity(String.class);

            assertThat(save.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(tagAt(save.getBody(), "data-query-ids=\"pid,ehic\""))
                    .as("the chosen alternative stays chosen instead of falling back to the first")
                    .contains("selected");
            assertThat(tagAt(save.getBody(), "id=\"select-pid-pid-erika-mustermann\""))
                    .as("the query that was not edited keeps its credential")
                    .contains("checked");
            assertThat(tagAt(save.getBody(), "id=\"select-pid-pid-thomas-bauer\""))
                    .as("the credential the user did not pick stays unchecked")
                    .doesNotContain("checked");
            assertThat(tagAt(save.getBody(), "id=\"select-ehic-ehic-maria-neumann\""))
                    .as("the issued credential answers the query it was created for")
                    .contains("checked");
        }
    }

    @Test
    void goingBackFromTheEditorKeepsTheChosenAlternativeAndSelections() throws Exception {
        try (TestVerifier verifier = new TestVerifier(SET_DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");

            ResponseEntity<String> picker = client(port)
                    .post()
                    .uri("/authorize/edit/cancel")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8) + CARRIED_PICKER_STATE)
                    .retrieve()
                    .toEntity(String.class);

            assertThat(picker.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(tagAt(picker.getBody(), "data-query-ids=\"pid,ehic\"")).contains("selected");
            assertThat(tagAt(picker.getBody(), "id=\"select-pid-pid-erika-mustermann\""))
                    .contains("checked");
            assertThat(tagAt(picker.getBody(), "id=\"select-ehic-ehic-maria-neumann\""))
                    .contains("checked");
        }
    }

    // the whole tag a marker sits in, so an assertion sees only that input or option element
    private static String tagAt(String html, String marker) {
        int position = html.indexOf(marker);
        assertThat(position).as("'%s' present", marker).isNotNegative();
        return html.substring(html.lastIndexOf('<', position), html.indexOf('>', position) + 1);
    }

    @Test
    void editedCredentialNotMatchingTheQueryRedisplaysFormWithError() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            URI authorizeUrl = URI.create("http://localhost:" + port + "/authorize?client_id="
                    + URLEncoder.encode(verifier.clientId(), StandardCharsets.UTF_8)
                    + "&request_uri="
                    + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
            String flowState =
                    hiddenField(client(port).get().uri(authorizeUrl).retrieve().body(String.class), "flowState");

            ResponseEntity<String> save = client(port)
                    .post()
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
}
