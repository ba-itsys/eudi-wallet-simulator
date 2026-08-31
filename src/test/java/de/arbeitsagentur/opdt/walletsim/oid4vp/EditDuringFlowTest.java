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
                    .body("credentialId=pid-jan-hart&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(editForm.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(editForm.getBody()).contains("id=\"claim-family_name\"");
            assertThat(editForm.getBody()).contains("t Hart");
            assertThat(editForm.getBody()).contains("name=\"flowState\"");
            assertThat(editForm.getBody())
                    .as("the credential keeps its id and status list slot")
                    .contains("value=\"pid-jan-hart\"")
                    .contains("name=\"statusIndex\"");

            ResponseEntity<String> save = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-jan-hart&statusIndex=0&name="
                            + URLEncoder.encode("PID Jan (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Hart"
                            + "&claimValues%5Bgiven_name%5D=Jan"
                            + "&claimValues%5Bbirthdate%5D=1978-02-12"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(save.getStatusCode())
                    .as("issuing returns to the selection instead of presenting")
                    .isEqualTo(HttpStatus.OK);
            assertThat(save.getBody()).contains("data-credential-id=\"pid-jan-hart\"");
            assertThat(save.getBody())
                    .as("the wallet credential is replaced for this flow, not duplicated")
                    .containsOnlyOnce("data-credential-id=\"pid-jan-hart\"");
            int radioStart = save.getBody().indexOf("select-pid-pid-jan-hart");
            assertThat(save.getBody().substring(radioStart, radioStart + 120))
                    .as("the new credential is preselected")
                    .contains("checked");
            assertThat(save.getBody()).contains("modified for this presentation");

            JsonNode stored = client(port)
                    .get()
                    .uri("/api/credentials/pid-jan-hart")
                    .retrieve()
                    .body(JsonNode.class);
            assertThat(stored.get("claims").get("family_name").asText())
                    .as("editing during a flow does not change the wallet content")
                    .isEqualTo("'t Hart");

            String carried = hiddenField(save.getBody(), "singlePresentationCredentials");
            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&singlePresentationCredentials="
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
                    .anyMatch(disclosure -> "Edited-Hart".equals(disclosure.getClaimValue()));

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
            + "&selection%5Behic%5D=ehic-erika-mustermann";

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
                    .body("id=ehic-erika-mustermann&name="
                            + URLEncoder.encode("EHIC Erika (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:ehic:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Mustermann"
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
            assertThat(tagAt(save.getBody(), "id=\"select-ehic-ehic-erika-mustermann\""))
                    .as("the issued credential answers the query it was created for")
                    .contains("checked");
        }
    }

    @Test
    void everyQueryOfASetKeepsItsOwnEditedCredential() throws Exception {
        try (TestVerifier verifier = new TestVerifier(SET_DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");
            String pickerState = "&setOption%5B0%5D=1"
                    + "&selection%5Bpid%5D=pid-erika-mustermann"
                    + "&selection%5Behic%5D=ehic-erika-mustermann";

            ResponseEntity<String> afterPidEdit = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-erika-mustermann&editQueryId=pid&name="
                            + URLEncoder.encode("PID Erika (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:pid:de:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Erika"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                            + pickerState)
                    .retrieve()
                    .toEntity(String.class);
            assertThat(afterPidEdit.getStatusCode()).isEqualTo(HttpStatus.OK);
            String carriedAfterPid = hiddenField(afterPidEdit.getBody(), "singlePresentationCredentials");

            ResponseEntity<String> afterEhicEdit = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=ehic-erika-mustermann&editQueryId=ehic&name="
                            + URLEncoder.encode("EHIC Erika (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:ehic:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Edited-Ehic"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                            + "&singlePresentationCredentials="
                            + URLEncoder.encode(carriedAfterPid, StandardCharsets.UTF_8)
                            + pickerState)
                    .retrieve()
                    .toEntity(String.class);
            assertThat(afterEhicEdit.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(afterEhicEdit.getBody())
                    .as("editing the second query keeps the credential edited for the first one")
                    .contains("PID Erika (edited)")
                    .contains("EHIC Erika (edited)");

            String carried = hiddenField(afterEhicEdit.getBody(), "singlePresentationCredentials");
            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                            + "&singlePresentationCredentials="
                            + URLEncoder.encode(carried, StandardCharsets.UTF_8)
                            + pickerState)
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            assertThat(disclosures(vpToken.get("pid").get(0).asText()))
                    .as("the pid presentation carries the edited claim")
                    .anyMatch(disclosure -> "Edited-Erika".equals(disclosure.getClaimValue()));
            assertThat(disclosures(vpToken.get("ehic").get(0).asText()))
                    .as("the ehic presentation carries the edited claim")
                    .anyMatch(disclosure -> "Edited-Ehic".equals(disclosure.getClaimValue()));
        }
    }

    @Test
    void reEditingACarriedCredentialReplacesItInsteadOfAddingASecondCard() throws Exception {
        try (TestVerifier verifier = new TestVerifier(SET_DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");
            String pickerState = "&setOption%5B0%5D=1"
                    + "&selection%5Bpid%5D=pid-erika-mustermann"
                    + "&selection%5Behic%5D=ehic-erika-mustermann";

            String carried =
                    hiddenField(editEhic(flowState, "First-Edit", "", pickerState), "singlePresentationCredentials");
            String pickerAfterSecondEdit = editEhic(flowState, "Second-Edit", carried, pickerState);

            // every credential is also offered as a non-matching pick in the other slot, so the
            // replacement check has to look at the ehic slot's own radio button
            assertThat(pickerAfterSecondEdit)
                    .as("the second edit replaces the first instead of adding a second candidate")
                    .containsOnlyOnce("id=\"select-ehic-ehic-erika-mustermann\"");
            assertThat(tagAt(pickerAfterSecondEdit, "id=\"select-pid-pid-erika-mustermann\""))
                    .as("the query that was never edited keeps its wallet credential")
                    .contains("checked");

            ResponseEntity<String> editor = client(port)
                    .post()
                    .uri("/authorize/edit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("editQueryId=ehic&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                            + "&singlePresentationCredentials="
                            + URLEncoder.encode(
                                    hiddenField(pickerAfterSecondEdit, "singlePresentationCredentials"),
                                    StandardCharsets.UTF_8)
                            + pickerState)
                    .retrieve()
                    .toEntity(String.class);
            assertThat(editor.getBody())
                    .as("re-opening the editor starts from the credential the flow carries, not the wallet one")
                    .contains("Second-Edit");
        }
    }

    // issues an ad-hoc ehic credential for the running flow and returns the picker that comes back
    private String editEhic(String flowState, String familyName, String carried, String pickerState) {
        return client(port)
                .post()
                .uri("/authorize/edit/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=ehic-erika-mustermann&editQueryId=ehic&name="
                        + URLEncoder.encode("EHIC " + familyName, StandardCharsets.UTF_8)
                        + "&vct=" + URLEncoder.encode("urn:eudi:ehic:1", StandardCharsets.UTF_8)
                        + "&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=" + familyName
                        + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8)
                        + "&singlePresentationCredentials=" + URLEncoder.encode(carried, StandardCharsets.UTF_8)
                        + pickerState)
                .retrieve()
                .body(String.class);
    }

    @Test
    void anUnreadableCarriedCredentialShowsTheFlowErrorPage() {
        ResponseEntity<String> response = client(port)
                .post()
                .uri("/authorize/edit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("credentialId=pid-jan-hart&singlePresentationCredentials=not-a-credential")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .as("a broken carried value is answered with the wallet error page, not a stack trace")
                .contains("The credentials this flow carries cannot be read")
                .doesNotContain("java.lang.IllegalArgumentException");
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
            assertThat(tagAt(picker.getBody(), "id=\"select-ehic-ehic-erika-mustermann\""))
                    .contains("checked");
        }
    }

    // the whole tag a marker sits in, so an assertion sees only that input or option element
    private static String tagAt(String html, String marker) {
        int position = html.indexOf(marker);
        assertThat(position).as("'%s' present", marker).isNotNegative();
        return html.substring(html.lastIndexOf('<', position), html.indexOf('>', position) + 1);
    }

    // a deliberately broken credential is a test tool, so issuing it returns to the picker with
    // show all turned on and the credential preselected as a non-matching offer
    @Test
    void editedCredentialNotMatchingTheQueryComesBackPreselectedBehindShowAll() throws Exception {
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
            assertThat(tagAt(save.getBody(), "id=\"show-all-credentials\"")).contains("checked");
            int badge = save.getBody().indexOf("id=\"mismatch-pid-pid-no-family-name\"");
            assertThat(badge).isNotNegative();
            assertThat(save.getBody().substring(badge, save.getBody().indexOf("</span>", badge)))
                    .contains("requested claims are missing");
            assertThat(tagAt(save.getBody(), "id=\"select-pid-pid-no-family-name\""))
                    .contains("checked");
        }
    }

    private static final String DE_PID_DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:de:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["title"]}]
            }]}
            """;

    // the German PID rulebook keeps claims the eID does not carry with an empty value, and a
    // verifier may ask for one of them
    @Test
    void editingACredentialWithAnEmptyClaimKeepsItAnswerableForTheQuery() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DE_PID_DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");

            String editForm = client(port)
                    .post()
                    .uri("/authorize/edit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("credentialId=pid-erika-mustermann&editQueryId=pid&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .body(String.class);
            assertThat(tagAt(editForm, "name=\"claimValues[title]\""))
                    .as("an empty claim renders as a quoted empty string instead of a blank field")
                    .contains("value=\"&quot;&quot;\"");

            String picker = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-erika-mustermann&editQueryId=pid&name="
                            + URLEncoder.encode("PID Erika (edited)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:pid:de:1", StandardCharsets.UTF_8)
                            + "&validityDays=14"
                            + submittedClaimValues(editForm)
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .body(String.class);
            assertThat(picker)
                    .as("saving the editor unchanged keeps the credential answering the query")
                    .doesNotContain("does not match the verifier");

            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-erika-mustermann&singlePresentationCredentials="
                            + URLEncoder.encode(
                                    hiddenField(picker, "singlePresentationCredentials"), StandardCharsets.UTF_8)
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            assertThat(disclosures(vpToken.get("pid").get(0).asText()))
                    .as("the empty claim is disclosed with its empty value")
                    .anyMatch(disclosure ->
                            "title".equals(disclosure.getClaimName()) && "".equals(disclosure.getClaimValue()));
        }
    }

    // the claim fields of the rendered editor, posted back the way the browser would
    private static String submittedClaimValues(String html) {
        StringBuilder body = new StringBuilder();
        java.util.regex.Matcher matcher = java.util.regex.Pattern.compile(
                        "<input[^>]*name=\"claimValues\\[([^\\]]+)\\][^>]*>")
                .matcher(html);
        while (matcher.find()) {
            java.util.regex.Matcher value =
                    java.util.regex.Pattern.compile("value=\"([^\"]*)\"").matcher(matcher.group());
            body.append("&claimValues%5B")
                    .append(URLEncoder.encode(matcher.group(1), StandardCharsets.UTF_8))
                    .append("%5D=")
                    .append(
                            value.find()
                                    ? URLEncoder.encode(
                                            org.springframework.web.util.HtmlUtils.htmlUnescape(value.group(1)),
                                            StandardCharsets.UTF_8)
                                    : "");
        }
        assertThat(body.length()).as("editor renders claim fields").isPositive();
        return body.toString();
    }
}
