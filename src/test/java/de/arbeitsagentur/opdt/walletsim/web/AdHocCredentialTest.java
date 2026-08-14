package de.arbeitsagentur.opdt.walletsim.web;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

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

/**
 * Ad-hoc credentials in the UI: the home page lists wallet content as cards, editing clones the
 * selected credential as a template (bundid-simulator mechanic), saving issues a fresh signed
 * SD-JWT into the store, and revocation can be toggled per card.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class AdHocCredentialTest {

    @LocalServerPort
    private int port;

    @Test
    void homePageListsWalletCredentialsAsCards() {
        ResponseEntity<String> home = client(port).get().uri("/").retrieve().toEntity(String.class);

        assertThat(home.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(home.getBody()).contains("data-credential-id=\"pid-maria-neumann\"");
        assertThat(home.getBody()).contains("urn:eudi:pid:1");
        assertThat(home.getBody()).contains("Maria Neumann");
    }

    @Test
    void cardsOfCredentialsWithoutNameClaimsStayEmptyInsteadOfShowingNull() {
        client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=nameless&name=Nameless&vct=urn:eudi:ehic:1&validityDays=30"
                        + "&claimValues%5Bdocument_number%5D=X1")
                .retrieve()
                .toBodilessEntity();

        ResponseEntity<String> home = client(port).get().uri("/").retrieve().toEntity(String.class);

        assertThat(home.getBody()).contains("data-credential-id=\"nameless\"");
        assertThat(home.getBody()).doesNotContain("null");
    }

    @Test
    void editClonesSelectedCredentialAsTemplateWithPerClaimFields() {
        ResponseEntity<String> editForm = client(port)
                .post()
                .uri("/credentials/edit")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("credentialId=pid-maria-neumann")
                .retrieve()
                .toEntity(String.class);

        assertThat(editForm.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(editForm.getBody())
                .as("every claim renders as its own input with a stable id")
                .contains("id=\"claim-family_name\"");
        assertThat(editForm.getBody()).contains("name=\"claimValues[family_name]\"");
        assertThat(editForm.getBody())
                .as("nested claims render as dot notation fields")
                .contains("id=\"claim-address.street_address\"");
        assertThat(editForm.getBody()).contains("id=\"claim-address.locality\"");
        assertThat(editForm.getBody()).contains("Neumann");
        assertThat(editForm.getBody()).contains("id=\"new-claim-name\"");
        assertThat(editForm.getBody())
                .as("clone gets a fresh id suggestion, not the original id")
                .doesNotContain("value=\"pid-maria-neumann\"");
    }

    @Test
    void savingAdHocCredentialIssuesSignedSdJwt() {
        ResponseEntity<String> saved = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=custom-ada&name=" + URLEncoder.encode("PID Ada Custom", StandardCharsets.UTF_8)
                        + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                        + "&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=Custom"
                        + "&claimValues%5Bgiven_name%5D=Ada"
                        + "&claimValues%5Bbirthdate%5D=1990-01-01"
                        + "&claimValues%5Baddress.locality%5D=Berlin"
                        + "&claimValues%5Baddress.postal_code%5D=%2210409%22"
                        + "&newClaimName=nickname&newClaimValue=Ady")
                .retrieve()
                .toEntity(String.class);

        assertThat(saved.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode credential =
                client(port).get().uri("/api/credentials/custom-ada").retrieve().body(JsonNode.class);
        assertThat(credential.get("name").asText()).isEqualTo("PID Ada Custom");
        assertThat(credential.get("source").asText()).isEqualTo("AD_HOC");
        assertThat(credential.get("claims").get("family_name").asText()).isEqualTo("Custom");
        assertThat(credential.get("claims").get("nickname").asText())
                .as("the add-claim row contributes a claim")
                .isEqualTo("Ady");
        assertThat(credential.get("claims").get("address").get("locality").asText())
                .as("dot notation reassembles nested claims")
                .isEqualTo("Berlin");
        assertThat(credential.get("claims").get("address").get("postal_code").isTextual())
                .as("quoted digit strings stay strings")
                .isTrue();
        assertThat(credential.get("claims").get("address").get("postal_code").asText())
                .isEqualTo("10409");
        assertThat(credential.get("sdJwt").asText()).contains("~");
    }

    @Test
    void claimsMarkedAlwaysDisclosedBecomePlainMembersOfTheCredentialBody() throws Exception {
        ResponseEntity<String> saved = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=always-disclosed-demo&name=Demo&vct=urn:eudi:pid:1&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=Custom"
                        + "&claimValues%5Bissuing_country%5D=DE"
                        + "&claimAlwaysDisclosed%5Bissuing_country%5D=true")
                .retrieve()
                .toEntity(String.class);
        assertThat(saved.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode credential = client(port)
                .get()
                .uri("/api/credentials/always-disclosed-demo")
                .retrieve()
                .body(JsonNode.class);
        assertThat(credential.get("alwaysDisclosedClaims").get(0).asText()).isEqualTo("issuing_country");

        Map<String, Object> body =
                issuerJwt(credential.get("sdJwt").asText()).getJWTClaimsSet().getClaims();
        assertThat(body).as("an always disclosed claim needs no disclosure").containsEntry("issuing_country", "DE");
        assertThat(body)
                .as("selectively disclosable claims stay behind a digest")
                .doesNotContainKey("family_name");
    }

    @Test
    void addClaimButtonAddsAFieldWithoutIssuing() {
        ResponseEntity<String> redisplayed = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=multi-add&name=Multi&vct=urn:eudi:pid:1&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=Custom"
                        + "&newClaimName=nickname&newClaimValue=Ady&action=add-claim")
                .retrieve()
                .toEntity(String.class);

        assertThat(redisplayed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(redisplayed.getBody())
                .as("the new claim becomes a regular field")
                .contains("id=\"claim-nickname\"");
        assertThat(redisplayed.getBody())
                .as("the add row is cleared for the next claim")
                .doesNotContain("value=\"nickname\"");

        ResponseEntity<String> lookup =
                client(port).get().uri("/api/credentials/multi-add").retrieve().toEntity(String.class);
        assertThat(lookup.getStatusCode()).as("add-claim does not issue").isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void emptyingAFieldRemovesTheClaim() {
        ResponseEntity<String> saved = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=no-birthdate&name=NoBirthdate&vct=urn:eudi:pid:1&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=Kept"
                        + "&claimValues%5Bbirthdate%5D=")
                .retrieve()
                .toEntity(String.class);
        assertThat(saved.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode credential = client(port)
                .get()
                .uri("/api/credentials/no-birthdate")
                .retrieve()
                .body(JsonNode.class);
        assertThat(credential.get("claims").hasNonNull("family_name")).isTrue();
        assertThat(credential.get("claims").has("birthdate")).isFalse();
    }

    @Test
    void emptyClaimsRedisplayFormWithError() {
        ResponseEntity<String> saved = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=broken&name=Broken&vct=urn:eudi:pid:1&validityDays=30")
                .retrieve()
                .toEntity(String.class);

        assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(saved.getBody()).contains("at least one claim");

        ResponseEntity<String> lookup =
                client(port).get().uri("/api/credentials/broken").retrieve().toEntity(String.class);
        assertThat(lookup.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void uiStatusFormPostRevokesThroughTheApi() {
        ResponseEntity<String> revoked = client(port)
                .post()
                .uri("/api/credentials/pid-thomas-bauer/status")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("status=1")
                .retrieve()
                .toEntity(String.class);
        assertThat(revoked.getStatusCode().is3xxRedirection())
                .as("the form variant redirects back to the home page")
                .isTrue();

        JsonNode status = client(port)
                .get()
                .uri("/api/credentials/pid-thomas-bauer/status")
                .retrieve()
                .body(JsonNode.class);
        assertThat(status.get("status").asInt()).isEqualTo(1);

        client(port)
                .post()
                .uri("/api/credentials/pid-thomas-bauer/status")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("status=0")
                .retrieve()
                .toBodilessEntity();
    }
}
