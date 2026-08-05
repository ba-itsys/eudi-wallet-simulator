package de.arbeitsagentur.opdt.walletsim.web;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
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

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void homePageListsWalletCredentialsAsCards() {
        ResponseEntity<String> home = client().get().uri("/").retrieve().toEntity(String.class);

        assertThat(home.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(home.getBody()).contains("data-credential-id=\"pid-maria-neumann\"");
        assertThat(home.getBody()).contains("urn:eudi:pid:1");
    }

    @Test
    void editClonesSelectedCredentialAsTemplateWithPerClaimFields() {
        ResponseEntity<String> editForm = client().post()
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
        assertThat(editForm.getBody()).contains("Neumann");
        assertThat(editForm.getBody()).contains("id=\"new-claim-name\"");
        assertThat(editForm.getBody())
                .as("clone gets a fresh id suggestion, not the original id")
                .doesNotContain("value=\"pid-maria-neumann\"");
    }

    @Test
    void savingAdHocCredentialIssuesSignedSdJwt() {
        ResponseEntity<String> saved = client().post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=custom-ada&name=" + URLEncoder.encode("PID Ada Custom", StandardCharsets.UTF_8)
                        + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                        + "&validityDays=30"
                        + "&claimValues%5Bfamily_name%5D=Custom"
                        + "&claimValues%5Bgiven_name%5D=Ada"
                        + "&claimValues%5Bbirthdate%5D=1990-01-01"
                        + "&newClaimName=nickname&newClaimValue=Ady")
                .retrieve()
                .toEntity(String.class);

        assertThat(saved.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode credential =
                client().get().uri("/api/credentials/custom-ada").retrieve().body(JsonNode.class);
        assertThat(credential.get("name").asText()).isEqualTo("PID Ada Custom");
        assertThat(credential.get("source").asText()).isEqualTo("AD_HOC");
        assertThat(credential.get("claims").get("family_name").asText()).isEqualTo("Custom");
        assertThat(credential.get("claims").get("nickname").asText())
                .as("the add-claim row contributes a claim")
                .isEqualTo("Ady");
        assertThat(credential.get("sdJwt").asText()).contains("~");
    }

    @Test
    void emptyClaimsRedisplayFormWithError() {
        ResponseEntity<String> saved = client().post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=broken&name=Broken&vct=urn:eudi:pid:1&validityDays=30")
                .retrieve()
                .toEntity(String.class);

        assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(saved.getBody()).contains("at least one claim");

        ResponseEntity<String> lookup =
                client().get().uri("/api/credentials/broken").retrieve().toEntity(String.class);
        assertThat(lookup.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void statusToggleRevokesCredentialFromTheUi() {
        ResponseEntity<String> toggled = client().post()
                .uri("/credentials/pid-thomas-bauer/status/toggle")
                .retrieve()
                .toEntity(String.class);
        assertThat(toggled.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode status = client().get()
                .uri("/api/credentials/pid-thomas-bauer/status")
                .retrieve()
                .body(JsonNode.class);
        assertThat(status.get("status").asInt()).isEqualTo(1);

        client().post()
                .uri("/credentials/pid-thomas-bauer/status/toggle")
                .retrieve()
                .toBodilessEntity();
    }
}
