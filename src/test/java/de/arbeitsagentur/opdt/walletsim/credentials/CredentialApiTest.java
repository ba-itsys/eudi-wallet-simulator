package de.arbeitsagentur.opdt.walletsim.credentials;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class CredentialApiTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }

    @Test
    void listsPredefinedCredentialsWithStableIds() {
        ResponseEntity<JsonNode> response =
                client().get().uri("/api/credentials").retrieve().toEntity(JsonNode.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode credentials = response.getBody();
        assertThat(credentials.isArray()).isTrue();
        assertThat(credentials.size()).isGreaterThanOrEqualTo(2);

        JsonNode first = credentials.get(0);
        assertThat(first.hasNonNull("id")).isTrue();
        assertThat(first.get("format").asText()).isEqualTo("dc+sd-jwt");
        assertThat(first.get("vct").asText()).isEqualTo("urn:eudi:pid:1");
        assertThat(first.hasNonNull("name")).isTrue();
        assertThat(first.get("claims").hasNonNull("family_name")).isTrue();
        assertThat(first.get("status").get("idx").isInt()).isTrue();
        assertThat(first.get("status").get("uri").asText()).endsWith("/status-list");
    }

    @Test
    void returnsSingleCredentialWithSdJwtById() {
        JsonNode list = client().get().uri("/api/credentials").retrieve().body(JsonNode.class);
        String id = list.get(0).get("id").asText();

        ResponseEntity<JsonNode> response =
                client().get().uri("/api/credentials/{id}", id).retrieve().toEntity(JsonNode.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        JsonNode credential = response.getBody();
        assertThat(credential.get("id").asText()).isEqualTo(id);
        assertThat(credential.get("sdJwt").asText()).contains("~");
    }

    @Test
    void unknownCredentialIdYields404() {
        ResponseEntity<String> response = client().get()
                .uri("/api/credentials/{id}", "does-not-exist")
                .retrieve()
                .onStatus(status -> true, (request, res) -> {})
                .toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
