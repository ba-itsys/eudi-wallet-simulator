package de.arbeitsagentur.opdt.walletsim;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApplicationSmokeTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }

    @Test
    void livenessProbeResponds() {
        ResponseEntity<String> response =
                client().get().uri("/livez").retrieve().toEntity(String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void readinessProbeResponds() {
        ResponseEntity<String> response =
                client().get().uri("/readyz").retrieve().toEntity(String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    @Test
    void homePageRendersShell() {
        ResponseEntity<String> response = client().get().uri("/").retrieve().toEntity(String.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).contains("EUDI Wallet Simulator");
        assertThat(response.getBody()).contains("Environment:");
        assertThat(response.getBody()).contains("localDEV");
    }
}
