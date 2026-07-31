package de.arbeitsagentur.opdt.walletsim.statuslist;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.io.ByteArrayOutputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;
import java.util.Map;
import java.util.zip.Inflater;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;

/**
 * Status list semantics as checked by keycloak-extension-oid4vp: typ statuslist+jwt, sub equal to
 * the list URI, zlib-deflated bitstring, and a revocation via the API flipping the credential's
 * bit on the next fetch.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class StatusListTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.create("http://localhost:" + port);
    }

    @Test
    void statusListTokenValidatesAndReflectsRevocation() throws Exception {
        JsonNode credential = client().get()
                .uri("/api/credentials")
                .retrieve()
                .body(JsonNode.class)
                .get(0);
        String id = credential.get("id").asText();
        int idx = credential.get("status").get("idx").asInt();
        String expectedSub = credential.get("status").get("uri").asText();

        assertThat(statusBitAt(idx, expectedSub)).isZero();

        ResponseEntity<JsonNode> revocation = client().post()
                .uri("/api/credentials/{id}/status", id)
                .header("Content-Type", "application/json")
                .body(Map.of("status", 1))
                .retrieve()
                .toEntity(JsonNode.class);
        assertThat(revocation.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(revocation.getBody().get("status").asInt()).isEqualTo(1);
        assertThat(revocation.getBody().get("statusName").asText()).isEqualTo("INVALID");

        assertThat(statusBitAt(idx, expectedSub)).isEqualTo(1);

        JsonNode liveStatus = client().get()
                .uri("/api/credentials/{id}/status", id)
                .retrieve()
                .body(JsonNode.class);
        assertThat(liveStatus.get("status").asInt()).isEqualTo(1);
        assertThat(liveStatus.get("idx").asInt()).isEqualTo(idx);
    }

    @Test
    void rejectsOutOfRangeStatusAndUnknownCredential() {
        JsonNode credential = client().get()
                .uri("/api/credentials")
                .retrieve()
                .body(JsonNode.class)
                .get(0);
        String id = credential.get("id").asText();

        ResponseEntity<String> outOfRange = client().post()
                .uri("/api/credentials/{id}/status", id)
                .header("Content-Type", "application/json")
                .body(Map.of("status", 300))
                .retrieve()
                .onStatus(status -> true, (request, response) -> {})
                .toEntity(String.class);
        assertThat(outOfRange.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        ResponseEntity<String> unknown = client().post()
                .uri("/api/credentials/{id}/status", "does-not-exist")
                .header("Content-Type", "application/json")
                .body(Map.of("status", 1))
                .retrieve()
                .onStatus(status -> true, (request, response) -> {})
                .toEntity(String.class);
        assertThat(unknown.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private int statusBitAt(int idx, String expectedSub) throws Exception {
        ResponseEntity<String> response = client().get()
                .uri("/status-list")
                .header("Accept", "application/statuslist+jwt")
                .retrieve()
                .toEntity(String.class);
        assertThat(response.getHeaders().getContentType().toString()).startsWith("application/statuslist+jwt");
        assertThat(response.getHeaders().getAccessControlAllowOrigin()).isEqualTo("*");

        SignedJWT jwt = SignedJWT.parse(response.getBody());
        assertThat(jwt.getHeader().getType().toString()).isEqualTo("statuslist+jwt");

        X509Certificate leaf = (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(
                        jwt.getHeader().getX509CertChain().getFirst().decode()));
        assertThat(jwt.verify(new ECDSAVerifier((ECPublicKey) leaf.getPublicKey())))
                .isTrue();

        Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
        assertThat(claims.get("sub")).isEqualTo(expectedSub);
        assertThat(jwt.getJWTClaimsSet().getExpirationTime()).isInTheFuture();

        @SuppressWarnings("unchecked")
        Map<String, Object> statusList = (Map<String, Object>) claims.get("status_list");
        int bits = ((Number) statusList.get("bits")).intValue();
        byte[] decompressed = inflate(Base64.getUrlDecoder().decode((String) statusList.get("lst")));
        assertThat(decompressed.length).as("privacy padding").isGreaterThanOrEqualTo(16);

        int bitOffset = (idx * bits) % 8;
        int mask = (1 << bits) - 1;
        return (decompressed[idx * bits / 8] >> bitOffset) & mask;
    }

    private static byte[] inflate(byte[] compressed) throws Exception {
        Inflater inflater = new Inflater();
        inflater.setInput(compressed);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            out.write(buffer, 0, inflater.inflate(buffer));
        }
        return out.toByteArray();
    }
}
