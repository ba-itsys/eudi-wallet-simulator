package de.arbeitsagentur.opdt.walletsim.conformance;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.client.RestClient;

/**
 * Each conformance finding branch fires in debug mode and shows up on the picker page. One test
 * per category of tampering: header, signature, client id, response parameters, DCQL structure
 * and verifier_info.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ValidatorFindingsTest {

    @LocalServerPort
    private int port;

    private RestClient client() {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    @Test
    void wrongTypHeaderIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withRequestObjectTyp("JWT")) {
            assertThat(picker(verifier)).contains("typ header must be");
        }
    }

    @Test
    void foreignSignatureKeyIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withForeignSignatureKey()) {
            assertThat(picker(verifier)).contains("signature does not verify");
        }
    }

    @Test
    void clientIdHashMismatchIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()
                .withRequestCustomizer(claims -> claims.put("client_id", "x509_hash:bm90LXRoZS1oYXNo"))) {
            assertThat(picker(verifier, "x509_hash:bm90LXRoZS1oYXNo"))
                    .contains("does not match SHA-256 of the request object signing certificate");
        }
    }

    @Test
    void urlAndRequestObjectClientIdMismatchIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()) {
            assertThat(picker(verifier, "x509_hash:c29tZXRoaW5nLWVsc2U"))
                    .contains("does not match the request object client_id");
        }
    }

    @Test
    void nonX509HashPrefixIsAFinding() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier()
                .withRequestCustomizer(claims -> claims.put("client_id", "redirect_uri:https://verifier.example"))) {
            assertThat(picker(verifier, "redirect_uri:https://verifier.example"))
                    .contains("HAIP 1.0 mandates x509_hash");
        }
    }

    @Test
    void missingClientIdIsAFinding() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.remove("client_id"))) {
            assertThat(picker(verifier)).contains("missing the client_id claim");
        }
    }

    @Test
    void invalidResponseModeAndTypeAreFindings() throws Exception {
        try (TestVerifier verifier = TestVerifier.pidVerifier().withRequestCustomizer(claims -> {
            claims.put("response_mode", "fragment");
            claims.put("response_type", "code");
        })) {
            String picker = picker(verifier);
            assertThat(picker).contains("response_mode must be direct_post");
            assertThat(picker).contains("response_type must be");
        }
    }

    @Test
    void malformedDcqlStructuresAreFindings() throws Exception {
        Map<String, Object> malformedDcql = Map.of(
                "credentials",
                List.of(
                        Map.of("id", "pid", "format", "dc+sd-jwt"),
                        Map.of("id", "broken"),
                        Map.of(
                                "id",
                                "with-authority",
                                "format",
                                "dc+sd-jwt",
                                "trusted_authorities",
                                List.of(Map.of("type", "openid_federation", "values", List.of("x"))))),
                "credential_sets",
                List.of(Map.of("options", List.of(List.of("unknown-query")))));
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withRequestCustomizer(claims -> claims.put("dcql_query", malformedDcql))) {
            String picker = picker(verifier);
            assertThat(picker).contains("needs string");
            assertThat(picker).contains("unsupported trusted_authorities type");
            assertThat(picker).contains("references unknown credential query id");
        }
    }

    @Test
    void garbageRegistrationCertificateIsAFinding() throws Exception {
        String data =
                Base64URL.encode("not-a-jwt".getBytes(StandardCharsets.UTF_8)).toString();
        try (TestVerifier verifier = TestVerifier.pidVerifier()
                .withVerifierInfo("[{\"format\":\"registrar_dataset\",\"data\":\"" + data + "\"}]")) {
            assertThat(picker(verifier)).contains("not a valid JWT");
        }
    }

    @Test
    void foreignRegistrarSignatureIsAFinding() throws Exception {
        ECKey foreignKey = new ECKeyGenerator(Curve.P_256).generate();
        SignedJWT foreignCertificate = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(new JOSEObjectType("rc-rp+jwt"))
                        .build(),
                new JWTClaimsSet.Builder()
                        .subject("x509_hash:whatever")
                        .expirationTime(new java.util.Date(System.currentTimeMillis() + 60000))
                        .build());
        foreignCertificate.sign(new ECDSASigner(foreignKey));
        String data = Base64URL.encode(foreignCertificate.serialize().getBytes(StandardCharsets.UTF_8))
                .toString();
        try (TestVerifier verifier = TestVerifier.pidVerifier()
                .withVerifierInfo("[{\"format\":\"registrar_dataset\",\"data\":\"" + data + "\"}]")) {
            assertThat(picker(verifier)).contains("not signed by this wallet");
        }
    }

    @Test
    void wrongVerifierInfoFormatValueIsAFinding() throws Exception {
        try (TestVerifier verifier =
                TestVerifier.pidVerifier().withVerifierInfo("[{\"format\":\"jwt\",\"data\":\"abc\"}]")) {
            assertThat(picker(verifier)).contains("needs format");
        }
    }

    private String picker(TestVerifier verifier) throws Exception {
        return picker(verifier, verifier.clientId());
    }

    private String picker(TestVerifier verifier, String urlClientId) throws Exception {
        URI uri = URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(urlClientId, StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
        return client().get().uri(uri).retrieve().body(String.class);
    }
}
