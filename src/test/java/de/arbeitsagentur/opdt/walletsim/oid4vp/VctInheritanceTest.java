package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.authorizeUri;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jwt.SignedJWT;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * vct inheritance: SD-JWT VC type metadata lets a vct extend a base type, and the wallet may
 * answer a request for the base type with an extending credential. The extends relation is
 * resolved here with a simplified urn child rule: the child inserts segments between the base
 * prefix and the version, so urn:eudi:pid:de:1 extends urn:eudi:pid:1.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VctInheritanceTest {

    @LocalServerPort
    private int port;

    @Test
    void baseVctRequestOffersInheritedCredentials() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlForVct("urn:eudi:pid:1"))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);

            assertThat(picker).contains("data-credential-id=\"pid-jan-hart\"");
            assertThat(picker)
                    .as("urn:eudi:pid:de:1 extends urn:eudi:pid:1")
                    .contains("data-credential-id=\"pid-thomas-bauer\"");
            assertThat(picker)
                    .as("urn:eudi:pid:it:1 extends urn:eudi:pid:1")
                    .contains("data-credential-id=\"pid-sofia-rossi\"");
        }
    }

    @Test
    void childVctRequestDoesNotOfferBaseOrSiblingCredentials() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlForVct("urn:eudi:pid:de:1"))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);

            assertThat(picker).contains("data-credential-id=\"pid-thomas-bauer\"");
            assertThat(picker).contains("data-credential-id=\"pid-erika-mustermann\"");
            assertThat(picker)
                    .as("the matching credentials carry no mismatch badge")
                    .doesNotContain("mismatch-pid-pid-thomas-bauer")
                    .doesNotContain("mismatch-pid-pid-erika-mustermann");
            assertThat(picker)
                    .as("the base type does not extend the child type")
                    .contains("id=\"mismatch-pid-pid-jan-hart\"");
            assertThat(picker)
                    .as("sibling country types do not extend each other")
                    .contains("id=\"mismatch-pid-pid-sofia-rossi\"");
        }
    }

    @Test
    void unrelatedVctRequestOffersNoMatch() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlForVct("urn:eudi:diploma:1"))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            assertThat(picker).contains("No credential in this wallet matches the verifier's query.");
            assertThat(picker)
                    .as("credentials appear only as non-matching offers behind the show all toggle")
                    .contains("id=\"mismatch-pid-pid-jan-hart\"");
        }
    }

    @Test
    void inheritedCredentialIsPresentedWithItsOwnVct() throws Exception {
        try (TestVerifier verifier = new TestVerifier(dcqlForVct("urn:eudi:pid:1"))) {
            String picker = client(port)
                    .get()
                    .uri(authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            String flowState = hiddenField(picker, "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-thomas-bauer&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            String vpToken = verifier.awaitResponse().formParameters().get("vp_token");
            String presentation = new ObjectMapper()
                    .readValue(vpToken, JsonNode.class)
                    .get("pid")
                    .get(0)
                    .asText();
            SignedJWT issuerJwt = issuerJwt(presentation);
            assertThat(issuerJwt.getJWTClaimsSet().getStringClaim("vct")).isEqualTo("urn:eudi:pid:de:1");
        }
    }

    private static String dcqlForVct(String vct) {
        return """
                {"credentials": [{
                    "id": "pid",
                    "format": "dc+sd-jwt",
                    "meta": {"vct_values": ["%s"]},
                    "claims": [{"path": ["family_name"]}]
                }]}
                """
                .formatted(vct);
    }
}
