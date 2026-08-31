package de.arbeitsagentur.opdt.walletsim.oid4vp;

import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.client;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.disclosures;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.hiddenField;
import static de.arbeitsagentur.opdt.walletsim.WalletTestSupport.issuerJwt;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.WalletTestSupport;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.io.ByteArrayInputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * The error answers a verifier must survive: a credential of another type, a credential missing
 * requested claims, and a credential signed by an untrusted issuer. The picker offers
 * non-matching credentials behind the show all toggle, the editor offers untrusted signing.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ErrorUseCasesTest {

    private static final String DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["given_name"]}]
            }]}
            """;

    private static final String UNSATISFIABLE_DCQL_QUERY =
            """
            {"credentials": [{
                "id": "pid",
                "format": "dc+sd-jwt",
                "meta": {"vct_values": ["urn:eudi:pid:1"]},
                "claims": [{"path": ["family_name"]}, {"path": ["shoe_size"]}]
            }]}
            """;

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    @Test
    void pickerOffersNonMatchingCredentialsBehindTheShowAllToggle() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            String picker = client(port)
                    .get()
                    .uri(WalletTestSupport.authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);

            assertThat(picker).contains("id=\"show-all-credentials\"");
            assertThat(badgeAt(picker, "id=\"mismatch-pid-ehic-erika-mustermann\""))
                    .as("the badge shows a short label and carries the full reason on hover")
                    .contains(">no match: vct")
                    .contains("title=\"vct does not match the requested values\"");
            assertThat(picker)
                    .as("matching credentials carry no mismatch badge")
                    .doesNotContain("mismatch-pid-pid-jan-hart");
            assertThat(picker).as("non-matching cards start hidden").contains("data-non-matching");
        }
    }

    // error use case: the presented credential has another vct than the verifier requested
    @Test
    void aCredentialOfAnotherTypeCanBePresented() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            String picker = client(port)
                    .get()
                    .uri(WalletTestSupport.authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);
            String flowState = hiddenField(picker, "flowState");

            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=ehic-erika-mustermann&showAll=true&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            String presentation = vpToken.get("pid").get(0).asText();
            assertThat(issuerJwt(presentation).getJWTClaimsSet().getStringClaim("vct"))
                    .as("the wrong credential type reaches the verifier")
                    .isEqualTo("urn:eudi:ehic:1");
        }
    }

    // error use case: the presented credential carries only part of the requested claims
    @Test
    void aCredentialMissingRequestedClaimsPresentsOnlyTheClaimsItHas() throws Exception {
        try (TestVerifier verifier = new TestVerifier(UNSATISFIABLE_DCQL_QUERY)) {
            String picker = client(port)
                    .get()
                    .uri(WalletTestSupport.authorizeUri(port, verifier))
                    .retrieve()
                    .body(String.class);

            assertThat(picker).contains("No credential in this wallet matches the verifier's query.");
            assertThat(badgeAt(picker, "id=\"mismatch-pid-pid-jan-hart\"")).contains("requested claims are missing");
            assertThat(tagAt(picker, "id=\"present-credential\""))
                    .as("without the toggle nothing can be presented")
                    .contains("disabled")
                    .contains("data-unsatisfiable");

            String flowState = hiddenField(picker, "flowState");
            ResponseEntity<String> submit = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&showAll=true&flowState="
                            + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(submit.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            List<String> disclosedNames = disclosures(vpToken.get("pid").get(0).asText()).stream()
                    .map(Disclosure::getClaimName)
                    .toList();
            assertThat(disclosedNames).contains("family_name");
            assertThat(disclosedNames)
                    .as("the claim the credential does not have is simply absent")
                    .doesNotContain("shoe_size");
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
            "credential_sets": [{"options": [["pid", "ehic"], ["pid"]]}]}
            """;

    // editing the only ehic credential into another type must not collapse the pid + ehic option,
    // the set selector and both query rows stay and the option is marked instead
    @Test
    void breakingTheOnlyCredentialOfASetOptionKeepsTheOptionAndItsQueriesOffered() throws Exception {
        try (TestVerifier verifier = new TestVerifier(SET_DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");

            ResponseEntity<String> save = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=ehic-erika-mustermann&editQueryId=ehic&name="
                            + URLEncoder.encode("EHIC (wrong type)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:wrong:1", StandardCharsets.UTF_8)
                            + "&validityDays=30"
                            + "&claimValues%5Bfamily_name%5D=Mustermann"
                            + "&setOption%5B0%5D=0"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);

            assertThat(save.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(save.getBody())
                    .as("both query rows stay offered")
                    .contains("data-query-slot=\"pid\"")
                    .contains("data-query-slot=\"ehic\"");
            assertThat(save.getBody()).as("the set selector stays offered").contains("id=\"set-option-0\"");
            assertThat(tagAt(save.getBody(), "data-query-ids=\"pid,ehic\""))
                    .as("the broken option stays chosen")
                    .contains("selected");
            assertThat(save.getBody()).contains("(no matching credentials)");
            assertThat(tagAt(save.getBody(), "id=\"select-ehic-ehic-erika-mustermann\""))
                    .as("the edited credential answers the query it was created for")
                    .contains("checked");
            assertThat(save.getBody()).contains("id=\"mismatch-ehic-ehic-erika-mustermann\"");
            assertThat(tagAt(save.getBody(), "id=\"show-all-credentials\"")).contains("checked");

            String carried = hiddenField(save.getBody(), "singlePresentationCredentials");
            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-erika-mustermann"
                            + "&selection%5Behic%5D=ehic-erika-mustermann"
                            + "&setOption%5B0%5D=0&showAll=true"
                            + "&singlePresentationCredentials=" + URLEncoder.encode(carried, StandardCharsets.UTF_8)
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            JsonNode vpToken = new ObjectMapper()
                    .readValue(verifier.awaitResponse().formParameters().get("vp_token"), JsonNode.class);
            assertThat(issuerJwt(vpToken.get("ehic").get(0).asText())
                            .getJWTClaimsSet()
                            .getStringClaim("vct"))
                    .as("the wrong type answers the ehic query")
                    .isEqualTo("urn:eudi:wrong:1");
        }
    }

    // error use case: the presented credential is signed by an issuer no trust list anchors
    @Test
    void untrustedIssuerToggleSignsWithAnAdHocSelfSignedCertificate() throws Exception {
        ResponseEntity<String> saved = client(port)
                .post()
                .uri("/credentials/save")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("id=untrusted-ada&name=" + URLEncoder.encode("PID Ada Untrusted", StandardCharsets.UTF_8)
                        + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                        + "&validityDays=30&untrustedIssuer=true"
                        + "&claimValues%5Bfamily_name%5D=Custom"
                        + "&claimValues%5Bgiven_name%5D=Ada")
                .retrieve()
                .toEntity(String.class);
        assertThat(saved.getStatusCode().is3xxRedirection()).isTrue();

        JsonNode credential = client(port)
                .get()
                .uri("/api/credentials/untrusted-ada")
                .retrieve()
                .body(JsonNode.class);
        assertThat(credential.get("untrustedIssuer").asBoolean()).isTrue();

        SignedJWT issuerJwt = issuerJwt(credential.get("sdJwt").asText());
        X509Certificate certificate = headerCertificate(issuerJwt);
        assertThat(certificate.getSubjectX500Principal().getName()).contains("Untrusted Issuer");
        assertThat(issuerJwt.verify(new ECDSAVerifier((ECPublicKey) certificate.getPublicKey())))
                .as("the credential is validly signed by the untrusted key")
                .isTrue();
        assertThat(issuerJwt.verify(
                        new ECDSAVerifier((ECPublicKey) pki.issuerCertificate().getPublicKey())))
                .as("the simulator issuer key did not sign it")
                .isFalse();
        assertThatThrownBy(() -> certificate.verify(pki.caCertificate().getPublicKey()))
                .as("the certificate is not anchored in the simulator CA")
                .isInstanceOf(GeneralSecurityException.class);

        assertThat(client(port).get().uri("/").retrieve().body(String.class))
                .as("the home page badges the untrusted credential")
                .contains("id=\"untrusted-issuer-untrusted-ada\"");
    }

    @Test
    void editingDuringAFlowCanPresentAnUntrustedSignedCredential() throws Exception {
        try (TestVerifier verifier = new TestVerifier(DCQL_QUERY)) {
            String flowState = hiddenField(
                    client(port)
                            .get()
                            .uri(WalletTestSupport.authorizeUri(port, verifier))
                            .retrieve()
                            .body(String.class),
                    "flowState");

            ResponseEntity<String> save = client(port)
                    .post()
                    .uri("/authorize/edit/save")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("id=pid-jan-hart&statusIndex=0&editQueryId=pid&name="
                            + URLEncoder.encode("PID Jan (untrusted)", StandardCharsets.UTF_8)
                            + "&vct=" + URLEncoder.encode("urn:eudi:pid:1", StandardCharsets.UTF_8)
                            + "&validityDays=30&untrustedIssuer=true"
                            + "&claimValues%5Bfamily_name%5D=Hart"
                            + "&claimValues%5Bgiven_name%5D=Jan"
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(save.getStatusCode()).isEqualTo(HttpStatus.OK);
            assertThat(save.getBody())
                    .as("the picker badges the untrusted credential")
                    .contains("id=\"untrusted-issuer-pid-pid-jan-hart\"");

            String carried = hiddenField(save.getBody(), "singlePresentationCredentials");
            ResponseEntity<String> present = client(port)
                    .post()
                    .uri("/authorize/submit")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body("selection%5Bpid%5D=pid-jan-hart&singlePresentationCredentials="
                            + URLEncoder.encode(carried, StandardCharsets.UTF_8)
                            + "&flowState=" + URLEncoder.encode(flowState, StandardCharsets.UTF_8))
                    .retrieve()
                    .toEntity(String.class);
            assertThat(present.getStatusCode().is3xxRedirection()).isTrue();

            ReceivedResponse response = verifier.awaitResponse();
            JsonNode vpToken =
                    new ObjectMapper().readValue(response.formParameters().get("vp_token"), JsonNode.class);
            SignedJWT issuerJwt = issuerJwt(vpToken.get("pid").get(0).asText());
            assertThat(headerCertificate(issuerJwt).getSubjectX500Principal().getName())
                    .contains("Untrusted Issuer");
        }
    }

    private static X509Certificate headerCertificate(SignedJWT jwt) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(
                        jwt.getHeader().getX509CertChain().getFirst().decode()));
    }

    // the whole tag a marker sits in, so an assertion sees only that element
    private static String tagAt(String html, String marker) {
        int position = html.indexOf(marker);
        assertThat(position).as("'%s' present", marker).isNotNegative();
        return html.substring(html.lastIndexOf('<', position), html.indexOf('>', position) + 1);
    }

    // a badge span including its text content
    private static String badgeAt(String html, String marker) {
        int position = html.indexOf(marker);
        assertThat(position).as("'%s' present", marker).isNotNegative();
        return html.substring(html.lastIndexOf('<', position), html.indexOf("</span>", position));
    }
}
