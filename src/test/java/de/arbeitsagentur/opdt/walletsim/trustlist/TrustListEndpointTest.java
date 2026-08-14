package de.arbeitsagentur.opdt.walletsim.trustlist;

import static org.assertj.core.api.Assertions.assertThat;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

/**
 * The trust list JWTs must have the LoTE shape ETSI trust list consumers parse: services keyed by ServiceTypeIdentifier suffix (Issuance/Revocation) carrying
 * base64-DER certificates, a matching LoTEType, and a future NextUpdate.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class TrustListEndpointTest {

    @LocalServerPort
    private int port;

    @Autowired
    private SimulatorPki pki;

    private ResponseEntity<String> fetch(String path) {
        return RestClient.create("http://localhost:" + port)
                .get()
                .uri(path)
                .header("Accept", "application/jwt")
                .retrieve()
                .toEntity(String.class);
    }

    @Test
    void credentialsTrustListIsSignedLoteJwtAnchoringTheCa() throws Exception {
        ResponseEntity<String> response = fetch("/api/trust-lists/credentials");

        assertThat(response.getHeaders().getContentType().toString()).startsWith("application/jwt");
        SignedJWT jwt = SignedJWT.parse(response.getBody());
        assertThat(jwt.verify(
                        new ECDSAVerifier((ECPublicKey) pki.caCertificate().getPublicKey())))
                .as("trust list signed with the simulator CA key")
                .isTrue();

        Map<String, Object> lote = asMap(jwt.getJWTClaimsSet().getClaim("LoTE"));
        Map<String, Object> schemeInfo = asMap(lote.get("ListAndSchemeInformation"));
        assertThat(schemeInfo.get("LoTEType")).isEqualTo("http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList");
        assertThat(Instant.parse((String) schemeInfo.get("NextUpdate"))).isAfter(Instant.now());

        List<Map<String, Object>> services = servicesOf(lote);
        assertThat(serviceCertificates(services, "/Issuance"))
                .as("issuance service carries the CA as trust anchor")
                .anySatisfy(cert -> assertThat(cert.getSubjectX500Principal())
                        .isEqualTo(pki.caCertificate().getSubjectX500Principal()));
        assertThat(serviceCertificates(services, "/Revocation")).isNotEmpty();
    }

    @Test
    void walletProvidersTrustListUsesWalletProviderProfile() throws Exception {
        ResponseEntity<String> response = fetch("/api/trust-lists/wallet-providers");

        SignedJWT jwt = SignedJWT.parse(response.getBody());
        Map<String, Object> lote = asMap(jwt.getJWTClaimsSet().getClaim("LoTE"));
        Map<String, Object> schemeInfo = asMap(lote.get("ListAndSchemeInformation"));
        assertThat(schemeInfo.get("LoTEType")).isEqualTo("http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList");

        List<Map<String, Object>> services = servicesOf(lote);
        assertThat(serviceCertificates(services, "/Issuance")).isNotEmpty();
    }

    @SuppressWarnings("unchecked")
    private static List<Map<String, Object>> servicesOf(Map<String, Object> lote) {
        List<Map<String, Object>> entities = (List<Map<String, Object>>) lote.get("TrustedEntitiesList");
        assertThat(entities).isNotEmpty();
        return (List<Map<String, Object>>) entities.getFirst().get("TrustedEntityServices");
    }

    private static List<X509Certificate> serviceCertificates(
            List<Map<String, Object>> services, String serviceTypeSuffix) {
        return services.stream()
                .map(service -> asMap(service.get("ServiceInformation")))
                .filter(info -> ((String) info.get("ServiceTypeIdentifier")).endsWith(serviceTypeSuffix))
                .flatMap(info -> certificatesOf(info).stream())
                .toList();
    }

    @SuppressWarnings("unchecked")
    private static List<X509Certificate> certificatesOf(Map<String, Object> serviceInformation) {
        Map<String, Object> identity = asMap(serviceInformation.get("ServiceDigitalIdentity"));
        List<Map<String, Object>> certificates = (List<Map<String, Object>>) identity.get("X509Certificates");
        return certificates.stream()
                .map(entry -> parseCertificate((String) entry.get("val")))
                .toList();
    }

    private static X509Certificate parseCertificate(String base64Der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(
                            new ByteArrayInputStream(Base64.getDecoder().decode(base64Der)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        assertThat(value).isInstanceOf(Map.class);
        return (Map<String, Object>) value;
    }
}
