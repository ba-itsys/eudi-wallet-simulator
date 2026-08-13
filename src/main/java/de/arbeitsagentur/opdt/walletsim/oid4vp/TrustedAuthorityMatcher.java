package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Evaluates trusted_authorities queries (OID4VP 1.0 §6.1.1) against a credential's issuer chain.
 * A credential matches when at least one authority object matches with at least one of its
 * values. Supported types: aki (base64url KeyIdentifier of the AuthorityKeyIdentifier) and
 * etsi_tl (issuer anchored in the referenced trust list).
 */
@Component
public class TrustedAuthorityMatcher {

    private static final Logger LOG = LoggerFactory.getLogger(TrustedAuthorityMatcher.class);

    private final RestClient restClient = RestClient.create();
    private final Map<String, List<X509Certificate>> trustListCache = new ConcurrentHashMap<>();

    public boolean matches(StoredCredential credential, List<TrustedAuthority> trustedAuthorities) {
        if (trustedAuthorities.isEmpty()) {
            return true;
        }
        List<X509Certificate> chain = certificateChain(credential);
        if (chain.isEmpty()) {
            return false;
        }
        return trustedAuthorities.stream().anyMatch(authority -> matchesAuthority(chain, authority));
    }

    private boolean matchesAuthority(List<X509Certificate> chain, TrustedAuthority authority) {
        return switch (authority.type() == null ? "" : authority.type()) {
            case "aki" -> authority.values().stream().anyMatch(value -> matchesAki(chain, value));
            case "etsi_tl" -> authority.values().stream().anyMatch(value -> matchesTrustList(chain, value));
            default -> false;
        };
    }

    private boolean matchesAki(List<X509Certificate> chain, String expectedKeyIdentifier) {
        return chain.stream()
                .map(TrustedAuthorityMatcher::authorityKeyIdentifier)
                .anyMatch(expectedKeyIdentifier::equals);
    }

    private static String authorityKeyIdentifier(X509Certificate certificate) {
        try {
            X509CertificateHolder holder = new X509CertificateHolder(certificate.getEncoded());
            AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.fromExtensions(holder.getExtensions());
            if (aki == null || aki.getKeyIdentifier() == null) {
                return null;
            }
            return Base64URL.encode(aki.getKeyIdentifier()).toString();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean matchesTrustList(List<X509Certificate> chain, String trustListUrl) {
        List<X509Certificate> anchors = trustListCache.get(trustListUrl);
        if (anchors == null) {
            anchors = fetchTrustListCertificates(trustListUrl);
            if (!anchors.isEmpty()) {
                trustListCache.put(trustListUrl, anchors);
            }
        }
        if (anchors.isEmpty()) {
            return false;
        }
        // OID4VP 1.0 §6.1.1.2: at least one certificate of the chain must match a list entry
        List<X509Certificate> trustAnchors = anchors;
        return chain.stream().anyMatch(certificate -> trustAnchors.stream()
                .anyMatch(anchor -> certificate.equals(anchor) || isIssuedBy(certificate, anchor)));
    }

    private static boolean isIssuedBy(X509Certificate leaf, X509Certificate anchor) {
        if (!leaf.getIssuerX500Principal().equals(anchor.getSubjectX500Principal())) {
            return false;
        }
        try {
            leaf.verify(anchor.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private List<X509Certificate> fetchTrustListCertificates(String trustListUrl) {
        try {
            String jwt = restClient
                    .get()
                    .uri(trustListUrl)
                    .header("Accept", "application/jwt")
                    .retrieve()
                    .body(String.class);
            return parseTrustListCertificates(jwt);
        } catch (Exception e) {
            LOG.warn("Failed to fetch trust list {}: {}", trustListUrl, e.getMessage());
            return List.of();
        }
    }

    @SuppressWarnings("unchecked")
    private static List<X509Certificate> parseTrustListCertificates(String jwt) throws Exception {
        Map<String, Object> claims = SignedJWT.parse(jwt).getJWTClaimsSet().getClaims();
        Map<String, Object> lote = (Map<String, Object>) claims.get("LoTE");
        List<Map<String, Object>> entities = (List<Map<String, Object>>) lote.get("TrustedEntitiesList");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return entities.stream()
                .flatMap(entity -> ((List<Map<String, Object>>) entity.get("TrustedEntityServices")).stream())
                .map(service -> (Map<String, Object>) service.get("ServiceInformation"))
                .map(info -> (Map<String, Object>) info.get("ServiceDigitalIdentity"))
                .flatMap(identity -> ((List<Map<String, Object>>) identity.get("X509Certificates")).stream())
                .map(entry -> parseCertificate(certificateFactory, (String) entry.get("val")))
                .distinct()
                .toList();
    }

    private static X509Certificate parseCertificate(CertificateFactory factory, String base64Der) {
        try {
            return (X509Certificate)
                    factory.generateCertificate(new ByteArrayInputStream(new Base64(base64Der).decode()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static List<X509Certificate> certificateChain(StoredCredential credential) {
        try {
            SignedJWT issuerJwt = SignedJWT.parse(credential.sdJwt().split("~")[0]);
            List<Base64> x5c = issuerJwt.getHeader().getX509CertChain();
            if (x5c == null || x5c.isEmpty()) {
                return List.of();
            }
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return x5c.stream()
                    .map(encoded -> {
                        try {
                            return (X509Certificate)
                                    certificateFactory.generateCertificate(new ByteArrayInputStream(encoded.decode()));
                        } catch (Exception e) {
                            throw new IllegalStateException(e);
                        }
                    })
                    .toList();
        } catch (Exception e) {
            return List.of();
        }
    }
}
