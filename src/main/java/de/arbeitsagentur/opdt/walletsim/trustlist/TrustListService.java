package de.arbeitsagentur.opdt.walletsim.trustlist;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Builds ETSI TS 119 602 LoTE trust list JWTs in the JSON shape ETSI trust list consumers
 * parse. Lists are signed with the CA key; the
 * services carry both the CA (PKIX anchor) and the signing leaf (direct pin) so either trust
 * resolution mode works.
 */
@Service
public class TrustListService {

    private static final String SCHEME_OPERATOR = "EUDI Wallet Simulator";

    private final SimulatorPki pki;

    public TrustListService(SimulatorPki pki) {
        this.pki = pki;
    }

    public String trustListJwt(TrustListProfile profile) {
        try {
            List<X509Certificate> serviceCertificates = serviceCertificates(profile);
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim(
                            "LoTE",
                            Map.of(
                                    "ListAndSchemeInformation", listAndSchemeInformation(profile, now),
                                    "TrustedEntitiesList", List.of(trustedEntity(profile, serviceCertificates))))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(JOSEObjectType.JWT)
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.caPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build trust list for " + profile, e);
        }
    }

    private List<X509Certificate> serviceCertificates(TrustListProfile profile) {
        return switch (profile) {
            case CREDENTIALS -> List.of(pki.caCertificate(), pki.issuerCertificate());
            case WALLET_PROVIDERS -> List.of(pki.caCertificate(), pki.walletProviderCertificate());
        };
    }

    private static Map<String, Object> listAndSchemeInformation(TrustListProfile profile, Instant now) {
        return Map.of(
                "LoTEVersionIdentifier", 1,
                "LoTESequenceNumber", 1,
                "LoTEType", profile.loteType(),
                "SchemeOperatorName", SCHEME_OPERATOR,
                "ListIssueDateTime", now.toString(),
                "NextUpdate", now.plus(24, ChronoUnit.HOURS).toString(),
                "StatusDeterminationApproach", profile.statusDeterminationApproach(),
                "SchemeTypeCommunityRules", List.of(profile.schemeTypeCommunityRules()));
    }

    private static Map<String, Object> trustedEntity(TrustListProfile profile, List<X509Certificate> certificates) {
        return Map.of(
                "TrustedEntityInformation",
                Map.of("TrustedEntityName", SCHEME_OPERATOR),
                "TrustedEntityServices",
                List.of(
                        service(profile.issuanceServiceType(), "Issuance", certificates),
                        service(profile.revocationServiceType(), "Revocation", certificates)));
    }

    private static Map<String, Object> service(
            String serviceTypeIdentifier, String serviceName, List<X509Certificate> certificates) {
        return Map.of(
                "ServiceInformation",
                Map.of(
                        "ServiceTypeIdentifier",
                        serviceTypeIdentifier,
                        "ServiceName",
                        SCHEME_OPERATOR + " " + serviceName,
                        "ServiceDigitalIdentity",
                        Map.of("X509Certificates", certificateValues(certificates))));
    }

    private static List<Map<String, String>> certificateValues(List<X509Certificate> certificates) {
        return certificates.stream()
                .map(certificate -> Map.of("val", base64Der(certificate)))
                .toList();
    }

    private static String base64Der(X509Certificate certificate) {
        try {
            return Base64.getEncoder().encodeToString(certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
