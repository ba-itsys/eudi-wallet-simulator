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
import tools.jackson.databind.ObjectMapper;

/**
 * Builds ETSI TS 119 602 LoTE trust list JWTs. Lists are signed with the CA key; the services
 * carry both the CA (PKIX anchor) and the signing leaf (direct pin) so either trust resolution
 * mode works.
 */
@Service
public class TrustListService {

    public static final String LOTE_CLAIM = "LoTE";

    private static final String SCHEME_OPERATOR = "EUDI Wallet Simulator";

    private final SimulatorPki pki;
    private final ObjectMapper objectMapper;

    public TrustListService(SimulatorPki pki, ObjectMapper objectMapper) {
        this.pki = pki;
        this.objectMapper = objectMapper;
    }

    public String trustListJwt(TrustListProfile profile) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .claim(LOTE_CLAIM, objectMapper.convertValue(trustList(profile), Map.class))
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

    private TrustList trustList(TrustListProfile profile) {
        Instant now = Instant.now();
        ServiceDigitalIdentity identity = new ServiceDigitalIdentity(serviceCertificates(profile).stream()
                .map(TrustListService::certificateValue)
                .toList());
        TrustedEntity entity = new TrustedEntity(
                new TrustedEntityInformation(SCHEME_OPERATOR),
                List.of(
                        service(profile.issuanceServiceType(), "Issuance", identity),
                        service(profile.revocationServiceType(), "Revocation", identity)));
        return new TrustList(
                new ListAndSchemeInformation(
                        1,
                        1,
                        profile.loteType(),
                        SCHEME_OPERATOR,
                        now.toString(),
                        now.plus(24, ChronoUnit.HOURS).toString(),
                        profile.statusDeterminationApproach(),
                        List.of(profile.schemeTypeCommunityRules())),
                List.of(entity));
    }

    private List<X509Certificate> serviceCertificates(TrustListProfile profile) {
        return switch (profile) {
            case CREDENTIALS -> List.of(pki.caCertificate(), pki.issuerCertificate());
        };
    }

    private static TrustedEntityService service(
            String serviceTypeIdentifier, String serviceName, ServiceDigitalIdentity identity) {
        return new TrustedEntityService(
                new ServiceInformation(serviceTypeIdentifier, SCHEME_OPERATOR + " " + serviceName, identity));
    }

    private static CertificateValue certificateValue(X509Certificate certificate) {
        try {
            return new CertificateValue(Base64.getEncoder().encodeToString(certificate.getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
