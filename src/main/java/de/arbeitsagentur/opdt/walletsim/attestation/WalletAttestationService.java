package de.arbeitsagentur.opdt.walletsim.attestation;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

/**
 * OAuth 2.0 attestation-based client authentication: the attestation JWT is signed by the wallet
 * provider (chained to the simulator CA, anchored via the wallet-providers trust list) and binds
 * the holder key; the PoP JWT is signed with that holder key.
 */
@Service
public class WalletAttestationService {

    private static final long VALIDITY_MINUTES = 5;

    private final SimulatorPki pki;
    private final AppUrls urls;

    public WalletAttestationService(SimulatorPki pki, AppUrls urls) {
        this.pki = pki;
        this.urls = urls;
    }

    public String attestationJwt(String clientId) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(urls.baseUrl())
                    .subject(clientId)
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(VALIDITY_MINUTES, ChronoUnit.MINUTES)))
                    .claim("cnf", Map.of("jwk", pki.holderKey().toPublicJWK().toJSONObject()))
                    .build();
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("oauth-client-attestation+jwt"))
                            .x509CertChain(List.of(Base64.encode(
                                    pki.walletProviderCertificate().getEncoded())))
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.walletProviderPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create wallet attestation", e);
        }
    }

    public String popJwt(String clientId, String audience, String challenge) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(clientId)
                    .audience(audience)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(now))
                    .notBeforeTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(VALIDITY_MINUTES, ChronoUnit.MINUTES)));
            if (challenge != null && !challenge.isBlank()) {
                claims.claim("challenge", challenge);
            }
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("oauth-client-attestation-pop+jwt"))
                            .jwk(pki.holderKey().toPublicJWK())
                            .build(),
                    claims.build());
            jwt.sign(new ECDSASigner(pki.holderKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create wallet attestation PoP", e);
        }
    }
}
