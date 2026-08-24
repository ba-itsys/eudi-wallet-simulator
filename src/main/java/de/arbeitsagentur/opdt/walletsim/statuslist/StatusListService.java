package de.arbeitsagentur.opdt.walletsim.statuslist;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppProperties;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import org.springframework.stereotype.Service;

/**
 * Builds the IETF Token Status List JWT over the credential store's status values. The simulator
 * only covers VALID and INVALID, so the list is always 1 bit wide. The bitstring is padded to at
 * least 16 bytes so a near-empty list does not identify its single referenced credential.
 */
@Service
public class StatusListService {

    private static final int MIN_BITSTRING_BYTES = 16;
    private static final long TTL_SECONDS = 43200;

    private final CredentialStore store;
    private final SimulatorPki pki;
    private final AppProperties properties;

    public StatusListService(CredentialStore store, SimulatorPki pki, AppProperties properties) {
        this.store = store;
        this.pki = pki;
        this.properties = properties;
    }

    public String statusListJwt() {
        try {
            Map<Integer, Integer> statusValues = store.statusValues();
            byte[] bitstring = buildBitstring(statusValues);

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(properties.statusListUri())
                    .issuer(properties.externalUrl())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(24, ChronoUnit.HOURS)))
                    .claim("ttl", TTL_SECONDS)
                    .claim(
                            "status_list",
                            Map.of(
                                    "bits",
                                    1,
                                    "lst",
                                    Base64URL.encode(deflate(bitstring)).toString()))
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("statuslist+jwt"))
                            .x509CertChain(List.of(
                                    Base64.encode(pki.issuerCertificate().getEncoded())))
                            .build(),
                    claims);
            jwt.sign(new ECDSASigner((ECPrivateKey) pki.issuerPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build status list token", e);
        }
    }

    private static byte[] buildBitstring(Map<Integer, Integer> statusValues) {
        int highestIndex =
                statusValues.keySet().stream().mapToInt(Integer::intValue).max().orElse(0);
        byte[] bitstring = new byte[Math.max(highestIndex / 8 + 1, MIN_BITSTRING_BYTES)];
        for (Map.Entry<Integer, Integer> entry : statusValues.entrySet()) {
            int idx = entry.getKey();
            bitstring[idx / 8] |= (byte) ((entry.getValue() & 1) << (idx % 8));
        }
        return bitstring;
    }

    private static byte[] deflate(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (DeflaterOutputStream deflater = new DeflaterOutputStream(out, new Deflater(Deflater.BEST_COMPRESSION))) {
            deflater.write(data);
        }
        return out.toByteArray();
    }
}
