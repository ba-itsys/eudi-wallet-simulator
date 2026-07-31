package de.arbeitsagentur.opdt.walletsim.statuslist;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import java.io.ByteArrayOutputStream;
import java.security.interfaces.ECPrivateKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.zip.Deflater;
import org.springframework.stereotype.Service;

/**
 * Builds the IETF Token Status List JWT over the credential store's status values. Bit width is
 * derived from the largest status value in the list so suspended (2) is not flattened; the
 * bitstring is padded to at least 16 bytes so a near-empty list does not identify its single
 * referenced credential.
 */
@Service
public class StatusListService {

    private static final int MIN_BITSTRING_BYTES = 16;
    private static final long TTL_SECONDS = 43200;

    private final CredentialStore store;
    private final SimulatorPki pki;
    private final AppUrls urls;

    public StatusListService(CredentialStore store, SimulatorPki pki, AppUrls urls) {
        this.store = store;
        this.pki = pki;
        this.urls = urls;
    }

    public String statusListJwt() {
        try {
            Map<Integer, Integer> statusValues = store.statusValues();
            int bits = bitsPerStatus(statusValues);
            byte[] bitstring = buildBitstring(statusValues, bits);

            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(urls.statusListUri())
                    .issuer(urls.baseUrl())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(24, ChronoUnit.HOURS)))
                    .claim("ttl", TTL_SECONDS)
                    .claim(
                            "status_list",
                            Map.of(
                                    "bits",
                                    bits,
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

    private static int bitsPerStatus(Map<Integer, Integer> statusValues) {
        int max =
                statusValues.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        if (max <= 1) {
            return 1;
        }
        if (max <= 3) {
            return 2;
        }
        if (max <= 15) {
            return 4;
        }
        return 8;
    }

    private static byte[] buildBitstring(Map<Integer, Integer> statusValues, int bits) {
        int highestIndex =
                statusValues.keySet().stream().mapToInt(Integer::intValue).max().orElse(0);
        int requiredBytes = (highestIndex * bits) / 8 + 1;
        byte[] bitstring = new byte[Math.max(requiredBytes, MIN_BITSTRING_BYTES)];
        for (Map.Entry<Integer, Integer> entry : statusValues.entrySet()) {
            int idx = entry.getKey();
            int bitOffset = (idx * bits) % 8;
            bitstring[idx * bits / 8] |= (byte) ((entry.getValue() & ((1 << bits) - 1)) << bitOffset);
        }
        return bitstring;
    }

    private static byte[] deflate(byte[] data) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(data);
        deflater.finish();
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            out.write(buffer, 0, deflater.deflate(buffer));
        }
        return out.toByteArray();
    }
}
