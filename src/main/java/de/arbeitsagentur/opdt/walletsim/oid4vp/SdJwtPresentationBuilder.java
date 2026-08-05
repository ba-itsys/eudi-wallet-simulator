package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Builds an SD-JWT VP: the issuer JWT with only the requested disclosures, completed by a KB-JWT
 * signed with the credential's own holder binding key, tying the presentation to the verifier's
 * client_id and nonce via sd_hash.
 */
@Component
public class SdJwtPresentationBuilder {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String build(StoredCredential credential, List<String> claimsToDisclose, String audience, String nonce) {
        try {
            String[] parts = credential.sdJwt().split("~");
            StringBuilder presentation = new StringBuilder(parts[0]);
            for (int i = 1; i < parts.length; i++) {
                if (claimsToDisclose.contains(disclosedClaimName(parts[i]))) {
                    presentation.append('~').append(parts[i]);
                }
            }
            presentation.append('~');

            String sdHash = Base64URL.encode(MessageDigest.getInstance("SHA-256")
                            .digest(presentation.toString().getBytes(StandardCharsets.US_ASCII)))
                    .toString();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .issueTime(Date.from(Instant.now()))
                    .claim("nonce", nonce)
                    .claim("sd_hash", sdHash)
                    .build();
            SignedJWT kbJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    claims);
            kbJwt.sign(new ECDSASigner(credential.holderKey()));

            return presentation.append(kbJwt.serialize()).toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SD-JWT presentation for " + credential.id(), e);
        }
    }

    private String disclosedClaimName(String disclosure) {
        List<?> decoded = objectMapper.readValue(
                new String(java.util.Base64.getUrlDecoder().decode(disclosure), StandardCharsets.UTF_8), List.class);
        return decoded.size() == 3 ? String.valueOf(decoded.get(1)) : null;
    }
}
