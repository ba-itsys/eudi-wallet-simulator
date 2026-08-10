package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.crypto.ECDHEncrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Encrypts a direct_post.jwt authorization response as a JWE to the verifier's ephemeral key from
 * client_metadata.jwks. The JWE echoes the verifier key's kid so the verifier can resolve the
 * flow without a state form field.
 */
@Component
public class ResponseEncryptor {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String encrypt(AuthorizationRequest request, Map<String, String> responseParameters) {
        try {
            List<Map<String, Object>> keys = ClientMetadataKeys.encryptionKeys(request.clientMetadata());
            if (keys.isEmpty()) {
                throw new InvalidRequestException(
                        "direct_post.jwt requires an EC encryption key in client_metadata.jwks");
            }
            ECKey verifierKey = ECKey.parse(objectMapper.writeValueAsString(keys.getFirst()));

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
            responseParameters.forEach(claims::claim);

            EncryptedJWT jwe = new EncryptedJWT(
                    new JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encryptionMethod(request.clientMetadata()))
                            .keyID(verifierKey.getKeyID())
                            .build(),
                    claims.build());
            jwe.encrypt(new ECDHEncrypter(verifierKey));
            return jwe.serialize();
        } catch (InvalidRequestException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to encrypt authorization response", e);
        }
    }

    private static EncryptionMethod encryptionMethod(Map<String, Object> clientMetadata) {
        if (clientMetadata != null
                && clientMetadata.get("encrypted_response_enc_values_supported") instanceof List<?> supported
                && !supported.isEmpty()
                && "A256GCM".equals(supported.getFirst())) {
            return EncryptionMethod.A256GCM;
        }
        return EncryptionMethod.A128GCM;
    }
}
