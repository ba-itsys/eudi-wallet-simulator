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

    public String encrypt(AuthorizationRequest request, Map<String, Object> responseParameters) {
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
                    new JWEHeader.Builder(keyAlgorithm(verifierKey), encryptionMethod(request.clientMetadata()))
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

    // OID4VP 1.0 §8.3: the JWE alg must equal the alg of the chosen verifier key
    private static JWEAlgorithm keyAlgorithm(ECKey verifierKey) {
        if (verifierKey.getAlgorithm() != null) {
            return JWEAlgorithm.parse(verifierKey.getAlgorithm().getName());
        }
        return JWEAlgorithm.ECDH_ES;
    }

    // HAIP 1.0 §5: prefer A256GCM when the verifier supports it; the enc must come from the
    // advertised list
    private static EncryptionMethod encryptionMethod(Map<String, Object> clientMetadata) {
        if (clientMetadata == null
                || !(clientMetadata.get("encrypted_response_enc_values_supported") instanceof List<?> supported)) {
            return EncryptionMethod.A128GCM;
        }
        if (supported.contains("A256GCM")) {
            return EncryptionMethod.A256GCM;
        }
        if (supported.contains("A128GCM")) {
            return EncryptionMethod.A128GCM;
        }
        throw new InvalidRequestException(
                "encrypted_response_enc_values_supported offers no encryption method this wallet supports");
    }
}
