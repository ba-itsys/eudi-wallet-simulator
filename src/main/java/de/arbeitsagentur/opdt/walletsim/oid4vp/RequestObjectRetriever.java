package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Retrieves the request object per OID4VP 1.0 §5.10: with GET by default, and for
 * request_uri_method=post with a form-encoded POST that carries a fresh wallet_nonce and a
 * wallet_metadata whose jwks asks the verifier to encrypt the request object to an ephemeral
 * wallet key. A JWE answer is decrypted with that key back to the signed request object. The
 * key lives only for the fetch, because decryption happens in the same request.
 */
@Component
public class RequestObjectRetriever {

    private static final Logger LOG = LoggerFactory.getLogger(RequestObjectRetriever.class);

    private final RequestObjectClient client;
    private final ObjectMapper objectMapper;

    public RequestObjectRetriever(RequestObjectClient client, ObjectMapper objectMapper) {
        this.client = client;
        this.objectMapper = objectMapper;
    }

    public RequestObjectRetrieval retrieve(String requestUri, String requestUriMethod) {
        if (!"post".equals(requestUriMethod)) {
            return RequestObjectRetrieval.viaGet(client.fetch(requestUri), requestUriMethod);
        }
        String walletNonce = UUID.randomUUID().toString();
        ECKey encryptionKey = ephemeralEncryptionKey();
        String response = client.post(requestUri, walletNonce, walletMetadataJson(encryptionKey));
        boolean encrypted = isJwe(response);
        String requestObjectJwt = encrypted ? decrypt(response, encryptionKey) : response;
        LOG.info(
                "Fetched request object via POST, answer was {}",
                encrypted ? "an encrypted request object (JWE)" : "unencrypted");
        return new RequestObjectRetrieval(requestObjectJwt, requestUriMethod, walletNonce, true, encrypted);
    }

    private static ECKey ephemeralEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyID(UUID.randomUUID().toString())
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .generate();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate the request object encryption key", e);
        }
    }

    // the wallet metadata of this fetch: jwks asks for an encrypted request object (OID4VP 1.0
    // §5.10), the enc values member is RFC 9101 authorization server metadata
    private String walletMetadataJson(ECKey encryptionKey) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("vp_formats_supported", Map.of("dc+sd-jwt", Map.of()));
        metadata.put("jwks", Map.of("keys", List.of(encryptionKey.toPublicJWK().toJSONObject())));
        metadata.put("request_object_encryption_enc_values_supported", List.of("A128GCM", "A256GCM"));
        return objectMapper.writeValueAsString(metadata);
    }

    // a compact JWE has five parts where a signed request object has three
    private static boolean isJwe(String response) {
        return response != null && response.trim().split("\\.", -1).length == 5;
    }

    private static String decrypt(String jwe, ECKey encryptionKey) {
        try {
            JWEObject jweObject = JWEObject.parse(jwe.trim());
            jweObject.decrypt(new ECDHDecrypter(encryptionKey));
            return jweObject.getPayload().toString();
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to decrypt the request object JWE", e);
        }
    }
}
