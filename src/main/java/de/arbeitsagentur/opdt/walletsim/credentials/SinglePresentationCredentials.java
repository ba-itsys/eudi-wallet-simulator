package de.arbeitsagentur.opdt.walletsim.credentials;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Serializes a single presentation credential into a hidden form field and back. The credential
 * travels with the browser for the duration of one presentation flow, so editing during a flow
 * never changes the wallet content.
 */
@Component
public class SinglePresentationCredentials {

    private record Payload(
            String id,
            String name,
            String vct,
            Map<String, Object> claims,
            List<String> alwaysDisclosedClaims,
            String sdJwt,
            int statusIndex,
            String holderKey) {}

    private final ObjectMapper objectMapper = new ObjectMapper();

    public String serialize(StoredCredential credential) {
        Payload payload = new Payload(
                credential.id(),
                credential.name(),
                credential.vct(),
                credential.claims(),
                credential.alwaysDisclosedClaims(),
                credential.sdJwt(),
                credential.statusIndex(),
                credential.holderKey().toJSONString());
        return Base64URL.encode(objectMapper.writeValueAsBytes(payload)).toString();
    }

    public Optional<StoredCredential> deserialize(String encoded) {
        if (encoded == null || encoded.isBlank()) {
            return Optional.empty();
        }
        try {
            Payload payload = objectMapper.readValue(
                    new String(new Base64URL(encoded).decode(), StandardCharsets.UTF_8), Payload.class);
            return Optional.of(new StoredCredential(
                    payload.id(),
                    payload.name(),
                    CredentialDefinition.FORMAT_SD_JWT_VC,
                    payload.vct(),
                    payload.claims(),
                    payload.alwaysDisclosedClaims(),
                    payload.sdJwt(),
                    payload.statusIndex(),
                    ECKey.parse(payload.holderKey()),
                    CredentialSource.SINGLE_PRESENTATION));
        } catch (Exception e) {
            throw new IllegalArgumentException("Single presentation credential cannot be read", e);
        }
    }
}
