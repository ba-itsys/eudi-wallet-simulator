package de.arbeitsagentur.opdt.walletsim.credentials;

import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

/**
 * Serializes the credentials issued for the running presentation into a hidden form field and
 * back. They travel with the browser for the duration of one presentation flow, so editing during
 * a flow never changes the wallet content. A flow answering several credential queries carries
 * one such credential per edited wallet credential, so the serialized payload is a list. The list
 * holds at most one credential per id, and deserializing enforces that.
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

    private static final TypeReference<List<Payload>> PAYLOAD_LIST = new TypeReference<>() {};

    private final ObjectMapper objectMapper;

    public SinglePresentationCredentials(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String serialize(List<StoredCredential> credentials) {
        List<Payload> payloads = credentials.stream()
                .map(credential -> new Payload(
                        credential.id(),
                        credential.name(),
                        credential.vct(),
                        credential.claims(),
                        credential.alwaysDisclosedClaims(),
                        credential.sdJwt(),
                        credential.statusIndex(),
                        credential.holderKey().toJSONString()))
                .toList();
        return Base64URL.encode(objectMapper.writeValueAsBytes(payloads)).toString();
    }

    public List<StoredCredential> deserialize(String encoded) {
        if (!StringUtils.hasText(encoded)) {
            return List.of();
        }
        try {
            List<Payload> payloads = objectMapper.readValue(
                    new String(new Base64URL(encoded).decode(), StandardCharsets.UTF_8), PAYLOAD_LIST);
            List<StoredCredential> credentials = new ArrayList<>();
            for (Payload payload : payloads) {
                credentials.add(toCredential(payload));
            }
            return dedupById(credentials);
        } catch (Exception e) {
            throw new IllegalArgumentException("Single presentation credentials cannot be read", e);
        }
    }

    /**
     * The carried credentials with the given one added, keyed by credential id. A credential
     * issued during the flow keeps the id of the wallet credential it was cloned from, so
     * re-editing one replaces the earlier version in place instead of adding a second candidate.
     */
    public List<StoredCredential> replacing(List<StoredCredential> carried, StoredCredential credential) {
        List<StoredCredential> merged = new ArrayList<>(carried);
        merged.add(credential);
        return dedupById(merged);
    }

    // last version wins, first occurrence keeps its position in the picker
    private static List<StoredCredential> dedupById(List<StoredCredential> credentials) {
        Map<String, StoredCredential> byId = new LinkedHashMap<>();
        credentials.forEach(credential -> byId.put(credential.id(), credential));
        return List.copyOf(byId.values());
    }

    private static StoredCredential toCredential(Payload payload) throws ParseException {
        return new StoredCredential(
                payload.id(),
                payload.name(),
                CredentialDefinition.FORMAT_SD_JWT_VC,
                payload.vct(),
                payload.claims(),
                payload.alwaysDisclosedClaims(),
                payload.sdJwt(),
                payload.statusIndex(),
                ECKey.parse(payload.holderKey()),
                CredentialSource.SINGLE_PRESENTATION);
    }
}
