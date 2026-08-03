package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Extracts usable response-encryption keys from a verifier's client_metadata. */
public final class ClientMetadataKeys {

    private ClientMetadataKeys() {}

    /** Usable EC encryption keys from client_metadata.jwks, in declaration order. */
    @SuppressWarnings("unchecked")
    public static List<Map<String, Object>> encryptionKeys(Map<String, Object> clientMetadata) {
        if (clientMetadata == null
                || !(clientMetadata.get("jwks") instanceof Map<?, ?> jwks)
                || !(((Map<String, Object>) jwks).get("keys") instanceof List<?> keys)) {
            return List.of();
        }
        return keys.stream()
                .map(key -> (Map<String, Object>) key)
                .filter(key -> "EC".equals(key.get("kty")))
                .filter(key -> !"sig".equals(key.get("use")))
                .filter(key -> Objects.nonNull(key.get("crv")))
                .toList();
    }
}
