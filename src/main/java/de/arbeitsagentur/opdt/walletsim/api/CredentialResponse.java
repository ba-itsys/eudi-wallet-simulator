package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.List;
import java.util.Map;

// JSON shape of a credential in the management API.
public record CredentialResponse(
        String id,
        String name,
        String format,
        String vct,
        Map<String, Object> claims,
        List<String> alwaysDisclosedClaims,
        String sdJwt,
        String source,
        StatusReference status) {

    public static CredentialResponse of(StoredCredential credential, String statusListUri, int status) {
        return new CredentialResponse(
                credential.id(),
                credential.name(),
                credential.format(),
                credential.vct(),
                credential.claims(),
                credential.alwaysDisclosedClaims(),
                credential.sdJwt(),
                credential.source().name(),
                StatusReference.of(statusListUri, credential.statusIndex(), status));
    }
}
