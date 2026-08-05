package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.Map;

// JSON shape of a credential in the management API.
public record CredentialResponse(
        String id,
        String name,
        String format,
        String vct,
        Map<String, Object> claims,
        String sdJwt,
        String source,
        StatusReference status) {

    public record StatusReference(String uri, int idx, int status, String statusName) {

        public static StatusReference of(String statusListUri, int idx, int status) {
            return new StatusReference(statusListUri, idx, status, statusName(status));
        }

        private static String statusName(int status) {
            return switch (status) {
                case 0 -> "VALID";
                case 1 -> "INVALID";
                case 2 -> "SUSPENDED";
                default -> "STATUS_" + status;
            };
        }
    }

    public static CredentialResponse of(StoredCredential credential, String statusListUri, int status) {
        return new CredentialResponse(
                credential.id(),
                credential.name(),
                credential.format(),
                credential.vct(),
                credential.claims(),
                credential.sdJwt(),
                credential.source().name(),
                StatusReference.of(statusListUri, credential.statusIndex(), status));
    }
}
