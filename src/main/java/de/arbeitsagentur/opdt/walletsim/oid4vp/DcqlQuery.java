package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import java.util.Map;

// Typed view of the DCQL query subset the simulator evaluates.
public record DcqlQuery(List<CredentialQuery> credentials) {

    public record CredentialQuery(String id, String format, List<String> vctValues, List<ClaimQuery> claims) {}

    public record ClaimQuery(List<Object> path) {

        // First path element; the top-level claim name deciding which disclosure to release.
        public String topLevelClaimName() {
            return path.isEmpty() ? null : String.valueOf(path.getFirst());
        }
    }

    @SuppressWarnings("unchecked")
    public static DcqlQuery from(Map<String, Object> dcqlQuery) {
        if (dcqlQuery == null || !(dcqlQuery.get("credentials") instanceof List<?> credentialEntries)) {
            throw new InvalidRequestException("dcql_query with a credentials array is required");
        }
        List<CredentialQuery> credentials = credentialEntries.stream()
                .map(entry -> toCredentialQuery((Map<String, Object>) entry))
                .toList();
        return new DcqlQuery(credentials);
    }

    @SuppressWarnings("unchecked")
    private static CredentialQuery toCredentialQuery(Map<String, Object> entry) {
        String id = (String) entry.get("id");
        String format = (String) entry.get("format");
        List<String> vctValues = entry.get("meta") instanceof Map<?, ?> meta
                        && ((Map<String, Object>) meta).get("vct_values") instanceof List<?> values
                ? values.stream().map(String::valueOf).toList()
                : List.of();
        List<ClaimQuery> claims = entry.get("claims") instanceof List<?> claimEntries
                ? claimEntries.stream()
                        .map(claim -> new ClaimQuery(((Map<String, List<Object>>) claim).get("path")))
                        .toList()
                : List.of();
        return new CredentialQuery(id, format, vctValues, claims);
    }
}
