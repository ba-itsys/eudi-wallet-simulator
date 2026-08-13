package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import java.util.Map;

// Typed view of the DCQL query subset the simulator evaluates (OID4VP 1.0 §6).
public record DcqlQuery(List<CredentialQuery> credentials, List<CredentialSetQuery> credentialSets) {

    @SuppressWarnings("unchecked")
    public static DcqlQuery from(Map<String, Object> dcqlQuery) {
        if (dcqlQuery == null || !(dcqlQuery.get("credentials") instanceof List<?> credentialEntries)) {
            throw new InvalidRequestException("dcql_query with a credentials array is required");
        }
        List<CredentialQuery> credentials = credentialEntries.stream()
                .map(entry -> toCredentialQuery((Map<String, Object>) entry))
                .toList();
        List<CredentialSetQuery> credentialSets = dcqlQuery.get("credential_sets") instanceof List<?> setEntries
                ? setEntries.stream()
                        .map(entry -> toCredentialSetQuery((Map<String, Object>) entry))
                        .toList()
                : List.of();
        return new DcqlQuery(credentials, credentialSets);
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
                        .map(claim -> toClaimQuery((Map<String, Object>) claim))
                        .toList()
                : List.of();
        List<List<String>> claimSets = entry.get("claim_sets") instanceof List<?> setEntries
                ? setEntries.stream()
                        .map(option -> ((List<Object>) option)
                                .stream().map(String::valueOf).toList())
                        .toList()
                : List.of();
        List<TrustedAuthority> trustedAuthorities = entry.get("trusted_authorities") instanceof List<?> authorityEntries
                ? authorityEntries.stream()
                        .map(authority -> toTrustedAuthority((Map<String, Object>) authority))
                        .toList()
                : List.of();
        return new CredentialQuery(id, format, vctValues, claims, claimSets, trustedAuthorities);
    }

    @SuppressWarnings("unchecked")
    private static ClaimQuery toClaimQuery(Map<String, Object> claim) {
        List<Object> values = claim.get("values") instanceof List<?> entries ? (List<Object>) entries : List.of();
        return new ClaimQuery((String) claim.get("id"), castPath(claim.get("path")), values);
    }

    @SuppressWarnings("unchecked")
    private static List<Object> castPath(Object path) {
        return path instanceof List<?> steps ? (List<Object>) steps : List.of();
    }

    private static TrustedAuthority toTrustedAuthority(Map<String, Object> authority) {
        List<String> values = authority.get("values") instanceof List<?> entries
                ? entries.stream().map(String::valueOf).toList()
                : List.of();
        return new TrustedAuthority((String) authority.get("type"), values);
    }

    @SuppressWarnings("unchecked")
    private static CredentialSetQuery toCredentialSetQuery(Map<String, Object> entry) {
        List<List<String>> options = entry.get("options") instanceof List<?> optionEntries
                ? optionEntries.stream()
                        .map(option -> ((List<Object>) option)
                                .stream().map(String::valueOf).toList())
                        .toList()
                : List.of();
        boolean required = !(entry.get("required") instanceof Boolean flag) || flag;
        return new CredentialSetQuery(options, required);
    }
}
