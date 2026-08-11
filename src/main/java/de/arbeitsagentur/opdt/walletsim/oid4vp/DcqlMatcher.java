package de.arbeitsagentur.opdt.walletsim.oid4vp;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

/**
 * Evaluates a DCQL query against the wallet content and produces a presentation plan: one slot
 * per requested credential query with all matching credentials. Covers vct and claim matching,
 * claim_sets in preference order, trusted_authorities, and credential_sets combinations
 * (OID4VP 1.0 §6).
 */
@Component
public class DcqlMatcher {

    public record CredentialMatch(
            String credentialQueryId, StoredCredential credential, List<List<Object>> claimsToDisclose) {

        // dot notation labels for the picker, null steps render as *
        public List<String> claimsToDiscloseDisplay() {
            return claimsToDisclose.stream()
                    .map(path -> path.stream()
                            .map(step -> step == null ? "*" : String.valueOf(step))
                            .collect(Collectors.joining(".")))
                    .toList();
        }
    }

    public record QuerySlot(String queryId, List<CredentialMatch> matches) {}

    // a credential set with more than one satisfiable option lets the user choose in the picker
    public record SetChoice(int index, boolean required, List<List<String>> options) {

        public List<String> optionLabels() {
            return options.stream().map(option -> String.join(" + ", option)).toList();
        }
    }

    public record PresentationPlan(
            List<QuerySlot> slots,
            List<String> alwaysRequestedQueryIds,
            List<SetChoice> setChoices,
            boolean satisfiable) {}

    private final CredentialStore store;
    private final TrustedAuthorityMatcher trustedAuthorityMatcher;

    public DcqlMatcher(CredentialStore store, TrustedAuthorityMatcher trustedAuthorityMatcher) {
        this.store = store;
        this.trustedAuthorityMatcher = trustedAuthorityMatcher;
    }

    public PresentationPlan plan(DcqlQuery query) {
        Map<String, List<CredentialMatch>> matchesByQuery = new LinkedHashMap<>();
        for (DcqlQuery.CredentialQuery credentialQuery : query.credentials()) {
            List<CredentialMatch> matches = new ArrayList<>();
            for (StoredCredential credential : store.findAll()) {
                match(credentialQuery, credential)
                        .ifPresent(
                                claims -> matches.add(new CredentialMatch(credentialQuery.id(), credential, claims)));
            }
            matchesByQuery.put(credentialQuery.id(), matches);
        }
        List<String> alwaysRequested = alwaysRequestedQueryIds(query);
        List<SetChoice> setChoices = satisfiableSetChoices(query, matchesByQuery);
        Set<String> displayedQueryIds = new LinkedHashSet<>(alwaysRequested);
        setChoices.forEach(choice -> choice.options().forEach(displayedQueryIds::addAll));
        if (displayedQueryIds.isEmpty() && query.credentialSets().isEmpty()) {
            query.credentials().forEach(credentialQuery -> displayedQueryIds.add(credentialQuery.id()));
        }
        List<QuerySlot> slots = new ArrayList<>();
        boolean satisfiable = !displayedQueryIds.isEmpty();
        for (DcqlQuery.CredentialQuery credentialQuery : query.credentials()) {
            if (!displayedQueryIds.contains(credentialQuery.id())) {
                continue;
            }
            List<CredentialMatch> matches = matchesByQuery.get(credentialQuery.id());
            slots.add(new QuerySlot(credentialQuery.id(), matches));
            if (matches.isEmpty() && alwaysRequested.contains(credentialQuery.id())) {
                satisfiable = false;
            }
        }
        if (hasUnsatisfiableRequiredSet(query, matchesByQuery)) {
            satisfiable = false;
        }
        return new PresentationPlan(slots, alwaysRequested, setChoices, satisfiable);
    }

    // queries not referenced by any credential set are always requested
    private static List<String> alwaysRequestedQueryIds(DcqlQuery query) {
        if (query.credentialSets().isEmpty()) {
            return query.credentials().stream()
                    .map(DcqlQuery.CredentialQuery::id)
                    .toList();
        }
        Set<String> referenced = new LinkedHashSet<>();
        query.credentialSets().forEach(set -> set.options().forEach(referenced::addAll));
        return query.credentials().stream()
                .map(DcqlQuery.CredentialQuery::id)
                .filter(id -> !referenced.contains(id))
                .toList();
    }

    // per credential set: the options whose queries all have at least one matching credential
    private static List<SetChoice> satisfiableSetChoices(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        List<SetChoice> choices = new ArrayList<>();
        for (int i = 0; i < query.credentialSets().size(); i++) {
            DcqlQuery.CredentialSetQuery set = query.credentialSets().get(i);
            List<List<String>> satisfiable = set.options().stream()
                    .filter(option -> option.stream()
                            .allMatch(id ->
                                    !matchesByQuery.getOrDefault(id, List.of()).isEmpty()))
                    .toList();
            if (!satisfiable.isEmpty()) {
                choices.add(new SetChoice(i, set.required(), satisfiable));
            }
        }
        return choices;
    }

    private static boolean hasUnsatisfiableRequiredSet(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        return query.credentialSets().stream()
                .filter(DcqlQuery.CredentialSetQuery::required)
                .anyMatch(set -> set.options().stream().noneMatch(option -> option.stream()
                        .allMatch(id ->
                                !matchesByQuery.getOrDefault(id, List.of()).isEmpty())));
    }

    private Optional<List<List<Object>>> match(DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (!CredentialDefinition.FORMAT_SD_JWT_VC.equals(query.format())) {
            return Optional.empty();
        }
        if (!VctMatcher.matches(query.vctValues(), credential.vct())) {
            return Optional.empty();
        }
        if (!trustedAuthorityMatcher.matches(credential, query.trustedAuthorities())) {
            return Optional.empty();
        }
        return claimsToDisclose(query, credential);
    }

    private static Optional<List<List<Object>>> claimsToDisclose(
            DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (query.claims().isEmpty()) {
            // OID4VP 1.0 §6.4.1: absent claims requests no selectively disclosable claims
            return Optional.of(List.of());
        }
        if (query.claimSets().isEmpty()) {
            return allResolve(query.claims(), credential) ? Optional.of(claimPaths(query.claims())) : Optional.empty();
        }
        Map<String, DcqlQuery.ClaimQuery> claimsById = new LinkedHashMap<>();
        query.claims().forEach(claim -> claimsById.put(claim.id(), claim));
        for (List<String> option : query.claimSets()) {
            List<DcqlQuery.ClaimQuery> optionClaims = option.stream()
                    .map(claimsById::get)
                    .filter(Objects::nonNull)
                    .toList();
            if (optionClaims.size() == option.size() && allResolve(optionClaims, credential)) {
                return Optional.of(claimPaths(optionClaims));
            }
        }
        return Optional.empty();
    }

    private static boolean allResolve(List<DcqlQuery.ClaimQuery> claims, StoredCredential credential) {
        return claims.stream().allMatch(claim -> resolve(credential.claims(), claim.path(), 0, claim.values()));
    }

    private static List<List<Object>> claimPaths(List<DcqlQuery.ClaimQuery> claims) {
        return claims.stream()
                .map(DcqlQuery.ClaimQuery::path)
                .filter(path -> !path.isEmpty())
                .distinct()
                .toList();
    }

    // claims path pointer processing per OID4VP 1.0 §7.1.1: null fans out over all array elements
    // and processing continues with the remaining components; a values list must match the
    // resolved claim value (§6.4.1)
    private static boolean resolve(Object current, List<Object> path, int position, List<Object> values) {
        if (current == null) {
            return false;
        }
        if (position == path.size()) {
            return values.isEmpty() || values.stream().anyMatch(value -> valueMatches(value, current));
        }
        Object step = path.get(position);
        if (step instanceof String key && current instanceof Map<?, ?> map) {
            return resolve(map.get(key), path, position + 1, values);
        }
        if (step instanceof Number index && current instanceof List<?> list) {
            int i = index.intValue();
            return i >= 0 && i < list.size() && resolve(list.get(i), path, position + 1, values);
        }
        if (step == null && current instanceof List<?> list) {
            return list.stream().anyMatch(element -> resolve(element, path, position + 1, values));
        }
        return false;
    }

    private static boolean valueMatches(Object requested, Object actual) {
        if (Objects.equals(requested, actual)) {
            return true;
        }
        return requested instanceof Number
                && actual instanceof Number
                && String.valueOf(requested).equals(String.valueOf(actual));
    }
}
