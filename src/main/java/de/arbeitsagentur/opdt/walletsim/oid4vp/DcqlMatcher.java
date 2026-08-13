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

    private final CredentialStore store;
    private final TrustedAuthorityMatcher trustedAuthorityMatcher;

    public DcqlMatcher(CredentialStore store, TrustedAuthorityMatcher trustedAuthorityMatcher) {
        this.store = store;
        this.trustedAuthorityMatcher = trustedAuthorityMatcher;
    }

    public PresentationPlan plan(DcqlQuery query) {
        return plan(query, List.of());
    }

    // extraCredentials are candidates that are not wallet content, for example a credential issued
    // for this presentation only
    public PresentationPlan plan(DcqlQuery query, List<StoredCredential> extraCredentials) {
        List<StoredCredential> candidates = new ArrayList<>(store.findAll());
        candidates.addAll(extraCredentials);
        Map<String, List<CredentialMatch>> matchesByQuery = new LinkedHashMap<>();
        for (CredentialQuery credentialQuery : query.credentials()) {
            List<CredentialMatch> matches = new ArrayList<>();
            for (StoredCredential credential : candidates) {
                match(credentialQuery, credential)
                        .ifPresent(
                                claims -> matches.add(new CredentialMatch(credentialQuery.id(), credential, claims)));
            }
            matchesByQuery.put(credentialQuery.id(), matches);
        }
        List<String> alwaysRequested = alwaysRequestedQueryIds(query);
        List<SetChoice> setChoices = satisfiableSetChoices(query, matchesByQuery);
        Set<String> displayedQueryIds = new LinkedHashSet<>(alwaysRequested);
        setChoices.forEach(choice -> choice.options().forEach(option -> displayedQueryIds.addAll(option.queryIds())));
        if (displayedQueryIds.isEmpty() && query.credentialSets().isEmpty()) {
            query.credentials().forEach(credentialQuery -> displayedQueryIds.add(credentialQuery.id()));
        }
        List<QuerySlot> slots = new ArrayList<>();
        boolean satisfiable = !displayedQueryIds.isEmpty();
        for (CredentialQuery credentialQuery : query.credentials()) {
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
            return query.credentials().stream().map(CredentialQuery::id).toList();
        }
        Set<String> referenced = new LinkedHashSet<>();
        query.credentialSets().forEach(set -> set.options().forEach(referenced::addAll));
        return query.credentials().stream()
                .map(CredentialQuery::id)
                .filter(id -> !referenced.contains(id))
                .toList();
    }

    // per credential set: the options whose queries all have at least one matching credential
    // labels name the credential types behind the query ids, which reads better than cred1 + cred2
    private static List<SetOption> setOptions(DcqlQuery query, List<List<String>> options) {
        Map<String, String> descriptions = new LinkedHashMap<>();
        query.credentials()
                .forEach(credentialQuery -> descriptions.put(
                        credentialQuery.id(),
                        credentialQuery.vctValues().isEmpty()
                                ? credentialQuery.id()
                                : String.join(" or ", credentialQuery.vctValues())));
        List<SetOption> setOptions = new ArrayList<>();
        for (int i = 0; i < options.size(); i++) {
            List<String> queryIds = options.get(i);
            String label = queryIds.stream()
                    .map(id -> descriptions.getOrDefault(id, id))
                    .collect(Collectors.joining(" + "));
            setOptions.add(new SetOption(i, label, queryIds));
        }
        return setOptions;
    }

    private static List<SetChoice> satisfiableSetChoices(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        List<SetChoice> choices = new ArrayList<>();
        for (int i = 0; i < query.credentialSets().size(); i++) {
            CredentialSetQuery set = query.credentialSets().get(i);
            List<List<String>> satisfiable = set.options().stream()
                    .filter(option -> option.stream()
                            .allMatch(id ->
                                    !matchesByQuery.getOrDefault(id, List.of()).isEmpty()))
                    .toList();
            if (!satisfiable.isEmpty()) {
                choices.add(new SetChoice(i, set.required(), setOptions(query, satisfiable)));
            }
        }
        return choices;
    }

    private static boolean hasUnsatisfiableRequiredSet(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        return query.credentialSets().stream()
                .filter(CredentialSetQuery::required)
                .anyMatch(set -> set.options().stream().noneMatch(option -> option.stream()
                        .allMatch(id ->
                                !matchesByQuery.getOrDefault(id, List.of()).isEmpty())));
    }

    private Optional<List<ClaimSetOption>> match(CredentialQuery query, StoredCredential credential) {
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

    /**
     * All claim_sets options this credential can satisfy, in the verifier's preference order. The
     * user picks one in the picker instead of the wallet silently taking the first, because the
     * point of the simulator is to produce every possible outcome.
     */
    private static Optional<List<ClaimSetOption>> claimsToDisclose(CredentialQuery query, StoredCredential credential) {
        if (query.claims().isEmpty()) {
            // OID4VP 1.0 §6.4.1: absent claims requests no selectively disclosable claims
            return Optional.of(List.of(ClaimSetOption.of(0, List.of())));
        }
        if (query.claimSets().isEmpty()) {
            return allResolve(query.claims(), credential)
                    ? Optional.of(List.of(ClaimSetOption.of(0, claimPaths(query.claims()))))
                    : Optional.empty();
        }
        Map<String, ClaimQuery> claimsById = new LinkedHashMap<>();
        query.claims().forEach(claim -> claimsById.put(claim.id(), claim));
        List<ClaimSetOption> options = new ArrayList<>();
        for (int i = 0; i < query.claimSets().size(); i++) {
            List<String> option = query.claimSets().get(i);
            List<ClaimQuery> optionClaims = option.stream()
                    .map(claimsById::get)
                    .filter(Objects::nonNull)
                    .toList();
            if (optionClaims.size() == option.size() && allResolve(optionClaims, credential)) {
                options.add(ClaimSetOption.of(i, claimPaths(optionClaims)));
            }
        }
        return options.isEmpty() ? Optional.empty() : Optional.of(options);
    }

    private static boolean allResolve(List<ClaimQuery> claims, StoredCredential credential) {
        return claims.stream().allMatch(claim -> resolve(credential.claims(), claim.path(), 0, claim.values()));
    }

    private static List<List<Object>> claimPaths(List<ClaimQuery> claims) {
        return claims.stream()
                .map(ClaimQuery::path)
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
