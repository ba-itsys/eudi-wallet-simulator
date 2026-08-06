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
            String credentialQueryId, StoredCredential credential, List<String> claimsToDisclose) {}

    public record QuerySlot(String queryId, List<CredentialMatch> matches) {}

    public record PresentationPlan(List<QuerySlot> slots, boolean satisfiable) {}

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
        Set<String> requestedQueryIds = selectQueryIds(query, matchesByQuery);
        List<QuerySlot> slots = new ArrayList<>();
        boolean satisfiable = !requestedQueryIds.isEmpty();
        for (DcqlQuery.CredentialQuery credentialQuery : query.credentials()) {
            if (!requestedQueryIds.contains(credentialQuery.id())) {
                continue;
            }
            List<CredentialMatch> matches = matchesByQuery.get(credentialQuery.id());
            slots.add(new QuerySlot(credentialQuery.id(), matches));
            if (matches.isEmpty()) {
                satisfiable = false;
            }
        }
        if (hasUnsatisfiableRequiredSet(query, matchesByQuery)) {
            satisfiable = false;
        }
        return new PresentationPlan(slots, satisfiable);
    }

    /**
     * Query ids to present: all queries without credential_sets, otherwise the queries not
     * referenced by any set plus the first satisfiable option of every set (required sets count
     * toward satisfiability, optional sets are included only when satisfiable).
     */
    private static Set<String> selectQueryIds(DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        Set<String> selected = new LinkedHashSet<>();
        if (query.credentialSets().isEmpty()) {
            query.credentials().forEach(credentialQuery -> selected.add(credentialQuery.id()));
            return selected;
        }
        Set<String> referenced = new LinkedHashSet<>();
        query.credentialSets().forEach(set -> set.options().forEach(referenced::addAll));
        query.credentials().stream()
                .map(DcqlQuery.CredentialQuery::id)
                .filter(id -> !referenced.contains(id))
                .forEach(selected::add);
        for (DcqlQuery.CredentialSetQuery set : query.credentialSets()) {
            Optional<List<String>> satisfiableOption = set.options().stream()
                    .filter(option -> option.stream()
                            .allMatch(id ->
                                    !matchesByQuery.getOrDefault(id, List.of()).isEmpty()))
                    .findFirst();
            if (satisfiableOption.isPresent()) {
                selected.addAll(satisfiableOption.get());
            } else if (set.required() && !set.options().isEmpty()) {
                selected.addAll(set.options().getFirst());
            }
        }
        return selected;
    }

    private static boolean hasUnsatisfiableRequiredSet(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        return query.credentialSets().stream()
                .filter(DcqlQuery.CredentialSetQuery::required)
                .anyMatch(set -> set.options().stream().noneMatch(option -> option.stream()
                        .allMatch(id ->
                                !matchesByQuery.getOrDefault(id, List.of()).isEmpty())));
    }

    private Optional<List<String>> match(DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (!CredentialDefinition.FORMAT_SD_JWT_VC.equals(query.format())) {
            return Optional.empty();
        }
        if (!query.vctValues().isEmpty() && !query.vctValues().contains(credential.vct())) {
            return Optional.empty();
        }
        if (!trustedAuthorityMatcher.matches(credential, query.trustedAuthorities())) {
            return Optional.empty();
        }
        return claimsToDisclose(query, credential);
    }

    private static Optional<List<String>> claimsToDisclose(
            DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (query.claims().isEmpty()) {
            return Optional.of(List.copyOf(credential.claims().keySet()));
        }
        if (query.claimSets().isEmpty()) {
            return allResolve(query.claims(), credential)
                    ? Optional.of(topLevelNames(query.claims()))
                    : Optional.empty();
        }
        Map<String, DcqlQuery.ClaimQuery> claimsById = new LinkedHashMap<>();
        query.claims().forEach(claim -> claimsById.put(claim.id(), claim));
        for (List<String> option : query.claimSets()) {
            List<DcqlQuery.ClaimQuery> optionClaims = option.stream()
                    .map(claimsById::get)
                    .filter(Objects::nonNull)
                    .toList();
            if (optionClaims.size() == option.size() && allResolve(optionClaims, credential)) {
                return Optional.of(topLevelNames(optionClaims));
            }
        }
        return Optional.empty();
    }

    private static boolean allResolve(List<DcqlQuery.ClaimQuery> claims, StoredCredential credential) {
        return claims.stream().allMatch(claim -> resolvesInClaims(claim.path(), credential.claims()));
    }

    private static List<String> topLevelNames(List<DcqlQuery.ClaimQuery> claims) {
        return claims.stream()
                .map(DcqlQuery.ClaimQuery::topLevelClaimName)
                .filter(Objects::nonNull)
                .distinct()
                .toList();
    }

    private static boolean resolvesInClaims(List<Object> path, Object claims) {
        Object current = claims;
        for (Object step : path) {
            if (step instanceof String key && current instanceof Map<?, ?> map) {
                current = map.get(key);
            } else if (step instanceof Number index && current instanceof List<?> list) {
                int i = index.intValue();
                current = i >= 0 && i < list.size() ? list.get(i) : null;
            } else if (step == null && current instanceof List<?> list) {
                return !list.isEmpty();
            } else {
                return false;
            }
            if (current == null) {
                return false;
            }
        }
        return true;
    }
}
