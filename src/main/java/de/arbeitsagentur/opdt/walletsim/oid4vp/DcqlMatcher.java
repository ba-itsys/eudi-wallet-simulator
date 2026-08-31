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
import tools.jackson.databind.ObjectMapper;

/**
 * Evaluates a DCQL query against the wallet content and produces a presentation plan: one slot
 * per requested credential query with all matching credentials. Covers vct and claim matching,
 * claim_sets in preference order, trusted_authorities, and credential_sets combinations
 * (OID4VP 1.0 §6). Credentials that do not satisfy a query are offered as well, each with the
 * reason and the requested claims it does have, so the picker can produce error answers on
 * purpose.
 */
@Component
public class DcqlMatcher {

    private final CredentialStore store;
    private final TrustedAuthorityMatcher trustedAuthorityMatcher;
    private final ObjectMapper objectMapper;

    public DcqlMatcher(
            CredentialStore store, TrustedAuthorityMatcher trustedAuthorityMatcher, ObjectMapper objectMapper) {
        this.store = store;
        this.trustedAuthorityMatcher = trustedAuthorityMatcher;
        this.objectMapper = objectMapper;
    }

    // Reads the dcql_query claim into the typed model. Structural violations are reported by the
    // conformance validator, so a query that cannot be read at all is an invalid request here.
    public DcqlQuery parse(Map<String, Object> dcqlQuery) {
        if (dcqlQuery == null) {
            throw new InvalidRequestException("dcql_query with a credentials array is required");
        }
        try {
            return objectMapper.convertValue(dcqlQuery, DcqlQuery.class);
        } catch (RuntimeException e) {
            throw new InvalidRequestException("dcql_query cannot be read: " + e.getMessage(), e);
        }
    }

    // extraCredentials are candidates that are not wallet content, for example a credential issued
    // for this presentation only
    public PresentationPlan plan(DcqlQuery query, List<StoredCredential> extraCredentials) {
        List<String> replacedIds =
                extraCredentials.stream().map(StoredCredential::id).toList();
        List<StoredCredential> candidates = new ArrayList<>(store.findAll().stream()
                .filter(credential -> !replacedIds.contains(credential.id()))
                .toList());
        candidates.addAll(extraCredentials);
        Map<String, List<CredentialMatch>> matchesByQuery = new LinkedHashMap<>();
        Map<String, List<CredentialMatch>> nonMatchesByQuery = new LinkedHashMap<>();
        for (CredentialQuery credentialQuery : query.credentials()) {
            List<CredentialMatch> matches = new ArrayList<>();
            List<CredentialMatch> nonMatches = new ArrayList<>();
            for (StoredCredential credential : candidates) {
                evaluate(credentialQuery, credential)
                        .ifPresent(offer -> (offer.matching() ? matches : nonMatches).add(offer));
            }
            matchesByQuery.put(credentialQuery.id(), matches);
            nonMatchesByQuery.put(credentialQuery.id(), nonMatches);
        }
        List<String> alwaysRequested = alwaysRequestedQueryIds(query);
        List<SetChoice> setChoices = setChoices(query, matchesByQuery);
        Set<String> displayedQueryIds = new LinkedHashSet<>(alwaysRequested);
        setChoices.forEach(choice -> choice.options().forEach(option -> displayedQueryIds.addAll(option.queryIds())));
        // satisfiable reflects fully matching answers only, so unsatisfiable options that are
        // merely choosable for error testing do not count
        Set<String> matchedQueryIds = new LinkedHashSet<>(alwaysRequested);
        setChoices.forEach(choice -> choice.options().stream()
                .filter(SetOption::satisfiable)
                .forEach(option -> matchedQueryIds.addAll(option.queryIds())));
        List<QuerySlot> slots = new ArrayList<>();
        boolean satisfiable = !matchedQueryIds.isEmpty();
        for (CredentialQuery credentialQuery : query.credentials()) {
            if (!displayedQueryIds.contains(credentialQuery.id())) {
                continue;
            }
            List<CredentialMatch> matches = matchesByQuery.get(credentialQuery.id());
            slots.add(new QuerySlot(credentialQuery.id(), matches, nonMatchesByQuery.get(credentialQuery.id())));
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

    // per credential set: every option, each marked whether all its queries have a matching
    // credential, so an option a modified credential broke stays choosable for error testing.
    // Labels name the credential types behind the query ids, which reads better than cred1 + cred2
    private static List<SetChoice> setChoices(DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        Map<String, String> descriptions = new LinkedHashMap<>();
        query.credentials()
                .forEach(credentialQuery -> descriptions.put(
                        credentialQuery.id(),
                        credentialQuery.vctValues().isEmpty()
                                ? credentialQuery.id()
                                : String.join(" or ", credentialQuery.vctValues())));
        List<SetChoice> choices = new ArrayList<>();
        for (int i = 0; i < query.credentialSets().size(); i++) {
            CredentialSetQuery set = query.credentialSets().get(i);
            List<SetOption> options = new ArrayList<>();
            for (int j = 0; j < set.options().size(); j++) {
                List<String> queryIds = set.options().get(j);
                String label = queryIds.stream()
                        .map(id -> descriptions.getOrDefault(id, id))
                        .collect(Collectors.joining(" + "));
                boolean optionSatisfiable = queryIds.stream()
                        .allMatch(id ->
                                !matchesByQuery.getOrDefault(id, List.of()).isEmpty());
                options.add(new SetOption(j, label, queryIds, optionSatisfiable));
            }
            choices.add(new SetChoice(i, set.isRequired(), options));
        }
        return choices;
    }

    private static boolean hasUnsatisfiableRequiredSet(
            DcqlQuery query, Map<String, List<CredentialMatch>> matchesByQuery) {
        return query.credentialSets().stream()
                .filter(CredentialSetQuery::isRequired)
                .anyMatch(set -> set.options().stream().noneMatch(option -> option.stream()
                        .allMatch(id ->
                                !matchesByQuery.getOrDefault(id, List.of()).isEmpty())));
    }

    // A credential's offer for one query: a match when it satisfies the query, an offer with the
    // mismatch reasons otherwise. The badge on the card only fits short labels, so the full
    // reasons go into a separate detail shown on hover. Queries for other formats offer nothing,
    // the wallet only holds SD-JWT VCs.
    private Optional<CredentialMatch> evaluate(CredentialQuery query, StoredCredential credential) {
        if (!CredentialDefinition.FORMAT_SD_JWT_VC.equals(query.format())) {
            return Optional.empty();
        }
        List<String> labels = new ArrayList<>();
        List<String> details = new ArrayList<>();
        if (!VctMatcher.matches(query.vctValues(), credential.vct())) {
            labels.add("vct");
            details.add("vct does not match the requested values");
        }
        if (!trustedAuthorityMatcher.matches(credential, query.trustedAuthorities())) {
            labels.add("issuer");
            details.add("issuer does not match the trusted authorities");
        }
        Optional<List<ClaimSetOption>> satisfied = claimsToDisclose(query, credential);
        if (satisfied.isEmpty()) {
            labels.add("claims");
            details.add("requested claims are missing");
        }
        if (labels.isEmpty()) {
            return Optional.of(new CredentialMatch(query.id(), credential, satisfied.get(), null, null));
        }
        return Optional.of(new CredentialMatch(
                query.id(),
                credential,
                availableClaimOptions(query, credential),
                "no match: " + String.join(", ", labels),
                String.join(", ", details)));
    }

    // the requested claims the credential does have, per claim set option, for partial answers
    private static List<ClaimSetOption> availableClaimOptions(CredentialQuery query, StoredCredential credential) {
        if (query.claims().isEmpty()) {
            return List.of(ClaimSetOption.of(0, List.of()));
        }
        if (query.claimSets().isEmpty()) {
            return List.of(ClaimSetOption.of(0, claimPaths(resolvable(query.claims(), credential))));
        }
        Map<String, ClaimQuery> claimsById = new LinkedHashMap<>();
        query.claims().forEach(claim -> claimsById.put(claim.id(), claim));
        List<ClaimSetOption> options = new ArrayList<>();
        for (int i = 0; i < query.claimSets().size(); i++) {
            List<ClaimQuery> optionClaims = query.claimSets().get(i).stream()
                    .map(claimsById::get)
                    .filter(Objects::nonNull)
                    .toList();
            options.add(ClaimSetOption.of(i, claimPaths(resolvable(optionClaims, credential))));
        }
        return options;
    }

    private static List<ClaimQuery> resolvable(List<ClaimQuery> claims, StoredCredential credential) {
        return claims.stream()
                .filter(claim -> resolve(credential.claims(), claim.path(), 0, claim.values()))
                .toList();
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
