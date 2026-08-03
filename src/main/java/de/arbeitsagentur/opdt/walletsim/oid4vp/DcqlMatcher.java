package de.arbeitsagentur.opdt.walletsim.oid4vp;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Matches held credentials against a DCQL query. A credential matches a credential query when
 * format and vct agree and every requested claim path resolves into its claims.
 */
@Component
public class DcqlMatcher {

    public record CredentialMatch(
            String credentialQueryId, StoredCredential credential, List<String> claimsToDisclose) {}

    private final CredentialStore store;

    public DcqlMatcher(CredentialStore store) {
        this.store = store;
    }

    public List<CredentialMatch> match(DcqlQuery query) {
        List<CredentialMatch> matches = new ArrayList<>();
        for (DcqlQuery.CredentialQuery credentialQuery : query.credentials()) {
            for (StoredCredential credential : store.findAll()) {
                if (matches(credentialQuery, credential)) {
                    matches.add(new CredentialMatch(
                            credentialQuery.id(), credential, claimsToDisclose(credentialQuery, credential)));
                }
            }
        }
        return matches;
    }

    private static boolean matches(DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (!CredentialDefinition.FORMAT_SD_JWT_VC.equals(query.format())) {
            return false;
        }
        if (!query.vctValues().isEmpty() && !query.vctValues().contains(credential.vct())) {
            return false;
        }
        return query.claims().stream().allMatch(claim -> resolvesInClaims(claim.path(), credential.claims()));
    }

    private static boolean resolvesInClaims(List<Object> path, Object claims) {
        Object current = claims;
        for (Object step : path) {
            if (step instanceof String key && current instanceof java.util.Map<?, ?> map) {
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

    private static List<String> claimsToDisclose(DcqlQuery.CredentialQuery query, StoredCredential credential) {
        if (query.claims().isEmpty()) {
            return List.copyOf(credential.claims().keySet());
        }
        return query.claims().stream()
                .map(DcqlQuery.ClaimQuery::topLevelClaimName)
                .filter(java.util.Objects::nonNull)
                .distinct()
                .toList();
    }
}
