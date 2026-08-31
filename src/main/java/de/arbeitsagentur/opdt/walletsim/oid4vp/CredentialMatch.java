package de.arbeitsagentur.opdt.walletsim.oid4vp;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.List;

/**
 * A credential offered for a DCQL credential query, with the claim set options it can answer.
 * Both mismatch fields are null for a credential that satisfies the query. For one that does
 * not, offered anyway so error answers can be tested, mismatchSummary carries a short badge
 * label like "no match: vct, claims" and mismatchDetail the full reasons for the badge tooltip.
 * Its claim set options then hold only the requested claims the credential actually has.
 */
public record CredentialMatch(
        String credentialQueryId,
        StoredCredential credential,
        List<ClaimSetOption> claimSetOptions,
        String mismatchSummary,
        String mismatchDetail) {

    public boolean matching() {
        return mismatchSummary == null;
    }

    public List<List<Object>> claimsToDisclose(int optionIndex) {
        return claimSetOptions.stream()
                .filter(option -> option.index() == optionIndex)
                .findFirst()
                .orElse(claimSetOptions.getFirst())
                .claimPaths();
    }
}
