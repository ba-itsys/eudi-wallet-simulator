package de.arbeitsagentur.opdt.walletsim.oid4vp;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.List;

// A credential that satisfies a DCQL credential query, with the claim set options it can answer.
public record CredentialMatch(
        String credentialQueryId, StoredCredential credential, List<ClaimSetOption> claimSetOptions) {

    public List<List<Object>> claimsToDisclose(int optionIndex) {
        return claimSetOptions.stream()
                .filter(option -> option.index() == optionIndex)
                .findFirst()
                .orElse(claimSetOptions.getFirst())
                .claimPaths();
    }

    public List<String> claimsToDiscloseDisplay() {
        return ClaimSetOption.displayPaths(claimSetOptions.getFirst().claimPaths());
    }
}
