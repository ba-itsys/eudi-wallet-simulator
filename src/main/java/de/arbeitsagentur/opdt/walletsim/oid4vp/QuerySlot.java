package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

// One requested DCQL credential query with every credential that can answer it.
public record QuerySlot(String queryId, List<CredentialMatch> matches) {

    // every claim set option any matching credential can satisfy, in the verifier's order
    public List<ClaimSetOption> claimSetOptions() {
        Set<Integer> seen = new LinkedHashSet<>();
        List<ClaimSetOption> options = new ArrayList<>();
        for (CredentialMatch match : matches) {
            for (ClaimSetOption option : match.claimSetOptions()) {
                if (seen.add(option.index())) {
                    options.add(option);
                }
            }
        }
        options.sort((left, right) -> Integer.compare(left.index(), right.index()));
        return options;
    }
}
