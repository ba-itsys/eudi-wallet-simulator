package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;

/**
 * One requested DCQL credential query with every credential that can answer it, plus the
 * credentials that cannot. The picker offers the latter behind the show all toggle, so error
 * answers like a wrong credential type or missing claims can be tested.
 */
public record QuerySlot(String queryId, List<CredentialMatch> matches, List<CredentialMatch> nonMatches) {

    // every offered credential, satisfying ones first, in one list for the picker
    public List<CredentialMatch> offers() {
        return Stream.concat(matches.stream(), nonMatches.stream()).toList();
    }

    public Optional<CredentialMatch> offerFor(String credentialId) {
        return offers().stream()
                .filter(offer -> offer.credential().id().equals(credentialId))
                .findFirst();
    }

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
        options.sort(Comparator.comparingInt(ClaimSetOption::index));
        return options;
    }
}
