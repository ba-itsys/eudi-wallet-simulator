package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import java.util.stream.Collectors;

// One satisfiable claim_sets option, or the single implicit option when the query has none.
public record ClaimSetOption(int index, String label, List<List<Object>> claimPaths) {

    public static ClaimSetOption of(int index, List<List<Object>> claimPaths) {
        String label = claimPaths.isEmpty()
                ? "no selectively disclosable claims"
                : String.join(", ", displayPaths(claimPaths));
        return new ClaimSetOption(index, label, claimPaths);
    }

    // dot notation labels for the picker, null steps render as *
    public static List<String> displayPaths(List<List<Object>> claimPaths) {
        return claimPaths.stream()
                .map(path -> path.stream()
                        .map(step -> step == null ? "*" : String.valueOf(step))
                        .collect(Collectors.joining(".")))
                .toList();
    }
}
