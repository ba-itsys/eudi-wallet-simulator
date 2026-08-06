package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

/**
 * vct matching for DCQL vct_values including inheritance: SD-JWT VC type metadata declares that
 * a vct extends a base type, and the wallet may answer a request for the base type with an
 * extending credential (SD-JWT VC draft, Type Metadata, extends). Instead of resolving type
 * metadata, the extends relation is simplified to urn children: the child type inserts segments
 * between the base prefix and the trailing version segment, so urn:eudi:pid:de:1 extends
 * urn:eudi:pid:1 while the reverse does not hold and siblings stay unrelated.
 */
public final class VctMatcher {

    private VctMatcher() {}

    public static boolean matches(List<String> requestedVctValues, String candidateVct) {
        if (requestedVctValues.isEmpty()) {
            return true;
        }
        return requestedVctValues.stream().anyMatch(requested -> matchesSingle(requested, candidateVct));
    }

    private static boolean matchesSingle(String requestedVct, String candidateVct) {
        if (requestedVct.equals(candidateVct)) {
            return true;
        }
        if (!requestedVct.startsWith("urn:") || !candidateVct.startsWith("urn:")) {
            return false;
        }
        String[] requested = requestedVct.split(":");
        String[] candidate = candidateVct.split(":");
        if (candidate.length <= requested.length) {
            return false;
        }
        if (!candidate[candidate.length - 1].equals(requested[requested.length - 1])) {
            return false;
        }
        for (int i = 0; i < requested.length - 1; i++) {
            if (!candidate[i].equals(requested[i])) {
                return false;
            }
        }
        return true;
    }
}
