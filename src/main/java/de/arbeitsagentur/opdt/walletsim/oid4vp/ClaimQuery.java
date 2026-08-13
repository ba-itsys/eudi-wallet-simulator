package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// One requested claim with its claims path pointer and optional expected values.
public record ClaimQuery(String id, List<Object> path, List<Object> values) {

    // First path element, the top-level claim name deciding which disclosure to release.
    public String topLevelClaimName() {
        return path == null || path.isEmpty() ? null : String.valueOf(path.getFirst());
    }
}
