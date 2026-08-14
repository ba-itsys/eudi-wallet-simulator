package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// One requested claim with its claims path pointer and optional expected values.
public record ClaimQuery(String id, List<Object> path, List<Object> values) {

    public ClaimQuery {
        path = path == null ? List.of() : path;
        values = values == null ? List.of() : values;
    }
}
