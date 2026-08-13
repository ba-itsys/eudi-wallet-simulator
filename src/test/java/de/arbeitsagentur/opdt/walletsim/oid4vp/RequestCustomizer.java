package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.Map;

// Mutates the request object claims before signing, to simulate non conformant verifiers.
@FunctionalInterface
public interface RequestCustomizer {
    void customize(Map<String, Object> claims);
}
