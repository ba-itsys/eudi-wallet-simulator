package de.arbeitsagentur.opdt.walletsim.conformance;

// What a conformance finding does: warn and continue, or refuse the request.
public enum ValidationMode {
    DEBUG,
    STRICT;

    public String asConfigValue() {
        return name().toLowerCase();
    }
}
