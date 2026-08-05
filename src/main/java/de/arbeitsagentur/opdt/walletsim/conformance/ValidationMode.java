package de.arbeitsagentur.opdt.walletsim.conformance;

// What a conformance finding does: warn and continue, or refuse the request.
public enum ValidationMode {
    DEBUG,
    STRICT;

    public static ValidationMode fromString(String value) {
        return switch (value == null ? "" : value.toLowerCase()) {
            case "strict" -> STRICT;
            case "debug" -> DEBUG;
            default -> throw new IllegalArgumentException("Unknown conformance mode: " + value);
        };
    }

    public String asConfigValue() {
        return name().toLowerCase();
    }
}
