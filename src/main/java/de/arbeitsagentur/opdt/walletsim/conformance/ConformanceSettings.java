package de.arbeitsagentur.opdt.walletsim.conformance;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

// The conformance mode is a static configuration option (app.mode), fixed for the process.
@Component
public class ConformanceSettings {

    private final ValidationMode mode;

    public ConformanceSettings(@Value("${app.mode}") String configuredMode) {
        this.mode = ValidationMode.fromString(configuredMode);
    }

    public ValidationMode mode() {
        return mode;
    }
}
