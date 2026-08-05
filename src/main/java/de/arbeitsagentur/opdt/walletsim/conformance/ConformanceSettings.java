package de.arbeitsagentur.opdt.walletsim.conformance;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

// Runtime-switchable conformance mode; the startup value comes from app.conformance.mode.
@Component
public class ConformanceSettings {

    private final ValidationMode startupMode;
    private volatile ValidationMode mode;

    public ConformanceSettings(@Value("${app.conformance.mode}") String configuredMode) {
        this.startupMode = ValidationMode.fromString(configuredMode);
        this.mode = startupMode;
    }

    public ValidationMode mode() {
        return mode;
    }

    public void setMode(ValidationMode mode) {
        this.mode = mode;
    }

    public void reset() {
        this.mode = startupMode;
    }
}
