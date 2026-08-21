package de.arbeitsagentur.opdt.walletsim.config;

import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The simulator settings, plus the external URLs derived from the base URL as they are embedded
 * into issued tokens and API responses.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(String baseUrl, String basepath, ValidationMode mode, boolean insecureTls) {

    public AppProperties {
        baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        basepath = basepath == null ? "" : basepath;
    }

    public String statusListUri() {
        return baseUrl + "/api/status-list";
    }

    public String credentialsTrustListUri() {
        return baseUrl + "/api/trust-lists/credentials";
    }
}
