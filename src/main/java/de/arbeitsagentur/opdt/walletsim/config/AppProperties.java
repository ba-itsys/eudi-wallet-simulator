package de.arbeitsagentur.opdt.walletsim.config;

import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * The simulator settings, plus the external URLs derived from the base URL and basepath as they
 * are embedded into issued tokens and API responses.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(String baseUrl, String basepath, ValidationMode mode, boolean insecureTls) {

    public AppProperties {
        baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        basepath = normalizeBasepath(basepath);
    }

    // the externally reachable base of the simulator, including the ingress path prefix
    public String externalUrl() {
        return baseUrl + basepath;
    }

    public String statusListUri() {
        return externalUrl() + "/api/status-list";
    }

    public String credentialsTrustListUri() {
        return externalUrl() + "/api/trust-lists/credentials";
    }

    // empty stays empty, everything else becomes "/prefix" without a trailing slash
    private static String normalizeBasepath(String basepath) {
        if (basepath == null || basepath.isBlank()) {
            return "";
        }
        String normalized = basepath.endsWith("/") ? basepath.substring(0, basepath.length() - 1) : basepath;
        return normalized.startsWith("/") ? normalized : "/" + normalized;
    }
}
