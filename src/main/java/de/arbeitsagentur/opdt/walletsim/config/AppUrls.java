package de.arbeitsagentur.opdt.walletsim.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** External URLs of the simulator as embedded into issued tokens and API responses. */
@Component
public class AppUrls {

    private final String baseUrl;

    public AppUrls(@Value("${app.base-url}") String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
    }

    public String baseUrl() {
        return baseUrl;
    }

    public String statusListUri() {
        return baseUrl + "/status-list";
    }
}
