package de.arbeitsagentur.opdt.walletsim.credentials;

import java.util.Map;

/** An issued credential held by the wallet, including its signed SD-JWT and status list slot. */
public record StoredCredential(
        String id,
        String name,
        String format,
        String vct,
        Map<String, Object> claims,
        String sdJwt,
        int statusIndex,
        Source source) {

    public enum Source {
        PREDEFINED,
        AD_HOC
    }
}
