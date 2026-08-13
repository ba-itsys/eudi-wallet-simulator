package de.arbeitsagentur.opdt.walletsim.credentials;

import com.nimbusds.jose.jwk.ECKey;
import java.util.List;
import java.util.Map;

/**
 * An issued credential held by the wallet, including its signed SD-JWT, status list slot and the
 * per-credential holder binding key matching the issued cnf.jwk.
 */
public record StoredCredential(
        String id,
        String name,
        String format,
        String vct,
        Map<String, Object> claims,
        List<String> alwaysDisclosedClaims,
        String sdJwt,
        int statusIndex,
        ECKey holderKey,
        CredentialSource source) {}
