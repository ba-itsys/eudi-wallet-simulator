package de.arbeitsagentur.opdt.walletsim.credentials;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

// Seeds the credential store from the YAML file configured via app.resources.credentials.
@Component
public class CredentialSeedLoader implements ApplicationRunner {

    private final WalletCredentialService credentialService;
    private final Resource seedResource;

    public CredentialSeedLoader(
            WalletCredentialService credentialService, @Value("${app.resources.credentials}") Resource seedResource) {
        this.credentialService = credentialService;
        this.seedResource = seedResource;
    }

    @Override
    public void run(ApplicationArguments args) throws IOException {
        for (CredentialDefinition definition : loadDefinitions()) {
            credentialService.issue(definition, CredentialSource.PREDEFINED);
        }
    }

    private List<CredentialDefinition> loadDefinitions() throws IOException {
        try (InputStream in = seedResource.getInputStream()) {
            Map<String, Object> root = new Yaml().load(in);
            @SuppressWarnings("unchecked")
            List<Map<String, Object>> entries = (List<Map<String, Object>>) root.get("credentials");
            if (entries == null) {
                throw new IllegalStateException("Credential seed file has no 'credentials' list: " + seedResource);
            }
            return entries.stream().map(CredentialSeedLoader::toDefinition).toList();
        }
    }

    private static CredentialDefinition toDefinition(Map<String, Object> entry) {
        String id = requireString(entry, "id");
        String name = requireString(entry, "name");
        String vct = requireString(entry, "vct");
        int validityDays = entry.get("validityDays") instanceof Integer days ? days : 365;
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) entry.get("claims");
        if (claims == null || claims.isEmpty()) {
            throw new IllegalStateException("Credential '" + id + "' has no claims");
        }
        @SuppressWarnings("unchecked")
        List<String> alwaysDisclosed = entry.get("alwaysDisclosedClaims") instanceof List<?> paths
                ? paths.stream().map(String::valueOf).toList()
                : List.of();
        boolean untrustedIssuer = entry.get("untrustedIssuer") instanceof Boolean value && value;
        // the seed order is the order the wallet shows the claims in, so it has to survive the copy
        return new CredentialDefinition(
                id,
                name,
                vct,
                validityDays,
                Collections.unmodifiableMap(new LinkedHashMap<>(claims)),
                alwaysDisclosed,
                untrustedIssuer);
    }

    private static String requireString(Map<String, Object> entry, String key) {
        if (!(entry.get(key) instanceof String value) || value.isBlank()) {
            throw new IllegalStateException("Credential seed entry is missing '" + key + "': " + entry);
        }
        return value;
    }
}
