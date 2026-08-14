package de.arbeitsagentur.opdt.walletsim.credentials;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.IntFunction;
import org.springframework.stereotype.Component;

/**
 * In-memory wallet content: credentials by stable id plus their status list values. Pre-defined
 * credentials are seeded from YAML at startup; ad-hoc credentials join at runtime. Everything
 * resets on restart.
 */
@Component
public class CredentialStore {

    private final Map<String, StoredCredential> credentials = new LinkedHashMap<>();
    private final Map<Integer, Integer> statusByIndex = new LinkedHashMap<>();
    private final AtomicInteger statusIndexCounter = new AtomicInteger();

    /**
     * Adds a credential under the next free status list index. The issuer needs that index before
     * it can sign, so it is handed to the given factory inside the lock.
     */
    public synchronized StoredCredential add(IntFunction<StoredCredential> credentialForStatusIndex) {
        int statusIndex = statusIndexCounter.getAndIncrement();
        StoredCredential credential = credentialForStatusIndex.apply(statusIndex);
        if (credentials.containsKey(credential.id())) {
            throw new IllegalArgumentException("Duplicate credential id: " + credential.id());
        }
        credentials.put(credential.id(), credential);
        statusByIndex.put(statusIndex, 0);
        return credential;
    }

    public synchronized List<StoredCredential> findAll() {
        return List.copyOf(credentials.values());
    }

    public synchronized Optional<StoredCredential> findById(String id) {
        return Optional.ofNullable(credentials.get(id));
    }

    public synchronized Optional<Integer> statusOf(String credentialId) {
        return findById(credentialId).map(credential -> statusByIndex.get(credential.statusIndex()));
    }

    public synchronized void setStatus(String credentialId, int status) {
        StoredCredential credential = findById(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + credentialId));
        statusByIndex.put(credential.statusIndex(), status);
    }

    // Status list values by index, for building the status list token.
    public synchronized Map<Integer, Integer> statusValues() {
        return Map.copyOf(statusByIndex);
    }
}
