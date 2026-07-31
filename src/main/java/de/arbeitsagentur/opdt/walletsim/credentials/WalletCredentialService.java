package de.arbeitsagentur.opdt.walletsim.credentials;

import org.springframework.stereotype.Service;

/** Coordinates credential issuance and storage so the status index and SD-JWT stay consistent. */
@Service
public class WalletCredentialService {

    private final CredentialStore store;
    private final SdJwtIssuer issuer;

    public WalletCredentialService(CredentialStore store, SdJwtIssuer issuer) {
        this.store = store;
        this.issuer = issuer;
    }

    public StoredCredential issue(CredentialDefinition definition, StoredCredential.Source source) {
        synchronized (store) {
            int statusIndex = store.reserveStatusIndex();
            String sdJwt = issuer.issue(definition, statusIndex);
            StoredCredential credential = new StoredCredential(
                    definition.id(),
                    definition.name(),
                    definition.format(),
                    definition.vct(),
                    definition.claims(),
                    sdJwt,
                    statusIndex,
                    source);
            store.add(credential);
            return credential;
        }
    }
}
