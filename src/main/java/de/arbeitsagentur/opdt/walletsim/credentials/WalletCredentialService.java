package de.arbeitsagentur.opdt.walletsim.credentials;

import com.nimbusds.jose.jwk.ECKey;
import de.arbeitsagentur.opdt.walletsim.pki.SimulatorPki;
import org.springframework.stereotype.Service;

/**
 * Coordinates credential issuance and storage so the status index, the SD-JWT and the fresh
 * per-credential holder binding key stay consistent.
 */
@Service
public class WalletCredentialService {

    private final CredentialStore store;
    private final SdJwtIssuer issuer;
    private final SimulatorPki pki;

    public WalletCredentialService(CredentialStore store, SdJwtIssuer issuer, SimulatorPki pki) {
        this.store = store;
        this.issuer = issuer;
        this.pki = pki;
    }

    /**
     * Issues a credential that exists only for the current presentation. It is signed like any
     * other credential but never enters the wallet, so a presentation flow cannot change the
     * wallet content. Persistent credentials are created from the start page instead.
     */
    public StoredCredential issueForSinglePresentation(CredentialDefinition definition) {
        ECKey holderKey = pki.generateCredentialBindingKey();
        return new StoredCredential(
                definition.id(),
                definition.name(),
                definition.format(),
                definition.vct(),
                definition.claims(),
                definition.alwaysDisclosedClaims(),
                issuer.issue(definition, null, holderKey),
                -1,
                holderKey,
                CredentialSource.SINGLE_PRESENTATION);
    }

    public StoredCredential issue(CredentialDefinition definition, CredentialSource source) {
        synchronized (store) {
            int statusIndex = store.reserveStatusIndex();
            ECKey holderKey = pki.generateCredentialBindingKey();
            String sdJwt = issuer.issue(definition, statusIndex, holderKey);
            StoredCredential credential = new StoredCredential(
                    definition.id(),
                    definition.name(),
                    definition.format(),
                    definition.vct(),
                    definition.claims(),
                    definition.alwaysDisclosedClaims(),
                    sdJwt,
                    statusIndex,
                    holderKey,
                    source);
            store.add(credential);
            return credential;
        }
    }
}
