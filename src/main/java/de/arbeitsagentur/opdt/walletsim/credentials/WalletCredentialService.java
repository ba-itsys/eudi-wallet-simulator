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
     * wallet content. Persistent credentials are created from the start page instead. The status
     * list slot is inherited from the credential it was derived from, so revoking that credential
     * also invalidates this one. Without a slot the credential carries no status reference.
     */
    public StoredCredential issueForSinglePresentation(CredentialDefinition definition, Integer statusIndex) {
        ECKey holderKey = pki.generateCredentialBindingKey();
        return new StoredCredential(
                definition.id(),
                definition.name(),
                definition.format(),
                definition.vct(),
                definition.claims(),
                definition.alwaysDisclosedClaims(),
                issuer.issue(definition, statusIndex, holderKey),
                statusIndex == null ? -1 : statusIndex,
                holderKey,
                CredentialSource.SINGLE_PRESENTATION);
    }

    public StoredCredential issue(CredentialDefinition definition, CredentialSource source) {
        ECKey holderKey = pki.generateCredentialBindingKey();
        return store.add(statusIndex -> new StoredCredential(
                definition.id(),
                definition.name(),
                definition.format(),
                definition.vct(),
                definition.claims(),
                definition.alwaysDisclosedClaims(),
                issuer.issue(definition, statusIndex, holderKey),
                statusIndex,
                holderKey,
                source));
    }
}
