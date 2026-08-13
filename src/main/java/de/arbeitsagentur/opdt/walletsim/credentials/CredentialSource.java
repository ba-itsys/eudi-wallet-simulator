package de.arbeitsagentur.opdt.walletsim.credentials;

// Where a wallet credential came from.
public enum CredentialSource {
    PREDEFINED,
    AD_HOC,
    // issued for a single presentation, never part of the wallet content
    SINGLE_PRESENTATION
}
