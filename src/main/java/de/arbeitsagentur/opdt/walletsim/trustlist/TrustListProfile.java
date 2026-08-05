package de.arbeitsagentur.opdt.walletsim.trustlist;

// The two ETSI TS 119 602 list profiles the simulator publishes.
public enum TrustListProfile {
    CREDENTIALS(
            "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
            "http://uri.etsi.org/19602/SvcType/PID/Issuance",
            "http://uri.etsi.org/19602/SvcType/PID/Revocation",
            "http://uri.etsi.org/19602/PIDProvidersList/StatusDetn/EU",
            "http://uri.etsi.org/19602/PIDProviders/schemerules/EU"),
    WALLET_PROVIDERS(
            "http://uri.etsi.org/19602/LoTEType/EUWalletProvidersList",
            "http://uri.etsi.org/19602/SvcType/WalletSolution/Issuance",
            "http://uri.etsi.org/19602/SvcType/WalletSolution/Revocation",
            "http://uri.etsi.org/19602/WalletProvidersList/StatusDetn/EU",
            "http://uri.etsi.org/19602/WalletProvidersList/schemerules/EU");

    private final String loteType;
    private final String issuanceServiceType;
    private final String revocationServiceType;
    private final String statusDeterminationApproach;
    private final String schemeTypeCommunityRules;

    TrustListProfile(
            String loteType,
            String issuanceServiceType,
            String revocationServiceType,
            String statusDeterminationApproach,
            String schemeTypeCommunityRules) {
        this.loteType = loteType;
        this.issuanceServiceType = issuanceServiceType;
        this.revocationServiceType = revocationServiceType;
        this.statusDeterminationApproach = statusDeterminationApproach;
        this.schemeTypeCommunityRules = schemeTypeCommunityRules;
    }

    public String loteType() {
        return loteType;
    }

    public String issuanceServiceType() {
        return issuanceServiceType;
    }

    public String revocationServiceType() {
        return revocationServiceType;
    }

    public String statusDeterminationApproach() {
        return statusDeterminationApproach;
    }

    public String schemeTypeCommunityRules() {
        return schemeTypeCommunityRules;
    }
}
