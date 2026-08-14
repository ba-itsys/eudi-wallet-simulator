package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

// One credential query of a DCQL query (OID4VP 1.0 §6.1).
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialQuery(
        String id,
        String format,
        CredentialQueryMeta meta,
        List<ClaimQuery> claims,
        List<List<String>> claimSets,
        List<TrustedAuthority> trustedAuthorities) {

    public CredentialQuery {
        claims = claims == null ? List.of() : claims;
        claimSets = claimSets == null ? List.of() : claimSets;
        trustedAuthorities = trustedAuthorities == null ? List.of() : trustedAuthorities;
    }

    public List<String> vctValues() {
        return meta == null ? List.of() : meta.vctValues();
    }
}
