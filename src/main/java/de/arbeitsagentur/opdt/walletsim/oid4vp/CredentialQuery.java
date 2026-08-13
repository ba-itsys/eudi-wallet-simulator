package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// One credential query of a DCQL query (OID4VP 1.0 §6.1).
public record CredentialQuery(
        String id,
        String format,
        List<String> vctValues,
        List<ClaimQuery> claims,
        List<List<String>> claimSets,
        List<TrustedAuthority> trustedAuthorities) {}
