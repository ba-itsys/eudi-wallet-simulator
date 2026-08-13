package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// A trusted authorities query entry (OID4VP 1.0 §6.1.1).
public record TrustedAuthority(String type, List<String> values) {}
