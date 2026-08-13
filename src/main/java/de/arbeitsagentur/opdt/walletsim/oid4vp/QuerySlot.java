package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// One requested DCQL credential query with every credential that can answer it.
public record QuerySlot(String queryId, List<CredentialMatch> matches) {}
