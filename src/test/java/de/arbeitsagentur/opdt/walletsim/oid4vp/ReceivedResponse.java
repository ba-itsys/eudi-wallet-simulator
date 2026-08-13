package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.Map;

// The authorization response the test verifier received, as form parameters.
public record ReceivedResponse(Map<String, String> formParameters) {}
