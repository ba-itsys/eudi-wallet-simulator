package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.Optional;

// The verifier's answer to an authorization response, carrying the same device redirect if any.
public record SubmissionResult(Optional<String> redirectUri) {}
