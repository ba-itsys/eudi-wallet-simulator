package de.arbeitsagentur.opdt.walletsim.api;

// Body of a revocation API call, 0 activates and 1 revokes.
public record StatusChangeRequest(int status) {}
