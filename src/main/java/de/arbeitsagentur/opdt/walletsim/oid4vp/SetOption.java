package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// One option of a credential set, naming the credential queries it requests.
public record SetOption(int index, String label, List<String> queryIds) {}
