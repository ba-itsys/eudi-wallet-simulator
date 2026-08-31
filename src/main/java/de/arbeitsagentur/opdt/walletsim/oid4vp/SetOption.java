package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

/**
 * One option of a credential set, naming the credential queries it requests. satisfiable means
 * every query of the option has at least one matching credential. Unsatisfiable options stay
 * choosable so error answers with non matching credentials can be tested.
 */
public record SetOption(int index, String label, List<String> queryIds, boolean satisfiable) {}
