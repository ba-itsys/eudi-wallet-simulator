package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// A credential set with more than one satisfiable option lets the user choose in the picker.
public record SetChoice(int index, boolean required, List<SetOption> options) {}
