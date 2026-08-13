package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// A credential set query with its options and whether it must be satisfied (OID4VP 1.0 §6.3.1).
public record CredentialSetQuery(List<List<String>> options, boolean required) {}
