package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;

// What the picker offers for one authorization request.
public record PresentationPlan(
        List<QuerySlot> slots, List<String> alwaysRequestedQueryIds, List<SetChoice> setChoices, boolean satisfiable) {}
