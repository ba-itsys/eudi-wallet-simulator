package de.arbeitsagentur.opdt.walletsim.web;

import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.util.StringUtils;

/**
 * What the user picked in the credential picker: one credential id per DCQL credential query, the
 * chosen option per credential set and the chosen claim set per query. The picker carries these
 * through the edit round trip, so creating a credential from a template returns to the page the
 * user left. A query without an entry falls back to the first offer, which is what a freshly
 * rendered picker shows.
 */
public record PickerSelection(
        Map<String, String> credentialIds, Map<String, String> setOptions, Map<String, String> claimSets) {

    public static final String SKIP_OPTION = "skip";

    public static PickerSelection empty() {
        return new PickerSelection(Map.of(), Map.of(), Map.of());
    }

    public boolean isCredentialSelected(String queryId, String credentialId, boolean firstInSlot) {
        String chosen = credentialIds.get(queryId);
        return StringUtils.hasText(chosen) ? chosen.equals(credentialId) : firstInSlot;
    }

    public boolean isSetOptionSelected(int choiceIndex, int optionIndex, boolean firstOption) {
        String chosen = setOptions.get(String.valueOf(choiceIndex));
        return StringUtils.hasText(chosen) ? chosen.equals(String.valueOf(optionIndex)) : firstOption;
    }

    public boolean isSetOptionSkipped(int choiceIndex) {
        return SKIP_OPTION.equals(setOptions.get(String.valueOf(choiceIndex)));
    }

    public boolean isClaimSetSelected(String queryId, int optionIndex, boolean firstOption) {
        String chosen = claimSets.get(queryId);
        return StringUtils.hasText(chosen) ? chosen.equals(String.valueOf(optionIndex)) : firstOption;
    }

    // the same picks with a credential selected for one query, used for a freshly issued one
    public PickerSelection withCredential(String queryId, String credentialId) {
        Map<String, String> updated = new LinkedHashMap<>(credentialIds);
        updated.put(queryId, credentialId);
        return new PickerSelection(updated, setOptions, claimSets);
    }
}
