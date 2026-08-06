package de.arbeitsagentur.opdt.walletsim.web;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

// Picker form: one selected credential id per DCQL credential query, plus the carried flow state.
public class SelectionForm {

    private Map<String, String> selection = new LinkedHashMap<>();
    private String flowState;

    public Map<String, String> getSelection() {
        return selection;
    }

    public void setSelection(Map<String, String> selection) {
        this.selection = selection;
    }

    public String getFlowState() {
        return flowState;
    }

    public void setFlowState(String flowState) {
        this.flowState = flowState;
    }

    public Optional<String> firstSelectedCredentialId() {
        return selection.values().stream()
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }
}
