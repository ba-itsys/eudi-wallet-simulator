package de.arbeitsagentur.opdt.walletsim.web;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import lombok.Getter;
import lombok.Setter;
import org.springframework.util.StringUtils;

// Picker form: one selected credential id per DCQL credential query, plus the carried flow state.
@Getter
@Setter
public class SelectionForm {

    private Map<String, String> selection = new LinkedHashMap<>();
    private Map<String, String> setOption = new LinkedHashMap<>();
    private Map<String, String> claimSet = new LinkedHashMap<>();
    private String flowState;
    private String singlePresentationCredential;

    public Optional<String> firstSelectedCredentialId() {
        return selection.values().stream().filter(StringUtils::hasText).findFirst();
    }

    public PickerSelection pickerSelection() {
        return new PickerSelection(selection, setOption, claimSet);
    }
}
