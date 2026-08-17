package de.arbeitsagentur.opdt.walletsim.web;

import java.util.LinkedHashMap;
import java.util.Map;
import lombok.Getter;
import lombok.Setter;

/**
 * Form backing bean for creating or cloning a credential in the UI. Claims are edited as one
 * field per claim; values keep their JSON type, plain text is treated as a string.
 */
@Getter
@Setter
public class CredentialEditForm {

    private String id;
    private String name;
    private String vct;
    private int validityDays = 365;
    private Map<String, String> claimValues = new LinkedHashMap<>();
    private Map<String, Boolean> claimAlwaysDisclosed = new LinkedHashMap<>();
    private String newClaimName;
    private String newClaimValue;
    private String flowState;
    private String singlePresentationCredential;
    private Integer statusIndex;
    // the picker state during a presentation flow, carried so the selection page comes back as it
    // was left, with the issued credential selected for the query it was created for
    private String editQueryId;
    private Map<String, String> selection = new LinkedHashMap<>();
    private Map<String, String> setOption = new LinkedHashMap<>();
    private Map<String, String> claimSet = new LinkedHashMap<>();

    public PickerSelection pickerSelection() {
        return new PickerSelection(selection, setOption, claimSet);
    }
}
