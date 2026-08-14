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
}
