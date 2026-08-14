package de.arbeitsagentur.opdt.walletsim.web;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Form backing bean for creating or cloning a credential in the UI. Claims are edited as one
 * field per claim; values keep their JSON type, plain text is treated as a string.
 */
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

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVct() {
        return vct;
    }

    public void setVct(String vct) {
        this.vct = vct;
    }

    public int getValidityDays() {
        return validityDays;
    }

    public void setValidityDays(int validityDays) {
        this.validityDays = validityDays;
    }

    public Map<String, String> getClaimValues() {
        return claimValues;
    }

    public void setClaimValues(Map<String, String> claimValues) {
        this.claimValues = claimValues;
    }

    public Map<String, Boolean> getClaimAlwaysDisclosed() {
        return claimAlwaysDisclosed;
    }

    public void setClaimAlwaysDisclosed(Map<String, Boolean> claimAlwaysDisclosed) {
        this.claimAlwaysDisclosed = claimAlwaysDisclosed;
    }

    public String getNewClaimName() {
        return newClaimName;
    }

    public void setNewClaimName(String newClaimName) {
        this.newClaimName = newClaimName;
    }

    public String getNewClaimValue() {
        return newClaimValue;
    }

    public void setNewClaimValue(String newClaimValue) {
        this.newClaimValue = newClaimValue;
    }

    public Integer getStatusIndex() {
        return statusIndex;
    }

    public void setStatusIndex(Integer statusIndex) {
        this.statusIndex = statusIndex;
    }

    public String getSinglePresentationCredential() {
        return singlePresentationCredential;
    }

    public void setSinglePresentationCredential(String singlePresentationCredential) {
        this.singlePresentationCredential = singlePresentationCredential;
    }

    public String getFlowState() {
        return flowState;
    }

    public void setFlowState(String flowState) {
        this.flowState = flowState;
    }
}
