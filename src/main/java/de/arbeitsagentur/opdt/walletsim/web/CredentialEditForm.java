package de.arbeitsagentur.opdt.walletsim.web;

/** Form backing bean for creating or cloning a credential in the UI. */
public class CredentialEditForm {

    private String id;
    private String name;
    private String vct;
    private int validityDays = 365;
    private String claimsJson;
    private String flowState;

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

    public String getClaimsJson() {
        return claimsJson;
    }

    public void setClaimsJson(String claimsJson) {
        this.claimsJson = claimsJson;
    }

    public String getFlowState() {
        return flowState;
    }

    public void setFlowState(String flowState) {
        this.flowState = flowState;
    }
}
