package de.arbeitsagentur.opdt.walletsim.api;

// The status list slot of a credential and its current value.
public record StatusReference(String uri, int idx, int status, String statusName) {

    public static StatusReference of(String statusListUri, int idx, int status) {
        return new StatusReference(statusListUri, idx, status, status == 0 ? "VALID" : "INVALID");
    }
}
