package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.stream.Stream;

// A wallet credential as shown on the home page, with its current status list value.
public record CredentialCard(StoredCredential credential, int status) {

    /**
     * The person behind the credential, empty when it carries no name claims. Credentials created
     * in the UI can have any claims, so the card must not render a name that is not there.
     */
    public String person() {
        return Stream.of("given_name", "family_name")
                .map(claim -> credential.claims().get(claim))
                .filter(value -> value instanceof String text && !text.isBlank())
                .map(String::valueOf)
                .reduce((given, family) -> given + " " + family)
                .orElse("");
    }
}
