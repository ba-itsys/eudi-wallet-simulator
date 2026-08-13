package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;

// A wallet credential as shown on the home page, with its current status list value.
public record CredentialCard(StoredCredential credential, int status) {}
