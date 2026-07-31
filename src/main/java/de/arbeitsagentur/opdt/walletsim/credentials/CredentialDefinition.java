package de.arbeitsagentur.opdt.walletsim.credentials;

import java.util.Map;

/** A credential as defined in the YAML seed file or created ad hoc in the UI. */
public record CredentialDefinition(String id, String name, String vct, int validityDays, Map<String, Object> claims) {

    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";

    public String format() {
        return FORMAT_SD_JWT_VC;
    }
}
