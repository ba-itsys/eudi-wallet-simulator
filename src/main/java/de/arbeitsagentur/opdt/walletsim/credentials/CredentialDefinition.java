package de.arbeitsagentur.opdt.walletsim.credentials;

import java.util.List;
import java.util.Map;

/**
 * A credential as defined in the YAML seed file or created ad hoc in the UI. Claims are
 * selectively disclosable unless their dot notation path is listed in alwaysDisclosedClaims, in
 * which case they are always visible to the verifier. With untrustedIssuer set, the credential is
 * signed by the ad hoc untrusted issuer instead of the simulator issuer, so verifiers reject its
 * signature chain.
 */
public record CredentialDefinition(
        String id,
        String name,
        String vct,
        int validityDays,
        Map<String, Object> claims,
        List<String> alwaysDisclosedClaims,
        boolean untrustedIssuer) {

    public static final String FORMAT_SD_JWT_VC = "dc+sd-jwt";

    public String format() {
        return FORMAT_SD_JWT_VC;
    }
}
