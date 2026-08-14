package de.arbeitsagentur.opdt.walletsim.oid4vp;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * The DCQL query subset the simulator evaluates (OID4VP 1.0 §6). The member names are snake case,
 * so one naming strategy per record replaces an annotation on every component. Unknown members of
 * a query are ignored here and reported by the conformance validator instead.
 */
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record DcqlQuery(List<CredentialQuery> credentials, List<CredentialSetQuery> credentialSets) {

    public DcqlQuery {
        credentials = credentials == null ? List.of() : credentials;
        credentialSets = credentialSets == null ? List.of() : credentialSets;
    }

    // true when every requested credential query asks for a format this wallet cannot present
    public boolean requestsOnlyUnsupportedFormats() {
        return !credentials.isEmpty()
                && credentials.stream()
                        .noneMatch(query -> CredentialDefinition.FORMAT_SD_JWT_VC.equals(query.format()));
    }
}
