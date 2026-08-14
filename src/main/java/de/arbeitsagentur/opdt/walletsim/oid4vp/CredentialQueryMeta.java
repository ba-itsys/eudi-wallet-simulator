package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

// Format specific metadata of a credential query. For dc+sd-jwt that is the accepted vct values.
@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record CredentialQueryMeta(List<String> vctValues) {

    public CredentialQueryMeta {
        vctValues = vctValues == null ? List.of() : vctValues;
    }
}
