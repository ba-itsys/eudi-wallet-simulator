package de.arbeitsagentur.opdt.walletsim.trustlist;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
public record TrustedEntity(
        TrustedEntityInformation trustedEntityInformation, List<TrustedEntityService> trustedEntityServices) {}
