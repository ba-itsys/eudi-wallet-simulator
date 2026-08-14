package de.arbeitsagentur.opdt.walletsim.trustlist;

import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
public record TrustedEntityInformation(String trustedEntityName) {}
