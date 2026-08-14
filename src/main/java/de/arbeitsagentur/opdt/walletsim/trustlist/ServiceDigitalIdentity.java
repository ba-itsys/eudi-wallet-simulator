package de.arbeitsagentur.opdt.walletsim.trustlist;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
public record ServiceDigitalIdentity(List<CertificateValue> x509Certificates) {}
