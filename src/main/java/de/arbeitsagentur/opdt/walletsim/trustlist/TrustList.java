package de.arbeitsagentur.opdt.walletsim.trustlist;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

/**
 * An ETSI TS 119 602 trust list in its JSON form. The member names are upper camel case, so one
 * naming strategy per record replaces an annotation on every component.
 */
@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
public record TrustList(ListAndSchemeInformation listAndSchemeInformation, List<TrustedEntity> trustedEntitiesList) {

    // The base64 DER certificates of every service in the list.
    public List<String> certificateValues() {
        return trustedEntitiesList.stream()
                .flatMap(entity -> entity.trustedEntityServices().stream())
                .map(TrustedEntityService::serviceInformation)
                .map(ServiceInformation::serviceDigitalIdentity)
                .flatMap(identity -> identity.x509Certificates().stream())
                .map(CertificateValue::val)
                .distinct()
                .toList();
    }
}
