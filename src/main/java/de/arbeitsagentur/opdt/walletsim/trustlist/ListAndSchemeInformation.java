package de.arbeitsagentur.opdt.walletsim.trustlist;

import java.util.List;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.annotation.JsonNaming;

@JsonNaming(PropertyNamingStrategies.UpperCamelCaseStrategy.class)
public record ListAndSchemeInformation(
        int loTEVersionIdentifier,
        int loTESequenceNumber,
        String loTEType,
        String schemeOperatorName,
        String listIssueDateTime,
        String nextUpdate,
        String statusDeterminationApproach,
        List<String> schemeTypeCommunityRules) {}
