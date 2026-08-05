package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.util.Map;

// Parsed OID4VP authorization request as carried in a signed request object.
public record AuthorizationRequest(
        String rawRequestObject,
        String clientId,
        String responseType,
        String responseMode,
        String responseUri,
        String nonce,
        String state,
        Map<String, Object> dcqlQuery,
        Map<String, Object> clientMetadata) {

    public static AuthorizationRequest parse(String requestObjectJwt) {
        try {
            SignedJWT jwt = SignedJWT.parse(requestObjectJwt);
            Map<String, Object> claims = jwt.getJWTClaimsSet().getClaims();
            return new AuthorizationRequest(
                    requestObjectJwt,
                    stringClaim(claims, "client_id"),
                    stringClaim(claims, "response_type"),
                    stringClaim(claims, "response_mode"),
                    stringClaim(claims, "response_uri"),
                    stringClaim(claims, "nonce"),
                    stringClaim(claims, "state"),
                    mapClaim(claims, "dcql_query"),
                    mapClaim(claims, "client_metadata"));
        } catch (ParseException e) {
            throw new InvalidRequestException("Request object is not a valid signed JWT", e);
        }
    }

    private static String stringClaim(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof String value ? value : null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> mapClaim(Map<String, Object> claims, String name) {
        return claims.get(name) instanceof Map<?, ?> value ? (Map<String, Object>) value : null;
    }
}
