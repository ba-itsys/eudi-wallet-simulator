package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Builds an SD-JWT VP: the issuer JWT with only the disclosures needed for the requested claim
 * paths, completed by a KB-JWT signed with the credential's own holder binding key. A disclosure
 * is released when its position is an ancestor or a descendant of a requested path, so nested
 * claims like address.locality disclose the address container and the locality but not the
 * sibling street_address.
 */
@Component
public class SdJwtPresentationBuilder {

    public String build(
            StoredCredential credential, List<List<Object>> claimPathsToDisclose, String audience, String nonce) {
        try {
            String[] parts = credential.sdJwt().split("~");
            SignedJWT issuerJwt = SignedJWT.parse(parts[0]);

            Map<String, Disclosure> byDigest = new HashMap<>();
            List<Disclosure> allDisclosures = new ArrayList<>();
            for (int i = 1; i < parts.length; i++) {
                Disclosure disclosure = Disclosure.parse(parts[i]);
                allDisclosures.add(disclosure);
                byDigest.put(disclosure.digest(), disclosure);
            }
            Map<Disclosure, List<Object>> positions = new LinkedHashMap<>();
            collectPositions(issuerJwt.getJWTClaimsSet().getClaims(), List.of(), byDigest, positions);

            StringBuilder presentation = new StringBuilder(parts[0]);
            for (Disclosure disclosure : allDisclosures) {
                List<Object> position = positions.get(disclosure);
                if (position != null && isNeeded(position, claimPathsToDisclose)) {
                    presentation.append('~').append(disclosure.getDisclosure());
                }
            }
            presentation.append('~');

            String sdHash = Base64URL.encode(MessageDigest.getInstance("SHA-256")
                            .digest(presentation.toString().getBytes(StandardCharsets.US_ASCII)))
                    .toString();
            JWTClaimsSet kbClaims = new JWTClaimsSet.Builder()
                    .audience(audience)
                    .issueTime(Date.from(Instant.now()))
                    .claim("nonce", nonce)
                    .claim("sd_hash", sdHash)
                    .build();
            SignedJWT kbJwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.ES256)
                            .type(new JOSEObjectType("kb+jwt"))
                            .build(),
                    kbClaims);
            kbJwt.sign(new ECDSASigner(credential.holderKey()));

            return presentation.append(kbJwt.serialize()).toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SD-JWT presentation for " + credential.id(), e);
        }
    }

    // walks the encoded structure to find each disclosure's claim path, following digests through
    // nested disclosure values
    @SuppressWarnings("unchecked")
    private static void collectPositions(
            Object node, List<Object> path, Map<String, Disclosure> byDigest, Map<Disclosure, List<Object>> positions) {
        if (node instanceof Map<?, ?> map) {
            if (map.get("_sd") instanceof List<?> digests) {
                for (Object digest : digests) {
                    Disclosure disclosure = byDigest.get(String.valueOf(digest));
                    if (disclosure != null) {
                        List<Object> position = childPath(path, disclosure.getClaimName());
                        positions.put(disclosure, position);
                        collectPositions(disclosure.getClaimValue(), position, byDigest, positions);
                    }
                }
            }
            for (Map.Entry<String, Object> entry : ((Map<String, Object>) map).entrySet()) {
                if (!"_sd".equals(entry.getKey()) && !"_sd_alg".equals(entry.getKey())) {
                    collectPositions(entry.getValue(), childPath(path, entry.getKey()), byDigest, positions);
                }
            }
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                Object element = list.get(i);
                if (element instanceof Map<?, ?> arrayElement && arrayElement.get("...") != null) {
                    Disclosure disclosure = byDigest.get(String.valueOf(arrayElement.get("...")));
                    if (disclosure != null) {
                        List<Object> position = childPath(path, i);
                        positions.put(disclosure, position);
                        collectPositions(disclosure.getClaimValue(), position, byDigest, positions);
                    }
                } else {
                    collectPositions(element, childPath(path, i), byDigest, positions);
                }
            }
        }
    }

    private static List<Object> childPath(List<Object> path, Object step) {
        List<Object> child = new ArrayList<>(path);
        child.add(step);
        return child;
    }

    private static boolean isNeeded(List<Object> position, List<List<Object>> requestedPaths) {
        return requestedPaths.stream().anyMatch(requested -> isRelated(position, requested));
    }

    // ancestor-or-descendant relation between a disclosure position and a requested claim path
    private static boolean isRelated(List<Object> position, List<Object> requested) {
        int comparable = Math.min(position.size(), requested.size());
        for (int i = 0; i < comparable; i++) {
            if (!stepMatches(requested.get(i), position.get(i))) {
                return false;
            }
        }
        return true;
    }

    // DCQL path steps are strings, non-negative integers, or null for all array elements
    private static boolean stepMatches(Object requestedStep, Object positionStep) {
        if (requestedStep == null) {
            return positionStep instanceof Integer;
        }
        if (requestedStep instanceof Number number && positionStep instanceof Integer index) {
            return number.intValue() == index;
        }
        return String.valueOf(requestedStep).equals(String.valueOf(positionStep));
    }
}
