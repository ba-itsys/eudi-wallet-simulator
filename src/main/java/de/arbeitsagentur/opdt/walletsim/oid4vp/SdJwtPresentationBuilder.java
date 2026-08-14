package de.arbeitsagentur.opdt.walletsim.oid4vp;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
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
 *
 * <p>Serialization, disclosure parsing and the sd_hash over the presented part come from the
 * SD-JWT library. Which disclosure sits at which claim path does not, so the wallet walks the
 * encoded payload for that.
 */
@Component
public class SdJwtPresentationBuilder {

    private static final JOSEObjectType KEY_BINDING_JWT_TYPE = new JOSEObjectType("kb+jwt");
    private static final String DIGEST_ARRAY = "_sd";
    private static final String HASH_ALGORITHM = "_sd_alg";
    private static final String ARRAY_ELEMENT_DIGEST = "...";

    public String build(
            StoredCredential credential, List<List<Object>> claimPathsToDisclose, String audience, String nonce) {
        try {
            SDJWT issued = SDJWT.parse(credential.sdJwt());
            List<Disclosure> disclosed = disclosuresFor(issued, claimPathsToDisclose);

            // the sd_hash covers the credential JWT and the released disclosures only (RFC 9901 §4.3.1)
            String sdHash = new SDJWT(issued.getCredentialJwt(), disclosed).getSDHash();
            String keyBindingJwt = keyBindingJwt(sdHash, audience, nonce, credential.holderKey());

            return new SDJWT(issued.getCredentialJwt(), disclosed, keyBindingJwt).toString();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to build SD-JWT presentation for " + credential.id(), e);
        }
    }

    private static List<Disclosure> disclosuresFor(SDJWT issued, List<List<Object>> requestedPaths) throws Exception {
        Map<String, Disclosure> byDigest = new HashMap<>();
        issued.getDisclosures().forEach(disclosure -> byDigest.put(disclosure.digest(), disclosure));

        Map<Disclosure, List<Object>> positions = new LinkedHashMap<>();
        Map<String, Object> payload =
                SignedJWT.parse(issued.getCredentialJwt()).getJWTClaimsSet().getClaims();
        collectPositions(payload, List.of(), byDigest, positions);

        return issued.getDisclosures().stream()
                .filter(disclosure -> isNeeded(positions.get(disclosure), requestedPaths))
                .toList();
    }

    private static String keyBindingJwt(String sdHash, String audience, String nonce, ECKey holderKey)
            throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .audience(audience)
                .issueTime(Date.from(Instant.now()))
                .claim("nonce", nonce)
                .claim("sd_hash", sdHash)
                .build();
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.ES256)
                        .type(KEY_BINDING_JWT_TYPE)
                        .build(),
                claims);
        jwt.sign(new ECDSASigner(holderKey));
        return jwt.serialize();
    }

    // walks the encoded structure to find each disclosure's claim path, following digests through
    // nested disclosure values
    @SuppressWarnings("unchecked")
    private static void collectPositions(
            Object node, List<Object> path, Map<String, Disclosure> byDigest, Map<Disclosure, List<Object>> positions) {
        if (node instanceof Map<?, ?> map) {
            if (map.get(DIGEST_ARRAY) instanceof List<?> digests) {
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
                if (!DIGEST_ARRAY.equals(entry.getKey()) && !HASH_ALGORITHM.equals(entry.getKey())) {
                    collectPositions(entry.getValue(), childPath(path, entry.getKey()), byDigest, positions);
                }
            }
        } else if (node instanceof List<?> list) {
            for (int i = 0; i < list.size(); i++) {
                Object element = list.get(i);
                if (element instanceof Map<?, ?> arrayElement && arrayElement.get(ARRAY_ELEMENT_DIGEST) != null) {
                    Disclosure disclosure = byDigest.get(String.valueOf(arrayElement.get(ARRAY_ELEMENT_DIGEST)));
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
        return position != null && requestedPaths.stream().anyMatch(requested -> isRelated(position, requested));
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
