package de.arbeitsagentur.opdt.walletsim.oid4vp;

/**
 * How the request object was retrieved: the signed JWT itself plus what the wallet sent and got
 * back, so the conformance validator can check the wallet_nonce echo and the encryption answer.
 */
public record RequestObjectRetrieval(
        String requestObjectJwt,
        String requestUriMethod,
        String sentWalletNonce,
        boolean encryptionRequested,
        boolean encrypted) {

    public static RequestObjectRetrieval viaGet(String requestObjectJwt, String requestUriMethod) {
        return new RequestObjectRetrieval(requestObjectJwt, requestUriMethod, null, false, false);
    }

    // OID4VP 1.0 §5.1 defines only get and post, anything else was answered with the GET fallback
    public boolean unknownMethod() {
        return requestUriMethod != null && !"get".equals(requestUriMethod) && !"post".equals(requestUriMethod);
    }
}
