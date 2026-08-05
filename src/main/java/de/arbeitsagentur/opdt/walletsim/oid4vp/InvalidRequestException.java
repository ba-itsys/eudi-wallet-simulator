package de.arbeitsagentur.opdt.walletsim.oid4vp;

// A verifier request that cannot be processed at all (hard syntax failure).
public class InvalidRequestException extends RuntimeException {

    public InvalidRequestException(String message) {
        super(message);
    }

    public InvalidRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}
