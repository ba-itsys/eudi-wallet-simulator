package de.arbeitsagentur.opdt.walletsim.oid4vp;

/**
 * A presentation that cannot be completed. The detail carries what the other side said, for
 * example the verifier's rejection reason, so the error page can show it instead of a bare
 * "request failed".
 */
public class InvalidRequestException extends RuntimeException {

    private final String detail;

    public InvalidRequestException(String message) {
        this(message, (String) null);
    }

    public InvalidRequestException(String message, String detail) {
        super(message);
        this.detail = detail;
    }

    public InvalidRequestException(String message, Throwable cause) {
        super(message, cause);
        this.detail = cause == null ? null : cause.getMessage();
    }

    public String detail() {
        return detail;
    }
}
