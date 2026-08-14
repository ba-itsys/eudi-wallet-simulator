package de.arbeitsagentur.opdt.walletsim;

import static org.assertj.core.api.Assertions.assertThat;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDJWT;
import com.nimbusds.jwt.SignedJWT;
import de.arbeitsagentur.opdt.walletsim.oid4vp.TestVerifier;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.List;
import org.springframework.web.client.RestClient;

// The three things every wallet test needs: a client, the wallet link of a verifier, and the flow
// state the picker carries in a hidden field.
public final class WalletTestSupport {

    private WalletTestSupport() {}

    // error responses reach the test as a status and a body instead of an exception
    public static RestClient client(int port) {
        return RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(status -> true, (request, response) -> {})
                .build();
    }

    public static URI authorizeUri(int port, TestVerifier verifier) {
        return authorizeUri(port, verifier, verifier.clientId());
    }

    // the client_id of the wallet link can differ from the one in the request object
    public static URI authorizeUri(int port, TestVerifier verifier, String clientId) {
        return URI.create("http://localhost:" + port + "/authorize?client_id="
                + URLEncoder.encode(clientId, StandardCharsets.UTF_8)
                + "&request_uri="
                + URLEncoder.encode(verifier.requestUri(), StandardCharsets.UTF_8));
    }

    // the issuer signed JWT of an SD-JWT, with the disclosures and any key binding JWT stripped
    public static SignedJWT issuerJwt(String sdJwt) throws ParseException {
        return SignedJWT.parse(SDJWT.parse(sdJwt).getCredentialJwt());
    }

    // the disclosures an SD-JWT releases, which for a presentation are the ones the verifier sees
    public static List<Disclosure> disclosures(String sdJwt) {
        return SDJWT.parse(sdJwt).getDisclosures();
    }

    // the key binding JWT a presentation ends with
    public static SignedJWT keyBindingJwt(String presentation) throws ParseException {
        return SignedJWT.parse(SDJWT.parse(presentation).getBindingJwt());
    }

    public static String hiddenField(String html, String name) {
        String marker = "name=\"" + name + "\" value=\"";
        int start = html.indexOf(marker);
        assertThat(start).as("hidden field '%s' present", name).isNotNegative();
        start += marker.length();
        return html.substring(start, html.indexOf('"', start));
    }
}
