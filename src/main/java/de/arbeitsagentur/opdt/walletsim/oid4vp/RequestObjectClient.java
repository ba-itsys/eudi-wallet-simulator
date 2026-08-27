package de.arbeitsagentur.opdt.walletsim.oid4vp;

import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

// Retrieves the verifier's request object from its request_uri.
@Component
public class RequestObjectClient {

    private static final String REQUEST_OBJECT_MEDIA_TYPE = "application/oauth-authz-req+jwt";

    private final RestClient restClient;

    public RequestObjectClient(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    public String fetch(String requestUri) {
        try {
            return restClient
                    .get()
                    .uri(requestUri)
                    .header("Accept", REQUEST_OBJECT_MEDIA_TYPE)
                    .retrieve()
                    .body(String.class);
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to fetch request object from " + requestUri, e);
        }
    }

    // request_uri_method=post fetch: form-encoded wallet_nonce and wallet_metadata (OID4VP 1.0 §5.10)
    public String post(String requestUri, String walletNonce, String walletMetadataJson) {
        try {
            MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
            form.add("wallet_nonce", walletNonce);
            form.add("wallet_metadata", walletMetadataJson);
            return restClient
                    .post()
                    .uri(requestUri)
                    .header("Accept", REQUEST_OBJECT_MEDIA_TYPE)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to fetch request object from " + requestUri, e);
        }
    }
}
