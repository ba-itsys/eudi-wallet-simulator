package de.arbeitsagentur.opdt.walletsim.oid4vp;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Retrieves the verifier's request object from its request_uri. */
@Component
public class RequestObjectClient {

    private final RestClient restClient = RestClient.create();

    public String fetch(String requestUri) {
        try {
            return restClient
                    .get()
                    .uri(requestUri)
                    .header("Accept", "application/oauth-authz-req+jwt")
                    .retrieve()
                    .body(String.class);
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to fetch request object from " + requestUri, e);
        }
    }
}
