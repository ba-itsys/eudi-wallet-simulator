package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Submits the authorization response to the verifier's response_uri via direct_post and extracts
 * the same-device redirect_uri if the verifier returns one.
 */
@Component
public class ResponseSubmitter {

    public record SubmissionResult(Optional<String> redirectUri) {}

    private final RestClient restClient = RestClient.create();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ResponseEncryptor responseEncryptor;

    public ResponseSubmitter(ResponseEncryptor responseEncryptor) {
        this.responseEncryptor = responseEncryptor;
    }

    // presentationsByQueryId keeps the DCQL credential query id to presentation association
    public SubmissionResult submitVpToken(AuthorizationRequest request, Map<String, String> presentationsByQueryId) {
        Map<String, List<String>> vpTokenEntries = new LinkedHashMap<>();
        presentationsByQueryId.forEach((queryId, presentation) -> vpTokenEntries.put(queryId, List.of(presentation)));
        Map<String, Object> parameters = new LinkedHashMap<>();
        if (request.state() != null) {
            parameters.put("state", request.state());
        }
        parameters.put("vp_token", vpTokenEntries);
        return submit(request, parameters);
    }

    // OID4VP 1.0 §8.5: error responses go to the response_uri like any other authorization response
    public SubmissionResult submitError(AuthorizationRequest request, String error, String errorDescription) {
        Map<String, Object> parameters = new LinkedHashMap<>();
        if (request.state() != null) {
            parameters.put("state", request.state());
        }
        parameters.put("error", error);
        parameters.put("error_description", errorDescription);
        return submit(request, parameters);
    }

    private SubmissionResult submit(AuthorizationRequest request, Map<String, Object> parameters) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        if ("direct_post.jwt".equals(request.responseMode())) {
            // OID4VP 1.0 §8.3.1 allows only the response parameter, a fallback to unencrypted
            // parameters would leak the presentation and be unparseable for the verifier
            form.add("response", responseEncryptor.encrypt(request, parameters));
        } else {
            parameters.forEach((name, value) ->
                    form.add(name, value instanceof String text ? text : objectMapper.writeValueAsString(value)));
        }
        return submit(request.responseUri(), form);
    }

    private SubmissionResult submit(String responseUri, MultiValueMap<String, String> form) {
        try {
            String body = restClient
                    .post()
                    .uri(responseUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(String.class);
            return new SubmissionResult(extractRedirectUri(body));
        } catch (Exception e) {
            throw new InvalidRequestException("Failed to post authorization response to " + responseUri, e);
        }
    }

    private Optional<String> extractRedirectUri(String body) {
        if (body == null || body.isBlank()) {
            return Optional.empty();
        }
        JsonNode json = objectMapper.readValue(body, JsonNode.class);
        return json.hasNonNull("redirect_uri")
                ? Optional.of(json.get("redirect_uri").asText())
                : Optional.empty();
    }
}
