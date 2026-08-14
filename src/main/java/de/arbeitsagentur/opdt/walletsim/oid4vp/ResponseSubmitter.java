package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

/**
 * Submits the authorization response to the verifier's response_uri via direct_post and extracts
 * the same-device redirect_uri if the verifier returns one.
 */
@Component
public class ResponseSubmitter {

    private final RestClient restClient = RestClient.create();
    private final ObjectMapper objectMapper;
    private final ResponseEncryptor responseEncryptor;

    public ResponseSubmitter(ObjectMapper objectMapper, ResponseEncryptor responseEncryptor) {
        this.objectMapper = objectMapper;
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
        ResponseEntity<String> response;
        try {
            response = restClient
                    .post()
                    .uri(responseUri)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    // the verifier's own answer is the interesting part of a failure, so it is read
                    // instead of being turned into an exception without a body
                    .exchange((request, clientResponse) -> ResponseEntity.status(clientResponse.getStatusCode())
                            .body(clientResponse.bodyTo(String.class)));
        } catch (Exception e) {
            throw new InvalidRequestException("Could not reach the verifier at " + responseUri, e);
        }
        if (response.getStatusCode().isError()) {
            throw new InvalidRequestException(
                    "The verifier rejected the presentation with HTTP "
                            + response.getStatusCode().value() + ".",
                    rejectionReason(response.getBody()));
        }
        return new SubmissionResult(redirectUri(response.getBody()));
    }

    /**
     * What the verifier said about the rejection. OAuth style errors carry error and
     * error_description, anything else is shown as it arrived.
     */
    private String rejectionReason(String body) {
        if (!StringUtils.hasText(body)) {
            return null;
        }
        try {
            JsonNode json = objectMapper.readValue(body, JsonNode.class);
            String description = json.path("error_description").asString(null);
            String error = json.path("error").asString(null);
            if (description != null) {
                return error == null ? description : error + ": " + description;
            }
            return error != null ? error : body;
        } catch (RuntimeException e) {
            return body;
        }
    }

    // a verifier answers with a redirect_uri for same device flows and with nothing for cross device ones
    private Optional<String> redirectUri(String body) {
        if (!StringUtils.hasText(body)) {
            return Optional.empty();
        }
        try {
            JsonNode json = objectMapper.readValue(body, JsonNode.class);
            return json.hasNonNull("redirect_uri")
                    ? Optional.of(json.get("redirect_uri").asText())
                    : Optional.empty();
        } catch (RuntimeException e) {
            throw new InvalidRequestException("The verifier answered with a body that is not JSON: " + body, e);
        }
    }
}
