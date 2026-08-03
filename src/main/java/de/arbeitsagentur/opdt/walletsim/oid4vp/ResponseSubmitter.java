package de.arbeitsagentur.opdt.walletsim.oid4vp;

import java.util.List;
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

    public SubmissionResult submitVpToken(AuthorizationRequest request, String credentialQueryId, String presentation) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        if (request.state() != null) {
            form.add("state", request.state());
        }
        form.add(
                "vp_token",
                objectMapper.writeValueAsString(java.util.Map.of(credentialQueryId, List.of(presentation))));
        return submit(request.responseUri(), form);
    }

    public SubmissionResult submitError(AuthorizationRequest request, String error, String errorDescription) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        if (request.state() != null) {
            form.add("state", request.state());
        }
        form.add("error", error);
        form.add("error_description", errorDescription);
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
