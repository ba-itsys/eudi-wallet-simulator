package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.oid4vp.AuthorizationRequest;
import de.arbeitsagentur.opdt.walletsim.oid4vp.DcqlMatcher;
import de.arbeitsagentur.opdt.walletsim.oid4vp.DcqlMatcher.CredentialMatch;
import de.arbeitsagentur.opdt.walletsim.oid4vp.DcqlQuery;
import de.arbeitsagentur.opdt.walletsim.oid4vp.InvalidRequestException;
import de.arbeitsagentur.opdt.walletsim.oid4vp.RequestObjectClient;
import de.arbeitsagentur.opdt.walletsim.oid4vp.ResponseSubmitter;
import de.arbeitsagentur.opdt.walletsim.oid4vp.ResponseSubmitter.SubmissionResult;
import de.arbeitsagentur.opdt.walletsim.oid4vp.SdJwtPresentationBuilder;
import java.util.List;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The wallet's web entry point for OID4VP: a verifier link opens the credential picker, the
 * user's selection is answered with a direct_post and the browser follows the verifier's
 * redirect_uri (same-device) or sees a completion page (cross-device).
 */
@Controller
public class AuthorizeController {

    private final RequestObjectClient requestObjectClient;
    private final DcqlMatcher dcqlMatcher;
    private final SdJwtPresentationBuilder presentationBuilder;
    private final ResponseSubmitter responseSubmitter;

    public AuthorizeController(
            RequestObjectClient requestObjectClient,
            DcqlMatcher dcqlMatcher,
            SdJwtPresentationBuilder presentationBuilder,
            ResponseSubmitter responseSubmitter) {
        this.requestObjectClient = requestObjectClient;
        this.dcqlMatcher = dcqlMatcher;
        this.presentationBuilder = presentationBuilder;
        this.responseSubmitter = responseSubmitter;
    }

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId, @RequestParam("request_uri") String requestUri, Model model) {
        String requestObjectJwt = requestObjectClient.fetch(requestUri);
        AuthorizationRequest request = AuthorizationRequest.parse(requestObjectJwt);
        List<CredentialMatch> matches = dcqlMatcher.match(DcqlQuery.from(request.dcqlQuery()));

        model.addAttribute("verifierClientId", request.clientId() != null ? request.clientId() : clientId);
        model.addAttribute("matches", matches);
        model.addAttribute("flowState", requestObjectJwt);
        return "presentation_select";
    }

    @PostMapping("/authorize/submit")
    public String submit(
            @RequestParam("credentialId") String credentialId,
            @RequestParam("flowState") String flowState,
            Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        CredentialMatch match = dcqlMatcher.match(DcqlQuery.from(request.dcqlQuery())).stream()
                .filter(candidate -> candidate.credential().id().equals(credentialId))
                .findFirst()
                .orElseThrow(() -> new InvalidRequestException(
                        "Selected credential does not match the verifier's query: " + credentialId));

        String presentation = presentationBuilder.build(
                match.credential(), match.claimsToDisclose(), request.clientId(), request.nonce());
        SubmissionResult result = responseSubmitter.submitVpToken(request, match.credentialQueryId(), presentation);
        return complete(result, model);
    }

    @PostMapping("/authorize/cancel")
    public String cancel(@RequestParam("flowState") String flowState, Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        SubmissionResult result =
                responseSubmitter.submitError(request, "access_denied", "The user cancelled the presentation");
        return complete(result, model);
    }

    private String complete(SubmissionResult result, Model model) {
        if (result.redirectUri().isPresent()) {
            return "redirect:" + result.redirectUri().get();
        }
        model.addAttribute("crossDevice", true);
        return "presentation_complete";
    }

    @ExceptionHandler(InvalidRequestException.class)
    public String invalidRequest(InvalidRequestException exception, Model model) {
        model.addAttribute("errorMessage", exception.getMessage());
        return "error_view";
    }
}
