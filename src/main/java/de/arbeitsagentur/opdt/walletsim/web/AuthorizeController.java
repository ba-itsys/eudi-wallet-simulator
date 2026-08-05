package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.conformance.ConformanceSettings;
import de.arbeitsagentur.opdt.walletsim.conformance.Finding;
import de.arbeitsagentur.opdt.walletsim.conformance.RequestObjectValidator;
import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import de.arbeitsagentur.opdt.walletsim.credentials.WalletCredentialService;
import de.arbeitsagentur.opdt.walletsim.logging.ActivityLog;
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
import java.util.Map;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The wallet's web entry point for OID4VP: a verifier link opens the credential picker, the
 * user's selection is answered with a direct_post and the browser follows the verifier's
 * redirect_uri (same-device) or sees a completion page (cross-device). Conformance findings warn
 * in debug mode and refuse the request in strict mode.
 */
@Controller
public class AuthorizeController {

    private final RequestObjectClient requestObjectClient;
    private final RequestObjectValidator validator;
    private final ConformanceSettings conformanceSettings;
    private final DcqlMatcher dcqlMatcher;
    private final SdJwtPresentationBuilder presentationBuilder;
    private final ResponseSubmitter responseSubmitter;
    private final ActivityLog activityLog;
    private final CredentialEditForms editForms;
    private final WalletCredentialService credentialService;

    public AuthorizeController(
            RequestObjectClient requestObjectClient,
            RequestObjectValidator validator,
            ConformanceSettings conformanceSettings,
            DcqlMatcher dcqlMatcher,
            SdJwtPresentationBuilder presentationBuilder,
            ResponseSubmitter responseSubmitter,
            ActivityLog activityLog,
            CredentialEditForms editForms,
            WalletCredentialService credentialService) {
        this.requestObjectClient = requestObjectClient;
        this.validator = validator;
        this.conformanceSettings = conformanceSettings;
        this.dcqlMatcher = dcqlMatcher;
        this.presentationBuilder = presentationBuilder;
        this.responseSubmitter = responseSubmitter;
        this.activityLog = activityLog;
        this.editForms = editForms;
        this.credentialService = credentialService;
    }

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId, @RequestParam("request_uri") String requestUri, Model model) {
        String requestObjectJwt = requestObjectClient.fetch(requestUri);
        AuthorizationRequest request = AuthorizationRequest.parse(requestObjectJwt);
        activityLog.success(
                "presentation",
                "Received authorization request from " + request.clientId(),
                Map.of("request_uri", requestUri, "request_object", requestObjectJwt));

        List<Finding> findings = validator.validate(clientId, request);
        findings.forEach(finding -> activityLog.warning(
                "presentation", "Request does not conform to OID4VP: " + finding.message(), Map.of()));
        if (conformanceSettings.mode() == ValidationMode.STRICT && !findings.isEmpty()) {
            activityLog.error(
                    "presentation",
                    "Refused non-conformant request in strict mode from " + request.clientId(),
                    Map.of());
            model.addAttribute("errorMessage", "The verifier request violates OID4VP conformance (strict mode).");
            model.addAttribute("findings", findings);
            return "error_view";
        }

        model.addAttribute("verifierClientId", request.clientId() != null ? request.clientId() : clientId);
        model.addAttribute("findings", findings);
        model.addAttribute("matches", matchCredentials(request));
        model.addAttribute("flowState", requestObjectJwt);
        return "presentation_select";
    }

    @PostMapping("/authorize/submit")
    public String submit(
            @RequestParam("credentialId") String credentialId,
            @RequestParam("flowState") String flowState,
            Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        CredentialMatch match = matchCredentials(request).stream()
                .filter(candidate -> candidate.credential().id().equals(credentialId))
                .findFirst()
                .orElseThrow(() -> new InvalidRequestException(
                        "Selected credential does not match the verifier's query: " + credentialId));

        String presentation = presentationBuilder.build(
                match.credential(), match.claimsToDisclose(), request.clientId(), request.nonce());
        SubmissionResult result = responseSubmitter.submitVpToken(request, match.credentialQueryId(), presentation);
        activityLog.success(
                "presentation",
                "Presented credential " + credentialId + " to " + request.clientId(),
                Map.of("disclosed_claims", match.claimsToDisclose()));
        return complete(result, model);
    }

    @PostMapping("/authorize/edit")
    public String editDuringFlow(
            @RequestParam("credentialId") String credentialId,
            @RequestParam("flowState") String flowState,
            Model model) {
        CredentialEditForm form = editForms.cloneForm(credentialId);
        form.setFlowState(flowState);
        return editView(form, model);
    }

    @PostMapping("/authorize/edit/save")
    public String saveAndPresent(@ModelAttribute("form") CredentialEditForm form, Model model) {
        String error = editForms.validationError(form);
        if (error != null) {
            model.addAttribute("formError", error);
            return editView(form, model);
        }
        AuthorizationRequest request = AuthorizationRequest.parse(form.getFlowState());
        StoredCredential credential =
                credentialService.issue(editForms.toDefinition(form), StoredCredential.Source.AD_HOC);
        CredentialMatch match = matchCredentials(request).stream()
                .filter(candidate -> candidate.credential().id().equals(credential.id()))
                .findFirst()
                .orElse(null);
        if (match == null) {
            model.addAttribute(
                    "formError",
                    "The credential was issued but does not match the verifier's query; adjust the claims or vct.");
            return editView(form, model);
        }
        String presentation = presentationBuilder.build(
                match.credential(), match.claimsToDisclose(), request.clientId(), request.nonce());
        SubmissionResult result = responseSubmitter.submitVpToken(request, match.credentialQueryId(), presentation);
        activityLog.success(
                "presentation",
                "Presented ad-hoc credential " + credential.id() + " to " + request.clientId(),
                Map.of("disclosed_claims", match.claimsToDisclose()));
        return complete(result, model);
    }

    private String editView(CredentialEditForm form, Model model) {
        model.addAttribute("form", form);
        model.addAttribute("formAction", "/authorize/edit/save");
        return "credential_edit";
    }

    @PostMapping("/authorize/cancel")
    public String cancel(@RequestParam("flowState") String flowState, Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        SubmissionResult result =
                responseSubmitter.submitError(request, "access_denied", "The user cancelled the presentation");
        activityLog.success("presentation", "Cancelled presentation for " + request.clientId(), Map.of());
        return complete(result, model);
    }

    private List<CredentialMatch> matchCredentials(AuthorizationRequest request) {
        try {
            return dcqlMatcher.match(DcqlQuery.from(request.dcqlQuery()));
        } catch (InvalidRequestException e) {
            return List.of();
        }
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
        activityLog.error("presentation", exception.getMessage(), Map.of());
        model.addAttribute("errorMessage", exception.getMessage());
        return "error_view";
    }
}
