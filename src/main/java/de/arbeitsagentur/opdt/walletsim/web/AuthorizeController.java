package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.conformance.ConformanceSettings;
import de.arbeitsagentur.opdt.walletsim.conformance.Finding;
import de.arbeitsagentur.opdt.walletsim.conformance.RequestObjectValidator;
import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialSource;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import de.arbeitsagentur.opdt.walletsim.credentials.WalletCredentialService;
import de.arbeitsagentur.opdt.walletsim.oid4vp.AuthorizationRequest;
import de.arbeitsagentur.opdt.walletsim.oid4vp.CredentialMatch;
import de.arbeitsagentur.opdt.walletsim.oid4vp.DcqlMatcher;
import de.arbeitsagentur.opdt.walletsim.oid4vp.DcqlQuery;
import de.arbeitsagentur.opdt.walletsim.oid4vp.InvalidRequestException;
import de.arbeitsagentur.opdt.walletsim.oid4vp.PresentationPlan;
import de.arbeitsagentur.opdt.walletsim.oid4vp.QuerySlot;
import de.arbeitsagentur.opdt.walletsim.oid4vp.RequestObjectClient;
import de.arbeitsagentur.opdt.walletsim.oid4vp.ResponseSubmitter;
import de.arbeitsagentur.opdt.walletsim.oid4vp.SdJwtPresentationBuilder;
import de.arbeitsagentur.opdt.walletsim.oid4vp.SetChoice;
import de.arbeitsagentur.opdt.walletsim.oid4vp.SubmissionResult;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * The wallet's web entry point for OID4VP: a verifier link opens the credential picker with one
 * selection group per requested credential query, the user's selection is answered with a
 * direct_post and the browser follows the verifier's redirect_uri (same-device) or sees a
 * completion page (cross-device). Conformance findings warn in debug mode; in strict mode the
 * request is refused and an invalid_request error response is sent to the verifier
 * (OID4VP 1.0 §8.5).
 */
@Controller
public class AuthorizeController {

    private static final Logger LOG = LoggerFactory.getLogger(AuthorizeController.class);

    private final RequestObjectClient requestObjectClient;
    private final RequestObjectValidator validator;
    private final ConformanceSettings conformanceSettings;
    private final DcqlMatcher dcqlMatcher;
    private final SdJwtPresentationBuilder presentationBuilder;
    private final ResponseSubmitter responseSubmitter;
    private final CredentialEditForms editForms;
    private final WalletCredentialService credentialService;

    public AuthorizeController(
            RequestObjectClient requestObjectClient,
            RequestObjectValidator validator,
            ConformanceSettings conformanceSettings,
            DcqlMatcher dcqlMatcher,
            SdJwtPresentationBuilder presentationBuilder,
            ResponseSubmitter responseSubmitter,
            CredentialEditForms editForms,
            WalletCredentialService credentialService) {
        this.requestObjectClient = requestObjectClient;
        this.validator = validator;
        this.conformanceSettings = conformanceSettings;
        this.dcqlMatcher = dcqlMatcher;
        this.presentationBuilder = presentationBuilder;
        this.responseSubmitter = responseSubmitter;
        this.editForms = editForms;
        this.credentialService = credentialService;
    }

    @GetMapping("/authorize")
    public String authorize(
            @RequestParam("client_id") String clientId, @RequestParam("request_uri") String requestUri, Model model) {
        String requestObjectJwt = requestObjectClient.fetch(requestUri);
        AuthorizationRequest request = AuthorizationRequest.parse(requestObjectJwt);
        LOG.info("Received authorization request from {} via {}", request.clientId(), requestUri);

        List<Finding> findings = validator.validate(clientId, request);
        findings.forEach(finding -> LOG.warn("Request does not conform to OID4VP: {}", finding.message()));
        if (conformanceSettings.mode() == ValidationMode.STRICT && !findings.isEmpty()) {
            return refuseNonConformantRequest(request, findings, model);
        }

        model.addAttribute("findings", findings);
        return renderPicker(request, model);
    }

    @PostMapping("/authorize/submit")
    public String submit(@ModelAttribute SelectionForm form, Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(form.getFlowState());
        PresentationPlan plan = plan(request);
        Set<String> requestedQueryIds = requestedQueryIds(plan, form);
        Map<String, String> presentations = new LinkedHashMap<>();
        Map<String, String> selectedCredentials = new LinkedHashMap<>();
        for (QuerySlot slot : plan.slots()) {
            if (!requestedQueryIds.contains(slot.queryId())) {
                continue;
            }
            String selectedId = form.getSelection().get(slot.queryId());
            CredentialMatch match = slot.matches().stream()
                    .filter(candidate -> candidate.credential().id().equals(selectedId))
                    .findFirst()
                    .orElseThrow(() -> new InvalidRequestException(
                            "No matching credential selected for query '" + slot.queryId() + "'"));
            selectedCredentials.put(slot.queryId(), match.credential().id());
            int claimSetIndex = chosenClaimSetIndex(form, slot.queryId());
            presentations.put(
                    slot.queryId(),
                    presentationBuilder.build(
                            match.credential(),
                            match.claimsToDisclose(claimSetIndex),
                            request.clientId(),
                            request.nonce()));
        }
        if (presentations.isEmpty()) {
            throw new InvalidRequestException("No credential in this wallet matches the verifier's query");
        }
        SubmissionResult result = responseSubmitter.submitVpToken(request, presentations);
        LOG.info("Presented credentials {} to {}", selectedCredentials, request.clientId());
        return complete(result, model);
    }

    private static Optional<String> firstNonBlank(String... values) {
        return java.util.Arrays.stream(values)
                .filter(value -> value != null && !value.isBlank())
                .findFirst();
    }

    private static int chosenClaimSetIndex(SelectionForm form, String queryId) {
        try {
            return Integer.parseInt(form.getClaimSet().getOrDefault(queryId, "0"));
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    // the queries to answer: always requested ones plus the chosen option of every credential set
    private static Set<String> requestedQueryIds(PresentationPlan plan, SelectionForm form) {
        Set<String> requested = new LinkedHashSet<>(plan.alwaysRequestedQueryIds());
        for (SetChoice choice : plan.setChoices()) {
            String value = form.getSetOption().getOrDefault(String.valueOf(choice.index()), "0");
            if ("skip".equals(value) && !choice.required()) {
                continue;
            }
            int optionIndex;
            try {
                optionIndex = Integer.parseInt(value);
            } catch (NumberFormatException e) {
                optionIndex = 0;
            }
            if (optionIndex < 0 || optionIndex >= choice.options().size()) {
                optionIndex = 0;
            }
            requested.addAll(choice.options().get(optionIndex).queryIds());
        }
        return requested;
    }

    @PostMapping("/authorize/edit")
    public String editDuringFlow(
            @RequestParam(name = "editQueryId", required = false) String editQueryId,
            @RequestParam(name = "credentialId", required = false) String credentialId,
            @ModelAttribute SelectionForm form,
            Model model) {
        String selectedForQuery =
                editQueryId == null ? null : form.getSelection().get(editQueryId);
        String templateId = firstNonBlank(selectedForQuery, credentialId)
                .or(form::firstSelectedCredentialId)
                .orElseThrow(() -> new InvalidRequestException("No credential selected for editing"));
        CredentialEditForm editForm = editForms.cloneForm(templateId);
        editForm.setFlowState(form.getFlowState());
        return editView(editForm, model);
    }

    @PostMapping("/authorize/edit/save")
    public String saveAndPresent(
            @ModelAttribute("form") CredentialEditForm form,
            @RequestParam(name = "action", required = false) String action,
            Model model) {
        if ("add-claim".equals(action)) {
            editForms.addNewClaim(form);
            return editView(form, model);
        }
        String error = editForms.validationError(form);
        if (error != null) {
            model.addAttribute("formError", error);
            return editView(form, model);
        }
        AuthorizationRequest request = AuthorizationRequest.parse(form.getFlowState());
        StoredCredential credential = credentialService.issue(editForms.toDefinition(form), CredentialSource.AD_HOC);
        PresentationPlan plan = plan(request);
        if (plan.slots().size() == 1) {
            QuerySlot slot = plan.slots().getFirst();
            CredentialMatch match = slot.matches().stream()
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
                    match.credential(), match.claimsToDisclose(0), request.clientId(), request.nonce());
            SubmissionResult result = responseSubmitter.submitVpToken(request, Map.of(slot.queryId(), presentation));
            LOG.info("Presented ad-hoc credential {} to {}", credential.id(), request.clientId());
            return complete(result, model);
        }
        model.addAttribute("findings", List.of());
        return renderPicker(request, model);
    }

    @PostMapping("/authorize/edit/cancel")
    public String cancelEditDuringFlow(@RequestParam("flowState") String flowState, Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        model.addAttribute("findings", List.of());
        return renderPicker(request, model);
    }

    @PostMapping("/authorize/cancel")
    public String cancel(@RequestParam("flowState") String flowState, Model model) {
        AuthorizationRequest request = AuthorizationRequest.parse(flowState);
        SubmissionResult result =
                responseSubmitter.submitError(request, "access_denied", "The user cancelled the presentation");
        LOG.info("Cancelled presentation for {}", request.clientId());
        return complete(result, model);
    }

    private String refuseNonConformantRequest(AuthorizationRequest request, List<Finding> findings, Model model) {
        String description = findings.stream().map(Finding::message).collect(Collectors.joining("; "));
        String errorCode =
                findings.stream().anyMatch(finding -> finding.message().contains("transaction_data"))
                        ? "invalid_transaction_data"
                        : "invalid_request";
        boolean errorSent = false;
        if (isUsableResponseUri(request.responseUri())) {
            try {
                responseSubmitter.submitError(request, errorCode, description);
                errorSent = true;
            } catch (InvalidRequestException e) {
                LOG.error("Could not deliver error response: {}", e.getMessage());
            }
        }
        LOG.error("Refused non-conformant request in strict mode from {}", request.clientId());
        model.addAttribute(
                "errorMessage",
                "The verifier request violates OID4VP conformance (strict mode)."
                        + (errorSent ? " An " + errorCode + " error response was sent to the verifier." : ""));
        model.addAttribute("findings", findings);
        return "error_view";
    }

    private static boolean isUsableResponseUri(String responseUri) {
        return responseUri != null && (responseUri.startsWith("http://") || responseUri.startsWith("https://"));
    }

    private String renderPicker(AuthorizationRequest request, Model model) {
        PresentationPlan plan = plan(request);
        model.addAttribute("verifierClientId", request.clientId());
        model.addAttribute("slots", plan.slots());
        model.addAttribute("setChoices", plan.setChoices());
        model.addAttribute("satisfiable", plan.satisfiable());
        model.addAttribute("flowState", request.rawRequestObject());
        return "presentation_select";
    }

    private PresentationPlan plan(AuthorizationRequest request) {
        try {
            return dcqlMatcher.plan(DcqlQuery.from(request.dcqlQuery()));
        } catch (InvalidRequestException e) {
            return new PresentationPlan(List.of(), List.of(), List.of(), false);
        }
    }

    private String editView(CredentialEditForm form, Model model) {
        model.addAttribute("form", form);
        model.addAttribute("formAction", "/authorize/edit/save");
        return "credential_edit";
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
        LOG.error("Presentation flow failed: {}", exception.getMessage());
        model.addAttribute("errorMessage", exception.getMessage());
        return "error_view";
    }
}
