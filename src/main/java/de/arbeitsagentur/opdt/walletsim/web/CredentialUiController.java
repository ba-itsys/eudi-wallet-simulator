package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import de.arbeitsagentur.opdt.walletsim.credentials.WalletCredentialService;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Ad-hoc credential management in the UI: clone the selected credential as a template (the
 * bundid-simulator formaction mechanic), create one from scratch, edit claims as raw JSON, and
 * toggle revocation per card.
 */
@Controller
public class CredentialUiController {

    private final CredentialStore store;
    private final WalletCredentialService credentialService;
    private final String basepath;
    private final ObjectMapper objectMapper =
            JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    public CredentialUiController(
            CredentialStore store,
            WalletCredentialService credentialService,
            @Value("${app.basepath:}") String basepath) {
        this.store = store;
        this.credentialService = credentialService;
        this.basepath = basepath == null ? "" : basepath;
    }

    @PostMapping("/credentials/edit")
    public String editFromExisting(@RequestParam("credentialId") String credentialId, Model model) {
        StoredCredential template = store.findById(credentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + credentialId));
        CredentialEditForm form = new CredentialEditForm();
        form.setId(uniqueIdFrom(credentialId));
        form.setName(template.name() + " (copy)");
        form.setVct(template.vct());
        form.setClaimsJson(objectMapper.writeValueAsString(template.claims()));
        model.addAttribute("form", form);
        return "credential_edit";
    }

    @GetMapping("/credentials/new")
    public String createNew(Model model) {
        CredentialEditForm form = new CredentialEditForm();
        form.setId("credential-" + shortRandom());
        form.setName("New credential");
        form.setVct("urn:eudi:pid:1");
        form.setClaimsJson(objectMapper.writeValueAsString(
                Map.of("family_name", "Doe", "given_name", "Jane", "birthdate", "1990-01-01")));
        model.addAttribute("form", form);
        return "credential_edit";
    }

    @PostMapping("/credentials/save")
    public String save(@ModelAttribute("form") CredentialEditForm form, Model model) {
        String claimsError = validate(form);
        if (claimsError != null) {
            model.addAttribute("form", form);
            model.addAttribute("formError", claimsError);
            return "credential_edit";
        }
        Map<String, Object> claims = parseClaims(form.getClaimsJson());
        credentialService.issue(
                new CredentialDefinition(
                        form.getId().trim(),
                        form.getName().trim(),
                        form.getVct().trim(),
                        form.getValidityDays(),
                        claims),
                StoredCredential.Source.AD_HOC);
        return "redirect:" + basepath + "/";
    }

    @PostMapping("/credentials/{id}/status/toggle")
    public String toggleStatus(@PathVariable String id) {
        int current =
                store.statusOf(id).orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + id));
        store.setStatus(id, current == 0 ? 1 : 0);
        return "redirect:" + basepath + "/";
    }

    private String validate(CredentialEditForm form) {
        if (form.getId() == null || form.getId().isBlank()) {
            return "Credential id is required.";
        }
        if (store.findById(form.getId().trim()).isPresent()) {
            return "A credential with id '" + form.getId().trim() + "' already exists.";
        }
        if (form.getName() == null || form.getName().isBlank()) {
            return "Name is required.";
        }
        if (form.getVct() == null || form.getVct().isBlank()) {
            return "vct is required.";
        }
        if (form.getValidityDays() <= 0) {
            return "Validity must be at least one day.";
        }
        try {
            Map<String, Object> claims = parseClaims(form.getClaimsJson());
            if (claims.isEmpty()) {
                return "Claims must be a non-empty JSON object.";
            }
        } catch (Exception e) {
            return "Claims are not a valid JSON object.";
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseClaims(String claimsJson) {
        return objectMapper.readValue(claimsJson, Map.class);
    }

    private String uniqueIdFrom(String templateId) {
        String candidate = templateId + "-copy";
        while (store.findById(candidate).isPresent()) {
            candidate = templateId + "-copy-" + shortRandom();
        }
        return candidate;
    }

    private static String shortRandom() {
        return UUID.randomUUID().toString().substring(0, 8);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String unknownCredential(IllegalArgumentException exception, Model model) {
        model.addAttribute("errorMessage", exception.getMessage());
        return "error_view";
    }
}
