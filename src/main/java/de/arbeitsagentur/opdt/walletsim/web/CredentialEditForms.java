package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Shared mechanics of the credential edit form: cloning an existing credential as template,
 * building a fresh template, validating the submitted form, and turning it into a definition.
 */
@Component
public class CredentialEditForms {

    private final CredentialStore store;
    private final ObjectMapper objectMapper =
            JsonMapper.builder().enable(SerializationFeature.INDENT_OUTPUT).build();

    public CredentialEditForms(CredentialStore store) {
        this.store = store;
    }

    public CredentialEditForm cloneForm(String templateCredentialId) {
        StoredCredential template = store.findById(templateCredentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + templateCredentialId));
        CredentialEditForm form = new CredentialEditForm();
        form.setId(uniqueIdFrom(templateCredentialId));
        form.setName(template.name() + " (copy)");
        form.setVct(template.vct());
        form.setClaimsJson(objectMapper.writeValueAsString(template.claims()));
        return form;
    }

    public CredentialEditForm newForm() {
        CredentialEditForm form = new CredentialEditForm();
        form.setId("credential-" + shortRandom());
        form.setName("New credential");
        form.setVct("urn:eudi:pid:1");
        form.setClaimsJson(objectMapper.writeValueAsString(
                Map.of("family_name", "Doe", "given_name", "Jane", "birthdate", "1990-01-01")));
        return form;
    }

    /** The validation violation for the submitted form, or null when it can be issued. */
    public String validationError(CredentialEditForm form) {
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
            if (parseClaims(form.getClaimsJson()).isEmpty()) {
                return "Claims must be a non-empty JSON object.";
            }
        } catch (Exception e) {
            return "Claims are not a valid JSON object.";
        }
        return null;
    }

    public CredentialDefinition toDefinition(CredentialEditForm form) {
        return new CredentialDefinition(
                form.getId().trim(),
                form.getName().trim(),
                form.getVct().trim(),
                form.getValidityDays(),
                parseClaims(form.getClaimsJson()));
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
}
