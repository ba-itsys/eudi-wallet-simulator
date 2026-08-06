package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared mechanics of the credential edit form: cloning an existing credential as template,
 * building a fresh template, validating the submitted form, and turning it into a definition.
 *
 * <p>Nested claim objects are flattened into dot notation fields (address.locality) and
 * reassembled on submit. Claim values round-trip as text: strings render raw, everything else
 * renders as JSON. On submit a value is parsed as JSON when possible and kept as a string
 * otherwise, so a postal code like {@code "10409"} renders quoted and survives as a string.
 */
@Component
public class CredentialEditForms {

    private final CredentialStore store;
    private final ObjectMapper objectMapper = new ObjectMapper();

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
        form.setClaimValues(renderClaimValues(template.claims()));
        return form;
    }

    public CredentialEditForm newForm() {
        CredentialEditForm form = new CredentialEditForm();
        form.setId("credential-" + shortRandom());
        form.setName("New credential");
        form.setVct("urn:eudi:pid:1");
        form.setClaimValues(
                renderClaimValues(Map.of("family_name", "Doe", "given_name", "Jane", "birthdate", "1990-01-01")));
        return form;
    }

    // Moves the add-claim row into a regular claim field and clears the row.
    public void addNewClaim(CredentialEditForm form) {
        if (form.getNewClaimName() != null && !form.getNewClaimName().isBlank()) {
            form.getClaimValues()
                    .put(
                            form.getNewClaimName().trim(),
                            form.getNewClaimValue() == null
                                    ? ""
                                    : form.getNewClaimValue().trim());
            form.setNewClaimName(null);
            form.setNewClaimValue(null);
        }
    }

    // The validation violation for the submitted form, or null when it can be issued.
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
        if (parseClaims(form).isEmpty()) {
            return "The credential needs at least one claim.";
        }
        return null;
    }

    public CredentialDefinition toDefinition(CredentialEditForm form) {
        return new CredentialDefinition(
                form.getId().trim(),
                form.getName().trim(),
                form.getVct().trim(),
                form.getValidityDays(),
                parseClaims(form));
    }

    private Map<String, Object> parseClaims(CredentialEditForm form) {
        Map<String, Object> claims = new LinkedHashMap<>();
        form.getClaimValues().forEach((claimPath, value) -> {
            if (value != null && !value.isBlank()) {
                putNested(claims, claimPath, parseClaimValue(value.trim()));
            }
        });
        if (form.getNewClaimName() != null
                && !form.getNewClaimName().isBlank()
                && form.getNewClaimValue() != null
                && !form.getNewClaimValue().isBlank()) {
            putNested(
                    claims,
                    form.getNewClaimName().trim(),
                    parseClaimValue(form.getNewClaimValue().trim()));
        }
        return claims;
    }

    @SuppressWarnings("unchecked")
    private static void putNested(Map<String, Object> claims, String claimPath, Object value) {
        String[] steps = claimPath.split("\\.");
        Map<String, Object> current = claims;
        for (int i = 0; i < steps.length - 1; i++) {
            Object next = current.get(steps[i]);
            if (!(next instanceof Map)) {
                next = new LinkedHashMap<String, Object>();
                current.put(steps[i], next);
            }
            current = (Map<String, Object>) next;
        }
        current.put(steps[steps.length - 1], value);
    }

    private Object parseClaimValue(String value) {
        try {
            return objectMapper.readValue(value, Object.class);
        } catch (Exception e) {
            return value;
        }
    }

    private Map<String, String> renderClaimValues(Map<String, Object> claims) {
        Map<String, String> values = new LinkedHashMap<>();
        flatten("", claims, values);
        return values;
    }

    @SuppressWarnings("unchecked")
    private void flatten(String prefix, Map<String, Object> claims, Map<String, String> values) {
        claims.forEach((claimName, value) -> {
            String path = prefix.isEmpty() ? claimName : prefix + "." + claimName;
            if (value instanceof Map<?, ?> nested) {
                flatten(path, (Map<String, Object>) nested, values);
            } else {
                values.put(path, renderClaimValue(value));
            }
        });
    }

    private String renderClaimValue(Object value) {
        if (value instanceof String text && !parsesAsJson(text)) {
            return text;
        }
        return objectMapper.writeValueAsString(value);
    }

    private boolean parsesAsJson(String text) {
        try {
            objectMapper.readValue(text, Object.class);
            return true;
        } catch (Exception e) {
            return false;
        }
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
