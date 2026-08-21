package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialDefinition;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import tools.jackson.databind.ObjectMapper;

/**
 * Shared mechanics of the credential edit form: cloning an existing credential as template,
 * building a fresh template, validating the submitted form, and turning it into a definition.
 *
 * <p>Nested claim objects are flattened into dot notation fields (address.locality) and
 * reassembled on submit. Claim values round-trip as text: strings render raw, everything else
 * renders as JSON. On submit a value is parsed as JSON when possible and kept as a string
 * otherwise, so a postal code like {@code "10409"} renders quoted and survives as a string. An
 * empty claim value renders as {@code ""} because an empty field drops the claim, and rulebooks
 * like the German PID keep claims with an empty value.
 */
@Component
public class CredentialEditForms {

    private final CredentialStore store;
    private final ObjectMapper objectMapper;

    public CredentialEditForms(CredentialStore store, ObjectMapper objectMapper) {
        this.store = store;
        this.objectMapper = objectMapper;
    }

    public CredentialEditForm cloneForm(String templateCredentialId) {
        return cloneForm(store.findById(templateCredentialId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + templateCredentialId)));
    }

    public CredentialEditForm cloneForm(StoredCredential template) {
        return cloneForm(template, uniqueIdFrom(template.id()));
    }

    /**
     * A credential modified for a single presentation keeps the id and the status list slot of the
     * credential it was derived from. It is the same credential from the verifier's point of view,
     * so revoking the wallet credential also invalidates the modified one.
     */
    public CredentialEditForm cloneForSinglePresentation(StoredCredential template) {
        CredentialEditForm form = cloneForm(template, template.id());
        form.setStatusIndex(template.statusIndex() >= 0 ? template.statusIndex() : null);
        return form;
    }

    private CredentialEditForm cloneForm(StoredCredential template, String id) {
        CredentialEditForm form = new CredentialEditForm();
        form.setId(id);
        form.setName(template.name());
        form.setVct(template.vct());
        form.setClaimValues(renderClaimValues(template.claims()));
        form.getClaimValues().keySet().forEach(path -> form.getClaimAlwaysDisclosed()
                .put(path, template.alwaysDisclosedClaims().contains(path)));
        return form;
    }

    public CredentialEditForm newForm() {
        CredentialEditForm form = new CredentialEditForm();
        form.setId("credential-" + shortRandom());
        form.setName("New credential");
        form.setVct("urn:eudi:pid:1");
        form.setClaimValues(
                renderClaimValues(Map.of("family_name", "Doe", "given_name", "Jane", "birthdate", "1990-01-01")));
        form.getClaimValues().keySet().forEach(path -> form.getClaimAlwaysDisclosed()
                .put(path, false));
        return form;
    }

    // Moves the add-claim row into a regular claim field and clears the row.
    public void addNewClaim(CredentialEditForm form) {
        if (StringUtils.hasText(form.getNewClaimName())) {
            String path = form.getNewClaimName().trim();
            form.getClaimValues()
                    .put(
                            path,
                            form.getNewClaimValue() == null
                                    ? ""
                                    : form.getNewClaimValue().trim());
            form.getClaimAlwaysDisclosed().putIfAbsent(path, false);
            form.setNewClaimName(null);
            form.setNewClaimValue(null);
        }
    }

    // The validation violation for the submitted form, or null when it can be issued.
    public String validationError(CredentialEditForm form) {
        return validationError(form, true);
    }

    // a credential for a single presentation may reuse the id of the wallet credential it replaces
    public String validationError(CredentialEditForm form, boolean requireUnusedId) {
        if (!StringUtils.hasText(form.getId())) {
            return "Credential id is required.";
        }
        if (requireUnusedId && store.findById(form.getId().trim()).isPresent()) {
            return "A credential with id '" + form.getId().trim() + "' already exists.";
        }
        if (!StringUtils.hasText(form.getName())) {
            return "Name is required.";
        }
        if (!StringUtils.hasText(form.getVct())) {
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
                parseClaims(form),
                alwaysDisclosedClaims(form));
    }

    private static List<String> alwaysDisclosedClaims(CredentialEditForm form) {
        return form.getClaimValues().entrySet().stream()
                .filter(entry -> StringUtils.hasText(entry.getValue()))
                .map(Map.Entry::getKey)
                .filter(path ->
                        Boolean.TRUE.equals(form.getClaimAlwaysDisclosed().get(path)))
                .toList();
    }

    private Map<String, Object> parseClaims(CredentialEditForm form) {
        Map<String, Object> claims = new LinkedHashMap<>();
        form.getClaimValues().forEach((claimPath, value) -> {
            if (StringUtils.hasText(value)) {
                putNested(claims, claimPath, parseClaimValue(value.trim()));
            }
        });
        if (StringUtils.hasText(form.getNewClaimName()) && StringUtils.hasText(form.getNewClaimValue())) {
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

    // a blank string renders quoted, so the field is not empty and the claim survives a round trip
    private String renderClaimValue(Object value) {
        if (value instanceof String text && StringUtils.hasText(text) && !parsesAsJson(text)) {
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
