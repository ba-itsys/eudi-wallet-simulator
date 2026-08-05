package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import de.arbeitsagentur.opdt.walletsim.credentials.WalletCredentialService;
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

/**
 * Ad-hoc credential management outside a presentation flow: clone the selected credential as a
 * template (the bundid-simulator formaction mechanic), create one from scratch, edit claims as
 * raw JSON, and toggle revocation per card.
 */
@Controller
public class CredentialUiController {

    private final CredentialStore store;
    private final WalletCredentialService credentialService;
    private final CredentialEditForms editForms;
    private final String basepath;

    public CredentialUiController(
            CredentialStore store,
            WalletCredentialService credentialService,
            CredentialEditForms editForms,
            @Value("${app.basepath:}") String basepath) {
        this.store = store;
        this.credentialService = credentialService;
        this.editForms = editForms;
        this.basepath = basepath == null ? "" : basepath;
    }

    @PostMapping("/credentials/edit")
    public String editFromExisting(@RequestParam("credentialId") String credentialId, Model model) {
        return editView(editForms.cloneForm(credentialId), model);
    }

    @GetMapping("/credentials/new")
    public String createNew(Model model) {
        return editView(editForms.newForm(), model);
    }

    @PostMapping("/credentials/save")
    public String save(@ModelAttribute("form") CredentialEditForm form, Model model) {
        String error = editForms.validationError(form);
        if (error != null) {
            model.addAttribute("formError", error);
            return editView(form, model);
        }
        credentialService.issue(editForms.toDefinition(form), StoredCredential.Source.AD_HOC);
        return "redirect:" + basepath + "/";
    }

    @PostMapping("/credentials/{id}/status/toggle")
    public String toggleStatus(@PathVariable String id) {
        int current =
                store.statusOf(id).orElseThrow(() -> new IllegalArgumentException("Unknown credential id: " + id));
        store.setStatus(id, current == 0 ? 1 : 0);
        return "redirect:" + basepath + "/";
    }

    private String editView(CredentialEditForm form, Model model) {
        model.addAttribute("form", form);
        model.addAttribute("formAction", basepath + "/credentials/save");
        return "credential_edit";
    }

    @ExceptionHandler(IllegalArgumentException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public String unknownCredential(IllegalArgumentException exception, Model model) {
        model.addAttribute("errorMessage", exception.getMessage());
        return "error_view";
    }
}
