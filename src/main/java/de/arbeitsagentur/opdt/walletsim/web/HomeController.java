package de.arbeitsagentur.opdt.walletsim.web;

import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.List;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {

    public record CredentialCard(StoredCredential credential, int status) {}

    private final CredentialStore store;

    public HomeController(CredentialStore store) {
        this.store = store;
    }

    @GetMapping("/")
    public String home(Model model) {
        List<CredentialCard> cards = store.findAll().stream()
                .map(credential -> new CredentialCard(
                        credential, store.statusOf(credential.id()).orElse(0)))
                .toList();
        model.addAttribute("cards", cards);
        return "index";
    }
}
