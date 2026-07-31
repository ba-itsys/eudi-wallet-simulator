package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/credentials")
public class CredentialApiController {

    private final CredentialStore store;
    private final AppUrls urls;

    public CredentialApiController(CredentialStore store, AppUrls urls) {
        this.store = store;
        this.urls = urls;
    }

    @GetMapping
    public List<CredentialResponse> list() {
        return store.findAll().stream().map(this::toResponse).toList();
    }

    @GetMapping("/{id}")
    public CredentialResponse get(@PathVariable String id) {
        StoredCredential credential =
                store.findById(id).orElseThrow(() -> new ErrorResponseException(HttpStatus.NOT_FOUND));
        return toResponse(credential);
    }

    private CredentialResponse toResponse(StoredCredential credential) {
        int status = store.statusOf(credential.id()).orElse(0);
        return CredentialResponse.of(credential, urls.statusListUri(), status);
    }
}
