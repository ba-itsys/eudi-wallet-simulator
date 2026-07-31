package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.api.CredentialResponse.StatusReference;
import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import org.springframework.http.HttpStatus;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Revocation API: set or read the status list value of a single credential. */
@RestController
@RequestMapping("/api/credentials/{id}/status")
public class CredentialStatusApiController {

    public record StatusChangeRequest(int status) {}

    private final CredentialStore store;
    private final AppUrls urls;

    public CredentialStatusApiController(CredentialStore store, AppUrls urls) {
        this.store = store;
        this.urls = urls;
    }

    @PostMapping
    public StatusReference setStatus(@PathVariable String id, @RequestBody StatusChangeRequest request) {
        if (request.status() < 0 || request.status() > 255) {
            throw new ErrorResponseException(HttpStatus.BAD_REQUEST);
        }
        StoredCredential credential = requireCredential(id);
        store.setStatus(id, request.status());
        return StatusReference.of(urls.statusListUri(), credential.statusIndex(), request.status());
    }

    @GetMapping
    public StatusReference getStatus(@PathVariable String id) {
        StoredCredential credential = requireCredential(id);
        int status = store.statusOf(id).orElse(0);
        return StatusReference.of(urls.statusListUri(), credential.statusIndex(), status);
    }

    private StoredCredential requireCredential(String id) {
        return store.findById(id).orElseThrow(() -> new ErrorResponseException(HttpStatus.NOT_FOUND));
    }
}
