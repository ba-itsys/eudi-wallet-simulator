package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.config.AppUrls;
import de.arbeitsagentur.opdt.walletsim.credentials.CredentialStore;
import de.arbeitsagentur.opdt.walletsim.credentials.StoredCredential;
import java.net.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

// Revocation API: set or read the status list value of a single credential.
@RestController
@RequestMapping("/api/credentials/{id}/status")
public class CredentialStatusApiController {

    private static final Logger LOG = LoggerFactory.getLogger(CredentialStatusApiController.class);

    private final CredentialStore store;
    private final AppUrls urls;
    private final String basepath;

    public CredentialStatusApiController(
            CredentialStore store, AppUrls urls, @Value("${app.basepath:}") String basepath) {
        this.store = store;
        this.urls = urls;
        this.basepath = basepath == null ? "" : basepath;
    }

    @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
    public StatusReference setStatus(@PathVariable String id, @RequestBody StatusChangeRequest request) {
        return applyStatus(id, request.status());
    }

    // form variant for the server rendered UI, answering with a redirect back to the home page
    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<Void> setStatusFromForm(@PathVariable String id, @RequestParam("status") int status) {
        applyStatus(id, status);
        return ResponseEntity.status(HttpStatus.SEE_OTHER)
                .location(URI.create(basepath + "/"))
                .build();
    }

    private StatusReference applyStatus(String id, int status) {
        if (status != 0 && status != 1) {
            throw new ErrorResponseException(HttpStatus.BAD_REQUEST);
        }
        StoredCredential credential = requireCredential(id);
        store.setStatus(id, status);
        StatusReference reference = StatusReference.of(urls.statusListUri(), credential.statusIndex(), status);
        LOG.info("Set status {} on credential {} (idx {})", reference.statusName(), id, credential.statusIndex());
        return reference;
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
