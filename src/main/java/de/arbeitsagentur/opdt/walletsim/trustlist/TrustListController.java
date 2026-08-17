package de.arbeitsagentur.opdt.walletsim.trustlist;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TrustListController {

    private static final MediaType APPLICATION_JWT = MediaType.parseMediaType("application/jwt");

    private final TrustListService trustListService;

    public TrustListController(TrustListService trustListService) {
        this.trustListService = trustListService;
    }

    @GetMapping("/api/trust-lists/credentials")
    public ResponseEntity<String> credentials() {
        return trustList(TrustListProfile.CREDENTIALS);
    }

    private ResponseEntity<String> trustList(TrustListProfile profile) {
        return ResponseEntity.ok().contentType(APPLICATION_JWT).body(trustListService.trustListJwt(profile));
    }
}
