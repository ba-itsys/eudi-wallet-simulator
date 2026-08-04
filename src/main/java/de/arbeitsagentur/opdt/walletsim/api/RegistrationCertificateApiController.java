package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.registrar.RegistrationCertificateService;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

/**
 * Issues relying-party registration certificates. The response contains the raw rc-rp+jwt and the
 * ready-to-paste value for the keycloak-extension-oid4vp {@code verifierInfo} configuration.
 */
@RestController
public class RegistrationCertificateApiController {

    private final RegistrationCertificateService registrationCertificates;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public RegistrationCertificateApiController(RegistrationCertificateService registrationCertificates) {
        this.registrationCertificates = registrationCertificates;
    }

    @GetMapping("/api/registration-certificates")
    public Map<String, String> issue(
            @RequestParam("client_id") String clientId,
            @RequestParam(name = "purpose", required = false) String purpose) {
        String jwt = registrationCertificates.issue(clientId, purpose);
        String verifierInfo = objectMapper.writeValueAsString(List.of(Map.of("format", "jwt", "data", jwt)));
        return Map.of("registrationCertificate", jwt, "verifierInfo", verifierInfo);
    }
}
