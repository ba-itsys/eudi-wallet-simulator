package de.arbeitsagentur.opdt.walletsim.api;

import com.nimbusds.jose.util.Base64URL;
import de.arbeitsagentur.opdt.walletsim.registrar.RegistrationCertificateService;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.ObjectMapper;

/**
 * Issues relying-party registration certificates. The response contains the raw rc-rp+jwt and the
 * ready-to-paste value for a verifier's verifier_info configuration.
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
        // IR (EU) 2024/2977 amendment: format registrar_dataset, data base64url of the signed
        // registration certificate, no credential_ids
        String data = Base64URL.encode(jwt.getBytes(StandardCharsets.UTF_8)).toString();
        String verifierInfo =
                objectMapper.writeValueAsString(List.of(Map.of("format", "registrar_dataset", "data", data)));
        return Map.of("registrationCertificate", jwt, "verifierInfo", verifierInfo);
    }
}
