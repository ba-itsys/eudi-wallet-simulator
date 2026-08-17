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
 * Issues relying-party registration certificates. The response contains the raw rc-wrp+jwt and the
 * ready-to-paste value for a verifier's verifier_info configuration.
 */
@RestController
public class RegistrationCertificateApiController {

    private final RegistrationCertificateService registrationCertificates;
    private final ObjectMapper objectMapper;

    public RegistrationCertificateApiController(
            RegistrationCertificateService registrationCertificates, ObjectMapper objectMapper) {
        this.registrationCertificates = registrationCertificates;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/api/registration-certificates")
    public Map<String, String> issue(
            @RequestParam("client_id") String clientId,
            @RequestParam(name = "purpose", required = false) String purpose) {
        String jwt = registrationCertificates.issue(clientId, purpose);
        // ETSI TS 119 472-2: format registration_cert, data base64url of the signed
        // registration certificate, no credential_ids
        String data = Base64URL.encode(jwt.getBytes(StandardCharsets.UTF_8)).toString();
        String verifierInfo =
                objectMapper.writeValueAsString(List.of(Map.of("format", "registration_cert", "data", data)));
        return Map.of("registrationCertificate", jwt, "verifierInfo", verifierInfo);
    }
}
