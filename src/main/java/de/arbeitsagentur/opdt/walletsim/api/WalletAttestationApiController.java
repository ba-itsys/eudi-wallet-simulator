package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.attestation.WalletAttestationService;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WalletAttestationApiController {

    private static final String DEFAULT_CLIENT_ID = "eudi-wallet-simulator";

    private final WalletAttestationService attestationService;

    public WalletAttestationApiController(WalletAttestationService attestationService) {
        this.attestationService = attestationService;
    }

    @GetMapping("/api/wallet-attestation")
    public Map<String, String> walletAttestation(
            @RequestParam(name = "client_id", defaultValue = DEFAULT_CLIENT_ID) String clientId,
            @RequestParam(name = "aud", required = false) String audience,
            @RequestParam(name = "challenge", required = false) String challenge) {
        Map<String, String> response = new LinkedHashMap<>();
        response.put("attestation", attestationService.attestationJwt(clientId));
        if (audience != null && !audience.isBlank()) {
            response.put("pop", attestationService.popJwt(clientId, audience, challenge));
        }
        return response;
    }
}
