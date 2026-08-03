package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.conformance.ConformanceSettings;
import de.arbeitsagentur.opdt.walletsim.conformance.ValidationMode;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/config")
public class ConfigApiController {

    public record ConformanceChangeRequest(String mode) {}

    private final ConformanceSettings settings;

    public ConfigApiController(ConformanceSettings settings) {
        this.settings = settings;
    }

    @GetMapping
    public Map<String, String> config() {
        return Map.of("conformanceMode", settings.mode().asConfigValue());
    }

    @PutMapping("/conformance")
    public Map<String, String> setConformance(@RequestBody ConformanceChangeRequest request) {
        try {
            settings.setMode(ValidationMode.fromString(request.mode()));
        } catch (IllegalArgumentException e) {
            throw new ErrorResponseException(HttpStatus.BAD_REQUEST);
        }
        return config();
    }

    @DeleteMapping("/conformance")
    public Map<String, String> resetConformance() {
        settings.reset();
        return config();
    }
}
