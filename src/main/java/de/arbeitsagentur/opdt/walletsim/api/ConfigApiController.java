package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.conformance.ConformanceSettings;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/config")
public class ConfigApiController {

    private final ConformanceSettings settings;

    public ConfigApiController(ConformanceSettings settings) {
        this.settings = settings;
    }

    @GetMapping
    public Map<String, String> config() {
        return Map.of("mode", settings.mode().asConfigValue());
    }
}
