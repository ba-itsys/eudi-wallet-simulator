package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.config.AppProperties;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/config")
public class ConfigApiController {

    private final AppProperties properties;

    public ConfigApiController(AppProperties properties) {
        this.properties = properties;
    }

    @GetMapping
    public Map<String, String> config() {
        return Map.of("mode", properties.mode().asConfigValue());
    }
}
