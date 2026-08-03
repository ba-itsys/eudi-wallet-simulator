package de.arbeitsagentur.opdt.walletsim.api;

import de.arbeitsagentur.opdt.walletsim.logging.ActivityLog;
import java.util.List;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/log")
public class LogApiController {

    private final ActivityLog activityLog;

    public LogApiController(ActivityLog activityLog) {
        this.activityLog = activityLog;
    }

    @GetMapping
    public List<ActivityLog.Entry> entries() {
        return activityLog.entries();
    }

    @DeleteMapping
    public void clear() {
        activityLog.clear();
    }
}
