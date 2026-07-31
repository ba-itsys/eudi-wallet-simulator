package de.arbeitsagentur.opdt.walletsim.statuslist;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class StatusListController {

    private static final MediaType STATUS_LIST_JWT = MediaType.parseMediaType("application/statuslist+jwt");

    private final StatusListService statusListService;

    public StatusListController(StatusListService statusListService) {
        this.statusListService = statusListService;
    }

    @GetMapping("/status-list")
    public ResponseEntity<String> statusList() {
        return ResponseEntity.ok()
                .contentType(STATUS_LIST_JWT)
                .header("Access-Control-Allow-Origin", "*")
                .body(statusListService.statusListJwt());
    }
}
