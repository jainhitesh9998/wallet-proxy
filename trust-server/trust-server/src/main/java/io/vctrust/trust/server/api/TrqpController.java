package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.TrqpService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** ToIP Trust Registry Query Protocol v2.0 HTTP binding. */
@RestController
@RequestMapping(value = "/trqp", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
public class TrqpController {

    private final TrqpService trqp;

    public TrqpController(TrqpService trqp) {
        this.trqp = trqp;
    }

    @PostMapping("/authorization")
    public Map<String, Object> authorization(ClientProfile client, @RequestBody Map<String, Object> body) {
        return trqp.authorization(body, client);
    }

    @PostMapping("/recognition")
    public Map<String, Object> recognition(ClientProfile client, @RequestBody Map<String, Object> body) {
        return trqp.recognition(body, client);
    }
}
