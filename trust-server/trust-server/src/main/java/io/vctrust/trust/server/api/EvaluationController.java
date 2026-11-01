package io.vctrust.trust.server.api;

import io.vctrust.trust.core.evaluation.TrustDecision;
import io.vctrust.trust.core.evaluation.TrustEvaluator;
import io.vctrust.trust.core.policy.ClientProfile;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** The spec-agnostic trust decision endpoint. */
@RestController
@RequestMapping("/api/v1")
public class EvaluationController {

    private static final int MAX_BATCH = 50;

    private final TrustEvaluator evaluator;
    private final ResponseSigner signer;

    public EvaluationController(TrustEvaluator evaluator, ResponseSigner signer) {
        this.evaluator = evaluator;
        this.signer = signer;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<Object> evaluate(ClientProfile client, HttpServletRequest req, @RequestBody Dtos.EvaluateRequest body) {
        TrustDecision d = evaluator.evaluate(body.toQuery(), client);
        return signer.respond(req, client, "trust-decision+jwt", d,
                ResponseEntity.ok().cacheControl(CacheControl.noStore()).header("X-Trust-Decision", d.decision().name()));
    }

    @PostMapping("/evaluate/batch")
    public ResponseEntity<Object> batch(ClientProfile client, HttpServletRequest req, @RequestBody Dtos.BatchEvaluateRequest body) {
        if (body.queries() == null || body.queries().isEmpty() || body.queries().size() > MAX_BATCH) {
            throw ApiException.badRequest("invalid_request", "queries must contain 1.." + MAX_BATCH + " entries");
        }
        List<TrustDecision> out = body.queries().parallelStream().map(q -> evaluator.evaluate(q.toQuery(), client)).toList();
        return signer.respond(req, client, "trust-decision+jwt", Map.of("decisions", out),
                ResponseEntity.ok().cacheControl(CacheControl.noStore()));
    }
}
