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

/**
 * The trust decision endpoint, for backends that do not carry the client library. Wallets decide on the device from
 * the snapshot; this evaluator applies the same rules, which shared test vectors hold equal.
 */
@RestController
@RequestMapping("/api/v1")
public class EvaluationController {

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
}
