package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.server.service.SnapshotService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

/** Signed offline snapshot for client-side fallback. Supports conditional GET. */
@RestController
public class SnapshotController {

    private final SnapshotService snapshots;

    public SnapshotController(SnapshotService snapshots) {
        this.snapshots = snapshots;
    }

    @GetMapping("/api/v1/snapshot")
    public ResponseEntity<String> snapshot(ClientProfile client, HttpServletRequest req) {
        SnapshotService.Snapshot s = snapshots.snapshot(client);
        if (s.etag().equals(req.getHeader("If-None-Match"))) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED).eTag(s.etag()).build();
        }
        return ResponseEntity.ok().contentType(ResponseSigner.JWT).eTag(s.etag())
                .cacheControl(CacheControl.maxAge(Duration.ofMinutes(5)).cachePrivate()).body(s.jwt());
    }
}
