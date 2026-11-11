package io.vctrust.trust.server.api;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.server.service.AdministrationService;
import io.vctrust.trust.server.service.ManagedEntryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** Operator API: source health and refresh, managed entities/anchors, caches. Requires an admin client. */
@RestController
@RequestMapping("/admin/v1")
public class AdminController {

    private final AdministrationService administration;
    private final ManagedEntryService managed;

    public AdminController(AdministrationService administration, ManagedEntryService managed) {
        this.administration = administration;
        this.managed = managed;
    }

    @GetMapping("/sources")
    public List<SourceState> sourceStates() {
        return administration.sourceStates();
    }

    @PostMapping("/sources/{id}/refresh")
    public SourceState refresh(ClientProfile admin, @PathVariable String id) {
        return administration.refreshSource(admin, id);
    }

    @GetMapping("/registry")
    public Map<String, Object> registrySummary() {
        return administration.registrySummary();
    }

    @GetMapping("/clients")
    public List<ClientProfile> clientProfiles() {
        return administration.clientProfiles();
    }

    @GetMapping("/managed/{kind}")
    public List<Map<String, Object>> listManaged(@PathVariable String kind) {
        return managed.list(kind);
    }

    @PutMapping("/managed/{kind}/{id}")
    public ResponseEntity<Map<String, Object>> putManaged(ClientProfile admin, @PathVariable String kind, @PathVariable String id,
                                                          @RequestBody Map<String, Object> doc) {
        return ResponseEntity.ok(managed.put(admin, kind, id, doc));
    }

    @DeleteMapping("/managed/{kind}/{id}")
    public ResponseEntity<Void> deleteManaged(ClientProfile admin, @PathVariable String kind, @PathVariable String id) {
        managed.delete(admin, kind, id);
        return ResponseEntity.noContent().build();
    }

    /** Empties every proxy cache: the next request for anything is fetched anew. */
    @PostMapping("/cache/clear")
    public Map<String, Object> clearCaches(ClientProfile admin) {
        return Map.of("cleared", administration.clearCaches(admin));
    }
}
