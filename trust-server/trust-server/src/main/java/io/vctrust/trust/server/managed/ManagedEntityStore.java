package io.vctrust.trust.server.managed;

import io.vctrust.trust.core.json.Json;
import org.springframework.jdbc.core.simple.JdbcClient;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** JDBC persistence for admin-managed entities and anchors, stored as JSON documents in the native format. */
public class ManagedEntityStore {

    public enum Kind { ENTITY, ANCHOR }

    private final JdbcClient jdbc;

    public ManagedEntityStore(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<Map<String, Object>> list(Kind kind) {
        return jdbc.sql("SELECT document FROM managed_document WHERE kind = ? ORDER BY id")
                .param(kind.name()).query(String.class).list().stream().map(Json::parseObject).toList();
    }

    public Optional<Map<String, Object>> get(Kind kind, String id) {
        return jdbc.sql("SELECT document FROM managed_document WHERE kind = ? AND id = ?")
                .param(kind.name()).param(id).query(String.class).optional().map(Json::parseObject);
    }

    public void put(Kind kind, String id, Map<String, Object> document) {
        String json = Json.write(document);
        int updated = jdbc.sql("UPDATE managed_document SET document = ?, updated_at = ? WHERE kind = ? AND id = ?")
                .param(json).param(Timestamp.from(Instant.now())).param(kind.name()).param(id).update();
        if (updated == 0) {
            jdbc.sql("INSERT INTO managed_document (kind, id, document, updated_at) VALUES (?, ?, ?, ?)")
                    .param(kind.name()).param(id).param(json).param(Timestamp.from(Instant.now())).update();
        }
    }

    public boolean delete(Kind kind, String id) {
        return jdbc.sql("DELETE FROM managed_document WHERE kind = ? AND id = ?").param(kind.name()).param(id).update() > 0;
    }
}
