package io.vctrust.trust.core.util;

import java.time.Clock;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * A small bounded map whose entries expire: for answers of on-demand registries, which must neither grow without
 * limit (the keys are chosen by callers) nor outlive a change in the registry. The least recently used entry goes
 * when the map is full.
 */
public final class ExpiringMap<K, V> {

    private record Entry<V>(V value, Instant expiresAt) {
    }

    private final Map<K, Entry<V>> entries;
    private final Clock clock;

    public ExpiringMap(int maxEntries, Clock clock) {
        this.clock = clock;
        this.entries = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<K, Entry<V>> eldest) {
                return size() > maxEntries;
            }
        };
    }

    /** The value, when present and not expired. */
    public synchronized Optional<V> get(K key) {
        Entry<V> e = entries.get(key);
        if (e == null) {
            return Optional.empty();
        }
        if (!e.expiresAt().isAfter(clock.instant())) {
            entries.remove(key);
            return Optional.empty();
        }
        return Optional.of(e.value());
    }

    public synchronized void put(K key, V value, Instant expiresAt) {
        entries.put(key, new Entry<>(value, expiresAt));
    }

    public synchronized int size() {
        return entries.size();
    }
}
