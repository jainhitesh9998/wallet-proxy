package io.vctrust.trust.adapters.mapped;

import java.time.Clock;
import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * What the lookups of a mapped source remember: answers, misses and failures, each until it expires. Callers choose
 * what is asked, so the memo is bounded twice: in entries, and in what they weigh (the characters of mapped text an
 * answer holds, and its key). When either bound is reached, the least recently used entries go first; an entry that
 * weighs more than the whole memo may is not kept at all. Expired entries go whenever something is put.
 */
final class Memo<V> {

    private record Entry<V>(V value, Instant expiresAt, long weight) {
    }

    private final int maxEntries;
    private final long maxWeight;
    private final Clock clock;
    private final LinkedHashMap<String, Entry<V>> entries = new LinkedHashMap<>(16, 0.75f, true);
    private long weight;
    /** When the first entry held expires, at the earliest: before then, a put has nothing to drop. */
    private Instant firstExpiry;

    Memo(int maxEntries, long maxWeight, Clock clock) {
        this.maxEntries = maxEntries;
        this.maxWeight = maxWeight;
        this.clock = clock;
    }

    /** The value, when present and not expired. */
    synchronized Optional<V> get(String key) {
        Entry<V> e = entries.get(key);
        if (e == null) {
            return Optional.empty();
        }
        if (!e.expiresAt().isAfter(clock.instant())) {
            remove(key);
            return Optional.empty();
        }
        return Optional.of(e.value());
    }

    /** @param weight what the value holds (characters of mapped text); the key's length is added to it */
    synchronized void put(String key, V value, Instant expiresAt, long weight) {
        Instant now = clock.instant();
        if (firstExpiry != null && !firstExpiry.isAfter(now)) {
            // At most one pass over the (bounded) memo for each time an entry may have expired.
            firstExpiry = null;
            for (Iterator<Map.Entry<String, Entry<V>>> it = entries.entrySet().iterator(); it.hasNext(); ) {
                Entry<V> e = it.next().getValue();
                if (!e.expiresAt().isAfter(now)) {
                    this.weight -= e.weight();
                    it.remove();
                } else if (firstExpiry == null || e.expiresAt().isBefore(firstExpiry)) {
                    firstExpiry = e.expiresAt();
                }
            }
        }
        remove(key);
        long w = weight + key.length();
        if (w > maxWeight) {
            return;
        }
        entries.put(key, new Entry<>(value, expiresAt, w));
        this.weight += w;
        for (Iterator<Map.Entry<String, Entry<V>>> it = entries.entrySet().iterator();
             it.hasNext() && (entries.size() > maxEntries || this.weight > maxWeight); ) {
            this.weight -= it.next().getValue().weight();
            it.remove();
        }
        if (firstExpiry == null || expiresAt.isBefore(firstExpiry)) {
            firstExpiry = expiresAt;
        }
    }

    synchronized int size() {
        return entries.size();
    }

    /** What the entries held weigh, all together. */
    synchronized long weight() {
        return weight;
    }

    private void remove(String key) {
        Entry<V> e = entries.remove(key);
        if (e != null) {
            weight -= e.weight();
        }
    }
}
