package io.vctrust.trust.core.registry;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** Holds the current {@link RegistrySnapshot} and notifies listeners when a new one is published. */
public class TrustRegistry {

    private final AtomicReference<RegistrySnapshot> current = new AtomicReference<>(RegistrySnapshot.empty());
    private final List<Consumer<RegistrySnapshot>> listeners = new CopyOnWriteArrayList<>();

    public RegistrySnapshot snapshot() {
        return current.get();
    }

    public void publish(RegistrySnapshot snapshot) {
        current.set(snapshot);
        for (Consumer<RegistrySnapshot> l : listeners) {
            try {
                l.accept(snapshot);
            } catch (RuntimeException ignored) {
                // a failing listener must not block publication
            }
        }
    }

    public void onChange(Consumer<RegistrySnapshot> listener) {
        listeners.add(listener);
    }
}
