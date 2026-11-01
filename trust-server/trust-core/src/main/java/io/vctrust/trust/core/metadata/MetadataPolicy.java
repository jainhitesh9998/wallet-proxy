package io.vctrust.trust.core.metadata;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * OpenID Federation 1.0 metadata policy (§6.1): operators {@code value}, {@code add}, {@code default},
 * {@code one_of}, {@code subset_of}, {@code superset_of} and {@code essential}.
 *
 * <p>Used both for federation trust chains and as the service's generic way to curate a registered entity's
 * live metadata (e.g. pin an issuer's {@code authorization_servers}).
 */
public final class MetadataPolicy {

    private static final List<String> ORDER = List.of("value", "add", "default", "one_of", "subset_of",
            "superset_of", "essential");

    private MetadataPolicy() {
    }

    public static final class PolicyException extends RuntimeException {
        public PolicyException(String message) {
            super(message);
        }
    }

    /**
     * Applies a policy (parameter name → operator map) to metadata and returns the resulting metadata.
     *
     * @throws PolicyException if the metadata violates the policy
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> apply(Map<String, Object> metadata, Map<String, Object> policy) {
        Map<String, Object> out = new LinkedHashMap<>(metadata == null ? Map.of() : metadata);
        if (policy == null) {
            return out;
        }
        for (Map.Entry<String, Object> p : policy.entrySet()) {
            String param = p.getKey();
            if (!(p.getValue() instanceof Map<?, ?> opsRaw)) {
                throw new PolicyException("Policy for '" + param + "' must be an object");
            }
            Map<String, Object> ops = (Map<String, Object>) opsRaw;
            for (String op : ORDER) {
                if (!ops.containsKey(op)) {
                    continue;
                }
                Object arg = ops.get(op);
                Object current = out.get(param);
                switch (op) {
                    case "value" -> {
                        if (arg == null) {
                            out.remove(param);
                        } else {
                            out.put(param, arg);
                        }
                    }
                    case "add" -> {
                        Set<Object> merged = new LinkedHashSet<>(asList(current));
                        merged.addAll(asList(arg));
                        out.put(param, new ArrayList<>(merged));
                    }
                    case "default" -> {
                        if (current == null) {
                            out.put(param, arg);
                        }
                    }
                    case "one_of" -> {
                        if (current != null && !asList(arg).contains(current)) {
                            throw new PolicyException("'" + param + "' value " + current + " is not one of " + arg);
                        }
                    }
                    case "subset_of" -> {
                        if (current != null) {
                            List<Object> kept = new ArrayList<>(asList(current));
                            kept.retainAll(asList(arg));
                            if (kept.isEmpty()) {
                                out.remove(param);
                            } else {
                                out.put(param, kept);
                            }
                        }
                    }
                    case "superset_of" -> {
                        if (current != null && !asList(current).containsAll(asList(arg))) {
                            throw new PolicyException("'" + param + "' must contain all of " + arg);
                        }
                    }
                    case "essential" -> {
                        if (Boolean.TRUE.equals(arg) && out.get(param) == null) {
                            throw new PolicyException("Essential parameter '" + param + "' is missing");
                        }
                    }
                    default -> throw new IllegalStateException(op);
                }
            }
        }
        return out;
    }

    /**
     * Combines a superior policy with a subordinate one (OpenID Federation §6.1.4.1). Conflicting
     * {@code value}/{@code default} operators or disjoint {@code one_of}/{@code subset_of} are errors.
     */
    @SuppressWarnings("unchecked")
    public static Map<String, Object> merge(Map<String, Object> superior, Map<String, Object> subordinate) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (superior != null) {
            superior.forEach((k, v) -> out.put(k, new LinkedHashMap<>((Map<String, Object>) v)));
        }
        if (subordinate == null) {
            return out;
        }
        for (Map.Entry<String, Object> e : subordinate.entrySet()) {
            Map<String, Object> sub = (Map<String, Object>) e.getValue();
            Map<String, Object> sup = (Map<String, Object>) out.computeIfAbsent(e.getKey(), k -> new LinkedHashMap<>());
            for (Map.Entry<String, Object> op : sub.entrySet()) {
                Object a = sup.get(op.getKey());
                Object b = op.getValue();
                if (a == null) {
                    sup.put(op.getKey(), b);
                    continue;
                }
                switch (op.getKey()) {
                    case "value", "default" -> {
                        if (!Objects.equals(a, b)) {
                            throw new PolicyException("Conflicting '" + op.getKey() + "' for " + e.getKey());
                        }
                    }
                    case "add", "superset_of" -> {
                        Set<Object> u = new LinkedHashSet<>(asList(a));
                        u.addAll(asList(b));
                        sup.put(op.getKey(), new ArrayList<>(u));
                    }
                    case "one_of", "subset_of" -> {
                        List<Object> i = new ArrayList<>(asList(a));
                        i.retainAll(asList(b));
                        if (i.isEmpty()) {
                            throw new PolicyException("Disjoint '" + op.getKey() + "' for " + e.getKey());
                        }
                        sup.put(op.getKey(), i);
                    }
                    case "essential" -> sup.put("essential", Boolean.TRUE.equals(a) || Boolean.TRUE.equals(b));
                    default -> sup.put(op.getKey(), b);
                }
            }
        }
        return out;
    }

    private static List<Object> asList(Object v) {
        if (v == null) {
            return List.of();
        }
        if (v instanceof List<?> l) {
            return new ArrayList<>(l);
        }
        return List.of(v);
    }
}
