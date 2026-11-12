package io.vctrust.trust.server.config;

import org.springframework.beans.BeanUtils;
import org.springframework.boot.context.properties.source.ConfigurationProperty;
import org.springframework.boot.context.properties.source.ConfigurationPropertyName;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.ConfigurationPropertySources;
import org.springframework.boot.context.properties.source.IterableConfigurationPropertySource;
import org.springframework.boot.origin.Origin;
import org.springframework.boot.origin.PropertySourceOrigin;
import org.springframework.core.ResolvableType;
import org.springframework.core.env.CommandLinePropertySource;
import org.springframework.core.env.Environment;
import org.springframework.core.env.PropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.beans.PropertyDescriptor;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * The names a configuration may set under {@code trust.}, derived from {@link TrustProperties} (its bean properties,
 * recursively), and the check at startup that every property under {@code trust.} is one of them.
 *
 * <p>A name that binds to nothing would be dropped without a word: a misspelt {@code trust.revocaton.enabled}, or
 * trust mechanisms written as a map by id instead of a list, and the service would run without what the operator
 * believes is configured. So such a name stops the service, with the name and where it was written.
 *
 * <p>List indices are not part of a name: {@code trust.clients[1].frameworks[0]} is the known property
 * {@code trust.clients[].frameworks[]} whatever its indices. Spring Boot takes a list as a whole from the source of
 * highest precedence that sets any of it, so a lower source's longer list, or members its elements name that the
 * replacing ones do not, are left behind unbound; that is a replacement, not a mistake, and is not refused. Names are
 * compared as Spring's relaxed binding compares them: kebab case, camel case and underscores are one name. Below a
 * map that the configuration reads as it comes ({@code sources[].properties}, a framework's {@code attributes},
 * {@code did.registries}, each of {@code mechanisms}) any name is accepted; the trust mechanisms are read strictly by
 * their own reader ({@code TrustMechanisms}).
 *
 * <p>Environment variables and system properties are not checked, as Spring Boot left them out of its own check
 * before: a variable that merely starts with {@code TRUST_} (a container platform sets such variables for a service
 * of that name) does not stop the service.
 */
final class TrustPropertyNames {

    private static final ConfigurationPropertyName TRUST = ConfigurationPropertyName.of("trust");
    private static final Set<String> NOT_CHECKED = Set.of(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME,
            StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);

    /** What the configuration knows at one place of a name. */
    private sealed interface Node permits Members, ListOf, AnyBelow, Value {
    }

    /** A configuration object: its members by their uniform name. */
    private record Members(Map<String, Node> members) implements Node {
    }

    /** A list: below it, an index and then what an element is. */
    private record ListOf(Node element) implements Node {
    }

    /** A map read as it comes: any name below it. */
    private record AnyBelow() implements Node {
    }

    /** A single value: nothing below it. */
    private record Value() implements Node {
    }

    private static final Node ROOT = node(ResolvableType.forClass(TrustProperties.class));

    private TrustPropertyNames() {
    }

    /** Stops the service when a configuration file or argument sets a property under {@code trust.} that is not known. */
    static void check(Environment environment) {
        List<String> problems = problems(ConfigurationPropertySources.get(environment));
        if (!problems.isEmpty()) {
            throw new IllegalStateException("Configuration under trust. that this service does not know (a misspelt name would "
                    + "otherwise be ignored): " + String.join("; ", problems));
        }
    }

    /** One message per property under {@code trust.} that the sources set and the configuration does not know. */
    static List<String> problems(Iterable<ConfigurationPropertySource> sources) {
        List<String> out = new ArrayList<>();
        for (ConfigurationPropertySource source : sources) {
            if (!(source instanceof IterableConfigurationPropertySource names)
                    || source.getUnderlyingSource() instanceof PropertySource<?> ps && NOT_CHECKED.contains(ps.getName())) {
                continue;
            }
            names.stream().filter(TRUST::isAncestorOf).forEach(name -> problem(name).ifPresent(p -> out.add(name + " (" + origin(source, name) + ") " + p)));
        }
        return out;
    }

    /** Why {@code name} is not a property the configuration knows; empty when it is one. */
    static Optional<String> problem(ConfigurationPropertyName name) {
        Node node = ROOT;
        for (int i = TRUST.getNumberOfElements(); i < name.getNumberOfElements(); i++) {
            String element = name.getElement(i, ConfigurationPropertyName.Form.ORIGINAL);
            switch (node) {
                case AnyBelow any -> {
                    return Optional.empty();
                }
                case Value value -> {
                    return Optional.of("is not a property this service knows: " + name.chop(i) + " is a single value");
                }
                case ListOf list -> {
                    if (!name.isNumericIndex(i) && !element.matches("[0-9]+")) {
                        return Optional.of("is not a property this service knows: " + name.chop(i) + " is a list, and '"
                                + element + "' is not an index");
                    }
                    node = list.element();
                }
                case Members members -> {
                    node = members.members().get(uniform(element));
                    if (node == null) {
                        return Optional.of("is not a property this service knows");
                    }
                }
            }
        }
        return Optional.empty();
    }

    /** Where a property was written: a file with line and column, an argument, or the property source that holds it. */
    private static String origin(ConfigurationPropertySource source, ConfigurationPropertyName name) {
        ConfigurationProperty property = source.getConfigurationProperty(name);
        Origin origin = property == null ? null : property.getOrigin();
        if (origin != null && !(origin instanceof PropertySourceOrigin)) {
            return "from " + origin;
        }
        if (source.getUnderlyingSource() instanceof PropertySource<?> ps) {
            return CommandLinePropertySource.COMMAND_LINE_PROPERTY_SOURCE_NAME.equals(ps.getName())
                    ? "from a command-line argument" : "from property source '" + ps.getName() + "'";
        }
        return "from " + source;
    }

    /** As Spring's relaxed binding compares an element: lower case, letters and digits only. */
    private static String uniform(String element) {
        return element.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]", "");
    }

    private static Node node(ResolvableType type) {
        Class<?> c = type.resolve(Object.class);
        if (c.isArray() || Collection.class.isAssignableFrom(c)) {
            return new ListOf(node(c.isArray() ? type.getComponentType() : type.asCollection().getGeneric(0)));
        }
        if (Map.class.isAssignableFrom(c)) {
            return new AnyBelow();
        }
        if (BeanUtils.isSimpleValueType(c) || c.getName().startsWith("java.")) {
            return new Value();
        }
        Map<String, Node> members = new LinkedHashMap<>();
        for (PropertyDescriptor p : BeanUtils.getPropertyDescriptors(c)) {
            Method write = p.getWriteMethod();
            if (write == null) {
                continue;  // not bound by the configuration (getClass, a derived value)
            }
            members.put(uniform(p.getName()), node(ResolvableType.forMethodParameter(write, 0)));
        }
        return new Members(members);
    }
}
