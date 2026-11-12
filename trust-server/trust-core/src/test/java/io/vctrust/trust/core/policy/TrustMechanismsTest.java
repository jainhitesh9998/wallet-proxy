package io.vctrust.trust.core.policy;

import io.vctrust.trust.core.model.EntityRole;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The configuration of trust mechanisms is read strictly, and a mechanism governs exactly the questions its {@code for} names. */
class TrustMechanismsTest {

    /** The example of the configuration guide, as YAML gives it: typed scalars. */
    static Map<String, Object> nationalId() {
        Map<String, Object> leaf = new LinkedHashMap<>();
        leaf.put("ca", false);
        leaf.put("key-usage", List.of("digitalSignature"));
        leaf.put("extended-key-usage", List.of("1.3.6.1.4.1.99999.1.1"));
        leaf.put("same-country-as-anchor", true);
        leaf.put("max-validity-days", 1100);
        leaf.put("crl-distribution-point", true);
        Map<String, Object> profile = new LinkedHashMap<>();
        profile.put("leaf", leaf);
        profile.put("max-intermediates", 0);
        Map<String, Object> x509 = new LinkedHashMap<>();
        x509.put("domain", "national-id");
        x509.put("profile", profile);
        x509.put("revocation", "required");
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", "national-id");
        m.put("for", new LinkedHashMap<>(Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.example.id.*"))));
        m.put("keys", List.of("x5c"));
        m.put("x509", x509);
        return m;
    }

    static Map<String, Object> mechanism(String id, Map<String, Object> question, Object... members) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("for", question);
        for (int i = 0; i < members.length; i += 2) {
            m.put((String) members[i], members[i + 1]);
        }
        return m;
    }

    /** A copy of the tree with the value at {@code path} (dotted) replaced, or removed when {@code value} is null. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> with(Map<String, Object> tree, String path, Object value) {
        Map<String, Object> copy = deepCopy(tree);
        String[] parts = path.split("\\.");
        Map<String, Object> at = copy;
        for (int i = 0; i < parts.length - 1; i++) {
            at = (Map<String, Object>) at.get(parts[i]);
        }
        if (value == null) {
            at.remove(parts[parts.length - 1]);
        } else {
            at.put(parts[parts.length - 1], value);
        }
        return copy;
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> deepCopy(Map<String, Object> m) {
        Map<String, Object> out = new LinkedHashMap<>();
        m.forEach((k, v) -> out.put(k, v instanceof Map<?, ?> sub ? deepCopy((Map<String, Object>) sub) : v instanceof List<?> l ? new ArrayList<>(l) : v));
        return out;
    }

    static TrustMechanisms read(Object... mechanisms) {
        return TrustMechanisms.fromConfiguration(List.of(mechanisms));
    }

    @Test
    void readsTheGuidesExampleIntoTheClaimsOneForm() {
        TrustMechanisms m = read(nationalId());
        assertThat(m.ids()).containsExactly("national-id");
        Map<String, Object> claim = m.claim().getFirst();
        assertThat(claim).isEqualTo(Map.of(
                "id", "national-id",
                "for", Map.of("role", "issuer", "formats", List.of("mso_mdoc"), "types", List.of("org.example.id.*")),
                "keys", List.of("x5c"),
                "x509", Map.of("domain", "national-id", "revocation", "required", "profile", Map.of(
                        "leaf", Map.of("ca", false, "keyUsage", List.of("digitalSignature"), "extendedKeyUsage", List.of("1.3.6.1.4.1.99999.1.1"),
                                "sameCountryAsAnchor", true, "maxValidityDays", 1100, "crlDistributionPoint", true),
                        "maxIntermediates", 0))));
        // Members in one order, so that the claim (and the snapshot's digest) does not depend on how a map was built.
        assertThat(claim.keySet()).containsExactly("id", "for", "keys", "x509");
        assertThat(((Map<?, ?>) claim.get("x509")).keySet().stream().map(String::valueOf).toList()).containsExactly("domain", "profile", "revocation");
    }

    @Test
    void readsScalarsGivenAsTextAsPropertiesAndTheEnvironmentGiveThem() {
        Map<String, Object> asText = with(with(with(with(nationalId(), "x509.profile.leaf.ca", "false"), "x509.profile.leaf.max-validity-days", "1100"),
                "x509.profile.max-intermediates", "0"), "x509.profile.leaf.crl-distribution-point", "true");
        assertThat(read(asText).claim()).isEqualTo(read(nationalId()).claim());
    }

    @Test
    void leavesOutWhatIsNotConfigured() {
        TrustMechanisms m = read(mechanism("any-did", Map.of("role", "verifier"), "did", Map.of("methods", List.of("web"))));
        assertThat(m.claim().getFirst()).isEqualTo(Map.of("id", "any-did", "for", Map.of("role", "verifier"), "did", Map.of("methods", List.of("web"))));
        assertThat(m.list().getFirst().accepts("x5c")).isTrue();
        assertThat(m.list().getFirst().accepts("jwk")).isTrue();
    }

    @Test
    void writesFormatsInTheirCanonicalSpelling() {
        TrustMechanisms m = read(mechanism("sd", Map.of("role", "issuer", "formats", List.of("vc+sd-jwt"))));
        assertThat(m.list().getFirst().question().formats()).containsExactly("dc+sd-jwt");
        assertThatThrownBy(() -> read(mechanism("sd", Map.of("role", "issuer", "formats", List.of("vc+sd-jwt", "dc+sd-jwt")))))
                .hasMessageContaining("trust.mechanisms[0] ('sd')").hasMessageContaining("dc+sd-jwt twice");
    }

    @Test
    void refusesWhatItDoesNotUnderstandAndNamesTheMechanism() {
        Map<String, Map<String, Object>> broken = new LinkedHashMap<>();
        broken.put("unknown member at the top", with(nationalId(), "x5c", List.of("x")));
        broken.put("unknown member of for", with(nationalId(), "for.issuer", "https://x.example"));
        broken.put("unknown member of x509", with(nationalId(), "x509.anchors", List.of("a")));
        broken.put("unknown member of the profile", with(nationalId(), "x509.profile.root", Map.of("ca", true)));
        broken.put("unknown member of the leaf", with(nationalId(), "x509.profile.leaf.policy", "1.2.3"));
        broken.put("camelCase member", with(with(nationalId(), "x509.profile.leaf.key-usage", null), "x509.profile.leaf.keyUsage", List.of("digitalSignature")));
        broken.put("unknown member of did", mechanism("d", Map.of("role", "issuer"), "did", Map.of("methods", List.of("web"), "resolver", "x")));
        broken.put("unknown role", with(nationalId(), "for.role", "authorization_server"));
        broken.put("role in another spelling", with(nationalId(), "for.role", "CREDENTIAL_ISSUER"));
        broken.put("no role", with(nationalId(), "for.role", null));
        broken.put("no for", with(nationalId(), "for", null));
        broken.put("unknown format", with(nationalId(), "for.formats", List.of("mdoc")));
        broken.put("empty formats", with(nationalId(), "for.formats", List.of()));
        broken.put("formats not a list", with(nationalId(), "for.formats", "mso_mdoc"));
        broken.put("type with * inside", with(nationalId(), "for.types", List.of("org.*.id")));
        broken.put("type that is only *", with(nationalId(), "for.types", List.of("*")));
        broken.put("type with a space", with(nationalId(), "for.types", List.of("org example")));
        broken.put("type twice", with(nationalId(), "for.types", List.of("a", "a")));
        broken.put("unknown key kind", with(nationalId(), "keys", List.of("x5c", "cose")));
        broken.put("empty keys", with(nationalId(), "keys", List.of()));
        broken.put("x509 when keys does not accept x5c", with(nationalId(), "keys", List.of("did")));
        broken.put("did when keys does not accept did", mechanism("d", Map.of("role", "issuer"), "keys", List.of("x5c"), "did", Map.of("methods", List.of("web"))));
        broken.put("did without methods", mechanism("d", Map.of("role", "issuer"), "did", Map.of()));
        broken.put("did method in upper case", mechanism("d", Map.of("role", "issuer"), "did", Map.of("methods", List.of("Web"))));
        broken.put("empty x509", with(nationalId(), "x509", Map.of()));
        broken.put("empty profile", with(nationalId(), "x509.profile", Map.of()));
        broken.put("empty leaf", with(nationalId(), "x509.profile.leaf", Map.of()));
        broken.put("domain in upper case", with(nationalId(), "x509.domain", "National-ID"));
        broken.put("domain with a space", with(nationalId(), "x509.domain", "national id"));
        broken.put("revocation other than required", with(nationalId(), "x509.revocation", "optional"));
        broken.put("leaf.ca true", with(nationalId(), "x509.profile.leaf.ca", true));
        broken.put("leaf.ca not a boolean", with(nationalId(), "x509.profile.leaf.ca", "no"));
        broken.put("unknown key usage", with(nationalId(), "x509.profile.leaf.key-usage", List.of("signing")));
        broken.put("key usage that this parser and the library's do not both read", with(nationalId(), "x509.profile.leaf.key-usage", List.of("encipherOnly")));
        broken.put("extended key usage that is not an OID", with(nationalId(), "x509.profile.leaf.extended-key-usage", List.of("serverAuth")));
        broken.put("extended key usage with an arc too long", with(nationalId(), "x509.profile.leaf.extended-key-usage", List.of("1.2.1234567890123456")));
        broken.put("same-country-as-anchor false", with(nationalId(), "x509.profile.leaf.same-country-as-anchor", false));
        broken.put("crl-distribution-point false", with(nationalId(), "x509.profile.leaf.crl-distribution-point", "false"));
        broken.put("max-validity-days 0", with(nationalId(), "x509.profile.leaf.max-validity-days", 0));
        broken.put("max-validity-days not a number", with(nationalId(), "x509.profile.leaf.max-validity-days", "3 years"));
        broken.put("max-validity-days a fraction", with(nationalId(), "x509.profile.leaf.max-validity-days", 1.5));
        broken.put("max-intermediates negative", with(nationalId(), "x509.profile.max-intermediates", -1));
        broken.put("max-intermediates beyond a chain", with(nationalId(), "x509.profile.max-intermediates", 10));
        for (Map.Entry<String, Map<String, Object>> e : broken.entrySet()) {
            String id = String.valueOf(e.getValue().get("id"));
            assertThatThrownBy(() -> read(e.getValue())).as(e.getKey()).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageStartingWith("Trust mechanism trust.mechanisms[0] ('" + id + "'): ");
        }
    }

    @Test
    void refusesAnEntryWithoutAValidIdOrADuplicateId() {
        assertThatThrownBy(() -> read(with(nationalId(), "id", null))).hasMessage("Trust mechanism trust.mechanisms[0]: id is required");
        assertThatThrownBy(() -> read(with(nationalId(), "id", "national id"))).hasMessageContaining("trust.mechanisms[0]: id must be");
        assertThatThrownBy(() -> read(nationalId(), nationalId())).hasMessage(
                "Trust mechanism trust.mechanisms[1] ('national-id'): the id is already used by trust.mechanisms[0]; ids must be unique");
        assertThatThrownBy(() -> TrustMechanisms.fromConfiguration(List.of("national-id"))).hasMessageContaining("must be a map of members");
    }

    @Test
    void theFirstMechanismThatMatchesGoverns() {
        TrustMechanisms m = read(
                mechanism("exact", Map.of("role", "issuer", "formats", List.of("ldp_vc"), "types", List.of("UniversityDegreeCredential"))),
                mechanism("prefix", Map.of("role", "issuer", "types", List.of("org.example.id.*"))),
                mechanism("any-ldp", Map.of("role", "issuer", "formats", List.of("ldp_vc"))),
                mechanism("verifiers", Map.of("role", "verifier")));
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "ldp_vc", "UniversityDegreeCredential")).isEqualTo("exact");
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "ldp_vc", "UniversityDegreeCredential2")).isEqualTo("any-ldp");
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "mso_mdoc", "org.example.id.card")).isEqualTo("prefix");
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "mso_mdoc", "org.example.idcard")).isNull();
        // A question that asserts no type matches only a mechanism without types; one that names no format, only one without formats.
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "ldp_vc")).isEqualTo("any-ldp");
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, null)).isNull();
        assertThat(select(m, EntityRole.VERIFIER, null)).isEqualTo("verifiers");
        assertThat(select(m, EntityRole.WALLET_PROVIDER, null)).isNull();
        assertThat(select(m, null, "ldp_vc", "UniversityDegreeCredential")).isNull();
        // Any of the types a question asserts: the order they are listed in does not let a question past a mechanism.
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "ldp_vc", "OtherCredential", "UniversityDegreeCredential")).isEqualTo("exact");
        assertThat(select(m, EntityRole.CREDENTIAL_ISSUER, "jwt_vc_json", "OtherCredential", "org.example.id.x")).isEqualTo("prefix");
    }

    static String select(TrustMechanisms m, EntityRole role, String format, String... types) {
        TrustMechanism found = m.select(role, format, Set.of(types));
        return found == null ? null : found.id();
    }
}
