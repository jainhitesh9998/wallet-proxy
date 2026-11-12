package io.vctrust.trust.adapters;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityStatus;
import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.HttpFetcher;
import io.vctrust.trust.adapters.mapped.MappedSourceFactory;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.OnDemandResolver;
import io.vctrust.trust.core.spi.ResourceLoader;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.Certificates;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static io.vctrust.trust.adapters.MappedTesting.jwks;
import static io.vctrust.trust.adapters.MappedTesting.key;
import static io.vctrust.trust.adapters.MappedTesting.manager;
import static io.vctrust.trust.adapters.MappedTesting.sign;
import static io.vctrust.trust.adapters.MappedTesting.signer;
import static io.vctrust.trust.adapters.MappedTesting.source;
import static io.vctrust.trust.adapters.MappedTesting.state;
import static io.vctrust.trust.adapters.MappedTesting.utf8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The rules of a mapped source (docs/configuration.md, "Mapped sources"), one test or more for each. */
@SuppressWarnings("unchecked")
class MappedSourceRulesTest {

    static final String LOCATION = "https://registry.partner.example/v1/issuers";
    static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    static final String TOKEN = "Bearer s3cret-token-value";

    static TestContext ctx() {
        TestContext ctx = new TestContext();
        ctx.clock = Clock.fixed(NOW, ZoneOffset.UTC);
        return ctx;
    }

    static Map<String, Object> mapping() {
        return Json.parseObject("""
                {"list": {"issuer": "$.publisher", "sequence": "$.version", "issuedAt": "$.issued", "nextUpdate": "$.next_update"},
                 "entities": [{"each": "$.issuers[*]", "id": {"template": "partner:{$.id}"}, "roles": ["CREDENTIAL_ISSUER"],
                   "name": "$.name", "identifiers": [{"type": "URL", "value": "$.credential_issuer"}],
                   "status": {"path": "$.state", "values": {"active": "ACTIVE", "suspended": "SUSPENDED"}, "default": "REVOKED"}}]}""");
    }

    /** A list in the partner's shape, version {@code v} issued {@code 10 - v} days ago, with one issuer per id. */
    static Map<String, Object> doc(int v, Instant nextUpdate, String... ids) {
        List<Object> issuers = new ArrayList<>();
        for (String id : ids) {
            issuers.add(Map.of("id", id, "name", "Issuer " + id, "credential_issuer", "https://" + id + ".example", "state", "active"));
        }
        Map<String, Object> d = new LinkedHashMap<>();
        d.put("publisher", "Partner");
        d.put("version", v);
        d.put("issued", NOW.minus(Duration.ofDays(10 - v)).toString());
        d.put("next_update", nextUpdate.toString());
        d.put("issuers", issuers);
        return d;
    }

    static Map<String, Object> doc(String... ids) {
        return doc(1, NOW.plus(Duration.ofDays(7)), ids);
    }

    static Map<String, Object> props(Object... kv) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("location", LOCATION);
        p.put("mapping", mapping());
        for (int i = 0; i < kv.length; i += 2) {
            if (kv[i + 1] == null) {
                p.remove((String) kv[i]);
            } else {
                p.put((String) kv[i], kv[i + 1]);
            }
        }
        return p;
    }

    static void serveJson(TestContext ctx, Object doc) {
        ctx.http.json(LOCATION, doc instanceof String s ? s : Json.write(doc));
    }

    static void serveJws(TestContext ctx, String compact) {
        ctx.http.respond(LOCATION, 200, "application/jwt", utf8(compact));
    }

    static String loadError(TrustSource source) {
        try {
            source.load();
        } catch (TrustSourceException e) {
            return e.getMessage();
        }
        throw new AssertionError("the load did not fail");
    }

    // Rule 1 ----------------------------------------------------------------------------------------------------

    @Test
    void rule1_anythingUnknownIsAConfigurationErrorThatTheSourceStateShows() {
        Map<String, Object> badMember = mapping();
        ((Map<String, Object>) ((List<?>) badMember.get("entities")).getFirst()).put("nmae", "$.name");
        Map<String, Object> badForm = mapping();
        ((Map<String, Object>) ((List<?>) badForm.get("entities")).getFirst()).put("status", Map.of("path", "$.state", "map", Map.of("a", "ACTIVE")));
        Map<String, Object> badEnum = mapping();
        ((Map<String, Object>) ((List<?>) badEnum.get("entities")).getFirst()).put("roles", List.of("ISSUER"));
        Map<String, Object> fileMember = mapping();
        ((Map<String, Object>) ((List<?>) fileMember.get("entities")).getFirst()).put("certificateLocation", "$.file");
        Map<String, Map<String, Object>> cases = new LinkedHashMap<>();
        cases.put("unknown property [locaton]", props("locaton", LOCATION));
        cases.put("mapping.entities[0]: unknown member [nmae]", props("mapping", badMember));
        cases.put("mapping.entities[0].status: unknown value form with members [map, path]", props("mapping", badForm));
        cases.put("mapping.entities[0].roles: Unknown role 'ISSUER'", props("mapping", badEnum));
        cases.put("mapping.entities[0]: unknown member [certificateLocation]", props("mapping", fileMember));
        cases.put("format must be json or jws, not 'xml'", props("format", "xml"));
        cases.put("verify: unknown member [kid]", props("format", "jws", "verify", Map.of("jwks", jwks(key("k1")), "kid", "k1")));
        cases.put("limits: unknown member [records]", props("limits", Map.of("records", 5)));
        cases.put("allowExpired must be true or false", props("allowExpired", "yes"));
        cases.forEach((message, properties) -> {
            TestContext ctx = ctx();
            serveJson(ctx, doc("a"));
            TrustSource s = source(ctx, properties);
            TrustRegistry registry = new TrustRegistry();
            try (TrustSourceManager m = manager(registry, s)) {
                SourceState st = state(m, "partner");
                assertThat(st.lastError()).as(message).startsWith("Source 'partner' (mapped): ").contains(message);
                assertThat(st.lastSuccess()).isNull();
                assertThat(m.ready()).isFalse();
                assertThat(registry.snapshot().entities()).isEmpty();
            }
            assertThat(ctx.http.requests).as("nothing is fetched for a source whose configuration is wrong").isEmpty();
        });
    }

    // Rule 2 ----------------------------------------------------------------------------------------------------

    @Test
    void rule2_aJwsListIsVerifiedWithThePinnedKeysBeforeAnythingIsRead() throws Exception {
        ECKey k1 = key("k1");
        ECKey k2 = key("k2");
        ECKey stranger = key("k1");
        Map<String, Object> p = props("format", "jws", "verify", Map.of("jwks", jwks(k1, k2)));
        TestContext ctx = ctx();
        TrustSource s = source(ctx, p);

        serveJws(ctx, sign(k1, doc("a", "b")));
        SourceLoadResult r = s.load();
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
        assertThat(r.entities()).extracting(TrustedEntity::id).containsExactly("partner:a", "partner:b");
        assertThat(ctx.http.requests.getLast().headers()).containsEntry("Accept", "application/jwt, application/jose");

        // Without a kid, every pinned key is tried.
        serveJws(ctx, sign(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), signer(k2), doc("a")));
        assertThat(s.load().entities()).hasSize(1);

        serveJws(ctx, sign(stranger, doc("a")));
        assertThat(loadError(s)).contains("signature does not verify with the pinned keys");
        serveJws(ctx, sign(key("k9"), doc("a")));
        assertThat(loadError(s)).contains("No pinned key has the kid");
        // The payload of one signed list under the signature of another.
        String[] good = sign(k1, doc("a")).split("\\.");
        String[] other = sign(k1, doc("a", "evil")).split("\\.");
        serveJws(ctx, good[0] + "." + other[1] + "." + good[2]);
        assertThat(loadError(s)).contains("does not verify");
        // Symmetric algorithms and none are never accepted.
        serveJws(ctx, sign(new JWSHeader.Builder(JWSAlgorithm.HS256).keyID("k1").build(), new MACSigner(new byte[32]), doc("a")));
        assertThat(loadError(s)).contains("HS256, which is not accepted");
        String none = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(utf8("{\"alg\":\"none\"}"));
        serveJws(ctx, none + "." + good[1] + ".");
        assertThat(loadError(s)).contains("not a compact JWS");
        serveJws(ctx, none + "." + good[1] + ".c2ln");
        assertThat(loadError(s)).contains("not a JWS");
        // A parameter marked critical is refused, whatever it is.
        serveJws(ctx, sign(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("k1").criticalParams(Set.of("urn:example:x"))
                .customParam("urn:example:x", true).build(), signer(k1), doc("a")));
        assertThat(loadError(s)).contains("crit");
        serveJson(ctx, doc("a"));
        assertThat(loadError(s)).contains("not a compact JWS");

        // With verify.typ, the header must say what the document is.
        TrustSource typed = source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "typ", "partner-list+jwt")));
        serveJws(ctx, sign(k1, doc("a")));
        assertThat(loadError(typed)).contains("typ is absent, not 'partner-list+jwt'");
        serveJws(ctx, sign(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("k1").type(new JOSEObjectType("application/partner-list+jwt")).build(),
                signer(k1), doc("a")));
        assertThat(typed.load().entities()).hasSize(1);
    }

    @Test
    void rule2_pinnedKeysComeFromTheConfigurationNeverFromTheNetwork() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        ctx.put("file:/etc/trust/partner-jwks.json", jwks(k1));
        ctx.put("classpath:partner-jwks.json", jwks(k1));
        ctx.http.json("https://registry.partner.example/jwks.json", jwks(k1));
        serveJws(ctx, sign(k1, doc("a")));
        assertThat(source(ctx, props("format", "jws", "verify", Map.of("jwksLocation", "file:/etc/trust/partner-jwks.json"))).load()
                .listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
        assertThat(source(ctx, props("format", "jws", "verify", Map.of("jwksLocation", "classpath:partner-jwks.json"))).load()
                .entities()).hasSize(1);
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwksLocation", "https://registry.partner.example/jwks.json")))))
                .contains("verify.jwksLocation must be a file: or classpath: location");
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("certificateLocation", "https://registry.partner.example/ca.pem")))))
                .contains("verify.certificateLocation must be a file: or classpath: location");
        assertThat(ctx.http.requests).noneMatch(r -> r.uri().getPath().endsWith("jwks.json") || r.uri().getPath().endsWith("ca.pem"));
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "certificates", List.of("x"))))))
                .contains("give one of");
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", new com.nimbusds.jose.jwk.JWKSet(k1).toString(false))))))
                .contains("holds a private key");
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", "{\"keys\":[{\"kty\":\"oct\",\"k\":\"AAAA\"}]}")))))
                .contains("only EC and RSA public keys");
    }

    @Test
    void rule2_withCertificatesTheX5cChainMustValidateToThePinnedOnes() throws Exception {
        TestPki.Issued root = TestPki.rootCa("CN=Partner List CA,C=UT");
        TestPki.Issued signerCert = TestPki.leaf("CN=Partner List Signer,C=UT", root, List.of(), null);
        TestPki.Issued otherRoot = TestPki.rootCa("CN=Other CA,C=UT");
        TestPki.Issued otherSigner = TestPki.leaf("CN=Partner List Signer,C=UT", otherRoot, List.of(), null);
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props("format", "jws", "verify", Map.of("certificates", List.of(Certificates.toPem(root.certificate())))));

        serveJws(ctx, signedWithChain(signerCert, signerCert, doc("a")));
        assertThat(s.load().listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.VERIFIED);
        serveJws(ctx, signedWithChain(otherSigner, otherSigner, doc("a")));
        assertThat(loadError(s)).contains("does not validate to a pinned certificate");
        serveJws(ctx, signedWithChain(signerCert, otherSigner, doc("a")));   // the pinned chain, another key's signature
        assertThat(loadError(s)).contains("does not verify with its x5c certificate");
        serveJws(ctx, sign(new JWSHeader.Builder(JWSAlgorithm.ES256).build(), new ECDSASigner(signerCert.keys().getPrivate(),
                com.nimbusds.jose.jwk.Curve.P_256), doc("a")));
        assertThat(loadError(s)).contains("carries no x5c chain");
    }

    static String signedWithChain(TestPki.Issued certificate, TestPki.Issued signingKey, Object payload) throws Exception {
        return sign(new JWSHeader.Builder(JWSAlgorithm.ES256).x509CertChain(List.of(Base64.encode(certificate.certificate().getEncoded()))).build(),
                new ECDSASigner(signingKey.keys().getPrivate(), com.nimbusds.jose.jwk.Curve.P_256), payload);
    }

    @Test
    void rule2_withoutPinnedKeysAJwsListLoadsOnlyWhenAllowedAndJsonIsNotSigned() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        serveJws(ctx, sign(k1, doc("a")));
        assertThat(loadError(source(ctx, props("format", "jws")))).contains("format: jws needs the keys the list is signed with");
        SourceLoadResult r = source(ctx, props("format", "jws", "allowUnverified", true)).load();
        assertThat(r.listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.NOT_CHECKED);
        assertThat(r.warnings()).contains("The list's signature is not verified (allowUnverified)");
        assertThat(loadError(source(ctx, props("format", "jws", "allowUnverified", true, "verify", Map.of("jwks", jwks(k1))))))
                .contains("contradict");

        serveJson(ctx, doc("a"));
        assertThat(source(ctx, props()).load().listInfo().signature()).isEqualTo(ListInfo.SignatureStatus.NOT_SIGNED);
        assertThat(loadError(source(ctx, props("verify", Map.of("jwks", jwks(k1)))))).contains("verify applies to format: jws only");
        assertThat(loadError(source(ctx, props("allowUnverified", true)))).contains("allowUnverified applies to format: jws only");
    }

    @Test
    void rule2_aSignedJwtIsHeldToItsClaims() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        Map<String, Object> claims = new LinkedHashMap<>(doc("a"));
        claims.put("exp", NOW.minus(Duration.ofHours(1)).getEpochSecond());
        serveJws(ctx, sign(k1, claims));
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)))))).contains("expired at");
        SourceLoadResult late = source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)), "allowExpired", true)).load();
        assertThat(late.warnings()).anyMatch(w -> w.contains("expired at"));

        claims.put("exp", NOW.plus(Duration.ofHours(1)).getEpochSecond());
        claims.put("aud", "wallet-proxy-b");
        serveJws(ctx, sign(k1, claims));
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1)))))).contains("addressed to 'wallet-proxy-b'");
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "audience", "someone-else")))))
                .contains("not to 'someone-else'");
        assertThat(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "audience", "wallet-proxy-b"))).load().entities()).hasSize(1);

        claims.put("nbf", NOW.plus(Duration.ofHours(1)).getEpochSecond());
        serveJws(ctx, sign(k1, claims));
        assertThat(loadError(source(ctx, props("format", "jws", "verify", Map.of("jwks", jwks(k1), "audience", "wallet-proxy-b")))))
                .contains("not valid before");
    }

    // Rule 3 ----------------------------------------------------------------------------------------------------

    @Test
    void rule3_aListPastItsNextUpdateIsNotLoadedUnlessAllowed() throws Exception {
        TestContext ctx = ctx();
        serveJson(ctx, doc(1, NOW.minus(Duration.ofDays(1)), "a"));
        assertThat(loadError(source(ctx, props()))).contains("past its next update");
        SourceLoadResult r = source(ctx, props("allowExpired", true)).load();
        assertThat(r.entities()).hasSize(1);
        assertThat(r.warnings()).anyMatch(w -> w.contains("past its next update"));
        assertThat(r.listInfo().nextUpdate()).isEqualTo(NOW.minus(Duration.ofDays(1)));

        // A fact the mapping reads from the list must be there: without it, the format has changed.
        Map<String, Object> d = doc("a");
        d.remove("next_update");
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props()))).contains("mapping.list.nextUpdate: the document has no value for it");
        d.put("next_update", "soon");
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props()))).contains("mapping.list.nextUpdate: the document has no date there: 'soon'");
        // Issued in the future, it would make every genuine list after it look older.
        d = doc("a");
        d.put("issued", NOW.plus(Duration.ofDays(1)).getEpochSecond());
        serveJson(ctx, d);
        assertThat(loadError(source(ctx, props()))).contains("in the future");

        d.put("issued", NOW.minus(Duration.ofDays(1)).getEpochSecond());   // seconds since the epoch are a date too
        serveJson(ctx, d);
        ListInfo info = source(ctx, props()).load().listInfo();
        assertThat(info.issuedAt()).isEqualTo(NOW.minus(Duration.ofDays(1)));
        assertThat(info.issuer()).isEqualTo("Partner");
        assertThat(info.sequence()).isEqualTo("1");
    }

    @Test
    void rule3_aListOlderThanTheOneHeldIsRefused() {
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props());
        TrustRegistry registry = new TrustRegistry();
        serveJson(ctx, doc(3, NOW.plus(Duration.ofDays(7)), "a", "b"));
        try (TrustSourceManager m = manager(registry, s)) {
            assertThat(registry.snapshot().entities()).hasSize(2);
            serveJson(ctx, doc(2, NOW.plus(Duration.ofDays(7)), "a"));   // issued earlier, lower version
            SourceState st = m.refresh("partner");
            assertThat(st.lastError()).contains("older than the one already loaded");
            assertThat(registry.snapshot().entities()).hasSize(2);
            Map<String, Object> sameDayLowerVersion = doc(3, NOW.plus(Duration.ofDays(7)), "a");
            sameDayLowerVersion.put("version", 2);
            serveJson(ctx, sameDayLowerVersion);
            assertThat(m.refresh("partner").lastError()).contains("older than the one already loaded");
            serveJson(ctx, doc(4, NOW.plus(Duration.ofDays(7)), "a"));
            assertThat(m.refresh("partner").lastError()).isNull();
            assertThat(registry.snapshot().entities()).hasSize(1);
        }
    }

    // Rule 4 ----------------------------------------------------------------------------------------------------

    @Test
    void rule4_headersGoOnlyToTheOriginOfLocation() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> m = mapping();
        m.put("pages", Map.of("next", "$.links.next"));
        m.put("lookup", Map.of("url", "https://lookup.elsewhere.example/v1/{identifier}", "identifierTypes", List.of("DID"),
                "startsWith", List.of("did:example:"), "entity", Map.of("id", "$.id", "identifiers", List.of(Map.of("type", "DID", "value", "$.did")))));
        Map<String, Object> page1 = doc("a");
        page1.put("links", Map.of("next", "/v1/issuers?page=2"));
        serveJson(ctx, page1);
        ctx.http.json(LOCATION + "?page=2", Json.write(doc("b")));
        ctx.http.json("https://lookup.elsewhere.example/v1/did%3Aexample%3Ax", "{\"id\": \"x\", \"did\": \"did:example:x\"}");
        TrustSource s = source(ctx, props("mapping", m, "headers", Map.of("Authorization", TOKEN, "X-Api-Key", "k")));

        assertThat(s.load().entities()).hasSize(2);
        assertThat(((OnDemandResolver) s).resolve(Identifier.did("did:example:x"))).isPresent();
        List<HttpFetcher.Request> requests = ctx.http.requests;
        assertThat(requests).hasSize(3);
        assertThat(requests.get(0).headers()).containsEntry("Authorization", TOKEN).containsEntry("X-Api-Key", "k");
        assertThat(requests.get(1).uri().toString()).isEqualTo(LOCATION + "?page=2");
        assertThat(requests.get(1).headers()).containsEntry("Authorization", TOKEN);
        assertThat(requests.get(2).uri().getHost()).isEqualTo("lookup.elsewhere.example");
        assertThat(requests.get(2).headers()).doesNotContainKeys("Authorization", "X-Api-Key").containsEntry("Accept", "application/json");
        // Not after a redirect to another origin either: SafeHttpFetcherTest.onlyAcceptFollowsARedirectToAnotherOrigin.
    }

    @Test
    void rule4_headerValuesAppearInNoMessageAndNoState() {
        TestContext ctx = ctx();
        ctx.http.respond(LOCATION, 401, "application/json", utf8("{\"error\": \"" + TOKEN + " is not accepted\"}"));
        TrustSource s = source(ctx, props("headers", Map.of("Authorization", TOKEN)));
        try (TrustSourceManager m = manager(new TrustRegistry(), s)) {
            SourceState st = state(m, "partner");
            assertThat(st.lastError()).contains("401");
            assertThat(st.toString()).doesNotContain("s3cret");
        }
        // A value that cannot be sent is refused without being repeated.
        String bad = loadError(source(ctx, props("headers", Map.of("Authorization", "Bearer s3cret\r\nX-Injected: 1"))));
        assertThat(bad).contains("the value of Authorization must be text on one line").doesNotContain("s3cret");
        assertThat(loadError(source(ctx, props("headers", Map.of("Bad Name", "v"))))).contains("'Bad Name' cannot be sent as a header name");
        // Headers need an origin to stay with.
        ctx.put("file:/etc/trust/partner.json", Json.write(doc("a")));
        assertThat(loadError(source(ctx, props("location", "file:/etc/trust/partner.json", "headers", Map.of("Authorization", TOKEN)))))
                .contains("headers are sent to the origin of an https location");
    }

    /** A context whose outbound client fails, as a real one does, with a message that names the whole URL. */
    static SourceContext failingFor(TestContext ctx, String url) {
        return new SourceContext() {
            @Override
            public HttpFetcher http() {
                return request -> {
                    if (request.uri().toString().equals(url)) {
                        throw new IOException("Refusing to fetch " + request.uri() + ": the host resolves to a private address");
                    }
                    return ctx.http.execute(request);
                };
            }

            @Override
            public ResourceLoader resources() {
                return ctx.resources();
            }

            @Override
            public Clock clock() {
                return ctx.clock();
            }
        };
    }

    @Test
    void rule4_theQueryOfALocationPageOrLookupUrlAppearsInNoMessageAndNoState() throws Exception {
        // A query is where a credential for fetching a list is often put; it goes no further than the request.
        String location = LOCATION + "?token=s3cret-query";
        TestContext ctx = ctx();
        ctx.http.respond(location, 401, "application/json", utf8("{}"));
        TrustSource s = source(ctx, props("location", location));
        try (TrustSourceManager m = manager(new TrustRegistry(), s)) {
            SourceState st = state(m, "partner");
            assertThat(st.lastError()).contains("401").contains(LOCATION).doesNotContain("s3cret");
            assertThat(st.toString()).doesNotContain("s3cret");
        }
        assertThat(loadError(new MappedSourceFactory().create(new SourceDefinition("partner", "mapped", "partner", null, true,
                props("location", location)), failingFor(ctx, location)))).contains("Refusing to fetch " + LOCATION + ":").doesNotContain("s3cret");

        // A page URL: the document's own next link, and where it leads.
        Map<String, Object> paged = mapping();
        paged.put("pages", Map.of("next", "$.next"));
        Map<String, Object> page1 = doc("a");
        page1.put("next", LOCATION + "?cursor=s3cret-cursor");
        serveJson(ctx, page1);
        ctx.http.respond(LOCATION + "?cursor=s3cret-cursor", 500, "text/plain", utf8("down"));
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("500").doesNotContain("s3cret");
        page1.put("next", "https://elsewhere.example/v1/issuers?sig=s3cret-sig");
        serveJson(ctx, page1);
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("is not on the origin of location").doesNotContain("s3cret");
        page1.put("next", "https://registry.partner.example:99999/v1?sig=s3cret-sig");
        serveJson(ctx, page1);
        assertThat(loadError(source(ctx, props("mapping", paged)))).doesNotContain("s3cret");

        // A lookup URL.
        Map<String, Object> lookup = lookupOnly();
        Map<String, Object> l = new LinkedHashMap<>((Map<String, Object>) ((Map<String, Object>) lookup.get("mapping")).get("lookup"));
        l.put("url", "https://registry.partner.example/v1/issuers?id={identifier}&key=s3cret-lookup");
        lookup.put("mapping", Map.of("lookup", l));
        String asked = "https://registry.partner.example/v1/issuers?id=did%3Aexample%3Ab&key=s3cret-lookup";
        ctx.http.respond(asked, 500, "text/plain", utf8("down"));
        assertThatThrownBy(() -> ((OnDemandResolver) source(ctx, lookup)).resolve(Identifier.did("did:example:b")))
                .hasMessageContaining("HTTP 500").satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cret"));
        assertThatThrownBy(() -> ((OnDemandResolver) new MappedSourceFactory().create(
                new SourceDefinition("partner", "mapped", "partner", null, true, lookup), failingFor(ctx, asked)))
                .resolve(Identifier.did("did:example:b")))
                .hasMessageContaining("Refusing to fetch https://registry.partner.example/v1/issuers:")
                .satisfies(e -> assertThat(e.getMessage()).doesNotContain("s3cret").doesNotContain("did%3Aexample"));
    }

    // Rule 5 ----------------------------------------------------------------------------------------------------

    @Test
    void rule5_recordsAndPagesAreBounded() throws Exception {
        TestContext ctx = ctx();
        serveJson(ctx, doc("a", "b", "c"));
        assertThat(loadError(source(ctx, props("limits", Map.of("entities", 2))))).contains("more than 2 entity records (limits.entities)");
        Map<String, Object> withAnchors = mapping();
        withAnchors.put("anchors", List.of(Map.of("each", "$.issuers[*]", "domain", "mdoc-iaca", "certificate", "$.certificate")));
        assertThat(loadError(source(ctx, props("mapping", withAnchors, "limits", Map.of("anchors", 2))))).contains("more than 2 anchor records");

        Map<String, Object> paged = mapping();
        paged.put("pages", Map.of("next", "$.next", "max", 2));
        Map<String, Object> p1 = doc("a");
        p1.put("next", LOCATION + "?page=2");
        Map<String, Object> p2 = doc("b");
        p2.put("next", LOCATION + "?page=3");
        Map<String, Object> p3 = doc("c");
        serveJson(ctx, p1);
        ctx.http.json(LOCATION + "?page=2", Json.write(p2));
        ctx.http.json(LOCATION + "?page=3", Json.write(p3));
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("more than 2 pages (mapping.pages.max)");
        paged.put("pages", Map.of("next", "$.next"));
        assertThat(source(ctx, props("mapping", paged)).load().entities()).hasSize(3);
        p2.put("next", LOCATION);
        ctx.http.json(LOCATION + "?page=2", Json.write(p2));
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("link back to a page already read");
        p2.put("next", "https://elsewhere.example/v1/issuers?page=3");
        ctx.http.json(LOCATION + "?page=2", Json.write(p2));
        ctx.http.requests.clear();
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("is not on the origin of location");
        assertThat(ctx.http.requests).noneMatch(r -> r.uri().getHost().equals("elsewhere.example"));
        p2.put("next", "https://registry.partner.example:8443/v1/issuers?page=3");   // another port is another origin
        ctx.http.json(LOCATION + "?page=2", Json.write(p2));
        assertThat(loadError(source(ctx, props("mapping", paged)))).contains("is not on the origin of location");
    }

    @Test
    void rule5_warningsAreBoundedWithACountOfTheRest() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> d = doc("a");
        List<Object> issuers = new ArrayList<>((List<?>) d.get("issuers"));
        for (int i = 0; i < 80; i++) {
            issuers.add(Map.of("name", "no id " + i));
        }
        d.put("issuers", issuers);
        serveJson(ctx, d);
        SourceLoadResult r = source(ctx, props()).load();
        assertThat(r.entities()).hasSize(1);
        assertThat(r.warnings()).hasSize(51);
        assertThat(r.warnings().getFirst()).isEqualTo("mapping.entities[0]: record 2 is skipped: Entity without id");
        assertThat(r.warnings().getLast()).isEqualTo("… and 30 more warnings");
    }

    @Test
    void rule5_theDocumentIsReadStrictlyAndNotTooDeep() {
        TestContext ctx = ctx();
        Map<String, String> bad = new LinkedHashMap<>();
        bad.put("[".repeat(40) + "]".repeat(40), "not valid JSON");
        bad.put("{\"issuers\": [], \"issuers\": [{\"id\": \"evil\"}]}", "not valid JSON");
        bad.put("{\"issuers\": []} {\"issuers\": [{\"id\": \"evil\"}]}", "not valid JSON");
        bad.put("{\"issuers\": [], /* note */ \"x\": 1}", "not valid JSON");
        bad.put("\"just text\"", "not a JSON object or array");
        bad.forEach((json, message) -> {
            ctx.http.respond(LOCATION, 200, "application/json", json.getBytes(StandardCharsets.UTF_8));
            assertThat(loadError(source(ctx, props()))).as(json).contains(message);
        });
    }

    // Rule 6 ----------------------------------------------------------------------------------------------------

    @Test
    void rule6_aMappingThatProducesNothingFailsAndTheSourceKeepsItsLastGoodContent() throws Exception {
        TestContext ctx = ctx();
        TrustSource s = source(ctx, props());
        TrustRegistry registry = new TrustRegistry();
        serveJson(ctx, doc(1, NOW.plus(Duration.ofDays(7)), "a", "b"));
        try (TrustSourceManager m = manager(registry, s)) {
            assertThat(registry.snapshot().entities()).hasSize(2);
            // The partner renamed "id" to "identifier": every record is still there, none maps.
            Map<String, Object> renamed = doc(2, NOW.plus(Duration.ofDays(7)));
            renamed.put("issuers", List.of(Map.of("identifier", "a", "state", "active"), Map.of("identifier", "b", "state", "active")));
            serveJson(ctx, renamed);
            SourceState st = m.refresh("partner");
            assertThat(st.lastError()).contains("mapping.entities[0]: none of the 2 records at $.issuers[*] could be mapped; "
                    + "record 1 is skipped: Entity without id");
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactlyInAnyOrder("partner:a", "partner:b");
        }
        // A block that finds no record at all fails too, unless it says that a list without any is a list.
        serveJson(ctx, doc(3, NOW.plus(Duration.ofDays(7))));
        assertThat(loadError(s)).contains("mapping.entities[0]: the document has no record at $.issuers[*]; "
                + "a block that finds none fails the load unless it says allowEmpty: true");
        Map<String, Object> m = mapping();
        ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).put("allowEmpty", true);
        SourceLoadResult empty = source(ctx, props("mapping", m)).load();
        assertThat(empty.entities()).isEmpty();
        assertThat(empty.warnings()).isEmpty();
    }

    // Rule 7 ----------------------------------------------------------------------------------------------------

    @Test
    void rule7_aMappedRecordNamingAnotherFrameworkDoesNotLandThere() {
        TestContext ctx = ctx();
        Map<String, Object> m = mapping();
        ((Map<String, Object>) ((List<?>) m.get("entities")).getFirst()).put("framework", "$.framework");
        Map<String, Object> d = doc();
        d.put("issuers", List.of(Map.of("id", "a", "framework", "other", "credential_issuer", "https://a.example"),
                Map.of("id", "b", "framework", "partner", "credential_issuer", "https://b.example"),
                Map.of("id", "c", "credential_issuer", "https://c.example")));
        serveJson(ctx, d);
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager manager = manager(registry, source(ctx, props("mapping", m)))) {
            assertThat(registry.snapshot().entities()).extracting(TrustedEntity::id).containsExactly("partner:b", "partner:c");
            assertThat(registry.snapshot().entities()).allMatch(e -> e.frameworkId().equals("partner"));
            assertThat(state(manager, "partner").warnings()).anyMatch(w -> w.contains("names framework 'other', but its source loads into 'partner'"));
        }
        // What the document says about frameworks is not read unless mapped: everything lands in the source's framework.
        try (TrustSourceManager manager = manager(registry, source(ctx, props()))) {
            assertThat(registry.snapshot().entities()).hasSize(3).allMatch(e -> e.frameworkId().equals("partner"));
        }
    }

    // Rule 8 ----------------------------------------------------------------------------------------------------

    static Map<String, Object> lookupOnly(Object... extra) {
        Map<String, Object> lookup = new LinkedHashMap<>(Map.of("url", "https://registry.partner.example/v1/issuers/{identifier}",
                "identifierTypes", List.of("DID"), "startsWith", List.of("did:example:"),
                "entity", Map.of("id", "$.id", "roles", List.of("CREDENTIAL_ISSUER"),
                        "identifiers", List.of(Map.of("type", "DID", "value", "$.did")))));
        for (int i = 0; i < extra.length; i += 2) {
            lookup.put((String) extra[i], extra[i + 1]);
        }
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("mapping", Map.of("lookup", lookup));
        return p;
    }

    static final String BASE = "https://registry.partner.example/v1/issuers/";

    @Test
    void rule8_aLookupIsAskedOnlyAboutTheListedTypesAndPrefixesWithTheIdentifierEncoded() throws Exception {
        TestContext ctx = ctx();
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        assertThat(r.canResolve(Identifier.did("did:example:a"))).isTrue();
        assertThat(r.canResolve(Identifier.did("did:web:a.example"))).isFalse();
        assertThat(r.canResolve(Identifier.url("did:example:a"))).isFalse();
        assertThat(r.resolve(Identifier.did("did:web:a.example"))).isEmpty();
        assertThat(ctx.http.requests).isEmpty();

        // Encoded, the identifier stays one path segment: no path, query or fragment of its own.
        String odd = "did:example:a/../b?c=d e";
        ctx.http.json(BASE + "did%3Aexample%3Aa%2F..%2Fb%3Fc%3Dd%20e", Json.write(Map.of("id", "odd", "did", odd)));
        assertThat(r.resolve(Identifier.did(odd))).map(TrustedEntity::id).contains("odd");
        assertThat(ctx.http.requests.getLast().uri().getRawPath()).isEqualTo("/v1/issuers/did%3Aexample%3Aa%2F..%2Fb%3Fc%3Dd%20e");
        assertThat(source(ctx, lookupOnly()).load().entities()).isEmpty();
    }

    @Test
    void rule8_anAnswerCountsOnlyForTheIdentifierAskedAbout() throws Exception {
        TestContext ctx = ctx();
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        // The registry answers for another party: that answer is not about the one asked.
        ctx.http.json(BASE + "did%3Aexample%3Aa", Json.write(Map.of("id", "mallory", "did", "did:example:mallory")));
        assertThat(r.resolve(Identifier.did("did:example:a"))).isEmpty();
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b")));
        TrustedEntity b = r.resolve(Identifier.did("did:example:b")).orElseThrow();
        assertThat(b.identifiers()).contains(Identifier.did("did:example:b"));
        // A DID URL asks about its DID, and is compared by the registry's identifier rule.
        assertThat(r.resolve(Identifier.did("did:example:b#key-1"))).contains(b);
    }

    @Test
    void rule8_answersAndMissesAreKeptForATimeAndOnlyAMissStatusIsAMiss() throws Exception {
        TestContext ctx = ctx();
        MutableClock clock = new MutableClock(NOW);
        ctx.clock = clock;
        OnDemandResolver r = (OnDemandResolver) source(ctx, lookupOnly());
        ctx.http.json(BASE + "did%3Aexample%3Ab", Json.write(Map.of("id", "b", "did", "did:example:b")));
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(r.resolve(Identifier.did("did:example:nobody"))).isEmpty();          // FakeHttp answers 404
        assertThat(r.resolve(Identifier.did("did:example:nobody"))).isEmpty();
        assertThat(ctx.http.requests).hasSize(2);
        // A miss is asked again after a minute, an answer after ten: a change in the registry takes effect.
        clock.now = NOW.plus(Duration.ofSeconds(61));
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(r.resolve(Identifier.did("did:example:nobody"))).isEmpty();
        assertThat(ctx.http.requests).hasSize(3);
        clock.now = NOW.plus(Duration.ofMinutes(11));
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        assertThat(ctx.http.requests).hasSize(4);

        ctx.http.respond(BASE + "did%3Aexample%3Abroken", 500, "text/plain", utf8("down"));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:broken"))).isInstanceOf(TrustSourceException.class)
                .hasMessageContaining("HTTP 500");
        OnDemandResolver gone = (OnDemandResolver) source(ctx, lookupOnly("missStatus", List.of(410)));
        ctx.http.respond(BASE + "did%3Aexample%3Aold", 410, "text/plain", utf8("gone"));
        assertThat(gone.resolve(Identifier.did("did:example:old"))).isEmpty();
        assertThatThrownBy(() -> gone.resolve(Identifier.did("did:example:nobody"))).hasMessageContaining("HTTP 404");
    }

    @Test
    void rule8_aSignedAnswerIsVerifiedLikeTheList() throws Exception {
        ECKey k1 = key("k1");
        TestContext ctx = ctx();
        Map<String, Object> p = lookupOnly();
        p.put("format", "jws");
        p.put("verify", Map.of("jwks", jwks(k1)));
        OnDemandResolver r = (OnDemandResolver) source(ctx, p);
        // A signed answer says when it was made (MappedSourceAttacksTest.f3_aSignedLookupAnswerMustSayWhenItWasMade).
        long iat = NOW.getEpochSecond();
        ctx.http.respond(BASE + "did%3Aexample%3Ab", 200, "application/jwt", utf8(sign(k1, Map.of("id", "b", "did", "did:example:b", "iat", iat))));
        assertThat(r.resolve(Identifier.did("did:example:b"))).isPresent();
        ctx.http.respond(BASE + "did%3Aexample%3Ac", 200, "application/jwt", utf8(sign(key("k1"), Map.of("id", "c", "did", "did:example:c",
                "iat", iat))));
        assertThatThrownBy(() -> r.resolve(Identifier.did("did:example:c"))).hasMessageContaining("does not verify");
    }

    // Rule 9 ----------------------------------------------------------------------------------------------------

    @Test
    void rule9_onlyAWebLocationOrThePublicUriIsPublished() throws Exception {
        TestContext ctx = ctx();
        serveJson(ctx, doc("a"));
        ctx.put("file:/etc/trust/partner.json", Json.write(doc("a")));
        ctx.put("/etc/trust/partner.json", Json.write(doc("a")));
        ctx.put("classpath:partner.json", Json.write(doc("a")));
        assertThat(published(source(ctx, props()))).isEqualTo(LOCATION);
        for (String local : List.of("file:/etc/trust/partner.json", "/etc/trust/partner.json", "classpath:partner.json")) {
            assertThat(published(source(ctx, props("location", local)))).as(local).isNull();
        }
        assertThat(published(source(ctx, props("location", "file:/etc/trust/partner.json", "publicUri", "https://partner.example/registry"))))
                .isEqualTo("https://partner.example/registry");
        assertThat(published(source(ctx, props("publicUri", "https://partner.example/registry")))).isEqualTo("https://partner.example/registry");
        assertThat(loadError(source(ctx, props("publicUri", "/etc/trust/partner.json")))).contains("publicUri must be an http(s) URL");
    }

    static final class MutableClock extends Clock {
        Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        @Override
        public Instant instant() {
            return now;
        }

        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }
    }

    static String published(TrustSource s) throws TrustSourceException {
        return s.load().entities().getFirst().provenance().sourceUri();
    }

    // Records ---------------------------------------------------------------------------------------------------

    @Test
    void aRecordIsHeldToTheRulesOfTheRegistryFormat() throws Exception {
        TestContext ctx = ctx();
        Map<String, Object> m = mapping();
        Map<String, Object> block = (Map<String, Object>) ((List<?>) m.get("entities")).getFirst();
        block.put("validUntil", "$.until");
        block.put("roles", "$.roles[*]");
        Map<String, Object> d = doc();
        d.put("issuers", List.of(
                Map.of("id", "ok", "roles", List.of("VERIFIER"), "state", "suspended"),
                Map.of("id", "bad role", "roles", List.of("VERIFIER")),
                Map.of("id", "x", "roles", List.of("PRESIDENT")),
                Map.of("id", "y", "roles", List.of("VERIFIER"), "until", "forever"),
                Map.of("roles", List.of("VERIFIER"))));
        serveJson(ctx, d);
        SourceLoadResult r = source(ctx, props("mapping", m)).load();
        assertThat(r.entities()).singleElement().satisfies(e -> {
            assertThat(e.id()).isEqualTo("partner:ok");
            assertThat(e.status()).isEqualTo(EntityStatus.SUSPENDED);
        });
        assertThat(r.warnings()).containsExactly(
                "mapping.entities[0]: record 2 is skipped: its id is not 1 to 128 letters, digits or . _ : @ ~ -",
                "mapping.entities[0]: record 3 (id 'partner:x') is skipped: Unknown role 'PRESIDENT'; one of CREDENTIAL_ISSUER, VERIFIER, "
                        + "WALLET_PROVIDER, AUTHORIZATION_SERVER, ACCREDITATION_AUTHORITY, STATUS_LIST_PROVIDER, OTHER",
                "mapping.entities[0]: record 4 is skipped: validUntil is not a date: 'forever'",
                "mapping.entities[0]: record 5 is skipped: Entity without id");
    }
}
