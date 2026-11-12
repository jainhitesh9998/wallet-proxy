package io.vctrust.trust.server.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import io.vctrust.trust.core.metadata.Oid4vciMetadataMapper;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.policy.TrustMechanisms;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.server.config.TrustJacksonModule;
import io.vctrust.trust.server.config.TrustProperties;
import io.vctrust.trust.server.signing.ServiceKeyManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.json.JsonMapper;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The snapshot carries JSON-LD contexts as one map from URL to digest, and a device takes a fetched context as genuine
 * when it has the digest stated for its URL. A pin is never replaced by another framework's statement: two different
 * pins for one URL in one client's view leave the context out of that client's snapshot (the device then reports it
 * as not vouched for), and the conflict is logged with both entity ids; a pin and an unpinned listing of the URL: the
 * pin holds. A client that sees one of the frameworks only is told that framework's statement.
 */
class ContextPinsTest {

    static final ClientProfile OTHER = new ClientProfile("other-wallet", "Other", Set.of("other"), false, false, false);
    static final ClientProfile PARTNER = new ClientProfile("partner-wallet", "Partner", Set.of("partner"), false, false, false);
    static final ClientProfile BOTH = new ClientProfile("both-wallet", "Both", Set.of("other", "partner"), false, false, false);

    /** The context as its publisher serves it, and what another framework says its digest is. */
    static final byte[] SERVED = "{\"@context\":{\"degree\":\"https://vocab.example/degree\"}}".getBytes(StandardCharsets.UTF_8);
    static final byte[] ALTERED = "{\"@context\":{\"degree\":\"https://vocab.example/@none\"}}".getBytes(StandardCharsets.UTF_8);
    static final String GENUINE = digest(SERVED);
    static final String OTHERWISE = digest(ALTERED);

    @TempDir
    Path dir;

    final HttpServer server;
    final String url;
    final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    final Logger log = (Logger) LoggerFactory.getLogger(ContextService.class);

    ContextPinsTest() throws Exception {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        url = "http://localhost:" + server.getAddress().getPort() + "/contexts/degree/v1";
        server.createContext("/contexts/degree/v1", ex -> {
            ex.getResponseHeaders().add("Content-Type", "application/ld+json");
            ex.sendResponseHeaders(200, SERVED.length);
            ex.getResponseBody().write(SERVED);
            ex.close();
        });
        server.start();
        logged.start();
        log.addAppender(logged);
    }

    @AfterEach
    void stop() {
        server.stop(0);
        log.detachAppender(logged);
    }

    static String digest(byte[] body) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(Hashes.sha256(body));
    }

    /** An issuer listing {@code url}, pinned to {@code sha256} when that is given. */
    TrustedEntity issuer(String id, String framework, String sha256) {
        TrustedEntity.Builder b = TrustedEntity.builder(id).framework(framework).role(EntityRole.CREDENTIAL_ISSUER)
                .identifier(io.vctrust.trust.core.model.IdentifierType.URL, "https://" + id + ".example")
                .attribute(Oid4vciMetadataMapper.CONTEXTS, List.of(url));
        if (sha256 != null) {
            b.attribute(Oid4vciMetadataMapper.CONTEXT_DIGESTS, Map.of(url, sha256));
        }
        return b.build();
    }

    /** A service whose registry lists {@code entities} in this order. */
    SnapshotService service(TrustedEntity... entities) {
        TrustRegistry registry = new TrustRegistry();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(new TrustFramework("other", "Other", null, null, null),
                new TrustFramework("partner", "Partner", null, null, null)), List.of(entities), List.of()));
        TrustProperties.Http http = new TrustProperties.Http();
        http.setAllowPrivateNetworks(true);
        http.setHttpAllowedHosts(List.of("localhost"));
        ContextService contexts = new ContextService(new io.vctrust.trust.server.http.SafeHttpFetcher(http), new TrustProperties.Cache(), Clock.systemUTC());
        return new SnapshotService(registry, new ServiceKeyManager(dir.resolve("key.jwk").toString(), "https://trust.test"),
                JsonMapper.builder().addModule(new TrustJacksonModule()).build(), null, null, contexts,
                new SnapshotService.Options(Duration.ofHours(1), false, 0, Duration.ofSeconds(10), 262144, 262144, Duration.ZERO),
                Clock.systemUTC(), TrustMechanisms.NONE);
    }

    /** The {@code contexts} claim of the snapshot {@code client} is given. */
    static Map<String, Object> contexts(SnapshotService service, ClientProfile client) throws Exception {
        return SignedJWT.parse(service.snapshot(client).jwt()).getJWTClaimsSet().getJSONObjectClaim("contexts");
    }

    /** The {@code contexts} claim of the snapshot each client is given, from a registry listing {@code entities} in this order. */
    Map<ClientProfile, Map<String, Object>> told(TrustedEntity... entities) throws Exception {
        SnapshotService service = service(entities);
        Map<ClientProfile, Map<String, Object>> out = new java.util.LinkedHashMap<>();
        for (ClientProfile client : List.of(OTHER, PARTNER, BOTH)) {
            out.put(client, contexts(service, client));
        }
        return out;
    }

    List<String> conflictsLogged(String... entityIds) {
        return logged.list.stream().map(ILoggingEvent::getFormattedMessage)
                .filter(m -> m.contains(url) && java.util.Arrays.stream(entityIds).allMatch(m::contains)).toList();
    }

    /** What the claim says about {@code url}: its digest and maybe the document; empty when it says nothing. */
    @SuppressWarnings("unchecked")
    static Map<String, Object> entry(Map<String, Object> contexts, String url) {
        return contexts.get(url) instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
    }

    static String sha256(Map<String, Object> contexts, String url) {
        return (String) entry(contexts, url).get("sha256");
    }

    @Test
    void twoDifferentPinsForOneUrlLeaveTheContextOutForAClientThatSeesBoth() throws Exception {
        TrustedEntity pinned = issuer("university", "other", GENUINE);
        TrustedEntity repinned = issuer("lookalike", "partner", OTHERWISE);
        for (List<TrustedEntity> order : List.of(List.of(pinned, repinned), List.of(repinned, pinned))) {
            String as = order.getFirst().id() + " first";
            logged.list.clear();
            SnapshotService service = service(order.toArray(TrustedEntity[]::new));
            // Neither framework's pin replaces the other's: the context is not vouched for at all.
            assertThat(contexts(service, BOTH)).as(as).doesNotContainKey(url);
            // A client of one framework is told that framework's statement.
            Map<String, Object> other = contexts(service, OTHER);
            assertThat(sha256(other, url)).as(as).isEqualTo(GENUINE);
            assertThat(entry(other, url)).as(as).containsKey("document");
            Map<String, Object> partner = contexts(service, PARTNER);
            assertThat(sha256(partner, url)).as(as).isEqualTo(OTHERWISE);
            assertThat(entry(partner, url)).as(as).doesNotContainKey("document");
            // The conflict is logged with both entity ids, once: not again on every snapshot build.
            assertThat(contexts(service, BOTH)).as(as).doesNotContainKey(url);
            assertThat(conflictsLogged("university", "lookalike")).as(as).hasSize(1);
        }
    }

    @Test
    void aPinHoldsAgainstAnUnpinnedListingOfTheSameUrl() throws Exception {
        TrustedEntity pinned = issuer("university", "other", GENUINE);
        TrustedEntity listed = issuer("lookalike", "partner", null);
        for (List<TrustedEntity> order : List.of(List.of(pinned, listed), List.of(listed, pinned))) {
            String as = order.getFirst().id() + " first";
            Map<ClientProfile, Map<String, Object>> told = told(order.toArray(TrustedEntity[]::new));
            assertThat(sha256(told.get(BOTH), url)).as(as).isEqualTo(GENUINE);
            assertThat(sha256(told.get(OTHER), url)).as(as).isEqualTo(GENUINE);
            assertThat(sha256(told.get(PARTNER), url)).as(as).isEqualTo(GENUINE);
        }
        // A pin that the served content does not match is never replaced by an unpinned listing either: the pin is
        // shipped without the document.
        TrustedEntity wrongPin = issuer("university", "other", OTHERWISE);
        for (List<TrustedEntity> order : List.of(List.of(wrongPin, listed), List.of(listed, wrongPin))) {
            Map<ClientProfile, Map<String, Object>> told = told(order.toArray(TrustedEntity[]::new));
            assertThat(sha256(told.get(BOTH), url)).isEqualTo(OTHERWISE);
            assertThat(entry(told.get(BOTH), url)).doesNotContainKey("document");
            assertThat(sha256(told.get(PARTNER), url)).isEqualTo(GENUINE);
        }
        assertThat(conflictsLogged("lookalike")).isEmpty();
    }

    /**
     * A digest written with base64 padding, or in the standard alphabet instead of the URL-safe one, is the same digest:
     * two pins that differ only so are one pin, not a conflict, and the context is shipped by its digest as devices
     * compute it (unpadded base64url).
     */
    @Test
    void theSameDigestInAnotherSpellingIsTheSamePin() throws Exception {
        byte[] bytes = Base64.getUrlDecoder().decode(GENUINE);
        String padded = Base64.getUrlEncoder().encodeToString(bytes);
        String standard = Base64.getEncoder().encodeToString(bytes);
        String standardUnpadded = Base64.getEncoder().withoutPadding().encodeToString(bytes);
        for (String spelling : List.of(padded, standard, standardUnpadded)) {
            for (List<TrustedEntity> order : List.of(List.of(issuer("university", "other", GENUINE), issuer("campus", "partner", spelling)),
                    List.of(issuer("campus", "partner", spelling), issuer("university", "other", GENUINE)))) {
                String as = spelling + ", " + order.getFirst().id() + " first";
                logged.list.clear();
                Map<ClientProfile, Map<String, Object>> told = told(order.toArray(TrustedEntity[]::new));
                assertThat(sha256(told.get(BOTH), url)).as(as).isEqualTo(GENUINE);
                assertThat(entry(told.get(BOTH), url)).as(as).containsKey("document");
                assertThat(sha256(told.get(PARTNER), url)).as(as).isEqualTo(GENUINE);
                assertThat(conflictsLogged("university", "campus")).as(as).isEmpty();
            }
        }
        // Both alphabets, where they differ.
        byte[] ones = new byte[32];
        java.util.Arrays.fill(ones, (byte) 0xff);
        String canonical = Base64.getUrlEncoder().withoutPadding().encodeToString(ones);
        assertThat(canonical).startsWith("____");
        for (String s : List.of(canonical, Base64.getUrlEncoder().encodeToString(ones), Base64.getEncoder().encodeToString(ones),
                Base64.getEncoder().withoutPadding().encodeToString(ones))) {
            assertThat(ContextService.canonicalDigest(s)).as(s).isEqualTo(canonical);
        }
        // Anything that is no SHA-256 in base64 stays as written, and then matches no content.
        for (String s : List.of("not a digest", "AAAA", GENUINE + "AAAA")) {
            assertThat(ContextService.canonicalDigest(s)).as(s).isEqualTo(s);
        }
    }

    @Test
    void theSamePinTwiceIsNoConflict() throws Exception {
        Map<ClientProfile, Map<String, Object>> told = told(issuer("university", "other", GENUINE), issuer("campus", "partner", GENUINE));
        assertThat(sha256(told.get(BOTH), url)).isEqualTo(GENUINE);
        assertThat(entry(told.get(BOTH), url)).containsKey("document");
        assertThat(conflictsLogged("campus")).isEmpty();
    }
}
