package io.vctrust.trust.server.service;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.RegistrySnapshot;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.server.cache.ResourceCache;
import io.vctrust.trust.server.config.TrustProperties;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** The operator use cases refuse a client that is not an operator themselves, however it got to them. */
class OperatorUseCasesTest {

    static final ClientProfile WALLET = new ClientProfile("wallet", "wallet", Set.of("fw"), false, false, false);
    static final ClientProfile OPERATOR = new ClientProfile("ops", "ops", Set.of(ClientProfile.ALL_FRAMEWORKS), false, false, true);

    @Test
    void everyOperatorUseCaseChecksTheActingClient() {
        TrustRegistry registry = new TrustRegistry();
        try (TrustSourceManager sources = new TrustSourceManager(registry, List.of(), List.of(), Clock.systemUTC())) {
            AdministrationService administration = new AdministrationService(sources, registry, List::of, null, null, null, null, null, 0);
            ManagedEntryService managed = new ManagedEntryService(null, location -> new byte[0], sources);
            List<Runnable> asWallet = List.of(
                    () -> administration.sourceStates(WALLET),
                    () -> administration.refreshSource(WALLET, "any"),
                    () -> administration.anchorCrls(WALLET),
                    () -> administration.registrySummary(WALLET),
                    () -> administration.clientProfiles(WALLET),
                    () -> administration.clearCaches(WALLET),
                    () -> managed.list(WALLET, "entities"),
                    () -> managed.put(WALLET, "entities", "x", Map.of()),
                    () -> managed.delete(WALLET, "entities", "x"),
                    () -> administration.sourceStates(null));
            for (Runnable useCase : asWallet) {
                assertThatThrownBy(useCase::run).isInstanceOfSatisfying(ServiceException.class,
                        e -> assertThat(e.kind()).isEqualTo(ServiceException.Kind.FORBIDDEN));
            }
            assertThat(administration.sourceStates(OPERATOR)).isEmpty();
        }
    }

    @Test
    void anOperatorSeesTheAnchorCrlsAndAnyoneElseIsRefusedOnTheRecord() throws Exception {
        var ca = TestPki.rootCa("CN=Listed IACA,C=UT");
        String crl = Base64.getEncoder().encodeToString(TestPki.crl(ca).getEncoded());
        TrustRegistry registry = new TrustRegistry();
        registry.publish(new RegistrySnapshot(1, Instant.now(), List.of(), List.of(), List.of(
                new TrustAnchor("listed", TrustDomain.MDOC_IACA, ca.certificate(), "fw", null, null, Map.of("crl", crl), null))));
        TrustProperties.Revocation revocation = new TrustProperties.Revocation();
        revocation.setEnabled(false); // no refresh thread: the test loads the CRLs itself
        Logger audit = (Logger) LoggerFactory.getLogger("io.vctrust.trust.audit");
        ListAppender<ILoggingEvent> recorded = new ListAppender<>();
        recorded.start();
        audit.addAppender(recorded);
        try (TrustSourceManager sources = new TrustSourceManager(registry, List.of(), List.of(), Clock.systemUTC());
             CrlService crls = new CrlService(registry, null, revocation,
                     new ResourceCache.Settings(1_000_000, Duration.ofSeconds(30), Duration.ofDays(1), false), Clock.systemUTC())) {
            crls.refresh();
            AdministrationService administration = new AdministrationService(sources, registry, List::of, null, null, null, null, crls, 262144);
            assertThat(administration.anchorCrls(OPERATOR)).singleElement().satisfies(m -> assertThat(m)
                    .containsEntry("anchorIds", List.of("listed")).containsEntry("current", true).containsEntry("inSnapshots", true));

            assertThatThrownBy(() -> administration.anchorCrls(WALLET)).isInstanceOfSatisfying(ServiceException.class,
                    e -> assertThat(e.kind()).isEqualTo(ServiceException.Kind.FORBIDDEN));
            assertThat(recorded.list).extracting(ILoggingEvent::getFormattedMessage)
                    .containsExactly("client=\"wallet\" action=list-crls refused=not-an-admin");

            // Revocation off: the service holds no CRL, and says so with an empty list rather than an error.
            assertThat(new AdministrationService(sources, registry, List::of, null, null, null, null, null, 262144).anchorCrls(OPERATOR)).isEmpty();
        } finally {
            audit.detachAppender(recorded);
        }
    }

    @Test
    void whatACallerChoseCannotPassForAFieldOfTheAuditLog() {
        assertThat(AuditLog.quoted("x\nclient=ops action=clear-caches")).isEqualTo("\"x\\nclient=ops action=clear-caches\"");
        assertThat(AuditLog.quoted("a\" id=\"b")).isEqualTo("\"a\\\" id=\\\"b\"");
        assertThat(AuditLog.quoted(null)).isEqualTo("null");
    }

    @Test
    void theRelayTellsAStatusListFromOtherDocuments() {
        var b64 = java.util.Base64.getUrlEncoder().withoutPadding();
        String token = "eyJhbGciOiJFUzI1NiJ9." + b64.encodeToString("{\"status_list\":{\"bits\":1,\"lst\":\"eNpjAAAAAQAB\"}}".getBytes()) + ".c2ln";
        String credentialJwt = "eyJhbGciOiJFUzI1NiJ9." + b64.encodeToString("{\"vc\":{\"credentialSubject\":{\"encodedList\":\"H4sI\"}}}".getBytes()) + ".c2ln";
        assertThat(StatusLists.isStatusList(token.getBytes())).isTrue();
        assertThat(StatusLists.isStatusList(credentialJwt.getBytes())).isTrue();
        assertThat(StatusLists.isStatusList("{\"credentialSubject\":{\"type\":\"BitstringStatusList\",\"encodedList\":\"uH4sI\"}}".getBytes())).isTrue();
        assertThat(StatusLists.isStatusList(("{\"type\":\"EnvelopedVerifiableCredential\",\"id\":\"data:application/vc+jwt," + credentialJwt + "\"}").getBytes())).isTrue();
        // COSE_Sign1 [protected, unprotected, payload, signature] whose payload is a CWT with claim 65533 {bits, lst}
        byte[] claims = hex("a11a0000fffda2646269747301636c737442aabb");
        byte[] cwt = concat(hex("8440a0"), new byte[] {(byte) (0x40 + claims.length)}, claims, hex("40"));
        assertThat(StatusLists.isStatusList(cwt)).isTrue();

        assertThat(StatusLists.isStatusList("{\"internal\":true}".getBytes())).isFalse();
        assertThat(StatusLists.isStatusList("[1,2,3]".getBytes())).isFalse();
        assertThat(StatusLists.isStatusList(("eyJhbGciOiJFUzI1NiJ9." + b64.encodeToString("{\"sub\":\"someone\"}".getBytes()) + ".c2ln").getBytes())).isFalse();
        assertThat(StatusLists.isStatusList(concat(hex("8440a0"), new byte[] {0x41}, hex("a0"), hex("40")))).isFalse();
        assertThat(StatusLists.isStatusList("<html></html>".getBytes())).isFalse();
        assertThat(StatusLists.isStatusList(new byte[0])).isFalse();
    }

    static byte[] hex(String s) {
        return java.util.HexFormat.of().parseHex(s);
    }

    static byte[] concat(byte[]... parts) {
        var out = new java.io.ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }
}
