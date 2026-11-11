package io.vctrust.trust.server.service;

import io.vctrust.trust.core.policy.ClientProfile;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import org.junit.jupiter.api.Test;

import java.time.Clock;
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
            AdministrationService administration = new AdministrationService(sources, registry, List::of, null, null, null, null);
            ManagedEntryService managed = new ManagedEntryService(null, location -> new byte[0], sources);
            List<Runnable> asWallet = List.of(
                    () -> administration.sourceStates(WALLET),
                    () -> administration.refreshSource(WALLET, "any"),
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
