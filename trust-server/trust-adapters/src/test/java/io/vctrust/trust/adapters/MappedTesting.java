package io.vctrust.trust.adapters;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import io.vctrust.trust.adapters.mapped.MappedSourceFactory;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.TrustFramework;
import io.vctrust.trust.core.registry.SourceState;
import io.vctrust.trust.core.registry.TrustRegistry;
import io.vctrust.trust.core.registry.TrustSourceManager;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.TrustSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.Map;

/** What the tests of the mapped source share: the test PKI, signing, and a source manager around a source. */
final class MappedTesting {

    private MappedTesting() {
    }

    static final Path ROOT = root();

    private static Path root() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        if (p == null) {
            throw new IllegalStateException("conformance/ not found above " + Path.of("").toAbsolutePath());
        }
        return p;
    }

    /** A certificate of conformance/pki as PEM. */
    static String pem(String name) {
        try {
            return Files.readString(ROOT.resolve("conformance/pki/" + name + ".pem"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    /** A certificate of conformance/pki as base64 DER (an x5c entry, DCC rawData). */
    static String der(String name) {
        return pem(name).replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
    }

    static ECKey key(String kid) {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(kid).generate();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static String jwks(ECKey... keys) {
        return new JWKSet(java.util.Arrays.stream(keys).map(k -> (com.nimbusds.jose.jwk.JWK) k.toPublicJWK()).toList()).toString();
    }

    /** A compact JWS of {@code payload}, ES256 with {@code key} and its kid. */
    static String sign(ECKey key, Object payload) {
        return sign(new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(key.getKeyID()).build(), signer(key), payload);
    }

    static String sign(JWSHeader header, JWSSigner signer, Object payload) {
        try {
            JWSObject jws = new JWSObject(header, new Payload(payload instanceof String s ? s : Json.write(payload)));
            jws.sign(signer);
            return jws.serialize();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static JWSSigner signer(ECKey key) {
        try {
            return new ECDSASigner(key);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static TrustSource source(TestContext ctx, String id, String framework, Map<String, Object> properties) {
        return new MappedSourceFactory().create(new SourceDefinition(id, "mapped", framework, null, true, properties), ctx);
    }

    static TrustSource source(TestContext ctx, Map<String, Object> properties) {
        return source(ctx, "partner", "partner", properties);
    }

    /** A manager with frameworks {@code partner} and {@code other} around the given sources; loaded once. */
    static TrustSourceManager manager(TrustRegistry registry, TrustSource... sources) {
        TrustSourceManager m = new TrustSourceManager(registry, List.of(
                new TrustFramework("partner", "Partner", null, null, null), new TrustFramework("other", "Other", null, null, null)),
                List.of(sources), Clock.systemUTC());
        for (TrustSource s : sources) {
            m.refresh(s.id());
        }
        return m;
    }

    static SourceState state(TrustSourceManager m, String id) {
        return m.states().stream().filter(s -> s.id().equals(id)).findFirst().orElseThrow();
    }

    static byte[] utf8(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }
}
