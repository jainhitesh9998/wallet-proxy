package io.vctrust.trust.server.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Map;

/**
 * The service's own ES256 signing key, used for signed responses and offline snapshots. Clients pin its JWK
 * thumbprint. The key is loaded from a JWK file, or generated and persisted on first start.
 */
public class ServiceKeyManager {

    private static final Logger log = LoggerFactory.getLogger(ServiceKeyManager.class);

    private final ECKey key;
    private final String issuer;

    public ServiceKeyManager(String keyFile, String issuer) throws IOException, JOSEException, java.text.ParseException {
        this.issuer = issuer;
        Path path = Path.of(keyFile);
        if (Files.exists(path)) {
            key = ECKey.parse(Files.readString(path));
        } else {
            ECKey generated = new ECKeyGenerator(Curve.P_256).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES256).generate();
            key = new ECKey.Builder(generated).keyIDFromThumbprint().build();
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            Files.writeString(path, key.toJSONString(), StandardCharsets.UTF_8);
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX file system
            }
            log.info("Generated service signing key {} at {}", key.getKeyID(), path.toAbsolutePath());
        }
    }

    public JWKSet publicJwks() {
        return new JWKSet(key.toPublicJWK());
    }

    public String keyId() {
        return key.getKeyID();
    }

    public String thumbprint() {
        try {
            return key.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public String issuer() {
        return issuer;
    }

    /** Signs {@code claims} as a JWT with {@code iss}, {@code iat} and {@code exp} added. */
    public String sign(String typ, Map<String, Object> claims, Duration ttl, String audience) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet.Builder b = new JWTClaimsSet.Builder().issuer(issuer).issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plus(ttl)));
            if (audience != null) {
                b.audience(audience);
            }
            claims.forEach(b::claim);
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).type(new JOSEObjectType(typ))
                    .keyID(key.getKeyID()).build(), b.build());
            jwt.sign(new ECDSASigner(key));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Signing failed", e);
        }
    }
}
