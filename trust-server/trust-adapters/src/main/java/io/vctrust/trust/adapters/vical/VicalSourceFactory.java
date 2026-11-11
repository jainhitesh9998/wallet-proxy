package io.vctrust.trust.adapters.vical;

import io.vctrust.trust.adapters.support.Cose;
import io.vctrust.trust.adapters.support.SignerVerification;
import io.vctrust.trust.core.model.CredentialAuthorization;
import io.vctrust.trust.core.model.CredentialFormats;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.IdentifierType;
import io.vctrust.trust.core.model.LocalizedDisplay;
import io.vctrust.trust.core.model.Provenance;
import io.vctrust.trust.core.model.TrustAnchor;
import io.vctrust.trust.core.model.TrustDomain;
import io.vctrust.trust.core.model.TrustedEntity;
import io.vctrust.trust.core.spi.ListInfo;
import io.vctrust.trust.core.spi.SourceContext;
import io.vctrust.trust.core.spi.SourceDefinition;
import io.vctrust.trust.core.spi.SourceLoadResult;
import io.vctrust.trust.core.spi.TrustSource;
import io.vctrust.trust.core.spi.TrustSourceException;
import io.vctrust.trust.core.spi.TrustSourceFactory;
import io.vctrust.trust.core.util.Base64Url;
import io.vctrust.trust.core.x509.Certificates;
import tools.jackson.databind.JsonNode;
import tools.jackson.dataformat.cbor.CBORMapper;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * {@code type: vical} — ISO/IEC 18013-5 Verified Issuer Certificate Authority List: a COSE_Sign1 whose payload
 * lists IACA certificates with their doctypes. Every listed IACA becomes an {@code mdoc-iaca} anchor
 * constrained to its doctypes, linked to an issuing-authority entity.
 *
 * <p>Properties: {@code location}; {@code signerCertificates} / {@code signerCertificateLocation} (the VICAL
 * provider's root; required unless {@code allowUnverified: true}); {@code allowExpired} (default false: a VICAL
 * past its nextUpdate is not loaded).
 */
public final class VicalSourceFactory implements TrustSourceFactory {

    private static final CBORMapper CBOR = CBORMapper.builder().build();

    @Override
    public String type() {
        return "vical";
    }

    @Override
    public TrustSource create(SourceDefinition def, SourceContext ctx) {
        return new TrustSource() {
            @Override
            public SourceDefinition definition() {
                return def;
            }

            @Override
            public SourceLoadResult load() throws TrustSourceException {
                String location = def.requireString("location");
                try {
                    return parse(ctx.resources().load(location), location, def, SignerVerification.from(def, ctx.resources()),
                            ctx.clock().instant());
                } catch (TrustSourceException e) {
                    throw e;
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load VICAL " + location + ": " + e.getMessage(), e);
                }
            }
        };
    }

    static SourceLoadResult parse(byte[] data, String location, SourceDefinition def, SignerVerification signers,
                                  Instant now) throws Exception {
        JsonNode sign1 = CBOR.readTree(data);
        if (!sign1.isArray() || sign1.size() != 4) {
            throw new TrustSourceException("VICAL is not a COSE_Sign1 structure");
        }
        byte[] protectedBytes = sign1.get(0).binaryValue();
        JsonNode protectedHeader = protectedBytes.length == 0 ? CBOR.createObjectNode() : CBOR.readTree(protectedBytes);
        JsonNode unprotected = sign1.get(1);
        byte[] payload = sign1.get(2).binaryValue();
        byte[] signature = sign1.get(3).binaryValue();
        int alg = protectedHeader.path("1").asInt(0);
        JsonNode x5 = unprotected.has("33") ? unprotected.get("33") : protectedHeader.get("33");
        List<X509Certificate> chain = new ArrayList<>();
        if (x5 != null && x5.isArray()) {
            for (JsonNode c : x5) chain.add(Certificates.fromDer(c.binaryValue()));
        } else if (x5 != null) {
            chain.add(Certificates.fromDer(x5.binaryValue()));
        }
        List<String> warnings = new ArrayList<>();
        ListInfo.SignatureStatus sig;
        if (chain.isEmpty()) {
            throw new TrustSourceException("VICAL has no x5chain");
        }
        if (!Cose.verifySign1(alg, protectedBytes, payload, signature, chain.getFirst().getPublicKey())) {
            throw new TrustSourceException("VICAL signature is invalid");
        }
        if (signers.configured()) {
            var pv = signers.validate(chain, now);
            if (!pv.valid()) {
                throw new TrustSourceException("VICAL signer is not trusted: " + pv.issues());
            }
            sig = ListInfo.SignatureStatus.VERIFIED;
        } else if (def.bool("allowUnverified", false)) {
            warnings.add("VICAL signer not checked against a pinned VICAL provider certificate");
            sig = ListInfo.SignatureStatus.NOT_CHECKED;
        } else {
            throw new TrustSourceException("VICAL signer certificates are not configured (set allowUnverified to override)");
        }

        JsonNode vical = CBOR.readTree(payload);
        String provider = vical.path("vicalProvider").asText(null);
        Provenance prov = Provenance.of(def.id(), "vical", def.frameworkId(), location, now);
        List<TrustedEntity> entities = new ArrayList<>();
        List<TrustAnchor> anchors = new ArrayList<>();
        Map<String, TrustedEntity.Builder> byAuthority = new LinkedHashMap<>();
        for (JsonNode info : vical.path("certificateInfos")) {
            X509Certificate cert;
            try {
                cert = Certificates.fromDer(info.get("certificate").binaryValue());
            } catch (Exception e) {
                warnings.add("Skipped unparseable certificate: " + e.getMessage());
                continue;
            }
            List<String> docTypes = new ArrayList<>();
            JsonNode dt = info.get("docType");
            if (dt != null && dt.isArray()) dt.forEach(d -> docTypes.add(d.asText()));
            else if (dt != null) docTypes.add(dt.asText());
            String authority = info.path("issuingAuthority").asText(cert.getSubjectX500Principal().getName());
            String country = info.path("issuingCountry").asText(Certificates.subjectCountry(cert).orElse(null));
            String state = info.path("stateOrProvinceName").asText(null);
            String entityId = "vical:" + (country == null ? "xx" : country.toLowerCase()) + ":"
                    + (state == null ? "" : state.toLowerCase() + ":") + Base64Url.encode(authority.getBytes()).substring(0, Math.min(16, Base64Url.encode(authority.getBytes()).length()));
            TrustedEntity.Builder b = byAuthority.computeIfAbsent(entityId, id -> TrustedEntity.builder(id)
                    .framework(def.frameworkId()).role(EntityRole.CREDENTIAL_ISSUER).provenance(prov)
                    .display(LocalizedDisplay.of("en", authority))
                    .attribute("issuingCountry", country).attribute("stateOrProvinceName", state)
                    .attribute("vicalProvider", provider).attribute("trustedListUri", location));
            docTypes.forEach(d -> b.authorization(CredentialAuthorization.of(CredentialFormats.MSO_MDOC, d)));
            b.identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(cert));
            Certificates.subjectKeyIdentifier(cert).ifPresent(s -> b.identifier(IdentifierType.X509_SKI, s));
            Map<String, Object> constraints = new LinkedHashMap<>();
            constraints.put("docTypes", docTypes);
            constraints.put("trustedListUri", location);
            if (country != null) constraints.put("issuingCountry", country);
            if (state != null) constraints.put("stateOrProvinceName", state);
            anchors.add(new TrustAnchor(null, TrustDomain.MDOC_IACA, cert, def.frameworkId(), entityId, null, constraints, prov));
        }
        byAuthority.values().forEach(b -> entities.add(b.build()));
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("version", vical.path("version").asText(null));
        details.put("certificates", anchors.size());
        Instant nextUpdate = parseDate(vical.path("nextUpdate").asText(null));
        if (nextUpdate != null && nextUpdate.isBefore(now)) {
            // An expired list may be one from before an IACA was taken off it, served again by whoever controls its location.
            if (!def.bool("allowExpired", false)) {
                throw new TrustSourceException("VICAL " + location + " is past its nextUpdate " + nextUpdate
                        + " and is not loaded (allowExpired: true overrides)");
            }
            warnings.add("VICAL " + location + " is past its nextUpdate " + nextUpdate + " (allowExpired)");
        }
        ListInfo li = new ListInfo(provider, vical.path("vicalIssueID").asText(null), parseDate(vical.path("date").asText(null)),
                nextUpdate, sig, details);
        return new SourceLoadResult(entities, anchors, li, warnings);
    }

    static Instant parseDate(String s) {
        if (s == null || s.isBlank()) return null;
        try {
            return Instant.parse(s);
        } catch (Exception e) {
            return null;
        }
    }
}
