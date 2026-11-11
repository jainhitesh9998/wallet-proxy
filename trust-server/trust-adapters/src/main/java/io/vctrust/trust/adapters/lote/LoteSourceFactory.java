package io.vctrust.trust.adapters.lote;

import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import io.vctrust.trust.adapters.support.SignerVerification;
import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.model.EntityRole;
import io.vctrust.trust.core.model.EntityStatus;
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
import io.vctrust.trust.core.util.Hashes;
import io.vctrust.trust.core.x509.Certificates;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * {@code type: etsi-lote} — ETSI TS 119 602 Lists of Trusted Entities, JSON binding (plain or as a compact
 * JAdES / JWS). Used by the EUDI Wallet ecosystem for PID providers, wallet providers, access-certificate
 * CAs (WRPAC), registration-certificate providers (WRPRC) and Pub-EAA providers.
 *
 * <p>Properties: {@code location}; {@code signerCertificates} (required to accept a signed list);
 * {@code serviceTypeDomains} overrides; {@code allowExpired} (default false: a LoTE past NextUpdate is
 * rejected as TS 119 602 requires).
 */
public final class LoteSourceFactory implements TrustSourceFactory {

    static final String SVC = "http://uri.etsi.org/19602/SvcType/";

    /** Service type → (role, domains). */
    record Mapping(EntityRole role, List<String> domains) {
    }

    static final Map<String, Mapping> DEFAULTS = Map.ofEntries(
            Map.entry(SVC + "PID/Issuance", new Mapping(EntityRole.CREDENTIAL_ISSUER,
                    List.of(TrustDomain.CREDENTIAL_ISSUER.name(), TrustDomain.MDOC_IACA.name()))),
            Map.entry(SVC + "PubEAA/Issuance", new Mapping(EntityRole.CREDENTIAL_ISSUER,
                    List.of(TrustDomain.CREDENTIAL_ISSUER.name(), TrustDomain.MDOC_IACA.name()))),
            Map.entry(SVC + "WalletSolution/Issuance", new Mapping(EntityRole.WALLET_PROVIDER, List.of(TrustDomain.WALLET_PROVIDER.name()))),
            Map.entry(SVC + "WRPAC/Issuance", new Mapping(EntityRole.ACCREDITATION_AUTHORITY, List.of(TrustDomain.VERIFIER_ACCESS.name()))),
            Map.entry(SVC + "WRPRC/Issuance", new Mapping(EntityRole.ACCREDITATION_AUTHORITY, List.of("verifier-registration"))),
            Map.entry(SVC + "PID/Revocation", new Mapping(EntityRole.STATUS_LIST_PROVIDER, List.of(TrustDomain.STATUS_LIST.name()))),
            Map.entry(SVC + "PubEAA/Revocation", new Mapping(EntityRole.STATUS_LIST_PROVIDER, List.of(TrustDomain.STATUS_LIST.name()))),
            Map.entry(SVC + "WalletSolution/Revocation", new Mapping(EntityRole.STATUS_LIST_PROVIDER, List.of(TrustDomain.STATUS_LIST.name()))),
            Map.entry(SVC + "WRPAC/Revocation", new Mapping(EntityRole.STATUS_LIST_PROVIDER, List.of(TrustDomain.STATUS_LIST.name()))),
            Map.entry(SVC + "WRPRC/Revocation", new Mapping(EntityRole.STATUS_LIST_PROVIDER, List.of(TrustDomain.STATUS_LIST.name()))),
            Map.entry(SVC + "Register", new Mapping(EntityRole.OTHER, List.of())));

    @Override
    public String type() {
        return "etsi-lote";
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
                    byte[] raw = ctx.resources().load(location);
                    SignerVerification signers = SignerVerification.from(def, ctx.resources());
                    List<String> warnings = new ArrayList<>();
                    Instant now = ctx.clock().instant();
                    String text = new String(raw, StandardCharsets.UTF_8).trim();
                    Map<String, Object> doc;
                    ListInfo.SignatureStatus sig;
                    if (text.startsWith("{")) {
                        doc = Json.parseObject(text);
                        sig = ListInfo.SignatureStatus.NOT_SIGNED;
                        if (signers.configured() || !def.bool("allowUnverified", false)) {
                            throw new TrustSourceException("LoTE is not signed");
                        }
                    } else {
                        JWSObject jws = JWSObject.parse(text);
                        doc = jws.getPayload().toJSONObject();
                        if (signers.configured()) {
                            List<X509Certificate> chain = jws.getHeader().getX509CertChain() == null ? List.of()
                                    : jws.getHeader().getX509CertChain().stream().map(b -> Certificates.fromDer(b.decode())).toList();
                            if (chain.isEmpty()) {
                                throw new TrustSourceException("Signed LoTE has no x5c header");
                            }
                            if (!jws.verify(new DefaultJWSVerifierFactory().createJWSVerifier(jws.getHeader(), chain.getFirst().getPublicKey()))) {
                                throw new TrustSourceException("LoTE signature is invalid");
                            }
                            var pv = signers.validate(chain, now);
                            if (!pv.valid()) {
                                throw new TrustSourceException("LoTE signer is not trusted: " + pv.issues());
                            }
                            sig = ListInfo.SignatureStatus.VERIFIED;
                        } else if (def.bool("allowUnverified", false)) {
                            warnings.add("LoTE signature not verified: no signer certificates configured (allowUnverified)");
                            sig = ListInfo.SignatureStatus.NOT_CHECKED;
                        } else {
                            throw new TrustSourceException("LoTE signature cannot be verified: configure signer certificates, "
                                    + "or set allowUnverified: true to load the list on the strength of its transport alone");
                        }
                    }
                    Map<String, Object> lote = Json.object(doc.get("LoTE"));
                    if (lote == null) {
                        throw new TrustSourceException("Document has no LoTE root object");
                    }
                    return map(lote, def, location, sig, now, warnings);
                } catch (TrustSourceException e) {
                    throw e;
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load LoTE " + location + ": " + e.getMessage(), e);
                }
            }
        };
    }

    static SourceLoadResult map(Map<String, Object> lote, SourceDefinition def, String location,
                                ListInfo.SignatureStatus sig, Instant now, List<String> warnings) throws TrustSourceException {
        Map<String, Object> info = Json.object(lote.get("ListAndSchemeInformation"));
        if (info == null) {
            throw new TrustSourceException("LoTE lacks ListAndSchemeInformation");
        }
        Instant nextUpdate = parse(Json.string(info, "NextUpdate"));
        if (nextUpdate != null && nextUpdate.isBefore(now) && !def.bool("allowExpired", false)) {
            throw new TrustSourceException("LoTE is past its NextUpdate " + nextUpdate + " and must be discarded");
        }
        String loteType = Json.string(info, "LoTEType");
        String territory = Json.string(info, "SchemeTerritory");
        Map<String, Mapping> mappings = new LinkedHashMap<>(DEFAULTS);
        def.map("serviceTypeDomains").forEach((k, v) -> mappings.put(k, new Mapping(EntityRole.OTHER, List.of(String.valueOf(v)))));
        Provenance prov = Provenance.of(def.id(), "etsi-lote", def.frameworkId(), location, now);

        List<TrustedEntity> entities = new ArrayList<>();
        List<TrustAnchor> anchors = new ArrayList<>();
        List<Object> tes = Json.array(lote.get("TrustedEntitiesList"));
        for (Object teo : tes == null ? List.of() : tes) {
            Map<String, Object> te = Json.object(teo);
            Map<String, Object> tei = Json.object(te.get("TrustedEntityInformation"));
            String name = localized(tei == null ? null : tei.get("TEName"));
            String id = "lote:" + (territory == null ? "xx" : territory.toLowerCase(Locale.ROOT)) + ":"
                    + HexFormat.of().formatHex(Hashes.sha256(String.valueOf(name).getBytes(StandardCharsets.UTF_8))).substring(0, 16);
            TrustedEntity.Builder b = TrustedEntity.builder(id).framework(def.frameworkId()).provenance(prov)
                    .display(new LocalizedDisplay("en", name, localized(tei == null ? null : tei.get("TETradeName")), null))
                    .attribute("territory", territory).attribute("loteType", loteType).attribute("trustedListUri", location);
            List<String> serviceTypes = new ArrayList<>();
            List<Object> services = Json.array(te.get("TrustedEntityServices"));
            for (Object so : services == null ? List.of() : services) {
                Map<String, Object> si = Json.object(Json.object(so).get("ServiceInformation"));
                if (si == null) {
                    continue;
                }
                String st = Json.string(si, "ServiceTypeIdentifier");
                String status = Json.string(si, "ServiceStatus");
                boolean active = status == null || status.endsWith("/notified") || status.endsWith("/granted");
                Mapping m = st == null ? null : mappings.get(st);
                if (st != null) serviceTypes.add(st);
                if (m != null) b.role(m.role());
                Map<String, Object> sdi = Json.object(si.get("ServiceDigitalIdentity"));
                if (sdi == null) {
                    continue;
                }
                for (Object c : listOrEmpty(sdi.get("X509Certificates"))) {
                    Object val = c instanceof Map<?, ?> cm ? Json.object(cm).get("val") : c;
                    try {
                        X509Certificate cert = Certificates.fromBase64(String.valueOf(val).replaceAll("\\s", ""));
                        b.identifier(IdentifierType.X509_SUBJECT, Certificates.subjectName(cert));
                        for (String domain : m == null ? List.<String>of() : m.domains()) {
                            Map<String, Object> constraints = new LinkedHashMap<>();
                            constraints.put("serviceType", st);
                            constraints.put("trustedListUri", location);
                            anchors.add(new TrustAnchor(null, TrustDomain.of(domain), cert, def.frameworkId(), id,
                                    active ? EntityStatus.ACTIVE : EntityStatus.REVOKED, constraints, prov));
                        }
                    } catch (IllegalArgumentException e) {
                        warnings.add(name + ": bad certificate: " + e.getMessage());
                    }
                }
                for (Object jwk : listOrEmpty(sdi.get("PublicKeyValues"))) {
                    try {
                        b.identifier(IdentifierType.JWK_THUMBPRINT,
                                com.nimbusds.jose.jwk.JWK.parse(Json.object(jwk)).computeThumbprint().toString());
                    } catch (Exception e) {
                        warnings.add(name + ": bad public key value");
                    }
                }
                for (Object ski : listOrEmpty(sdi.get("X509SKIs"))) {
                    b.identifier(IdentifierType.X509_SKI, String.valueOf(ski));
                }
            }
            b.attribute("serviceTypes", serviceTypes);
            if (b.build().roles().isEmpty()) {
                b.role(EntityRole.OTHER);
            }
            entities.add(b.build());
        }
        Map<String, Object> details = new LinkedHashMap<>();
        if (loteType != null) details.put("loteType", loteType);
        if (territory != null) details.put("territory", territory);
        ListInfo li = new ListInfo(localized(info.get("SchemeOperatorName")), String.valueOf(info.get("LoTESequenceNumber")),
                parse(Json.string(info, "ListIssueDateTime")), nextUpdate, sig, details);
        return new SourceLoadResult(entities, anchors, li, warnings);
    }

    private static List<Object> listOrEmpty(Object o) {
        List<Object> l = Json.array(o);
        return l == null ? List.of() : l;
    }

    /** Value of a multilingual [{lang, value}] array, preferring English. */
    static String localized(Object v) {
        if (v instanceof String s) {
            return s;
        }
        List<Object> l = Json.array(v);
        if (l == null || l.isEmpty()) {
            return null;
        }
        String first = null;
        for (Object o : l) {
            Map<String, Object> m = Json.object(o);
            if (m == null) continue;
            String val = Json.string(m, "value");
            if ("en".equalsIgnoreCase(Json.string(m, "lang"))) return val;
            if (first == null) first = val;
        }
        return first;
    }

    static Instant parse(String s) {
        if (s == null) return null;
        try {
            return Instant.parse(s);
        } catch (Exception e) {
            return java.time.OffsetDateTime.parse(s).toInstant();
        }
    }
}
