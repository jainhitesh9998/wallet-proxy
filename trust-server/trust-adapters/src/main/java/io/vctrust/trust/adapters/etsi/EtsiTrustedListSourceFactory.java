package io.vctrust.trust.adapters.etsi;

import io.vctrust.trust.adapters.support.SignerVerification;
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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * {@code type: etsi-tl} — ETSI TS 119 612 Trusted Lists (XML), including the EU List of Trusted Lists.
 *
 * <p>Properties: {@code location} (TL or LOTL URL); {@code followPointers} (LOTL → national TLs, default true
 * for a LOTL); {@code territories} filter; {@code serviceTypeDomains} (service type URI → trust domain);
 * {@code signerCertificates} / {@code signerCertificateLocation} to require a valid XML signature;
 * {@code verifyPointerSignatures} (validate national TLs against the LOTL's pointer certificates).
 */
public final class EtsiTrustedListSourceFactory implements TrustSourceFactory {

    static final String NS = "http://uri.etsi.org/02231/v2#";
    static final String LOTL_TYPE = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists";
    static final String TSL_MIME = "application/vnd.etsi.tsl+xml";
    static final String SVC = "http://uri.etsi.org/TrstSvc/Svctype/";

    /** Default mapping of EAA-relevant service types to trust domains. */
    static final Map<String, String> DEFAULT_DOMAINS = Map.of(
            SVC + "EAA/Q", TrustDomain.CREDENTIAL_ISSUER.name(),
            SVC + "EAA", TrustDomain.CREDENTIAL_ISSUER.name(),
            SVC + "EAA/Pub-EAA", TrustDomain.CREDENTIAL_ISSUER.name());

    static final Set<String> ACTIVE_STATUS = Set.of("granted", "recognisedatnationallevel", "undersupervision",
            "accredited", "setbynationallaw", "supervisionincessation");

    @Override
    public String type() {
        return "etsi-tl";
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
                    SignerVerification signers = SignerVerification.from(def, ctx.resources());
                    Map<String, String> domains = new LinkedHashMap<>(DEFAULT_DOMAINS);
                    def.map("serviceTypeDomains").forEach((k, v) -> domains.put(k, String.valueOf(v)));
                    boolean includeAll = def.bool("includeAllServiceTypes", false);
                    Parsed root = parse(ctx.resources().load(location), location, signers, ctx.clock().instant());
                    List<TrustedEntity> entities = new ArrayList<>();
                    List<TrustAnchor> anchors = new ArrayList<>();
                    List<String> warnings = new ArrayList<>(root.warnings);
                    Set<String> territories = Set.copyOf(def.strings("territories").stream().map(s -> s.toUpperCase(Locale.ROOT)).toList());
                    boolean isLotl = LOTL_TYPE.equals(root.info.details().get("tslType"));
                    if (isLotl && def.bool("followPointers", true)) {
                        for (Pointer p : root.pointers) {
                            if (!TSL_MIME.equals(p.mimeType) || (!territories.isEmpty() && !territories.contains(p.territory))
                                    || p.location.equals(location)) {
                                continue;
                            }
                            try {
                                SignerVerification ps = def.bool("verifyPointerSignatures", true)
                                        ? SignerVerification.of(p.certificates) : SignerVerification.of(List.of());
                                Parsed tl = parse(ctx.resources().load(p.location), p.location, ps, ctx.clock().instant());
                                warnings.addAll(tl.warnings);
                                map(tl, def, domains, includeAll, ctx.clock().instant(), entities, anchors);
                            } catch (Exception e) {
                                warnings.add("TL " + p.territory + " (" + p.location + "): " + e.getMessage());
                            }
                        }
                    } else {
                        map(root, def, domains, includeAll, ctx.clock().instant(), entities, anchors);
                    }
                    Map<String, Object> details = new LinkedHashMap<>(root.info.details());
                    details.put("pointers", root.pointers.size());
                    ListInfo info = new ListInfo(root.info.issuer(), root.info.sequence(), root.info.issuedAt(),
                            root.info.nextUpdate(), root.info.signature(), details);
                    return new SourceLoadResult(entities, anchors, info, warnings);
                } catch (TrustSourceException e) {
                    throw e;
                } catch (Exception e) {
                    throw new TrustSourceException("Cannot load trusted list " + location + ": " + e.getMessage(), e);
                }
            }
        };
    }

    record Pointer(String location, String territory, String mimeType, List<X509Certificate> certificates) {
    }

    record Service(String type, String name, String status, Instant statusSince, List<X509Certificate> certificates,
                   List<String> skis) {
    }

    record Provider(String name, String tradeName, String informationUri, List<Service> services) {
    }

    record Parsed(String location, ListInfo info, String territory, List<Pointer> pointers, List<Provider> providers,
                  List<String> warnings) {
    }

    static Parsed parse(byte[] xml, String location, SignerVerification signers, Instant now) throws Exception {
        Document doc = secureParse(xml);
        Element root = doc.getDocumentElement();
        if (!"TrustServiceStatusList".equals(root.getLocalName()) || !NS.equals(root.getNamespaceURI())) {
            throw new TrustSourceException("Not an ETSI TS 119 612 TrustServiceStatusList");
        }
        List<String> warnings = new ArrayList<>();
        ListInfo.SignatureStatus sig = verifySignature(doc, signers, now, warnings);
        Element si = child(root, "SchemeInformation");
        String territory = text(child(si, "SchemeTerritory"));
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tslType", text(child(si, "TSLType")));
        details.put("territory", territory);
        details.put("version", text(child(si, "TSLVersionIdentifier")));
        Element nu = child(si, "NextUpdate");
        Instant nextUpdate = nu == null ? null : parseInstant(text(child(nu, "dateTime")));
        ListInfo info = new ListInfo(firstName(child(si, "SchemeOperatorName")), text(child(si, "TSLSequenceNumber")),
                parseInstant(text(child(si, "ListIssueDateTime"))), nextUpdate, sig, details);
        if (nextUpdate != null && nextUpdate.isBefore(now)) {
            warnings.add("Trusted list " + location + " is past its NextUpdate " + nextUpdate);
        }

        List<Pointer> pointers = new ArrayList<>();
        Element pots = child(si, "PointersToOtherTSL");
        if (pots != null) {
            for (Element p : children(pots, "OtherTSLPointer")) {
                List<X509Certificate> certs = new ArrayList<>();
                for (Element x : descendants(p, "X509Certificate")) {
                    try {
                        certs.add(Certificates.fromBase64(text(x).replaceAll("\\s", "")));
                    } catch (IllegalArgumentException e) {
                        warnings.add("Bad pointer certificate: " + e.getMessage());
                    }
                }
                String mime = null;
                String terr = null;
                for (Element oi : descendants(p, "OtherInformation")) {
                    for (Node n = oi.getFirstChild(); n != null; n = n.getNextSibling()) {
                        if (n instanceof Element e) {
                            if ("MimeType".equals(e.getLocalName())) mime = text(e);
                            if ("SchemeTerritory".equals(e.getLocalName())) terr = text(e);
                        }
                    }
                }
                pointers.add(new Pointer(text(child(p, "TSLLocation")), terr == null ? null : terr.toUpperCase(Locale.ROOT), mime, certs));
            }
        }

        List<Provider> providers = new ArrayList<>();
        Element tspList = child(root, "TrustServiceProviderList");
        if (tspList != null) {
            for (Element tsp : children(tspList, "TrustServiceProvider")) {
                Element inf = child(tsp, "TSPInformation");
                List<Service> services = new ArrayList<>();
                Element svcs = child(tsp, "TSPServices");
                if (svcs != null) {
                    for (Element s : children(svcs, "TSPService")) {
                        Element sinf = child(s, "ServiceInformation");
                        List<X509Certificate> certs = new ArrayList<>();
                        List<String> skis = new ArrayList<>();
                        Element sdi = child(sinf, "ServiceDigitalIdentity");
                        if (sdi != null) {
                            for (Element x : descendants(sdi, "X509Certificate")) {
                                try {
                                    certs.add(Certificates.fromBase64(text(x).replaceAll("\\s", "")));
                                } catch (IllegalArgumentException e) {
                                    warnings.add("Bad service certificate: " + e.getMessage());
                                }
                            }
                            for (Element x : descendants(sdi, "X509SKI")) {
                                skis.add(text(x).replaceAll("\\s", ""));
                            }
                        }
                        String status = text(child(sinf, "ServiceStatus"));
                        services.add(new Service(text(child(sinf, "ServiceTypeIdentifier")), firstName(child(sinf, "ServiceName")),
                                status == null ? null : status.substring(status.lastIndexOf('/') + 1),
                                parseInstant(text(child(sinf, "StatusStartingTime"))), certs, skis));
                    }
                }
                Element uri = child(inf, "TSPInformationURI");
                providers.add(new Provider(firstName(child(inf, "TSPName")), firstName(child(inf, "TSPTradeName")),
                        uri == null ? null : firstName(uri), services));
            }
        }
        return new Parsed(location, info, territory, pointers, providers, warnings);
    }

    static void map(Parsed tl, SourceDefinition def, Map<String, String> domains, boolean includeAll, Instant now,
                    List<TrustedEntity> entities, List<TrustAnchor> anchors) {
        Provenance prov = Provenance.of(def.id(), "etsi-tl", def.frameworkId(), tl.location, now);
        for (Provider p : tl.providers) {
            String entityId = "etsi-tl:" + (tl.territory == null ? "xx" : tl.territory.toLowerCase(Locale.ROOT)) + ":"
                    + HexFormat.of().formatHex(Hashes.sha256(String.valueOf(p.name).getBytes(StandardCharsets.UTF_8))).substring(0, 16);
            TrustedEntity.Builder b = TrustedEntity.builder(entityId).framework(def.frameworkId()).provenance(prov)
                    .display(new LocalizedDisplay("en", p.name, p.tradeName, null))
                    .attribute("territory", tl.territory).attribute("trustedListUri", tl.location)
                    .attribute("informationUri", p.informationUri);
            boolean anyRelevant = false;
            boolean anyActive = false;
            List<String> serviceTypes = new ArrayList<>();
            for (Service s : p.services) {
                String domain = domains.get(s.type);
                if (domain == null && includeAll && s.type != null) {
                    domain = "etsi-" + s.type.substring(s.type.indexOf("Svctype/") + 8).replace('/', '-').toLowerCase(Locale.ROOT);
                }
                if (domain == null) {
                    continue;
                }
                anyRelevant = true;
                serviceTypes.add(s.type);
                boolean active = s.status == null || ACTIVE_STATUS.contains(s.status.toLowerCase(Locale.ROOT));
                anyActive |= active;
                if (TrustDomain.CREDENTIAL_ISSUER.name().equals(domain)) {
                    b.role(EntityRole.CREDENTIAL_ISSUER);
                }
                for (X509Certificate c : s.certificates) {
                    Map<String, Object> constraints = new LinkedHashMap<>();
                    constraints.put("serviceType", s.type);
                    if (s.name != null) constraints.put("serviceName", s.name);
                    constraints.put("trustedListUri", tl.location);
                    anchors.add(new TrustAnchor(null, TrustDomain.of(domain), c, def.frameworkId(), entityId,
                            active ? EntityStatus.ACTIVE : EntityStatus.REVOKED, constraints, prov));
                    b.identifier(IdentifierType.X509_SUBJECT, c.getSubjectX500Principal().getName());
                }
                s.skis.forEach(ski -> b.identifier(IdentifierType.X509_SKI, ski));
            }
            if (!anyRelevant) {
                continue;
            }
            if (!b.build().hasRole(EntityRole.CREDENTIAL_ISSUER)) {
                b.role(EntityRole.OTHER);
            }
            b.attribute("serviceTypes", serviceTypes);
            b.status(anyActive ? EntityStatus.ACTIVE : EntityStatus.REVOKED);
            entities.add(b.build());
        }
    }

    private static ListInfo.SignatureStatus verifySignature(Document doc, SignerVerification signers, Instant now,
                                                            List<String> warnings) throws TrustSourceException {
        NodeList sigs = doc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (sigs.getLength() == 0) {
            if (signers.configured()) {
                throw new TrustSourceException("Trusted list is not signed but signer certificates are configured");
            }
            return ListInfo.SignatureStatus.NOT_SIGNED;
        }
        if (!signers.configured()) {
            warnings.add("Trusted list signature not verified: no signer certificates configured");
            return ListInfo.SignatureStatus.NOT_CHECKED;
        }
        registerIds(doc.getDocumentElement());
        X509Certificate[] signer = new X509Certificate[1];
        try {
            DOMValidateContext vc = new DOMValidateContext(new KeySelector() {
                @Override
                public KeySelectorResult select(KeyInfo keyInfo, Purpose purpose, AlgorithmMethod method,
                                                XMLCryptoContext context) throws KeySelectorException {
                    if (keyInfo == null) {
                        throw new KeySelectorException("Signature has no KeyInfo");
                    }
                    for (Object o : keyInfo.getContent()) {
                        if (o instanceof X509Data xd) {
                            for (Object c : xd.getContent()) {
                                if (c instanceof X509Certificate cert) {
                                    signer[0] = cert;
                                    return cert::getPublicKey;
                                }
                            }
                        }
                    }
                    throw new KeySelectorException("No X509Certificate in KeyInfo");
                }
            }, sigs.item(0));
            vc.setProperty("org.jcp.xml.dsig.secureValidation", Boolean.TRUE);
            XMLSignature signature = XMLSignatureFactory.getInstance("DOM").unmarshalXMLSignature(vc);
            if (!signature.validate(vc)) {
                throw new TrustSourceException("Trusted list XML signature is invalid");
            }
        } catch (TrustSourceException e) {
            throw e;
        } catch (Exception e) {
            throw new TrustSourceException("Trusted list XML signature could not be validated: " + e.getMessage(), e);
        }
        var pv = signers.validate(List.of(signer[0]), now);
        if (!pv.valid()) {
            throw new TrustSourceException("Trusted list signer is not trusted: " + pv.issues());
        }
        return ListInfo.SignatureStatus.VERIFIED;
    }

    /** Marks every {@code Id} attribute as an XML ID so that same-document references resolve. */
    private static void registerIds(Element e) {
        if (e.hasAttribute("Id")) {
            e.setIdAttribute("Id", true);
        }
        for (Node n = e.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element c) {
                registerIds(c);
            }
        }
    }

    static Document secureParse(byte[] xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setNamespaceAware(true);
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        f.setXIncludeAware(false);
        f.setExpandEntityReferences(false);
        return f.newDocumentBuilder().parse(new ByteArrayInputStream(xml));
    }

    static Element child(Element parent, String localName) {
        if (parent == null) {
            return null;
        }
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && localName.equals(e.getLocalName())) {
                return e;
            }
        }
        return null;
    }

    static List<Element> children(Element parent, String localName) {
        List<Element> out = new ArrayList<>();
        for (Node n = parent.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e && localName.equals(e.getLocalName())) {
                out.add(e);
            }
        }
        return out;
    }

    static List<Element> descendants(Element parent, String localName) {
        List<Element> out = new ArrayList<>();
        NodeList nl = parent.getElementsByTagNameNS("*", localName);
        for (int i = 0; i < nl.getLength(); i++) {
            out.add((Element) nl.item(i));
        }
        return out;
    }

    static String text(Element e) {
        return e == null ? null : e.getTextContent().trim();
    }

    /** First {@code Name}/{@code URI} child, preferring xml:lang="en". */
    static String firstName(Element multiLang) {
        if (multiLang == null) {
            return null;
        }
        String first = null;
        for (Node n = multiLang.getFirstChild(); n != null; n = n.getNextSibling()) {
            if (n instanceof Element e) {
                String lang = e.getAttributeNS(XMLConstants.XML_NS_URI, "lang");
                if ("en".equalsIgnoreCase(lang)) {
                    return text(e);
                }
                if (first == null) {
                    first = text(e);
                }
            }
        }
        return first;
    }

    static Instant parseInstant(String s) {
        if (s == null || s.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(s);
        } catch (Exception e) {
            try {
                return java.time.OffsetDateTime.parse(s).toInstant();
            } catch (Exception ignored) {
                return null;
            }
        }
    }
}
