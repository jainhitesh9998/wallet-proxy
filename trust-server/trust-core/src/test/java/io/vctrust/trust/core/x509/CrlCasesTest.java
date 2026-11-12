package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.json.Json;
import io.vctrust.trust.core.testing.TestPki;
import io.vctrust.trust.core.x509.RevocationChecker.Crl;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import tools.jackson.core.type.TypeReference;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * How one CRL is read, and how several for one certificate decide: {@code conformance/revocation/crl-cases.json}, the
 * device's rule ({@code checkRevocation} in trust-client) written down case by case. The service's
 * {@link RevocationChecker} must give every case its expected status (and, where one is decided, its reason and the CRL
 * that decided it), and {@code crl-cases.test.ts} holds the device to the same file.
 *
 * <p>The file is written by this test with {@code -Dcrl.cases.update=true}: the certificates and CRLs are built here,
 * the expected outcomes are written here by hand (they are the rule, not what either side happens to say). Without the
 * flag the test only replays the file.
 */
class CrlCasesTest {

    static final Instant AT = Instant.parse("2026-06-01T00:00:00Z");
    static final String DP = "http://crl.test/ca.crl";
    static final String OTHER_DP = "http://crl.test/partition-2.crl";
    static final BigInteger LEAF = BigInteger.valueOf(0x1001);
    static final BigInteger OTHER = BigInteger.valueOf(0x9999);
    static final String UNKNOWN_OID = "1.3.6.1.4.1.99999.2";

    record Expect(String status, String reason, Integer crl) {
    }

    record Case(String name, String about, String certificate, String issuer, List<String> crls, Expect expect) {
    }

    record Cases(String description, String at, Map<String, String> certificates, List<Case> cases) {
    }

    static Path file() {
        Path p = Path.of("").toAbsolutePath();
        while (p != null && !Files.isDirectory(p.resolve("conformance"))) {
            p = p.getParent();
        }
        assertThat(p).as("conformance/ above the working directory").isNotNull();
        return p.resolve("conformance/revocation/crl-cases.json");
    }

    @Test
    void everyCaseIsDecidedAsTheSharedFileSays() throws Exception {
        if (Boolean.getBoolean("crl.cases.update")) {
            Files.createDirectories(file().getParent());
            Files.writeString(file(), Json.MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(generate()) + "\n");
        }
        Cases cases = Json.MAPPER.readValue(Files.readString(file()), new TypeReference<Cases>() { });
        Instant at = Instant.parse(cases.at());
        Map<String, X509Certificate> certs = new LinkedHashMap<>();
        cases.certificates().forEach((name, b64) -> certs.put(name, certificate(Base64.getDecoder().decode(b64))));
        assertThat(cases.cases()).isNotEmpty();
        List<String> wrong = new ArrayList<>();
        for (Case c : cases.cases()) {
            List<Crl> held = new ArrayList<>();
            for (int i = 0; i < c.crls().size(); i++) {
                held.add(Crl.parse(Base64.getDecoder().decode(c.crls().get(i)), heldUrl(i), at));
            }
            RevocationChecker.CrlSource source = new RevocationChecker.CrlSource() {
                @Override
                public List<Crl> heldFor(X509Certificate issuer) {
                    return held;
                }

                @Override
                public Crl fetch(String url) throws IOException {
                    throw new IOException("no CRL is fetched in these cases");
                }
            };
            CertificateRevocation r = new RevocationChecker(source, "conformance")
                    .check(List.of(certs.get(c.certificate())), certs.get(c.issuer()), at, false).statuses().getFirst();
            Expect got = new Expect(r.status().name(),
                    r.status() == CertificateRevocation.Status.REVOKED || r.status() == CertificateRevocation.Status.ON_HOLD ? r.reason() : null,
                    r.status() == CertificateRevocation.Status.UNKNOWN ? null : heldIndex(r.crlUrl()));
            if (!got.equals(c.expect())) {
                wrong.add(c.name() + ": expected " + c.expect() + ", got " + got + (r.status() == CertificateRevocation.Status.UNKNOWN ? " (" + r.reason() + ")" : ""));
            }
        }
        assertThat(wrong).as("cases the service decides otherwise than the shared file").isEmpty();
    }

    /** The URL each held CRL of a case is held under, by its position: the outcome names the CRL that decided by it. */
    static String heldUrl(int i) {
        return "https://crl.test/held/" + i;
    }

    static Integer heldIndex(String url) {
        return url == null || !url.startsWith("https://crl.test/held/") ? null : Integer.valueOf(url.substring("https://crl.test/held/".length()));
    }

    static X509Certificate certificate(byte[] der) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    // ---- generation (-Dcrl.cases.update=true) -------------------------------------------------------------------

    /** A CRL entry: a serial number, a reason code (null: none, read as unspecified) and further entry extensions. */
    record Entry(BigInteger serial, Integer reason, List<Extension> extensions) {
        static Entry of(BigInteger serial, Integer reason, Extension... extensions) {
            return new Entry(serial, reason, List.of(extensions));
        }
    }

    /** What a CRL of a case is: issuer name and signing key, dates, entries, CRL number and further extensions. */
    record CrlSpec(X500Name issuer, PrivateKey signer, Instant thisUpdate, Instant nextUpdate, List<Entry> entries,
                   BigInteger number, List<Extension> extensions) {
    }

    static final class Pki {
        final KeyPair caKeys = TestPki.ecKey();
        final KeyPair noCrlSignKeys = TestPki.ecKey();
        final KeyPair otherKeys = TestPki.ecKey();
        final X509Certificate ca = cert("CN=CRL Cases CA,O=Conformance,C=UT", caKeys, null, caKeys, BigInteger.valueOf(1), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign, null);
        final X509Certificate caNoCrlSign = cert("CN=CRL Cases CA without cRLSign,O=Conformance,C=UT", noCrlSignKeys, null, noCrlSignKeys,
                BigInteger.valueOf(2), true, KeyUsage.keyCertSign, null);
        final X509Certificate other = cert("CN=Another CA,O=Conformance,C=UT", otherKeys, null, otherKeys, BigInteger.valueOf(3), true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign, null);
        final X509Certificate leaf = cert("CN=Leaf,O=Conformance,C=UT", TestPki.ecKey(), ca, caKeys, LEAF, false, KeyUsage.digitalSignature,
                points(new DistributionPoint(uriName(DP), null, null)));
        final X509Certificate leafNoDp = cert("CN=Leaf without a distribution point,O=Conformance,C=UT", TestPki.ecKey(), ca, caKeys, LEAF,
                false, KeyUsage.digitalSignature, null);
        final X509Certificate leafDpReasons = cert("CN=Leaf with a distribution point for some reasons,O=Conformance,C=UT", TestPki.ecKey(), ca,
                caKeys, LEAF, false, KeyUsage.digitalSignature,
                points(new DistributionPoint(uriName(DP), new ReasonFlags(ReasonFlags.keyCompromise), null)));
        final X509Certificate leafDpCrlIssuer = cert("CN=Leaf with a distribution point of another CRL issuer,O=Conformance,C=UT",
                TestPki.ecKey(), ca, caKeys, LEAF, false, KeyUsage.digitalSignature,
                points(new DistributionPoint(uriName(DP), null, new GeneralNames(new GeneralName(new X500Name("CN=Other CRL Issuer"))))));
        final X509Certificate subCa = cert("CN=Sub CA,O=Conformance,C=UT", TestPki.ecKey(), ca, caKeys, LEAF, true,
                KeyUsage.keyCertSign | KeyUsage.cRLSign, points(new DistributionPoint(uriName(DP), null, null)));
        final X509Certificate leafOfNoCrlSign = cert("CN=Leaf of a CA without cRLSign,O=Conformance,C=UT", TestPki.ecKey(), caNoCrlSign,
                noCrlSignKeys, LEAF, false, KeyUsage.digitalSignature, points(new DistributionPoint(uriName(DP), null, null)));

        X500Name caName() {
            return X500Name.getInstance(ca.getSubjectX500Principal().getEncoded());
        }
    }

    static Cases generate() {
        Pki pki = new Pki();
        Map<String, X509Certificate> certs = new LinkedHashMap<>();
        certs.put("ca", pki.ca);
        certs.put("ca-without-crl-sign", pki.caNoCrlSign);
        certs.put("another-ca", pki.other);
        certs.put("leaf", pki.leaf);
        certs.put("leaf-without-dp", pki.leafNoDp);
        certs.put("leaf-dp-some-reasons", pki.leafDpReasons);
        certs.put("leaf-dp-other-crl-issuer", pki.leafDpCrlIssuer);
        certs.put("sub-ca", pki.subCa);
        certs.put("leaf-of-ca-without-crl-sign", pki.leafOfNoCrlSign);

        Instant older = AT.minus(Duration.ofDays(6));
        Instant newer = AT.minus(Duration.ofHours(1));
        Instant next = AT.plus(Duration.ofDays(7));
        X500Name ca = pki.caName();
        PrivateKey key = pki.caKeys.getPrivate();
        Extension delta = ext(Extension.deltaCRLIndicator, true, new CRLNumber(BigInteger.ONE));
        Extension unknownCritical = ext(new ASN1ObjectIdentifier(UNKNOWN_OID), true, new DERUTF8String("x"));
        Extension unknownNonCritical = ext(new ASN1ObjectIdentifier(UNKNOWN_OID), false, new DERUTF8String("x"));
        Extension otherIssuer = ext(Extension.certificateIssuer, false, new GeneralNames(new GeneralName(new X500Name("CN=Other CA"))));
        Extension otherIssuerCritical = ext(Extension.certificateIssuer, true, new GeneralNames(new GeneralName(new X500Name("CN=Other CA"))));

        // Shorthands: a complete CRL of the CA, current at AT, issued an hour before (or at the instant given).
        record B(X500Name issuer, PrivateKey signer, Instant thisUpdate, Instant nextUpdate, BigInteger number) {
            CrlSpec with(List<Entry> entries, Extension... exts) {
                return new CrlSpec(issuer, signer, thisUpdate, nextUpdate, entries, number, List.of(exts));
            }

            CrlSpec good(Extension... exts) {
                return with(List.of(), exts);
            }

            CrlSpec listing(Integer reason, Extension... exts) {
                return with(List.of(Entry.of(LEAF, reason)), exts);
            }
        }
        B now = new B(ca, key, newer, next, BigInteger.TWO);
        B old = new B(ca, key, older, next, BigInteger.ONE);
        B at = new B(ca, key, newer, next, BigInteger.ONE);
        Integer keyCompromise = 1;
        Integer superseded = 4;
        Integer hold = 6;
        Integer remove = 8;

        List<Object[]> cases = new ArrayList<>();
        Consumer<Object[]> add = cases::add;
        // name, about, certificate, issuer, CRLs, expected status, reason, deciding CRL
        add.accept(c("not-listed", "A complete, current CRL that does not list the certificate", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(OTHER, keyCompromise)))), "GOOD", null, 0));
        add.accept(c("revoked", "A complete CRL lists the certificate as revoked", "leaf", "ca", List.of(now.listing(keyCompromise)), "REVOKED", "keyCompromise", 0));
        add.accept(c("revoked-without-reason", "Listed without a reason code: unspecified", "leaf", "ca", List.of(now.listing(null)), "REVOKED", "unspecified", 0));
        add.accept(c("on-hold", "Listed with certificateHold", "leaf", "ca", List.of(now.listing(hold)), "ON_HOLD", "certificateHold", 0));
        add.accept(c("unknown-non-critical-crl-extension", "A CRL extension nobody knows, not critical, is ignored", "leaf", "ca",
                List.of(now.good(unknownNonCritical)), "GOOD", null, 0));

        // The situations in which the two sides read one CRL differently before (integration-fixes item 8).
        add.accept(c("remove-from-crl-in-a-complete-crl", "removeFromCRL lifts a hold in a delta CRL; in a complete CRL it should not appear, and proves nothing",
                "leaf", "ca", List.of(now.listing(remove)), "UNKNOWN", null, null));
        add.accept(c("hold-in-older-remove-from-crl-in-newer", "A hold in the older complete CRL, removeFromCRL in the newer one: the newer decides, and proves nothing",
                "leaf", "ca", List.of(old.listing(hold), now.listing(remove)), "UNKNOWN", null, null));
        add.accept(c("hold-in-older-remove-from-crl-in-newer-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(remove), old.listing(hold)), "UNKNOWN", null, null));
        add.accept(c("no-next-update-issued-30-days-ago", "A CRL that states no next update is used for seven days after it was issued",
                "leaf", "ca", List.of(new B(ca, key, AT.minus(Duration.ofDays(30)), null, BigInteger.ONE).good()), "UNKNOWN", null, null));
        add.accept(c("no-next-update-issued-6-days-ago", "Within the seven days it is used", "leaf", "ca",
                List.of(new B(ca, key, AT.minus(Duration.ofDays(6)), null, BigInteger.ONE).good()), "GOOD", null, 0));
        add.accept(c("delta-crl-alone-revokes", "A delta CRL alone that lists the certificate: a revocation it shows stands", "leaf", "ca",
                List.of(now.listing(keyCompromise, delta)), "REVOKED", "keyCompromise", 0));
        add.accept(c("delta-crl-alone-holds", "A delta CRL alone that lists the certificate on hold", "leaf", "ca",
                List.of(now.listing(hold, delta)), "ON_HOLD", "certificateHold", 0));
        add.accept(c("delta-crl-alone-silent", "A delta CRL is not a complete list: that it does not list the certificate proves nothing",
                "leaf", "ca", List.of(now.good(delta)), "UNKNOWN", null, null));
        add.accept(c("complete-good-newer-delta-revokes", "The complete CRL does not list it, a newer delta CRL revokes it", "leaf", "ca",
                List.of(old.good(), now.listing(keyCompromise, delta)), "REVOKED", "keyCompromise", 1));
        add.accept(c("complete-good-newer-delta-revokes-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(keyCompromise, delta), old.good()), "REVOKED", "keyCompromise", 0));
        add.accept(c("listed-twice-revoked-then-removed", "The serial listed twice, keyCompromise then removeFromCRL: the gravest entry stands",
                "leaf", "ca", List.of(now.with(List.of(Entry.of(LEAF, keyCompromise), Entry.of(LEAF, remove)))), "REVOKED", "keyCompromise", 0));
        add.accept(c("listed-twice-removed-then-revoked", "The same entries in the other order", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(LEAF, remove), Entry.of(LEAF, keyCompromise)))), "REVOKED", "keyCompromise", 0));
        add.accept(c("listed-twice-hold-then-removed", "A hold and a removeFromCRL for the serial: the hold is the graver", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(LEAF, hold), Entry.of(LEAF, remove)))), "ON_HOLD", "certificateHold", 0));
        add.accept(c("another-serial-listed-twice", "A CRL that lists another serial twice is not a sound list: it proves no certificate good that it does not list",
                "leaf", "ca", List.of(now.with(List.of(Entry.of(OTHER, keyCompromise), Entry.of(OTHER, keyCompromise)))), "UNKNOWN", null, null));
        add.accept(c("another-serial-listed-twice-then-a-sound-crl", "A sound CRL next to it decides", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(OTHER, keyCompromise), Entry.of(OTHER, keyCompromise))), old.good()), "GOOD", null, 1));
        add.accept(c("certificate-issuer-on-another-entry", "A non-critical certificateIssuer on another entry: an indirect CRL, which is not evaluated",
                "leaf", "ca", List.of(now.with(List.of(Entry.of(OTHER, keyCompromise, otherIssuer)))), "UNKNOWN", null, null));
        add.accept(c("critical-certificate-issuer-on-another-entry", "The same with the extension critical", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(OTHER, keyCompromise, otherIssuerCritical)))), "UNKNOWN", null, null));
        add.accept(c("complete-holds-newer-delta-removes", "The complete CRL holds it, a newer delta CRL has removeFromCRL: deltas are not combined with their base",
                "leaf", "ca", List.of(old.listing(hold), now.listing(remove, delta)), "UNKNOWN", null, null));
        add.accept(c("complete-holds-newer-delta-removes-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(remove, delta), old.listing(hold)), "UNKNOWN", null, null));

        // Extensions.
        add.accept(c("unknown-critical-crl-extension", "A critical CRL extension nobody knows: the CRL is not used", "leaf", "ca",
                List.of(now.good(unknownCritical)), "UNKNOWN", null, null));
        add.accept(c("unknown-critical-entry-extension-on-another-entry", "A critical entry extension nobody knows, on another entry: the CRL is not used",
                "leaf", "ca", List.of(now.with(List.of(Entry.of(OTHER, keyCompromise, unknownCritical)))), "UNKNOWN", null, null));
        add.accept(c("unknown-non-critical-entry-extension", "Not critical, it is ignored", "leaf", "ca",
                List.of(now.with(List.of(Entry.of(OTHER, keyCompromise, unknownNonCritical)))), "GOOD", null, 0));
        add.accept(c("critical-reason-code-on-another-entry", "A reason code marked critical is still a known extension", "leaf", "ca",
                List.of(now.with(List.of(new Entry(OTHER, null, List.of(ext(Extension.reasonCode, true, CRLReason.lookup(1))))))), "GOOD", null, 0));

        // Scope: the issuing distribution point.
        Extension idpDp = idp(new IssuingDistributionPoint(uriName(DP), false, false, null, false, false));
        add.accept(c("idp-names-the-certificates-point", "The CRL is for the distribution point the certificate names", "leaf", "ca",
                List.of(now.good(idpDp)), "GOOD", null, 0));
        add.accept(c("idp-names-the-certificates-point-revoked", "Such a CRL that lists it", "leaf", "ca",
                List.of(now.listing(keyCompromise, idpDp)), "REVOKED", "keyCompromise", 0));
        add.accept(c("idp-names-another-point", "A CRL for another distribution point does not cover the certificate", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(uriName(OTHER_DP), false, false, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-names-another-point-revoked", "Nor does what it lists count", "leaf", "ca",
                List.of(now.listing(keyCompromise, idp(new IssuingDistributionPoint(uriName(OTHER_DP), false, false, null, false, false)))),
                "UNKNOWN", null, null));
        add.accept(c("idp-certificate-names-no-point", "A certificate that names no distribution point is in no partition", "leaf-without-dp", "ca",
                List.of(now.good(idpDp)), "UNKNOWN", null, null));
        add.accept(c("idp-certificate-point-limited-to-reasons", "A certificate's point limited to some reasons does not place it in the partition",
                "leaf-dp-some-reasons", "ca", List.of(now.good(idpDp)), "UNKNOWN", null, null));
        add.accept(c("idp-certificate-point-of-another-crl-issuer", "Nor does a point that names another CRL issuer", "leaf-dp-other-crl-issuer", "ca",
                List.of(now.good(idpDp)), "UNKNOWN", null, null));
        add.accept(c("complete-crl-certificate-point-limited-to-reasons", "A complete CRL covers that certificate all the same",
                "leaf-dp-some-reasons", "ca", List.of(now.good()), "GOOD", null, 0));
        add.accept(c("idp-directory-name", "A distribution point named by a directoryName is a partition that is not matched here: it covers nothing",
                "leaf", "ca", List.of(now.good(idp(new IssuingDistributionPoint(new DistributionPointName(new GeneralNames(
                        new GeneralName(new X500Name("CN=CRL partition 7")))), false, false, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-directory-name-certificate-names-no-point", "Also for a certificate that names no point", "leaf-without-dp", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(new DistributionPointName(new GeneralNames(
                        new GeneralName(new X500Name("CN=CRL partition 7")))), false, false, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-name-relative-to-issuer", "A distribution point named relative to the CRL issuer covers nothing either", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(new DistributionPointName(DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER,
                        new RDN(BCStyle.CN, new DERUTF8String("partition 7"))), false, false, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-uri-and-directory-name", "A point named by the certificate's URI and a directoryName: the URI matches", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName[] {
                        new GeneralName(GeneralName.uniformResourceIdentifier, DP), new GeneralName(new X500Name("CN=CRL partition 7"))})),
                        false, false, null, false, false)))), "GOOD", null, 0));
        add.accept(c("idp-only-user-certificates", "A CRL of end-entity certificates covers an end-entity certificate", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, true, false, null, false, false)))), "GOOD", null, 0));
        add.accept(c("idp-only-ca-certificates", "A CRL of CA certificates does not", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, false, true, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-only-attribute-certificates", "A CRL of attribute certificates covers no public-key certificate", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, false, false, null, false, true)))), "UNKNOWN", null, null));
        add.accept(c("idp-only-user-certificates-ca-subject", "A CRL of end-entity certificates does not cover a CA", "sub-ca", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, true, false, null, false, false)))), "UNKNOWN", null, null));
        add.accept(c("idp-only-ca-certificates-ca-subject", "A CRL of CA certificates covers a CA", "sub-ca", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, false, true, null, false, false)))), "GOOD", null, 0));
        add.accept(c("idp-only-some-reasons", "A CRL partitioned by reason is not evaluated", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, false, false, new ReasonFlags(ReasonFlags.keyCompromise), false, false)))),
                "UNKNOWN", null, null));
        add.accept(c("idp-indirect", "An indirect CRL is not evaluated", "leaf", "ca",
                List.of(now.good(idp(new IssuingDistributionPoint(null, false, false, null, true, false)))), "UNKNOWN", null, null));

        // Whether a CRL can be used at all.
        add.accept(c("signed-by-another-key", "The CA's name, another key's signature", "leaf", "ca",
                List.of(new B(ca, pki.otherKeys.getPrivate(), newer, next, BigInteger.ONE).listing(keyCompromise)), "UNKNOWN", null, null));
        add.accept(c("issuer-may-not-sign-crls", "The issuer's key usage does not allow cRLSign", "leaf-of-ca-without-crl-sign", "ca-without-crl-sign",
                List.of(new B(X500Name.getInstance(pki.caNoCrlSign.getSubjectX500Principal().getEncoded()), pki.noCrlSignKeys.getPrivate(), newer, next,
                        BigInteger.ONE).good()), "UNKNOWN", null, null));
        add.accept(c("crl-of-another-issuer", "A CRL another CA issued says nothing about this certificate", "leaf", "ca",
                List.of(new B(X500Name.getInstance(pki.other.getSubjectX500Principal().getEncoded()), pki.otherKeys.getPrivate(), newer, next,
                        BigInteger.ONE).good()), "UNKNOWN", null, null));
        add.accept(c("expired", "Past its next update", "leaf", "ca",
                List.of(new B(ca, key, AT.minus(Duration.ofDays(8)), AT.minus(Duration.ofDays(1)), BigInteger.ONE).good()), "UNKNOWN", null, null));
        add.accept(c("issued-beyond-clock-skew", "Issued six minutes after the instant of the check: beyond five minutes of clock skew", "leaf", "ca",
                List.of(new B(ca, key, AT.plus(Duration.ofMinutes(6)), next, BigInteger.ONE).good()), "UNKNOWN", null, null));
        add.accept(c("issued-within-clock-skew", "Issued four minutes after the instant of the check: within the skew", "leaf", "ca",
                List.of(new B(ca, key, AT.plus(Duration.ofMinutes(4)), next, BigInteger.ONE).good()), "GOOD", null, 0));

        // Several CRLs for one certificate: a revocation in any stands; otherwise the newest decides (thisUpdate, then
        // CRL number; on a tie the first held).
        add.accept(c("revoked-in-older", "Revoked in the older CRL, not listed in the newer: a revocation does not come back", "leaf", "ca",
                List.of(old.listing(keyCompromise), now.good()), "REVOKED", "keyCompromise", 0));
        add.accept(c("revoked-in-older-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.good(), old.listing(keyCompromise)), "REVOKED", "keyCompromise", 1));
        add.accept(c("revoked-in-newer", "Not listed in the older CRL, revoked in the newer", "leaf", "ca",
                List.of(old.good(), now.listing(keyCompromise)), "REVOKED", "keyCompromise", 1));
        add.accept(c("revoked-in-newer-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(keyCompromise), old.good()), "REVOKED", "keyCompromise", 0));
        add.accept(c("held-in-older", "On hold in the older CRL, not listed in the newer: the hold was lifted", "leaf", "ca",
                List.of(old.listing(hold), now.good()), "GOOD", null, 1));
        add.accept(c("held-in-older-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.good(), old.listing(hold)), "GOOD", null, 0));
        add.accept(c("held-in-newer", "Not listed in the older CRL, on hold in the newer", "leaf", "ca",
                List.of(old.good(), now.listing(hold)), "ON_HOLD", "certificateHold", 1));
        add.accept(c("held-in-newer-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(hold), old.good()), "ON_HOLD", "certificateHold", 0));
        add.accept(c("revoked-in-both", "Revoked in both: the newest revocation is reported", "leaf", "ca",
                List.of(old.listing(keyCompromise), now.listing(superseded)), "REVOKED", "superseded", 1));
        add.accept(c("tie-higher-crl-number-good", "Issued at the same instant: the higher CRL number is the newer", "leaf", "ca",
                List.of(at.listing(hold), now.good()), "GOOD", null, 1));
        add.accept(c("tie-higher-crl-number-good-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.good(), at.listing(hold)), "GOOD", null, 0));
        add.accept(c("tie-higher-crl-number-holds", "The higher CRL number holds it", "leaf", "ca",
                List.of(at.good(), now.listing(hold)), "ON_HOLD", "certificateHold", 1));
        add.accept(c("tie-higher-crl-number-holds-reversed", "The same, held in the other order", "leaf", "ca",
                List.of(now.listing(hold), at.good()), "ON_HOLD", "certificateHold", 0));
        add.accept(c("tie-same-crl-number-first-good", "Same instant, same CRL number: the first held decides", "leaf", "ca",
                List.of(at.good(), at.listing(hold)), "GOOD", null, 0));
        add.accept(c("tie-same-crl-number-first-holds", "The same, held in the other order", "leaf", "ca",
                List.of(at.listing(hold), at.good()), "ON_HOLD", "certificateHold", 0));
        B noNumber = new B(ca, key, newer, next, null);
        add.accept(c("tie-without-crl-numbers-first", "Same instant, no CRL numbers: the first held decides", "leaf", "ca",
                List.of(noNumber.good(), noNumber.listing(hold)), "GOOD", null, 0));
        add.accept(c("this-update-before-crl-number", "The later thisUpdate is the newer, whatever the CRL numbers say", "leaf", "ca",
                List.of(new B(ca, key, newer, next, BigInteger.ONE).listing(hold), new B(ca, key, AT.minus(Duration.ofHours(2)), next, BigInteger.TEN).good()),
                "ON_HOLD", "certificateHold", 0));
        add.accept(c("unusable-first-expired-revoking", "An expired CRL that revokes, held first, decides nothing", "leaf", "ca",
                List.of(new B(ca, key, AT.minus(Duration.ofDays(14)), AT.minus(Duration.ofDays(1)), BigInteger.TEN).listing(keyCompromise), old.good()),
                "GOOD", null, 1));
        add.accept(c("unusable-first-forged-revoking", "A CRL signed by another key that revokes, held first, decides nothing", "leaf", "ca",
                List.of(new B(ca, pki.otherKeys.getPrivate(), newer, next, BigInteger.TEN).listing(keyCompromise), old.good()), "GOOD", null, 1));
        add.accept(c("unusable-first-silent-delta", "A delta CRL that does not list it, held first, decides nothing", "leaf", "ca",
                List.of(now.good(delta), old.good()), "GOOD", null, 1));
        add.accept(c("newer-beyond-clock-skew-revoking", "A revoking CRL issued beyond the clock skew is not used", "leaf", "ca",
                List.of(old.good(), new B(ca, key, AT.plus(Duration.ofMinutes(6)), next, BigInteger.TEN).listing(keyCompromise)), "GOOD", null, 0));
        add.accept(c("newer-within-clock-skew-revoking", "Within the clock skew it is", "leaf", "ca",
                List.of(old.good(), new B(ca, key, AT.plus(Duration.ofMinutes(4)), next, BigInteger.TEN).listing(keyCompromise)), "REVOKED", "keyCompromise", 1));
        add.accept(c("newer-within-clock-skew-holds", "A hold in a CRL issued within the clock skew is the newest", "leaf", "ca",
                List.of(old.good(), new B(ca, key, AT.plus(Duration.ofMinutes(4)), next, BigInteger.TEN).listing(hold)), "ON_HOLD", "certificateHold", 1));
        add.accept(c("old-without-next-update-and-a-current-revocation", "An old CRL without a next update does not hide the revocation in a current one",
                "leaf", "ca", List.of(new B(ca, key, AT.minus(Duration.ofDays(30)), null, BigInteger.ONE).good(), now.listing(keyCompromise)),
                "REVOKED", "keyCompromise", 1));
        add.accept(c("remove-from-crl-in-newer-good-in-older", "Not listed in the older CRL, removeFromCRL in the newer complete one: the newer decides, and proves nothing",
                "leaf", "ca", List.of(old.good(), now.listing(remove)), "UNKNOWN", null, null));

        Map<String, String> encodedCerts = new LinkedHashMap<>();
        certs.forEach((name, cert) -> encodedCerts.put(name, b64(encoded(cert))));
        List<Case> out = new ArrayList<>();
        for (Object[] a : cases) {
            @SuppressWarnings("unchecked")
            List<CrlSpec> specs = (List<CrlSpec>) a[4];
            out.add(new Case((String) a[0], (String) a[1], (String) a[2], (String) a[3], specs.stream().map(s -> b64(build(s))).toList(),
                    new Expect((String) a[5], (String) a[6], (Integer) a[7])));
        }
        return new Cases("How one CRL is read, and how several CRLs for one certificate decide: the device's rule (checkRevocation in "
                + "packages/trust-client/src/x509/revocation.ts) written down case by case. Each case checks 'certificate' (a key of "
                + "'certificates', base64 DER), issued by 'issuer', at the instant 'at', against the CRLs held for it in the order given "
                + "(base64 DER), and nothing fetched. 'expect' is the status, for REVOKED and ON_HOLD the reason, and for every status "
                + "but UNKNOWN the position of the CRL that decided. CrlCasesTest.java and crl-cases.test.ts hold the service and the "
                + "library to this file; CrlCasesTest -Dcrl.cases.update=true writes it, with the expectations written there by hand.",
                AT.toString(), encodedCerts, out);
    }

    static Object[] c(String name, String about, String cert, String issuer, List<CrlSpec> crls, String status, String reason, Integer crl) {
        return new Object[] {name, about, cert, issuer, crls, status, reason, crl};
    }

    static String b64(byte[] der) {
        return Base64.getEncoder().encodeToString(der);
    }

    static byte[] encoded(X509Certificate c) {
        try {
            return c.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static DistributionPointName uriName(String uri) {
        return new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, uri)));
    }

    static Consumer<X509v3CertificateBuilder> points(DistributionPoint... points) {
        return b -> {
            try {
                b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(points));
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        };
    }

    static Extension ext(ASN1ObjectIdentifier oid, boolean critical, ASN1Encodable value) {
        try {
            return new Extension(oid, critical, value.toASN1Primitive().getEncoded("DER"));
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    static Extension idp(IssuingDistributionPoint idp) {
        return ext(Extension.issuingDistributionPoint, true, idp);
    }

    static X509Certificate cert(String subject, KeyPair subjectKeys, X509Certificate issuer, KeyPair issuerKeys, BigInteger serial,
                                boolean ca, int keyUsage, Consumer<X509v3CertificateBuilder> extra) {
        try {
            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            X500Name issuerName = issuer != null ? X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()) : new X500Name(subject);
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName, serial, Date.from(Instant.parse("2026-01-01T00:00:00Z")),
                    Date.from(Instant.parse("2027-01-01T00:00:00Z")), new X500Name(subject), subjectKeys.getPublic());
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subjectKeys.getPublic()));
            b.addExtension(Extension.authorityKeyIdentifier, false, issuer != null ? ext.createAuthorityKeyIdentifier(issuer)
                    : ext.createAuthorityKeyIdentifier(subjectKeys.getPublic()));
            b.addExtension(Extension.basicConstraints, true, ca ? new BasicConstraints(0) : new BasicConstraints(false));
            b.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            if (extra != null) {
                extra.accept(b);
            }
            return new JcaX509CertificateConverter().getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] build(CrlSpec s) {
        try {
            X509v2CRLBuilder b = new X509v2CRLBuilder(s.issuer(), Date.from(s.thisUpdate()));
            if (s.nextUpdate() != null) {
                b.setNextUpdate(Date.from(s.nextUpdate()));
            }
            Date revokedAt = Date.from(AT.minus(Duration.ofDays(10)));
            for (Entry e : s.entries()) {
                ExtensionsGenerator g = new ExtensionsGenerator();
                if (e.reason() != null) {
                    g.addExtension(Extension.reasonCode, false, CRLReason.lookup(e.reason()));
                }
                for (Extension x : e.extensions()) {
                    g.addExtension(x);
                }
                if (g.isEmpty()) {
                    b.addCRLEntry(e.serial(), revokedAt, 0);
                } else {
                    b.addCRLEntry(e.serial(), revokedAt, g.generate());
                }
            }
            if (s.number() != null) {
                b.addExtension(Extension.cRLNumber, false, new CRLNumber(s.number()));
            }
            for (Extension x : s.extensions()) {
                b.addExtension(x);
            }
            return b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(s.signer())).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
