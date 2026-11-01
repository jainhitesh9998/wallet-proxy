package io.vctrust.trust.core.testing;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

/** Generates throwaway X.509 hierarchies for tests. */
public final class TestPki {

    private static final AtomicLong SERIAL = new AtomicLong(1000);

    public record Issued(X509Certificate certificate, KeyPair keys) {
    }

    private TestPki() {
    }

    public static KeyPair ecKey() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static Issued rootCa(String dn) {
        return rootCa(dn, Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(3650)));
    }

    public static Issued rootCa(String dn, Instant notBefore, Instant notAfter) {
        KeyPair kp = ecKey();
        return new Issued(build(dn, dn, kp, kp, notBefore, notAfter, true, 0, null, List.of(), null), kp);
    }

    /** A root CA whose certificate names its own CRL distribution points. */
    public static Issued rootCa(String dn, List<String> crlUrls) {
        KeyPair kp = ecKey();
        return new Issued(build(dn, dn, kp, kp, Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(3650)),
                true, 0, null, List.of(), null, b -> {
                    try {
                        b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(crlUrls.stream()
                                .map(u -> new DistributionPoint(new DistributionPointName(new GeneralNames(
                                        new GeneralName(GeneralName.uniformResourceIdentifier, u))), null, null))
                                .toArray(DistributionPoint[]::new)));
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }), kp);
    }

    public static Issued intermediateCa(String dn, Issued issuer) {
        KeyPair kp = ecKey();
        return new Issued(build(dn, issuer.certificate().getSubjectX500Principal().getName(), kp, issuer.keys(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(1000)), true, 0,
                issuer.certificate(), List.of(), null), kp);
    }

    /** ISO 18013-5 Document Signer: EKU 1.0.18013.5.1.2, digitalSignature. */
    public static Issued documentSigner(String dn, Issued iaca) {
        return leaf(dn, iaca, List.of(), "1.0.18013.5.1.2", Instant.now().minus(Duration.ofDays(1)),
                Instant.now().plus(Duration.ofDays(365)));
    }

    public static Issued leaf(String dn, Issued issuer, List<String> dnsNames, String eku) {
        return leaf(dn, issuer, dnsNames, eku, Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)));
    }

    public static Issued leaf(String dn, Issued issuer, List<String> dnsNames, String eku, Instant notBefore, Instant notAfter) {
        KeyPair kp = ecKey();
        return new Issued(build(dn, issuer.certificate().getSubjectX500Principal().getName(), kp, issuer.keys(),
                notBefore, notAfter, false, -1, issuer.certificate(), dnsNames, eku), kp);
    }

    /** A certificate with CRL distribution points and / or an OCSP responder URL; {@code ca}: an intermediate CA. */
    public static Issued withRevocationUrls(String dn, Issued issuer, boolean ca, List<String> crlUrls, List<String> ocspUrls,
                                            String eku) {
        KeyPair kp = ecKey();
        return new Issued(build(dn, issuer.certificate().getSubjectX500Principal().getName(), kp, issuer.keys(),
                Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(365)), ca, ca ? 0 : -1,
                issuer.certificate(), List.of(), eku, b -> {
                    try {
                        if (!crlUrls.isEmpty()) {
                            b.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(crlUrls.stream()
                                    .map(u -> new DistributionPoint(new DistributionPointName(new GeneralNames(
                                            new GeneralName(GeneralName.uniformResourceIdentifier, u))), null, null))
                                    .toArray(DistributionPoint[]::new)));
                        }
                        if (!ocspUrls.isEmpty()) {
                            b.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(ocspUrls.stream()
                                    .map(u -> new AccessDescription(AccessDescription.id_ad_ocsp,
                                            new GeneralName(GeneralName.uniformResourceIdentifier, u)))
                                    .toArray(AccessDescription[]::new)));
                        }
                    } catch (Exception e) {
                        throw new IllegalStateException(e);
                    }
                }), kp);
    }

    /** A CRL entry; {@code reason} is an RFC 5280 CRLReason code (0 = unspecified, no extension). */
    public record Revoked(BigInteger serial, Instant date, int reason) {
        public static Revoked of(Issued cert, int reason) {
            return new Revoked(cert.certificate().getSerialNumber(), Instant.now().minus(Duration.ofHours(1)), reason);
        }
    }

    /** A CRL issued by {@code issuer} (signed with {@code signer}'s key when given), with crlNumber 1. */
    public static X509CRL crl(Issued issuer, Instant thisUpdate, Instant nextUpdate, List<Revoked> revoked,
                              Consumer<X509v2CRLBuilder> extra, PrivateKey signer) {
        try {
            X509v2CRLBuilder b = new X509v2CRLBuilder(X500Name.getInstance(issuer.certificate().getSubjectX500Principal().getEncoded()),
                    Date.from(thisUpdate));
            if (nextUpdate != null) {
                b.setNextUpdate(Date.from(nextUpdate));
            }
            for (Revoked r : revoked) {
                b.addCRLEntry(r.serial(), Date.from(r.date()), r.reason());
            }
            b.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
            b.addExtension(Extension.authorityKeyIdentifier, false, new JcaX509ExtensionUtils().createAuthorityKeyIdentifier(issuer.certificate()));
            if (extra != null) {
                extra.accept(b);
            }
            return new JcaX509CRLConverter().getCRL(b.build(new JcaContentSignerBuilder("SHA256withECDSA")
                    .build(signer != null ? signer : issuer.keys().getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** A current CRL (valid for a week) issued and signed by {@code issuer}. */
    public static X509CRL crl(Issued issuer, Revoked... revoked) {
        return crl(issuer, Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(7)), List.of(revoked), null, null);
    }

    private static X509Certificate build(String subject, String issuer, KeyPair subjectKeys, KeyPair issuerKeys,
                                         Instant notBefore, Instant notAfter, boolean ca, int pathLen,
                                         X509Certificate issuerCert, List<String> dnsNames, String eku) {
        return build(subject, issuer, subjectKeys, issuerKeys, notBefore, notAfter, ca, pathLen, issuerCert, dnsNames, eku, null);
    }

    private static X509Certificate build(String subject, String issuer, KeyPair subjectKeys, KeyPair issuerKeys,
                                         Instant notBefore, Instant notAfter, boolean ca, int pathLen,
                                         X509Certificate issuerCert, List<String> dnsNames, String eku,
                                         Consumer<X509v3CertificateBuilder> extra) {
        try {
            JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
            X500Name issuerName = issuerCert != null
                    ? X500Name.getInstance(issuerCert.getSubjectX500Principal().getEncoded())
                    : new X500Name(issuer);
            X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(issuerName,
                    BigInteger.valueOf(SERIAL.incrementAndGet()), Date.from(notBefore), Date.from(notAfter),
                    new X500Name(subject), subjectKeys.getPublic());
            b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subjectKeys.getPublic()));
            if (issuerCert != null) {
                b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerCert));
            } else {
                b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(subjectKeys.getPublic()));
            }
            if (ca) {
                b.addExtension(Extension.basicConstraints, true, new BasicConstraints(pathLen));
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
            } else {
                b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
            }
            if (dnsNames != null && !dnsNames.isEmpty()) {
                b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(
                        dnsNames.stream().map(d -> new GeneralName(GeneralName.dNSName, d)).toArray(GeneralName[]::new)));
            }
            if (eku != null) {
                b.addExtension(Extension.extendedKeyUsage, true,
                        new ExtendedKeyUsage(KeyPurposeId.getInstance(new ASN1ObjectIdentifier(eku))));
            }
            if (extra != null) {
                extra.accept(b);
            }
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
