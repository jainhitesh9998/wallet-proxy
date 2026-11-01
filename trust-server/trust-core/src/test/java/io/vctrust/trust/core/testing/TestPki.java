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
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

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

    private static X509Certificate build(String subject, String issuer, KeyPair subjectKeys, KeyPair issuerKeys,
                                         Instant notBefore, Instant notAfter, boolean ca, int pathLen,
                                         X509Certificate issuerCert, List<String> dnsNames, String eku) {
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
            return new JcaX509CertificateConverter().getCertificate(
                    b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
