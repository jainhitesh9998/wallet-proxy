package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.TrustDomain;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Built-in certificate profiles, and the default profile per trust domain. */
public final class CertificateProfiles {

    /** ISO/IEC 18013-5 extended key usage for mdoc Document Signer certificates. */
    public static final String EKU_MDL_DS = "1.0.18013.5.1.2";

    private CertificateProfiles() {
    }

    /** No extra checks beyond RFC 5280. */
    public static final CertificateProfile NONE = new CertificateProfile() {
        @Override
        public String name() {
            return "none";
        }

        @Override
        public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext ctx) {
            return List.of();
        }
    };

    /**
     * ISO/IEC 18013-5 Annex B: the Document Signer must carry EKU 1.0.18013.5.1.2, must not be a CA, and its
     * country must match the IACA's. Missing EKU is an error; country mismatch is an error when both are set.
     */
    public static final CertificateProfile MDOC_DOCUMENT_SIGNER = new CertificateProfile() {
        @Override
        public String name() {
            return "iso18013-5-document-signer";
        }

        @Override
        public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext ctx) {
            List<ValidationIssue> issues = new ArrayList<>();
            X509Certificate ds = path.getFirst();
            if (Certificates.isCa(ds)) {
                issues.add(ValidationIssue.error("mdoc.ds.is_ca", "Document Signer certificate must not be a CA"));
            }
            if (!Certificates.extendedKeyUsage(ds).contains(EKU_MDL_DS)) {
                issues.add(ValidationIssue.error("mdoc.ds.eku",
                        "Document Signer certificate lacks extended key usage " + EKU_MDL_DS));
            }
            boolean[] ku = ds.getKeyUsage();
            if (ku != null && !ku[0]) {
                issues.add(ValidationIssue.error("mdoc.ds.key_usage", "Document Signer key usage must include digitalSignature"));
            }
            Optional<String> dsC = Certificates.subjectCountry(ds);
            Optional<String> iacaC = Certificates.subjectCountry(anchor);
            if (dsC.isPresent() && iacaC.isPresent() && !dsC.get().equalsIgnoreCase(iacaC.get())) {
                issues.add(ValidationIssue.error("mdoc.ds.country",
                        "Document Signer country " + dsC.get() + " differs from IACA country " + iacaC.get()));
            }
            return issues;
        }
    };

    /** Credential issuer certificates (SD-JWT VC x5c, HAIP §6.1): leaf must be an end-entity with digitalSignature. */
    public static final CertificateProfile CREDENTIAL_ISSUER = new CertificateProfile() {
        @Override
        public String name() {
            return "credential-issuer";
        }

        @Override
        public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext ctx) {
            List<ValidationIssue> issues = new ArrayList<>();
            X509Certificate leaf = path.getFirst();
            if (Certificates.isCa(leaf) && path.size() > 1) {
                issues.add(ValidationIssue.warning("issuer.leaf_is_ca", "Signing certificate is a CA certificate"));
            }
            boolean[] ku = leaf.getKeyUsage();
            if (ku != null && !ku[0]) {
                issues.add(ValidationIssue.error("issuer.key_usage", "Signing certificate key usage must include digitalSignature"));
            }
            return issues;
        }
    };

    /**
     * Verifier access certificates (OpenID4VP {@code x509_san_dns} / {@code x509_hash}). When the client id
     * names a DNS name it must appear as a SAN dNSName of the leaf.
     */
    public static final CertificateProfile VERIFIER_ACCESS = new CertificateProfile() {
        @Override
        public String name() {
            return "verifier-access";
        }

        @Override
        public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext ctx) {
            List<ValidationIssue> issues = new ArrayList<>();
            X509Certificate leaf = path.getFirst();
            if (Certificates.isCa(leaf) && path.size() > 1) {
                issues.add(ValidationIssue.error("verifier.leaf_is_ca", "Request signing certificate must not be a CA"));
            }
            if (ctx.expectedDnsName() != null
                    && Certificates.dnsNames(leaf).stream().noneMatch(d -> d.equalsIgnoreCase(ctx.expectedDnsName()))) {
                issues.add(ValidationIssue.error("verifier.san_dns",
                        "Leaf certificate has no SAN dNSName matching " + ctx.expectedDnsName()));
            }
            return issues;
        }
    };

    private static final Map<String, CertificateProfile> BY_DOMAIN = Map.of(
            TrustDomain.MDOC_IACA.name(), MDOC_DOCUMENT_SIGNER,
            TrustDomain.CREDENTIAL_ISSUER.name(), CREDENTIAL_ISSUER,
            TrustDomain.VERIFIER_ACCESS.name(), VERIFIER_ACCESS);

    public static CertificateProfile forDomain(TrustDomain domain) {
        return BY_DOMAIN.getOrDefault(domain.name(), NONE);
    }
}
