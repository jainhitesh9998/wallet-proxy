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

    /** The doctype ISO/IEC 18013-5 defines, and whose signer certificates its Annex B profiles. */
    public static final String MDL_DOCTYPE = "org.iso.18013.5.1.mDL";

    /**
     * The signer of an mdoc must not be a CA and must be allowed to sign. For an mDL, ISO/IEC 18013-5 Annex B
     * applies on top: the Document Signer carries EKU 1.0.18013.5.1.2, and its country is the IACA's. Other
     * doctypes (an EUDI PID as mdoc, say) are issued under other certificate profiles, so those two rules are
     * applied to an mDL, and when the doctype is not known.
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
            boolean mdl = ctx == null || ctx.docType() == null || MDL_DOCTYPE.equals(ctx.docType());
            if (mdl && !Certificates.extendedKeyUsage(ds).contains(EKU_MDL_DS)) {
                issues.add(ValidationIssue.error("mdoc.ds.eku",
                        "Document Signer certificate lacks extended key usage " + EKU_MDL_DS));
            }
            boolean[] ku = ds.getKeyUsage();
            if (ku != null && !ku[0]) {
                issues.add(ValidationIssue.error("mdoc.ds.key_usage", "Document Signer key usage must include digitalSignature"));
            }
            Optional<String> dsC = Certificates.subjectCountry(ds);
            Optional<String> iacaC = Certificates.subjectCountry(anchor);
            if (mdl && dsC.isPresent() && iacaC.isPresent() && !dsC.get().equalsIgnoreCase(iacaC.get())) {
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

    /**
     * {@code profile} with an operator's requirements on top (a trust mechanism's {@code x509.profile}). The built-in
     * checks keep applying, and the result keeps the built-in's name: requirements only add refusals.
     */
    public static CertificateProfile withRequirements(CertificateProfile profile, CertificateRequirements requirements) {
        if (requirements == null) {
            return profile;
        }
        return new CertificateProfile() {
            @Override
            public String name() {
                return profile.name();
            }

            @Override
            public List<ValidationIssue> check(List<X509Certificate> path, X509Certificate anchor, ProfileContext ctx) {
                List<ValidationIssue> issues = new ArrayList<>(profile.check(path, anchor, ctx));
                issues.addAll(requirements.check(path, anchor));
                return issues;
            }
        };
    }
}
