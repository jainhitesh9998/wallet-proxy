package io.vctrust.trust.core.x509;

import io.vctrust.trust.core.model.Identifier;
import io.vctrust.trust.core.model.IdentifierType;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The text form of a distinguished name is part of the contract with client libraries: they render the same string
 * from the same bytes (packages/trust-client, parseName) and compare. The shared vectors hold real certificates; this
 * test pins the rules themselves.
 */
class NameRenderingTest {

    static final String CN = "2.5.4.3";
    static final String O = "2.5.4.10";
    static final String C = "2.5.4.6";
    static final String ORGANIZATION_IDENTIFIER = "2.5.4.97";

    static ASN1Encodable attribute(String oid, ASN1Encodable value) {
        return new DERSequence(new ASN1Encodable[] {new ASN1ObjectIdentifier(oid), value});
    }

    static byte[] name(ASN1Encodable... rdns) throws IOException {
        return new DERSequence(rdns).getEncoded();
    }

    static DERSet rdn(ASN1Encodable... attributes) {
        return new DERSet(attributes);
    }

    @Test
    void writesTheLastRdnFirstWithKeywordsForTheCommonTypes() throws IOException {
        byte[] der = name(rdn(attribute(C, new DERPrintableString("UT"))), rdn(attribute(O, new DERUTF8String("Utopia DMV"))),
                rdn(attribute(CN, new DERUTF8String("Utopia DS"))));
        assertThat(Certificates.rfc2253(der)).isEqualTo("CN=Utopia DS,O=Utopia DMV,C=UT");
        assertThat(Certificates.country(der)).contains("UT");
    }

    @Test
    void escapesSpecialCharactersWhereverTheyStandAndSpacesAtEitherEnd() throws IOException {
        byte[] der = name(rdn(attribute(CN, new DERUTF8String(" a,b=c+d<e>f#g;h\"i\\j "))));
        assertThat(Certificates.rfc2253(der)).isEqualTo("CN=\\ a\\,b\\=c\\+d\\<e\\>f\\#g\\;h\\\"i\\\\j\\ ");
        // A value that spells out another name stays one value.
        assertThat(Certificates.rfc2253(name(rdn(attribute(CN, new DERUTF8String("Root CA,O=Test,C=US")))))).isEqualTo("CN=Root CA\\,O\\=Test\\,C\\=US");
    }

    @Test
    void writesOtherTypesAndOtherStringTypesAsHexOfTheirEncoding() throws IOException {
        byte[] der = name(rdn(attribute(C, new DERPrintableString("AT"))), rdn(attribute(ORGANIZATION_IDENTIFIER, new DERUTF8String("VATAT-1"))),
                rdn(attribute(CN, new DERBMPString("BMP"))), rdn(attribute(O, new DERIA5String("ia5"))), rdn(attribute(CN, new DEROctetString(new byte[] {1, 2}))));
        assertThat(Certificates.rfc2253(der)).isEqualTo("CN=#04020102,O=ia5,CN=#1e060042004d0050,2.5.4.97=#0c0756415441542d31,C=AT");
    }

    @Test
    void keepsTheAttributesOfAMultiValuedRdnInEncodedOrderAndFindsACountryInside() throws IOException {
        byte[] der = name(rdn(attribute(O, new DERUTF8String("Utopia"))), rdn(attribute(C, new DERPrintableString("XX")), attribute(CN, new DERUTF8String("Odd DS"))));
        assertThat(Certificates.rfc2253(der)).isEqualTo("C=XX+CN=Odd DS,O=Utopia");
        assertThat(Certificates.country(der)).contains("XX");
        assertThat(Certificates.country(name(rdn(attribute(O, new DERUTF8String("Nowhere")))))).isEmpty();
    }

    @Test
    void rendersBytesThatAreNotUtf8AsHex() {
        // CN as a PrintableString whose bytes are Latin-1 ("M\u00fcller" with 0xfc): not text by this rule.
        byte[] der = java.util.HexFormat.of().parseHex("3011310f300d060355040313064dfc6c6c6572");
        assertThat(Certificates.rfc2253(der)).isEqualTo("CN=#13064dfc6c6c6572");
    }

    @Test
    void aRegistryIdentifierIsBroughtToTheSameForm() {
        assertThat(Identifier.of(IdentifierType.X509_SUBJECT, "cn=Utopia DS, o=Utopia DMV, c=UT").value()).isEqualTo("CN=Utopia DS,O=Utopia DMV,C=UT");
        assertThat(Identifier.of(IdentifierType.X509_SUBJECT, "2.5.4.97=#0c0756415441542d31,C=AT").value()).isEqualTo("2.5.4.97=#0c0756415441542d31,C=AT");
        assertThat(Identifier.of(IdentifierType.X509_SUBJECT, "CN=#1e060042004d0050").value()).isEqualTo("CN=#1e060042004d0050");
        // What cannot be parsed is kept, and matches nothing.
        assertThat(Identifier.of(IdentifierType.X509_SUBJECT, "not a name").value()).isEqualTo("not a name");
    }
}
