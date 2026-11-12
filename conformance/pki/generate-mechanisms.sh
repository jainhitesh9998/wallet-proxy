#!/bin/sh
# Adds the certificates of the trust mechanism vectors (conformance/evaluation/mechanisms.cases.json) to the test PKI,
# on top of generate-pki.sh (test only). Run from conformance/pki.
#   nid-ca            a root CA for national identity documents: an anchor of a trust domain of the operator's naming
#   nid-ca.crl        its CRL (DER), which revokes nothing: the signers below it have a known status
#   nid-signer        a signer under it that meets every member of the vectors' certificate profile
#   nid-no-ku         ... without a key usage extension
#   nid-other-eku     ... whose extended key usage is the mDL Document Signer's only, not the national one
#   nid-no-mdl-eku    ... whose extended key usage is the national one only, not the mDL Document Signer's
#   nid-foreign       ... of another country than the CA
#   nid-long          ... valid for 7200 days
#   nid-no-dp         ... that names no CRL distribution point
#   nid-sub-ca        an intermediate CA under nid-ca, and nid-sub-signer, a signer under it
#   ca-signer         a CA certificate allowed to sign (digitalSignature) under the RSA root, presented as a signer
# Each signer differs from nid-signer in one thing, so that each member of a mechanism's profile is seen to fail alone.
set -e
cat > nid.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[root]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[sub]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[signer]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.3.6.1.4.1.99999.1.1,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.nation.example/id.crl
[no_ku]
basicConstraints=critical,CA:FALSE
extendedKeyUsage=critical,1.3.6.1.4.1.99999.1.1,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.nation.example/id.crl
[other_eku]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.nation.example/id.crl
[no_mdl_eku]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.3.6.1.4.1.99999.1.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.nation.example/id.crl
[no_dp]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.3.6.1.4.1.99999.1.1,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[ca_signer]
basicConstraints=critical,CA:TRUE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > nid-ca.cnf <<'CNF'
[ca]
default_ca=nid
[nid]
dir=.
database=./nid-index.txt
crlnumber=./nid-crl-number
certificate=./nid-ca.pem
private_key=./nid-ca.key
default_md=sha256
default_crl_days=7000
crl_extensions=crl_ext
[crl_ext]
authorityKeyIdentifier=keyid:always
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
# leaf NAME SUBJECT ISSUER EXTENSIONS DAYS
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config nid.cnf; openssl x509 -req -in $1.csr -CA $3.pem -CAkey $3.key -CAcreateserial -out $1.pem -days $5 -extfile nid.cnf -extensions $4 -sha256; rm $1.csr; }
ec nid-ca
openssl req -new -x509 -key nid-ca.key -out nid-ca.pem -days 7300 -subj "/C=UT/O=Utopia Nation/CN=Utopia National ID CA" -extensions root -config nid.cnf -sha256
leaf nid-signer "/C=UT/O=Utopia Nation/CN=National ID signer" nid-ca signer 7000
leaf nid-no-ku "/C=UT/O=Utopia Nation/CN=National ID signer without key usage" nid-ca no_ku 7000
leaf nid-other-eku "/C=UT/O=Utopia Nation/CN=National ID signer for another purpose" nid-ca other_eku 7000
leaf nid-no-mdl-eku "/C=UT/O=Utopia Nation/CN=National ID signer without the mDL purpose" nid-ca no_mdl_eku 7000
leaf nid-foreign "/C=NL/O=Utopia Nation/CN=National ID signer abroad" nid-ca signer 7000
leaf nid-long "/C=UT/O=Utopia Nation/CN=Long-lived national ID signer" nid-ca signer 7200
leaf nid-no-dp "/C=UT/O=Utopia Nation/CN=National ID signer without a CRL" nid-ca no_dp 7000
leaf nid-sub-ca "/C=UT/O=Utopia Nation/CN=Utopia National ID sub-CA" nid-ca sub 7000
leaf nid-sub-signer "/C=UT/O=Utopia Nation/CN=National ID signer under the sub-CA" nid-sub-ca signer 7000
leaf ca-signer "/C=UT/CN=CA certificate presented as a signer" rsa-root ca_signer 7000
: > nid-index.txt; echo 01 > nid-crl-number
openssl ca -config nid-ca.cnf -gencrl -out nid-ca.crl.pem
openssl crl -in nid-ca.crl.pem -outform der -out nid-ca.crl
rm -f nid-ca.crl.pem nid-index.txt* nid-crl-number* *.srl nid.cnf nid-ca.cnf
