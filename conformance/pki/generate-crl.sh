#!/bin/sh
# Generates the revocation fixtures on top of generate-pki.sh (test only). Run from conformance/pki.
# Document Signers that point at the IACA's CRL, and the IACA's CRL (DER) revoking one and suspending another.
set -e
cat > ext.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ds_crl]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.utopia.example/iaca.crl
[ds_ocsp]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
authorityInfoAccess=OCSP;URI:http://ocsp.utopia.example
CNF
cat > ca.cnf <<'CNF'
[ca]
default_ca=iaca
[iaca]
dir=.
database=./crl-index.txt
crlnumber=./crl-number
certificate=./iaca.pem
private_key=./iaca.key
default_md=sha256
default_crl_days=7000
crl_extensions=crl_ext
[crl_ext]
authorityKeyIdentifier=keyid:always
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config ext.cnf; openssl x509 -req -in $1.csr -CA iaca.pem -CAkey iaca.key -CAcreateserial -out $1.pem -days 7000 -extfile ext.cnf -extensions $3 -sha256; rm $1.csr; }
leaf ds-crldp "/C=UT/O=Utopia DMV/CN=Utopia DS (CRL)" ds_crl
leaf ds-revoked "/C=UT/O=Utopia DMV/CN=Utopia DS (revoked)" ds_crl
leaf ds-hold "/C=UT/O=Utopia DMV/CN=Utopia DS (on hold)" ds_crl
leaf ds-ocsp "/C=UT/O=Utopia DMV/CN=Utopia DS (OCSP only)" ds_ocsp
: > crl-index.txt; echo 01 > crl-number
openssl ca -config ca.cnf -revoke ds-revoked.pem -crl_reason keyCompromise
openssl ca -config ca.cnf -revoke ds-hold.pem -crl_hold 1.2.840.10040.2.2
openssl ca -config ca.cnf -gencrl -out iaca.crl.pem
openssl crl -in iaca.crl.pem -outform der -out iaca.crl
rm -f iaca.crl.pem crl-index.txt* crl-number* *.srl ext.cnf ca.cnf
