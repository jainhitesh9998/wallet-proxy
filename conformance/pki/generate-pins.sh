#!/bin/sh
# Adds a certificate for the pin cases of the trust mechanism vectors (conformance/evaluation/mechanisms.cases.json), on
# top of generate-mechanisms.sh (test only). Run from conformance/pki.
#   nid-pinned  a signer under nid-ca that an entity of the vectors pins by its hash: it meets every member of the
#               national-id mechanism's certificate profile, and has the national extended key usage only, not the mDL
#               Document Signer's
# It is a certificate of its own so that pinning it changes the outcome of no other case.
set -e
cat > pins.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[signer]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.3.6.1.4.1.99999.1.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
crlDistributionPoints=URI:http://crl.nation.example/id.crl
CNF
openssl ecparam -name prime256v1 -genkey -noout -out nid-pinned.key
openssl req -new -key nid-pinned.key -out nid-pinned.csr -subj "/C=UT/O=Utopia Nation/CN=National ID signer pinned by its holder" -config pins.cnf
openssl x509 -req -in nid-pinned.csr -CA nid-ca.pem -CAkey nid-ca.key -CAcreateserial -out nid-pinned.pem -days 7000 -extfile pins.cnf -extensions signer -sha256
rm -f nid-pinned.csr *.srl pins.cnf
