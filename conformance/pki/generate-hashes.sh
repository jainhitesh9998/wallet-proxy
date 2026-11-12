#!/bin/sh
# Adds the certificates of the vector cases about a certificate's hash written another way than the evaluators compute it
# (conformance/evaluation/cases.json), on top of generate-pki.sh (test only). Run from conformance/pki. Each is a signer
# of its own, so that naming it changes the outcome of no other case.
#   ds-hash-hex   a Document Signer under the IACA (whose anchor belongs to an active entity), named by a revoked entity
#                 by its SHA-256 in hexadecimal with colons, as openssl prints a fingerprint
#   rp-hash-b64   a signer under the RP Access CA (an anchor of no entity), named by a revoked verifier by its SHA-256 in
#                 padded standard base64 (one whose base64 holds '+' or '/' was kept, so that the alphabet matters)
set -e
cat > hashes.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ds]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config hashes.cnf; openssl x509 -req -in $1.csr -CA $3.pem -CAkey $3.key -CAcreateserial -out $1.pem -days 7000 -extfile hashes.cnf -extensions $4 -sha256; rm $1.csr; }
leaf ds-hash-hex "/C=UT/O=Utopia DMV/CN=Utopia DS named by its hash in hexadecimal" iaca ds
leaf rp-hash-b64 "/C=UT/O=Hashed Verifier/CN=Verifier named by its hash in base64" rp-ca leaf
rm -f *.srl hashes.cnf
