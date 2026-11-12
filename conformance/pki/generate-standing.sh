#!/bin/sh
# Adds the certificates of the vector cases about whose standing decides (conformance/evaluation/cases.json), on top of
# generate-pki.sh (test only). Run from conformance/pki. Each is a signer that entities of the vectors pin or name, and
# each is a certificate of its own so that binding it changes the outcome of no other case.
#   ds-pin-revoked, ds-pin-suspended, ds-pin-ended, ds-pin-both
#                     Document Signers under the IACA (whose anchor belongs to an active entity): pinned by a revoked
#                     entity, a suspended one, one whose registration has ended, and by a revoked and an active one
#   rp-pin-both       a signer under the RP Access CA (an anchor of no entity), pinned by a revoked and an active entity
#   rp-named-pinned   a signer under the RP Access CA whose DNS name an active entity is registered by, and which a
#                     revoked entity pins
#   rp-named-hashed   the same, with the revoked entity naming the certificate's hash instead of pinning it
set -e
cat > standing.cnf <<'CNF'
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
[named-pinned]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:named-pinned.vectors.example
[named-hashed]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:named-hashed.vectors.example
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config standing.cnf; openssl x509 -req -in $1.csr -CA $3.pem -CAkey $3.key -CAcreateserial -out $1.pem -days 7000 -extfile standing.cnf -extensions $4 -sha256; rm $1.csr; }
leaf ds-pin-revoked "/C=UT/O=Utopia DMV/CN=Utopia DS pinned by a revoked entity" iaca ds
leaf ds-pin-suspended "/C=UT/O=Utopia DMV/CN=Utopia DS pinned by a suspended entity" iaca ds
leaf ds-pin-ended "/C=UT/O=Utopia DMV/CN=Utopia DS pinned by an entity whose registration ended" iaca ds
leaf ds-pin-both "/C=UT/O=Utopia DMV/CN=Utopia DS pinned by a revoked and an active entity" iaca ds
leaf rp-pin-both "/C=UT/O=Pinned Issuer/CN=Signer pinned by a revoked and an active entity" rp-ca leaf
leaf rp-named-pinned "/C=UT/O=Named Issuer/CN=named-pinned.vectors.example" rp-ca named-pinned
leaf rp-named-hashed "/C=UT/O=Named Issuer/CN=named-hashed.vectors.example" rp-ca named-hashed
rm -f *.srl standing.cnf
