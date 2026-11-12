#!/bin/sh
# Adds the certificates of the vector cases about which entries the role asked leaves out
# (conformance/evaluation/cases.json), on top of generate-pki.sh (test only). Run from conformance/pki. Each is a signer
# under the RP Access CA (an anchor of no entity, for issuers and for verifiers) that entities of the vectors pin or are
# registered by, and each is a certificate of its own so that binding it changes the outcome of no other case.
#   rp-noroles-revoked   whose DNS name a revoked entity without any role is registered by
#   rp-noroles-active    whose DNS name an active entity without any role is registered by
#   rp-verifier-pinned   which a revoked verifier pins
#   rp-verifier-named    whose DNS name a revoked verifier is registered by
set -e
cat > roles.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[noroles-revoked]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:noroles-revoked.vectors.example
[noroles-active]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:noroles-active.vectors.example
[verifier-pinned]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:verifier-pinned.vectors.example
[verifier-named]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:verifier-named.vectors.example
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config roles.cnf; openssl x509 -req -in $1.csr -CA rp-ca.pem -CAkey rp-ca.key -CAcreateserial -out $1.pem -days 7000 -extfile roles.cnf -extensions $3 -sha256; rm $1.csr; }
leaf rp-noroles-revoked "/C=UT/O=Withdrawn Party/CN=noroles-revoked.vectors.example" noroles-revoked
leaf rp-noroles-active "/C=UT/O=Party Without Role/CN=noroles-active.vectors.example" noroles-active
leaf rp-verifier-pinned "/C=UT/O=Withdrawn Verifier/CN=verifier-pinned.vectors.example" verifier-pinned
leaf rp-verifier-named "/C=UT/O=Withdrawn Verifier/CN=verifier-named.vectors.example" verifier-named
rm -f *.srl roles.cnf
