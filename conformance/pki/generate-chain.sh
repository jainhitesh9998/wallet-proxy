#!/bin/sh
# Adds a three-certificate chain to the test PKI, on top of generate-pki.sh (test only). Run from conformance/pki.
#   chain-ca    an intermediate CA under the RSA root (the only root that allows one below it)
#   chain-leaf  a leaf under that intermediate
# They exist so that the service and the client library are seen to walk a chain with an intermediate alike, and to
# name the same authority key identifier when a query lists more than one that the chain carries.
set -e
cat > chain.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
[leaf]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
ec chain-ca
openssl req -new -key chain-ca.key -out chain-ca.csr -subj "/C=UT/O=Chained/CN=Intermediate CA" -config chain.cnf
openssl x509 -req -in chain-ca.csr -CA rsa-root.pem -CAkey rsa-root.key -CAcreateserial -out chain-ca.pem -days 7000 -extfile chain.cnf -extensions ca -sha256
ec chain-leaf
openssl req -new -key chain-leaf.key -out chain-leaf.csr -subj "/C=UT/O=Chained/CN=Leaf under an intermediate" -config chain.cnf
openssl x509 -req -in chain-leaf.csr -CA chain-ca.pem -CAkey chain-ca.key -CAcreateserial -out chain-leaf.pem -days 7000 -extfile chain.cnf -extensions leaf -sha256
rm -f *.srl *.csr chain.cnf
