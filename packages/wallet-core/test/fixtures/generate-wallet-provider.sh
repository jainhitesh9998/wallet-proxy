#!/bin/sh
# Demo wallet provider PKI for wallet / key attestations (HAIP: x5c without trust anchor, signer not self-signed).
set -e
cat > ext.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[signer]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=URI:https://wallet.vctrust.dev
CNF
openssl ecparam -name prime256v1 -genkey -noout -out wp-root.key
openssl req -new -x509 -key wp-root.key -out wp-root.pem -days 7300 -subj "/C=IN/O=VC Trust Demo/CN=VC Trust Demo Wallet Provider Root" -extensions ca -config ext.cnf -sha256
openssl ecparam -name prime256v1 -genkey -noout -out wp-signer.key.sec1
openssl pkcs8 -topk8 -nocrypt -in wp-signer.key.sec1 -out wp-signer.key
openssl req -new -key wp-signer.key -out wp-signer.csr -subj "/C=IN/O=VC Trust Demo/CN=VC Trust Demo Wallet Provider" -config ext.cnf
openssl x509 -req -in wp-signer.csr -CA wp-root.pem -CAkey wp-root.key -CAcreateserial -out wp-signer.pem -days 7000 -extfile ext.cnf -extensions signer -sha256
rm -f wp-signer.csr wp-root.srl ext.cnf wp-signer.key.sec1
