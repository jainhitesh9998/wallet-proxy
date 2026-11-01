#!/bin/sh
# Generates the X.509 test fixtures (long-lived, test only). Run from test/fixtures/pki.
set -e
cat > ext.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ca]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[ca1]
basicConstraints=critical,CA:TRUE,pathlen:1
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
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
[rp]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
subjectAltName=DNS:verifier.example
CNF
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
root() { ec $1; openssl req -new -x509 -key $1.key -out $1.pem -days 7300 -subj "$2" -extensions $3 -config ext.cnf -sha256; }
leaf() { ec $1; openssl req -new -key $1.key -out $1.csr -subj "$2" -config ext.cnf; openssl x509 -req -in $1.csr -CA $3.pem -CAkey $3.key -CAcreateserial -out $1.pem -days $5 -extfile ext.cnf -extensions $4 -sha256; rm $1.csr; }
root iaca "/C=UT/O=Utopia DMV/CN=Utopia IACA" ca
leaf ds "/C=UT/O=Utopia DMV/CN=Utopia DS" iaca ds 7000
leaf ds-noeku "/C=UT/O=Utopia DMV/CN=Utopia not-a-DS" iaca leaf 7000
leaf ds-nl "/C=NL/O=Elsewhere/CN=Foreign DS" iaca ds 7000
root rogue-iaca "/C=UT/O=Rogue/CN=Rogue IACA" ca
leaf rogue-ds "/C=UT/O=Rogue/CN=Rogue DS" rogue-iaca ds 7000
root rp-ca "/C=UT/O=Registrar/CN=RP Access CA" ca
leaf rp "/C=UT/O=Verifier Inc/CN=verifier.example" rp-ca rp 7000
openssl genrsa -out rsa-root.key 2048
openssl req -new -x509 -key rsa-root.key -out rsa-root.pem -days 7300 -subj "/C=UT/CN=RSA Root" -extensions ca1 -config ext.cnf -sha256
leaf rsa-leaf "/C=UT/CN=RSA signed leaf" rsa-root leaf 7000
rm -f *.srl ext.cnf
