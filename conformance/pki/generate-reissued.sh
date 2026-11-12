#!/bin/sh
# Generates the fixture of a CA with two certificates (test only). Run from conformance/pki.
# A CA is reissued: reissued-ca.pem and reissued-ca-2.pem have the same subject and the same key (reissued-ca.key),
# and differ in serial number and in that only the first names a CRL distribution point. reissued-ds.pem is a Document
# Signer of that CA, valid under either certificate. Two CRLs of the CA: reissued-ca-old.crl (CRL number 1, revokes
# nothing) and reissued-ca.crl (CRL number 2, revokes reissued-ds, keyCompromise). A CRL is the CA's, whichever of its
# certificates a chain is validated to: the service and the device must match a CRL to the issuer's name and key.
set -e
cat > ext.cnf <<'CNF'
[req]
distinguished_name=dn
[dn]
[ca_dp]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
crlDistributionPoints=URI:http://crl.registry.example/current.crl
[ca_plain]
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
[ds]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,1.0.18013.5.1.2
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
CNF
cat > ca.cnf <<'CNF'
[ca]
default_ca=reissued
[reissued]
dir=.
database=./reissued-index.txt
crlnumber=./reissued-crl-number
certificate=./reissued-ca.pem
private_key=./reissued-ca.key
default_md=sha256
default_crl_days=7000
crl_extensions=crl_ext
[crl_ext]
authorityKeyIdentifier=keyid:always
CNF
subject="/C=UT/O=Utopia Registry/CN=Utopia Registry IACA"
openssl ecparam -name prime256v1 -genkey -noout -out reissued-ca.key
openssl req -new -x509 -key reissued-ca.key -subj "$subject" -set_serial 1 -days 7000 -sha256 -config ext.cnf -extensions ca_dp -out reissued-ca.pem
openssl req -new -x509 -key reissued-ca.key -subj "$subject" -set_serial 2 -days 7000 -sha256 -config ext.cnf -extensions ca_plain -out reissued-ca-2.pem
openssl ecparam -name prime256v1 -genkey -noout -out reissued-ds.key
openssl req -new -key reissued-ds.key -subj "/C=UT/O=Utopia Registry/CN=Utopia Registry DS" -config ext.cnf -out reissued-ds.csr
openssl x509 -req -in reissued-ds.csr -CA reissued-ca.pem -CAkey reissued-ca.key -set_serial 3 -days 7000 -sha256 -extfile ext.cnf -extensions ds -out reissued-ds.pem
: > reissued-index.txt; echo 01 > reissued-crl-number
openssl ca -config ca.cnf -gencrl -out reissued-ca-old.crl.pem
openssl ca -config ca.cnf -revoke reissued-ds.pem -crl_reason keyCompromise
openssl ca -config ca.cnf -gencrl -out reissued-ca.crl.pem
openssl crl -in reissued-ca-old.crl.pem -outform der -out reissued-ca-old.crl
openssl crl -in reissued-ca.crl.pem -outform der -out reissued-ca.crl
rm -f reissued-ca-old.crl.pem reissued-ca.crl.pem reissued-index.txt* reissued-crl-number* reissued-ds.csr ext.cnf ca.cnf
