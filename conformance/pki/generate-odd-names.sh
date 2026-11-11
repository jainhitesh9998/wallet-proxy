#!/bin/sh
# Adds certificates with unusual subject names to the test PKI, on top of generate-pki.sh (test only). Run from
# conformance/pki. They exist so that the service and the client library are seen to read such names alike.
#   odd-ds-multi  a Document Signer whose only country sits in a multi-valued RDN (CN=...+C=XX), under the IACA (C=UT)
#   odd-bmp       a leaf whose common name is a BMPString, under the RP access CA
set -e
cat > odd.cnf <<'CNF'
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
sed 's/^\[req\]$/[req]\nstring_mask=MASK:0x800/' odd.cnf > odd-bmp.cnf
ec() { openssl ecparam -name prime256v1 -genkey -noout -out $1.key; }
ec odd-ds-multi
openssl req -new -key odd-ds-multi.key -out odd-ds-multi.csr -subj "/O=Utopia DMV/CN=Odd DS+C=XX" -multivalue-rdn -config odd.cnf
openssl x509 -req -in odd-ds-multi.csr -CA iaca.pem -CAkey iaca.key -CAcreateserial -out odd-ds-multi.pem -days 7000 -extfile odd.cnf -extensions ds -sha256
ec odd-bmp
openssl req -new -key odd-bmp.key -out odd-bmp.csr -subj "/C=UT/O=Odd Names/CN=BMP name" -config odd-bmp.cnf
openssl x509 -req -in odd-bmp.csr -CA rp-ca.pem -CAkey rp-ca.key -CAcreateserial -out odd-bmp.pem -days 7000 -extfile odd.cnf -extensions leaf -sha256
rm -f *.srl *.csr odd.cnf odd-bmp.cnf
