#!/bin/bash
javac ImportKey.java
export M=m2
for F in wsc wsp idp; do
 openssl pkcs8 -topk8 -nocrypt -in metro$F$M.key -inform PEM -out metro$F$M.key.der -outform DER
 openssl x509 -in metro$F$M.crt -inform PEM -out metro$F$M.crt.der -outform DER
 java ImportKey metro$F$M.key.der metro$F$M.crt.der cure$F$M cure$F$M-keystore.jks
 rm metro$F$M.key.der metro$F$M.crt.der
done
