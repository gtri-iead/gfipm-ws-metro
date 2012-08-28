#!/bin/bash
export M=m2
for F in wsc wsp idp; do

keytool -import -noprompt -trustcacerts -alias nief-ca -file nief-ca.cer -keystore cure$F$M-cacerts.jks -storepass changeit
keytool -import -noprompt -trustcacerts -alias nief-ca-new -file nief-ca-new.cer -keystore cure$F$M-cacerts.jks -storepass changeit
keytool -import -noprompt -trustcacerts -alias ref-gfipm-ca -file ref-gfipm-ca-2012.crt -keystore cure$F$M-cacerts.jks -storepass changeit

for A in metro net; do  
	if [ $A == "metro" ]
	then export N=cure 
	fi 
	if [ $A == "net" ]
	then export N=ha50 
	fi 
keytool -import -noprompt -trustcacerts -alias $N"wsc"$M -file $A"wsc"$M.crt -keystore cure$F$M-cacerts.jks -storepass changeit
keytool -import -noprompt -trustcacerts -alias $N"wsp"$M -file $A"wsp"$M.crt -keystore cure$F$M-cacerts.jks -storepass changeit
keytool -import -noprompt -trustcacerts -alias $N"idp"$M -file $A"idp"$M.crt -keystore cure$F$M-cacerts.jks -storepass changeit
done

done
