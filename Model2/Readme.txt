GFIPM Web Services : System 2 System SIP : Model 2

TOC
    About
    System Components
    Software Installation
    Environment Setup
    Application Build 
    Application Server Setup
    Certificates Installation
    Application Deployment
    Running tests
    References
    Appendixes


About
This file covers required software, installation, configuration, build and 
deployment of the major components for Model 2 of the GFIPM Web Services 
System 2 System Profiles document. Instructions contain sample commands, scripts, 
and configuration files that were tested on CentOS 6.2 (To determine the version 
of your distribution run the following command: "uname -a; cat /etc/redhat-release")
Listed environment, commands, and scripts are included to assist the user, 
rather then to enforce certain way of uniform distribution.


System Components
  GFIPM Web Services S2S Profile Model 2 distribution contains the following modules:
  
  gfipm-ws-m2 - GFIPM Model 2 Web Services
    m2client - GFIPM Model 2 Web Service Client
    m2lib - GFIPM Web Services auxiliary library, contains common code, 
        JAXB implementation for SAML V2.0 Delegation restriction [8]
    m2sts - GFIPM Web Services Model 2 Security Token Service(STS)/Assertion Delegate Service (ADS)
    m2wsc - GFIPM Web Services Model 2 Web Service Consumer(WSC)
    m2wsp - GFIPM Web Services Model 2 Web Service Provider(WSP)

  trustfabric - GFIPM Cryptographic Trust Fabric Application / Library

  wscontract - Information Exchange Service Contract Implementation Library

    Current source distribution assumes, that each component (m2sts, m2wsc, m2wsp) will 
    be deployed to it's own machine (Virtual Machine). ( Please, note that it is possible 
    to deploy these components on one machine within each own domain, however current
    distribution assumes one machine per component ). Software installation steps
    will need to be repeated for each deployment component (WSC, STS/ADS, WSP).

Software Installation

    Current instructions assume that you elevate your permissions either by prepending 
    every command with "sudo su" (for ex: ">sudo su ls")  
    or running them as root user ("sudo su -").

    It is assumed that you have NTP daemon running on each system.

    1) Install Java 7 (jdk-7u3-linux-x64.rpm)
    Current model was tested with Java 7, however there is nothing in 
    Java 6 that should prevent current implementation from proper execution. For
    instructions on use of the latest JAXB and JAX-WS with Java 6 see references [XXX] 
    for the endorsed mechanism. 

    >which java; java -version
    >yum erase java-1.6.0-openjdk-1.6.0.0-1.43.1.10.6.el6_2.x86_64
    >wget http://download.oracle.com/otn-pub/java/jdk/7u3-b04/jdk-7u3-linux-x64.rpm
    >rpm -iv jdk-7u3-linux-x64.rpm
    >which java; java -version

    2) Install Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy (optional)
    
    >wget http://download.oracle.com/otn-pub/java/jce/7/UnlimitedJCEPolicyJDK7.zip
    >unzip UnlimitedJCEPolicyJDK7.zip
    >cd /usr/java/default/jre/lib/
    >mkdir security.old
    >cp -R security security.old
    >cd security
    >cp ~/UnlimitedJCEPolicy/*.jar .
    
    3) Install Maven (Apache Maven 2.2.1)
    Installation of the Maven in /var/opt is optional.

    >wget http://apache.mirrors.pair.com/maven/binaries/apache-maven-2.2.1-bin.tar.gz
    >gunzip apache-maven-2.2.1-bin.tar.gz
    >tar -xvf apache-maven-2.2.1-bin.tar
    >mv apache-maven-2.2.1 /var/opt
    >cd /var/opt
    >ln -s apache-maven-2.2.1 maven

    4) Configure IPTables (optional)
    Save scripts from Appendix A and Appendix B to the corresponding files and 
    set execution permissions 
    
    >chmod 700 *.rules
    >./iptables.DISABLE_4848.rules
    >service iptables save

    5) Configure hosts file
    Distribution uses aliases for all components ( Metro: curewscm2, cureidpm2, 
    curewspm2; .NET: ha50wscm2, ha50idpm2; ha50wspm2 ) which could be easily mapped to
    the ip addresses through /etc/hosts file. For example, add the following to
    the /etc/hosts 
    10.51.4.124   cureidpm2
    10.51.4.123   curewscm2
    10.51.4.132   curewspm2
    10.51.8.81    ha50idpm2
    130.207.211.163 ha50wspm2
    10.51.8.25    ha50wscm2

    6) Install Glassfish (v 3.1.2) 
    The following instructions suggest running Glassfish as non privileged user (glassfish).
    Installation of the Glassfish in /var/opt is optional.
    
    >wget http://download.oracle.com/otn-pub/java/java_ee_sdk/6u4/ogs-3.1.2.zip 
    >unzip ogs-3.1.2.zip
    >mv glassfish3 /var/opt
    >cd /var/opt/
    >mv glassfish3 glassfish3.1.2
    >ln -s glassfish3.1.2 glassfish
    >useradd -d /var/opt/glassfish3 -m -g glassfish glassfish
    You can manually verify in /etc/passwd home directory for the glassfish
    glassfish:x:502:502::/var/opt/glassfish:/bin/bash
    >chown -R glassfish:glassfish /var/opt/glassfish3.1.2
    >sudo su - glassfish


Environment Setup
    Appendix C contains sample environment settings for "glassfish" user.
    Settings could be configured through .bashrc in "glassfish" user's home directory.
    >sudo su - glassfish
    >vi .bashrc
    You will need to logout and login to enable environment settings.


Application Server Setup

    By default Glassfish comes with domain1 which could be located under
    /var/opt/glassfish/domains/domain1

    Following steps must be repeated for each deployable component (WSC, STS/ADS, WSP)
    If domain1 is used for the Model 1 deployment, use the other domain name (domain2).

    >asadmin
    >delete-domain domain1
    >create-domain domain1
     *Enter password for Glassfish admin (default password "adminadmin")
    >start-domain domain1
    >enable-secure-admin
    >stop-domain domain1

    Now Glassfish web-based GUI will be available via:
    https://yourhost:4848/common/index.jsf

    Open Glassfish domain (domain1) configuration file:
    >vi glassfish/domains/domain1/config/domain.xml

    Replace default glassfish domain certificates "s1as" with corresponding 
    component certificate:
        wsc: curewscm2
        wsp: curewspm2
        sts: cureidpm2
    Following vi command could be used to do a global search and replace:
    :%s/search_string/replacement_string/g

    After '<config name="server-config">' locate lines containing jvm-options.
    There are multiple sections of the configuration file that include
    jvm-options, so it is IMPORTANT that you alter the correct section.

    Following options could be added to the configuration file:
        <jvm-options>-server</jvm-options>
        <jvm-options>-Xmx2048m</jvm-options>
        <jvm-options>-Xms1024m</jvm-options>
        <jvm-options>-Dproduct.name=</jvm-options>
        <jvm-options>-Dcom.sun.xml.ws.transport.http.HttpAdapter.dump=false</jvm-options>
        <jvm-options>-Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=false</jvm-options>
        <jvm-options>-Dcom.sun.xml.ws.fault.SOAPFaultBuilder.disableCaptureStackTrace=false</jvm-options>

    Don't forget to remove the old values:
        <jvm-options>-Xmx512m</jvm-options>
        <jvm-options>-client</jvm-options>



Application Build

    To build the components use the following commands:
    >cd trustfabric-1.0-SNAPSHOT
    >mvn clean install
    >cd ../
    >cd wscontract-1.0-SNAPSHOT
    >mvn clean install
    >cd ../
    >cd gfipm-ws-m2-1.0-SNAPSHOT
    >mvn clean install

    After build is completed locate deployable WAR files:
    >find . -name *.war 
    ./m2sts/target/m2sts.war
    ./m2wsc/target/m2wsc.war
    ./m2wsp/target/m2wsp.war

    Upload component WAR file to the corresponding system. 


Certificates Installation

    On the system with corresponding component install certificates and provide
    application deployments. If you uploaded WAR file under "admin" user, change
    user permissions to be readable by user glassfish. 

    WSC: (m2wsc.war)
    >cd $GF_HOME/domains/domain1/config/
    >unzip -j ~/m2wsc.war "*-*.jks"
    >keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore curewscm2-keystore.jks -srcstorepass changeit
    >keytool -trustcacerts -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore curewscm2-cacerts.jks -srcstorepass changeit
    >keytool -list -keystore keystore.jks -storepass changeit -alias curewscm2 -v
    >keytool -list -keystore cacerts.jks -storepass changeit |more

    WSP: (m2wsp.war)
    >cd $GF_HOME/domains/domain1/config/
    >unzip -j ~/m2wsp.war "*-*.jks"
    >keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore curewspm2-keystore.jks -srcstorepass changeit
    >keytool -trustcacerts -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore curewspm2-cacerts.jks -srcstorepass changeit
    >keytool -list -keystore keystore.jks -storepass changeit -alias curewspm2 -v
    >keytool -list -keystore cacerts.jks -storepass changeit |more

    STS: (m2sts.war)
    >cd $GF_HOME/domains/domain1/config/
    >unzip -j ~/m2sts.war "*-*.jks"
    >keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore cureidpm2-keystore.jks -srcstorepass changeit
    >keytool -trustcacerts -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore cureidpm2-cacerts.jks -srcstorepass changeit
    >keytool -list -keystore keystore.jks -storepass changeit -alias cureidpm2 -v
    >keytool -list -keystore cacerts.jks -storepass changeit |more

    
Application Deployment

    On each system start configured Glassfish domain:
    >asadmin start-domain domain1
    >asadmin list-domains

    Deploy corresponding application:
    >asadmin deploy m2wsc.war
    >asadmin deploy m2wsp.war
    >asadmin deploy m2sts.war

    Check the status of the applications:
    >asadmin list-applications

    Undeploy application(s) if necessary:
    >asadmin undeploy war-name

    All functions listed above are also available via Glassfish administration GUI 
    accessible at https://yourhost:4848/common/index.jsf

    Also, you can also use maven plugin to deploy / undeploy war files for corresponding components directly to the glassfish:
    Command should be executed from component directory (>cd m2sts or >cd m2wsc or >cd m2wsp)
    >mvn cargo:deploy
    >mvn cargo:undeploy

Running tests

    To run tests execute client application as following:
    >cd m2client
    >mvn exec:exec

References
1. GlassFish Server Open Source Edition Quick Start Guide
    http://glassfish.java.net/docs/3.1.2/quick-start-guide.pdf
2. Security Token Configuration in Metro
    http://weblogs.java.net/blog/2009/06/01/security-token-configuration-metro
3. https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements
4. https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements3
5. https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements2
6. https://blogs.oracle.com/trustjdg/entry/handling_claims_with_sts
7. http://metro.java.net/guide/Handling_Token_and_Key_Requirements_at_Run_Time.html
8. SAML V2.0 Condition for Delegation Restriction Version 1.0
   http://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-delegation-cs-01.pdf

Sample VM settings
    User Accounts (user name / password )
        Non-privileged  gfipmws / “gfipmws@gfipmws” 
                        glassfish / no password is set
        Privileged (can execute sudo commands) 
                        admin / “@dmin@dmin”

-----
Appendix A: iptables.DISABLE_4848.rules

#!/bin/bash
# ATTENTION: flush/delete all existing rules
iptables -F
################################################################
# set the default policy for each of the pre-defined chains
################################################################
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP
# allow establishment of connections initialised by my outgoing packets
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# accept anything on localhost
iptables -A INPUT -i lo -j ACCEPT
################################################################
#individual ports tcp
################################################################
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8181 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
#uncomment next line to enable AdminGUI on port 4848:
#iptables -A INPUT -p tcp --dport 4848 -j ACCEPT
################################################################
#slow down the amount of ssh connections by the same ip address:
#wait 60 seconds if 3 times failed to connect
################################################################
iptables -I INPUT -p tcp -i eth0 --dport 22 -m state --state NEW -m recent --name sshprobe --set -j ACCEPT
iptables -I INPUT -p tcp -i eth0 --dport 22 -m state --state NEW -m recent --name sshprobe --update --seconds 60 --hitcount 3 --rttl -j DROP
#drop everything else
iptables -A INPUT -j DROP
################################################################
#Redirection Rules
################################################################
#1. redirection rules (allowing forwarding from localhost)
iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A OUTPUT -o lo -p tcp --dport 443 -j REDIRECT --to-port 8181
#2. redirection http
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
#3. redirection https
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8181
################################################################
#save the rules somewhere and make sure
#our rules get loaded if the ubuntu server is restarted
################################################################
iptables-save > /etc/my-iptables.rules
iptables-restore < /etc/my-iptables.rules
#List Rules to see what we have now
iptables -L
################################################################

Appendix B: iptables.ENABLE_4848.rules

#!/bin/bash
# ATTENTION: flush/delete all existing rules
iptables -F
################################################################
# set the default policy for each of the pre-defined chains
################################################################
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP
# allow establishment of connections initialised by my outgoing packets
iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
# accept anything on localhost
iptables -A INPUT -i lo -j ACCEPT
################################################################
#individual ports tcp
################################################################
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8181 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
#uncomment next line to enable AdminGUI on port 4848:
iptables -A INPUT -p tcp --dport 4848 -j ACCEPT
################################################################
#slow down the amount of ssh connections by the same ip address:
#wait 60 seconds if 3 times failed to connect
################################################################
iptables -I INPUT -p tcp -i eth0 --dport 22 -m state --state NEW -m recent --name sshprobe --set -j ACCEPT
iptables -I INPUT -p tcp -i eth0 --dport 22 -m state --state NEW -m recent --name sshprobe --update --seconds 60 --hitcount 3 --rttl -j DROP
#drop everything else
iptables -A INPUT -j DROP
################################################################
#Redirection Rules
################################################################
#1. redirection rules (allowing forwarding from localhost)
iptables -t nat -A OUTPUT -o lo -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A OUTPUT -o lo -p tcp --dport 443 -j REDIRECT --to-port 8181
#2. redirection http
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 80 -j REDIRECT --to-ports 8080
#3. redirection https
iptables -t nat -A PREROUTING -p tcp -m tcp --dport 443 -j REDIRECT --to-ports 8181
################################################################
#save the rules somewhere and make sure
#our rules get loaded if the ubuntu server is restarted
################################################################
iptables-save > /etc/my-iptables.rules
iptables-restore < /etc/my-iptables.rules
#List Rules to see what we have now
iptables -L
################################################################

Appendix C: environment settings (.bashrc)

#JAVA_HOME
JAVA_HOME=/usr/java/default
JAVA_OPTS=-Xmx1024m

# Glassfish Server V3
AS_HOME=/var/opt/glassfish/glassfish
GF_HOME=/var/opt/glassfish/glassfish
GLASSFISH_HOME=/var/opt/glassfish/glassfish
AS_ADMIN_USER=asadmin

# Maven
MAVEN_HOME=/var/opt/maven
M2_HOME=/var/opt/maven
MAVEN_OPTS=-Xmx512m

# Classpath
CLASSPATH=$CLASSPATH:.:$JAVA_HOME/lib/tools.jar

PATH=${PATH}:$JAVA_HOME/bin:$AS_HOME/bin

export JAVA_OPTS JAVA_HOME MAVEN_OPTS AS_HOME AS_ADMIN_USER GF_HOME PATH CLASSPATH MAVEN_HOME M2_HOME


################################################################
Appendix D: How to import existing .key and .crt into .jks
(src: http://wiki.eclipse.org/Generating_a_Private_Key_and_a_Keystore)
Assume you have an existing .key and .crt.
You do this:
1. You convert the private key into PKCS#8 format:
 openssl pkcs8 -topk8 -nocrypt -outform der -in /etc/httpd/conf/ssl.key/server.key -out tmpfile
2. Since the stupid Java keytool doesn't allow you to import private keys, you download this tool:
 http://www.agentbob.info/agentbob/79-AB.html
3. Now you can import the key into the Java Keystore:
 java ImportKey tmpfile /etc/httpd/conf/ssl.crt/server.crt
4. Now you have the Java Keystore:
 /root/keystore.ImportKey
5. Delete the tmpfile:
 rm tmpfile

################################################################
Appendix E: ImportKey.java

import java.security.*;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.DataInputStream;
import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.security.spec.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Collection;
import java.util.Iterator;
import java.io.BufferedInputStream;
/**
 * ImportKey.java
 *
 * <p>This class imports a key and a certificate into a keystore
 * (<code>$home/keystore.ImportKey</code>). If the keystore is
 * already present, it is simply deleted. Both the key and the
 * certificate file must be in <code>DER</code>-format. The key must be
 * encoded with <code>PKCS#8</code>-format. The certificate must be
 * encoded in <code>X.509</code>-format.</p>
 *
 * <p>Key format:</p>
 * <p><code>openssl pkcs8 -topk8 -nocrypt -in YOUR.KEY -out YOUR.KEY.der
 * -outform der</code></p>
 * <p>Format of the certificate:</p>
 * <p><code>openssl x509 -in YOUR.CERT -out YOUR.CERT.der -outform
 * der</code></p>
 * <p>Import key and certificate:</p>
 * <p><code>java comu.ImportKey YOUR.KEY.der YOUR.CERT.der</code></p><br />
 *
 * <p><em>Caution:</em> the old <code>keystore.ImportKey</code>-file is
 * deleted and replaced with a keystore only containing <code>YOUR.KEY</code>
 * and <code>YOUR.CERT</code>. The keystore and the key has no password; 
 * they can be set by the <code>keytool -keypasswd</code>-command for setting
 * the key password, and the <code>keytool -storepasswd</code>-command to set
 * the keystore password.
 * <p>The key and the certificate is stored under the alias
 * <code>importkey</code>; to change this, use <code>keytool -keyclone</code>.
 *
 * Created: Fri Apr 13 18:15:07 2001
 * Updated: Fri Apr 19 11:03:00 2002
 *
 * @author Joachim Karrer, Jens Carlberg
 * @version 1.1
 **/
public class ImportKey  {
    
    /**
     * <p>Creates an InputStream from a file, and fills it with the complete
     * file. Thus, available() on the returned InputStream will return the
     * full number of bytes the file contains</p>
     * @param fname The filename
     * @return The filled InputStream
     * @exception IOException, if the Streams couldn't be created.
     **/
    private static InputStream fullStream ( String fname ) throws IOException {
        FileInputStream fis = new FileInputStream(fname);
        DataInputStream dis = new DataInputStream(fis);
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        return bais;
    }

private static String readFileAsString(String filePath) throws IOException{
    byte[] buffer = new byte[(int) new File(filePath).length()];
    BufferedInputStream f = null;
    try {
        f = new BufferedInputStream(new FileInputStream(filePath));
        f.read(buffer);
    } finally {
        if (f != null) try { f.close(); } catch (IOException ignored) { }
    }
    return new String(buffer);
}
    
        
    /**
     * <p>Takes two file names for a key and the certificate for the key, 
     * and imports those into a keystore. Optionally it takes an alias
     * for the key.
     * <p>The first argument is the filename for the key. The key should be
     * in PKCS8-format.
     * <p>The second argument is the filename for the certificate for the key.
     * <p>If a third argument is given it is used as the alias. If missing,
     * the key is imported with the alias importkey
     * <p>The name of the keystore file can be controlled by setting
     * the keystore property (java -Dkeystore=mykeystore). If no name
     * is given, the file is named <code>keystore.ImportKey</code>
     * and placed in your home directory.
     * @param args [0] Name of the key file, [1] Name of the certificate file
     * [2] Alias for the key.
     **/
    public static void main ( String args[]) {
        
        // change this if you want another password by default
        String keypass = "changeit";
        // change this if you want another alias by default
        String alias = null; 
        // change this if you want another keystorefile by default
        String keystorename = null;
        // parsing command line input
        String keyfile = null;
        String certfile = null;

        if (args.length != 4) {
            System.out.println("Usage: java ImportKey keyfile certfile alias keystorename");
            System.exit(0);
        } else {
            keyfile = args[0];
            certfile = args[1];
	    alias = args[2];
	    keystorename = args[3];
        }

        try {
            // initializing and clearing keystore 
            KeyStore ks = KeyStore.getInstance("JKS", "SUN");
            ks.load( null , keypass.toCharArray());
            System.out.println("Using keystore-file : "+keystorename);
            ks.store(new FileOutputStream ( keystorename  ),
                    keypass.toCharArray());
            ks.load(new FileInputStream ( keystorename ),
                    keypass.toCharArray());

            // loading Private Key
            InputStream fl = fullStream (keyfile);
            byte[] key = new byte[fl.available()];
            KeyFactory kf = KeyFactory.getInstance("RSA");
            fl.read ( key, 0, fl.available() );
            fl.close();
            PKCS8EncodedKeySpec keysp = new PKCS8EncodedKeySpec ( key );
            PrivateKey ff = kf.generatePrivate (keysp);

            // loading CertificateChain
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream certstream = fullStream (certfile);

            Collection c = cf.generateCertificates(certstream) ;
            Certificate[] certs = new Certificate[c.toArray().length];

            if (c.size() == 1) {
                certstream = fullStream (certfile);
                System.out.println("One certificate, no chain.");
                Certificate cert = cf.generateCertificate(certstream) ;
                certs[0] = cert;
            } else {
                System.out.println("Certificate chain length: "+c.size());
                certs = (Certificate[])c.toArray();
            }

            // storing keystore
            ks.setKeyEntry(alias, ff, 
                           keypass.toCharArray(),
                           certs );
            System.out.println ("Key and certificate stored.");
            System.out.println ("Alias:"+alias+"  Password:"+keypass);
            ks.store(new FileOutputStream ( keystorename ),
                     keypass.toCharArray());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}// KeyStore

################################################################
Appendix E: create_private_stores_metro_m1.sh
#!/bin/bash
javac ImportKey.java
export M=m1
for F in wsc wsp; do
 openssl pkcs8 -topk8 -nocrypt -in metro$F$M.key -inform PEM -out metro$F$M.key.der -outform DER
 openssl x509 -in metro$F$M.crt -inform PEM -out metro$F$M.crt.der -outform DER
 java ImportKey metro$F$M.key.der metro$F$M.crt.der cure$F$M cure$F$M-keystore.jks
 rm metro$F$M.key.der metro$F$M.crt.der
done

################################################################
Appendix E: create_private_stores_metro_m2.sh
#!/bin/bash
javac ImportKey.java
export M=m2
for F in wsc wsp idp; do
 openssl pkcs8 -topk8 -nocrypt -in metro$F$M.key -inform PEM -out metro$F$M.key.der -outform DER
 openssl x509 -in metro$F$M.crt -inform PEM -out metro$F$M.crt.der -outform DER
 java ImportKey metro$F$M.key.der metro$F$M.crt.der cure$F$M cure$F$M-keystore.jks
 rm metro$F$M.key.der metro$F$M.crt.der
done
