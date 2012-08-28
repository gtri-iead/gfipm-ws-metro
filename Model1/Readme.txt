GFIPM Web Services : System 2 System SIP : Model 1

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
deployment of the major components for Model 1 of the GFIPM Web Services 
System 2 System Profiles document. Instructions contain sample commands, scripts, 
and configuration files that were tested on CentOS 6.2 (To determine the version 
of your distribution run the following command: "uname -a; cat /etc/redhat-release")
Listed environment, commands, and scripts are included to assist the user, 
rather then to enforce certain way of uniform distribution.


System Components
  GFIPM Web Services S2S Profile Model 1 distribution contains the following modules:
  
  gfipm-ws-m1 - GFIPM Model 1 Web Services
    m1wsc - GFIPM Web Services Model 1 Web Service Consumer(WSC)
    m1wsp - GFIPM Web Services Model 1 Web Service Provider(WSP)

  trustfabric - GFIPM Cryptographic Trust Fabric Application / Library

  wscontract - Information Exchange Service Contract Implementation Library

Software Installation

    Current instructions assume that you elevate your permissions either by prepending 
    every command with "sudo su" (for ex: ">sudo su ls")  
    or running them as root user ("sudo su -").

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
    Distribution uses aliases for all components ( Metro: curewsc, cureidp, 
    curewsp; .NET: ha50wsc, ha50idp; ha50wsp ) which could be easily mapped to
    the ip addresses through /etc/hosts file. For example, add the following to
    the /etc/hosts 
    10.51.4.132   curewspm1
    130.207.211.163 ha50wspm1

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

    If domain1 is used for the Model 2 deployment, use the other domain name (domain2).

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
        wsp: curewspm1
    Following vi command could be used to do a global search and replace:
    :%s/search_string/replacement_string/g

    After '<config name="server-config">' locate lines containing jvm-options.
    There are multiple sections of the configuration file that include jvm-options, 
    so it is IMPORTANT that you alter the correct section.
    Following options could be added to the configuration file (not mandatory):
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
    >cd gfipm-ws-m1-1.0-SNAPSHOT
    >mvn clean install

    After build is completed locate deployable WAR files:
    >find . -name *.war 
    ./m1wsp/target/m1wsp.war

    Upload component WAR file to the corresponding system. 


Certificates Installation

    On the system with corresponding component install certificates and provide
    application deployments. If you uploaded WAR file under "admin" user, change
    user permissions to be readable by user glassfish. 

    WSP: (m1wsp.war)
    >cd $GF_HOME/domains/domain1/config/
    >unzip -j ~/m1wsp.war "*-*.jks"
    >keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore curewspm1-keystore.jks -srcstorepass changeit
    >keytool -trustcacerts -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore curewspm1-cacerts.jks -srcstorepass changeit
    >keytool -list -keystore keystore.jks -storepass changeit -alias curewspm1 -v
    >keytool -list -keystore cacerts.jks -storepass changeit |more

Application Deployment

    On each system start configured Glassfish domain:
    >asadmin start-domain domain1
    >asadmin list-domains

    Deploy corresponding application:
    >asadmin deploy m1wsp.war

    Check the status of the applications:
    >asadmin list-applications

    Undeploy application(s) if necessary:
    >asadmin undeploy war-name

    All functions listed above are also available via Glassfish administration GUI 
    accessible at https://yourhost:4848/common/index.jsf


Running tests

    To run tests execute the WSC application as following:
    >cd m1wsc 
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



