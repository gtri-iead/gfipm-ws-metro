Add to hosts file:

        130.207.211.163 ha50wspm2
        10.50.76.214    cureidpm2
        10.50.76.214    curewscm2
        10.50.76.214    curewspm2



String stsEndpoint = "http://localhost:8080/jaxws-sts/SecurityTokenService";
 String stsMexAddress = "http://localhost:8080/jaxws-sts/SecurityTokenService/mex";
 STSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(
 stsEndpoint, stsMexAddress);
 IssuedTokenManager manager = IssuedTokenManager.getInstance();
 String appliesTo = "http://localhost:8080/jaxws-fs/FinancialService";
 IssuedTokenContext ctx = manager.createIssuedTokenContext(config, appliesTo);
 manager.getIssuedToken(ctx);
 
Token issuedToken = ctx.getSecurityToken();
 byte[] proofKey = ctx.getProofKey();


http://weblogs.java.net/blog/2008/09/15/support-programmatic-authorization-webservices-metro-13


http://metro.java.net/guide/Handling_Token_and_Key_Requirements_at_Run_Time.html
 DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration();                
 Claims claims = ...                
 config.setClaims(claims);
configure.getOtherOptions().get(STSIssuedTokenConfiguration.ISSUED_TOKEN);

https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements
https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements3
https://blogs.oracle.com/trustjdg/entry/handling_token_and_key_requirements2
https://blogs.oracle.com/trustjdg/entry/handling_claims_with_sts

<wst:Claims Dialect="http://schemas.xmlsoap.org/ws/2005/05/identity"                               xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">                 </wst:Claims>

<wst:Claims Dialect="http://schemas.xmlsoap.org/ws/2005/05/identity"                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"                    xmlns:ic="http://schemas.xmlsoap.org/ws/2005/05/identity">                    <ic:ClaimType                        Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality"/>                    <ic:ClaimType                        Uri="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/role"/>                </wst:Claims>


    xmlns:soap11="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"

    xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" 
    xmlns:wsp="http://www.w3.org/ns/ws-policy"


http://blogs.oracle.com/arungupta/entry/totd_1_soap_messaging_logging
    -Dcom.sun.xml.ws.transport.http.HttpAdapter.dump=true:
    -Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=true


Enable logging:
JDK_HOME/jre/lib/logging.properties file and run your application ? Then send us
 the complete server side logging messages :

com.sun.xml.wss.logging.impl.opt.level = FINEST
com.sun.xml.wss.logging.impl.opt.crypto.level = FINEST
com.sun.xml.wss.logging.impl.opt.signature.level = FINEST
com.sun.xml.wss.logging.impl.opt.token.level = FINEST 
javax.enterprise.resource.webservices.jaxws.wspolicy 
com.sun.xml.ws.security.trust.level = FINER

org.jcp.xml.dsig.internal.dom.level= FINEST in your
<JAVA_HOME>/jre/lib/logging.properties 


http://software-security.sans.org/blog/2010/08/11/security-misconfigurations-java-webxml-files/

keytool -importkeystore -srckeystore ~/curewspm2-cacerts.jks -destkeystore cacerts.jks -srcstorepass changeit

openssl pkcs12 -export -out curewspm2.pfx -inkey curewspm2.key -in curewspm2.crt


http://weblogs.java.net/blog/kumarjayanti/archive/2010/03/25/custom-authentication-client-certificate-mutual-ssl-scenarios-g


<jvm-options>-Dcom.sun.xml.ws.transport.http.HttpAdapter.dump=true</jvm-options> 
<jvm-options>-Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=true</jvm-options>

http://nzpcmad.blogspot.com/2010/01/metro-printing-dumping-out-contents-of.html
import com.sun.xml.ws.assembler.MessageDumpingFeature
http://blogs.oracle.com/ritzmann/entry/printing_soap_messages_ii


http://java.net/jira/browse/METRO-16
Metro modifies SAML assertion before appending it to ActAs element in RequestSecurityToken message

URL url =  this.getClass().getResource("/package/name/file.properties"); 
p = new Properties(); 
p.load(new FileInputStream(new File(url.getFile()))); 
InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("META-INF/system.properties");  

http://blogs.oracle.com/arungupta/entry/message_logging_in_wsit_updated



====Useful code snippets ====================

//import com.sun.xml.ws.api.WSBinding;
//import com.sun.xml.ws.api.message.Packet;
//import com.sun.xml.ws.api.server.WSEndpoint;
//import com.sun.xml.ws.api.server.WSWebServiceContext;
//import com.sun.xml.ws.dump.MessageDumpingFeature;
//import com.sun.xml.ws.dump.MessageDumping;

//@MessageDumping(storeMessages=true)

        //http://blogs.oracle.com/ritzmann/entry/printing_soap_messages_ii
//        if (wsContext != null) {
//            // We need to get access to the MessageDumpingFeature object. This is a little tricky,
//            // we need to work our way through some JAX-WS implementation classes.
//            WSWebServiceContext dumpContext = (WSWebServiceContext) wsContext;
//            Packet packet = dumpContext.getRequestPacket();
//            WSEndpoint endpoint = packet.endpoint;
//            WSBinding binding = endpoint.getBinding();
//            // Got it finally
//            MessageDumpingFeature messageDump = binding.getFeature(MessageDumpingFeature.class);
//            if (messageDump != null) {
//                // The first time this method is invoked, it will return the SOAP request. All other invocations will
//                // return the SOAP response of the previous invocation.
//                String previousResponse = messageDump.nextMessage();
//                if(DEBUG) logger.log(Level.INFO,"\n\n\nWSP: Previous Response \n" + previousResponse);
//                // The first time this method is invoked, it will return null. All other invocations will return the
//                // current SOAP request.
//                String request = messageDump.nextMessage();
//                if(DEBUG) logger.log(Level.INFO,"\n\n\nWSP: Request \n" + request);
//            }
//        }
//        

//    public static void configureTrace(Boolean enable) {
//        logger.log(Level.INFO, "WSP: Setting trace to : " + enable.toString());
////            http://blogs.oracle.com/arungupta/entry/totd_1_soap_messaging_logging
////                -Dcom.sun.xml.ws.transport.http.HttpAdapter.dump=true:
////                -Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=true
//        //Server
//        System.setProperty("com.sun.xml.ws.transport.http.HttpAdapter.dump", enable.toString());
//        //Client
//        System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", enable.toString());
//
//        //http://metro.java.net/guide/Logging.html
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.TerminalTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.HandlerTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.ValidationTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.MustUnderstandTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.MonitoringTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.AddressingTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.tx.runtime.TxTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.rx.rm.runtime.RmTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.rx.mc.runtime.McTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.wss.provider.wsit.SecurityTubeFactory", enable.toString());//enable this to check messages
//        System.setProperty("com.sun.xml.ws.dump.ActionDumpTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.rx.testing.PacketFilteringTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.dump.MessageDumpingTubeFactory", enable.toString());
//        System.setProperty("com.sun.xml.ws.assembler.jaxws.TransportTubeFactory", enable.toString());        
//    }    


com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=true;
System.out.print("BizTalk Services Username:");
BizTalkServicesRelayCredentials.setUsername("JavaInteropTest1"); //consoleInput.readLine());
System.out.print("BizTalk Services Password:");
BizTalkServicesRelayCredentials.setPassword("zurich"); //consoleInput.readLine());


Handlers 
http://jax-ws.java.net/articles/handlers_introduction.html
http://jax-ws.java.net/articles/MessageContext.html
http://www.jroller.com/gmazza/entry/jaxws_handler_tutorial
http://weblogs.java.net/blog/ramapulavarthi/archive/2007/12/extend_your_web.html
http://fusesource.com/docs/framework/2.2/jaxws/JAXWSHandlers.html
http://fusesource.com/docs/framework/2.2/jaxws/JAXWSContextsUnderstanding.html


<!-- http://blogs.oracle.com/venu/entry/disabling_inclusiveprefixlist_in_wsit -->
<sunsp:DisableStreamingSecurity xmlns:sunsp="http://schemas.sun.com/2006/03/wss/client"/>
<sc:DisableInclusivePrefixList/>
<wspe:Utf816FFFECharacterEncoding xmlns:wspe="http://schemas.xmlsoap.org/ws/2004/09/policy/encoding" />
<sp:InclusiveC14N/>

    xmlns:soap11="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:soap12="http://schemas.xmlsoap.org/wsdl/soap12/"

    xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" 
    xmlns:wsp="http://www.w3.org/ns/ws-policy"

http://blogs.oracle.com/trustjdg/entry/issuing_saml_token_of_bearer
http://metro.java.net/nonav/1.2/guide/Example_Applications.html

((javax.xml.ws.BindingProvider)port).getRequestContext().put(com.sun.xml.wss.XWSSConstants.USERNAME_PROPERTY, "alice");
((javax.xml.ws.BindingProvider)port).getRequestContext().put(com.sun.xml.wss.XWSSConstants.PASSWORD_PROPERTY, "passwd");

((javax.xml.ws.BindingProvider)port).getResponseContext().

http://spnego.sourceforge.net/

http://www.jroller.com/gmazza/entry/metro_sts_tutorial#MetroSTS7


http://www.oracle.com/technetwork/middleware/id-mgmt/overview/oraclests-166231.html
http://www.oracle.com/technetwork/middleware/id-mgmt/oraclesecuritytokenservicefaq-405119.pdf


http://metro.1045641.n5.nabble.com/Configuring-Multiple-Security-Mechanisms-for-STS-td1066239.html
Two ports for STS, each with different policy: 
   <wsdl:service name="SecurityTokenService"> 
        <wsdl:port name="Binding_ISecurityTokenService" 
binding="tns:Binding_ISecurityTokenService"> 
            <soap12:address location="https://locast/sts/enduser"/> 
        </wsdl:port> 
       <wsdl:port name="Binding_ISecurityTokenService_ActAs" 
binding="tns:Binding_ISecurityTokenService_ActAs"> 
            <soap12:address location="https://locast/sts/actas"/> 
        </wsdl:port> 
  </wsdl:service> 

<endpoint 
        name="sts" 
        interface="simple.sts.ISecurityTokenService" 
        implementation="simple.sts.STSImpl" 
        wsdl="WEB-INF/wsdl/sts.wsdl"     
        service="{http://tempuri.org/}SecurityTokenService" 
        port="{http://tempuri.org/}ISecurityTokenService" 
        binding="http://www.w3.org/2003/05/soap/bindings/HTTP/" 
        url-pattern="/sts" /> 
<endpoint 
        name="sts_actas" 
        interface="simple.sts.ISecurityTokenService" 
        implementation="simple.sts.STSImpl" 
        wsdl="WEB-INF/wsdl/sts.wsdl"     
        service="{http://tempuri.org/}SecurityTokenService" 
        port="{http://tempuri.org/}ISecurityTokenService_ActAS" 
        binding="http://www.w3.org/2003/05/soap/bindings/HTTP/" 
        url-pattern="/sts/actas" /> 
    <endpoint 
        name="sts_mex" 
        implementation="com.sun.xml.ws.mex.server.MEXEndpoint" 
        binding="http://www.w3.org/2003/05/soap/bindings/HTTP/" 
        url-pattern="/sts/mex" /> 

    <servlet-mapping> 
        <servlet-name>sts</servlet-name> 
        <url-pattern>/sts</url-pattern> 
      </servlet-mapping> 
    <servlet-mapping> 
        <servlet-name>sts</servlet-name> 
        <url-pattern>/sts/actas</url-pattern> 
      </servlet-mapping> 
      <servlet-mapping> 
          <servlet-name>sts</servlet-name> 
          <url-pattern>/sts/mex</url-pattern> 
      </servlet-mapping> 

!!!! Very useful article
http://weblogs.java.net/blog/2009/06/01/security-token-configuration-metro

<sc:CallbackHandlerConfiguration timestampTimeout="{Timeout value in Second(s) : 
    This value is used to compute the Expiry time of the WSU:Timestamp being sent in the message,value specified should be greater than zero}"/>

<sc:Validator  name="timestampValidator" classname ={class name of a Timestamp Validator, 
    should implement com.sun.xml.wss.impl.callback.TimestampValidationCallback.TimestampValidator, 
    a default Timestamp validator from XWSS runtime is used when not supplied} />

Review com.sun.xml.wss.impl.misc.DefaultCallbackHandler for use of com.sun.xml.wss.impl.callback.SAMLCallback



Changes to remove STR transform
com.sun.xml.ws.security.impl.policyconv.SupportingTokensProcessor

Line 149 add:
            if(PolicyUtil.isIssuedToken((PolicyAssertion) token, spVersion) &&
                    this instanceof SignedSupportingTokensProcessor){
                ((IssuedTokenKeyBinding)policy).setSTRID(null);
                System.out.println("HERE HERE HERE STRID is null now !!!");
            }  

Line 156 add:

                if( ! (PolicyUtil.isIssuedToken((PolicyAssertion) token, spVersion) &&
                    this instanceof SignedSupportingTokensProcessor) ){
                    addToPrimarySignature(policy,token);
                }else{
                    System.out.println("Skipping addToPrimarySignature");
                }

                encryptToken(token, spVersion);



http://www.jroller.com/gmazza/entry/metro_usernametoken_profile#MetroUT6
http://metro.1045641.n5.nabble.com/How-to-configure-client-for-UsernameToken-with-plaintext-password-and-Nonce-td1052111.html
                <sp:SignedSupportingTokens> 
                    <wsp:Policy> 
                        <sp:UsernameToken sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient">
                             <wsp:Policy> 
                                <sp:WssUsernameToken11/> 
                                <sp:HashPassword/> 
                            </wsp:Policy> 
                        </sp:UsernameToken> 
                    </wsp:Policy> 
                </sp:SignedSupportingTokens> 

> sp:SupportingTokens/../sp:SamlToken policy instead of
 > sp:SignedSupportingTokens/../sp:SamlToken in your
 
ArrayIndexOutOfBoundsException for SAML HOK-secured service invocation
http://java.net/jira/browse/WSIT-728

Subject.getPublicCredentials() returns
 - XMLStreamReader containing the AttributeStatement assertion (HOK)
 - XMLStreamReader containing the XAMLPolicyStatement assertion (SV)
 - com.sun.xml.wss.saml.assertion.saml11.jaxb20.Assertion containing the AttributeStatement assertion (HOK)


CentOS setup
0) Uninstall OpenJDK 
    yum erase java-1.6.0-openjdk-1.6.0.0-1.43.1.10.6.el6_2.x86_64
1) Install OracleJDK
    rpm -iv jdk-7u3-linux-x64.rpm
2) Install & Configure Glassfish 
    see 
        https://blogs.oracle.com/foo/entry/run_glassfish_v3_as_a
        https://blogs.oracle.com/foo/entry/tip_9_advanced_debugger_attach
    !!! http://www.nabisoft.com/tutorials/glassfish/installing-glassfish-31-on-ubuntu

    >asadmin
    delete-domain domain1
    create-domain domain1
    start-domain domain1
    enable-secure-admin

3) Configure environment variables for glassfish
    see sample .bashrc

4) Configure CentOS iptables
    http://wiki.centos.org/HowTos/Network/IPTables
    http://chiralsoftware.com/linux-system-administration/ubuntu-firewall-iptables.seam
    service iptables save
    service iptables stop
    chkconfig iptables off


asadmin
adminadmin

<jvm-options>-DWSIT_HOME=${com.sun.aas.instanceRoot}</jvm-options>
<jvm-options>-Xss128k</jvm-options>
<jvm-options>-XX:+DisableExplicitGC</jvm-options>
<jvm-options>-XX:+AggressiveHeap</jvm-options>


http://weblogs.java.net/blog/kumarjayanti/archive/2008/11/client_side_cer_1.html
((BindingProvider) port).getRequestContext().put(XWSSConstants.CERTIFICATE_PROPERTY, cert);
 ((BindingProvider) port).getRequestContext().put(XWSSConstants.PRIVATEKEY_PROPERTY, key);
 ((BindingProvider) port).getRequestContext().put(XWSSConstants.SERVER_CERTIFICATE_PROPERTY, serverCert);
 

https://blogs.oracle.com/SureshMandalapu/entry/support_of_endpoint_references_with
<sc:EnableEPRIdentity wspp:visibility="private"xmlns:wspp="http://java.sun.com/xml/ns/wsit/policy"/>


                URL url = SecurityUtil.loadFromClasspath("META-INF/ServerCertificate.cert");
                if (url != null) {
                    CertificateFactory certFact = CertificateFactory.getInstance("X.509");
                    InputStream is = url.openStream();
                    this.cs = certFact.generateCertificate(is);
                    is.close();
                } else {
                    cs = cr.getServerKeyStore(wse);
                    if (cs == null) {
                        return null;
                    }
                }

keytool -importkeystore -srckeystore cureidpm2-cacerts.jks -destkeystore cacerts.jks
keytool -importkeystore -srckeystore cureidpm2-keystore.jks -destkeystore keystore.jks
keytool -list -keystore keystore.jks -storepass changeit

gfipmws to �gfipmws@gfipmws� and admin to �@dmin@dmin�

:%s/search_string/replacement_string/g

http://weblogs.java.net/blog/2009/06/01/security-token-configuration-metro


openssl req -x509 -days 3650 -newkey rsa:1024 -keyout alicekey.pem -out alicecert.pem -passout pass:changeit 
openssl pkcs12 -export -inkey alicekey.pem -in alicecert.pem -out alice.p12 -name alice -passin pass:changeit -passout pass:changeit
keytool -importkeystore -destkeystore alicestore.jks -deststorepass changeit -deststoretype jks -srckeystore alice.p12 -srcstorepass changeit -srcstoretype pkcs12
keytool -list -keystore alicestore.jks -storepass changeit -v
keytool -exportcert -alias alice -storepass changeit -keystore alicestore.jks -file alice.cer 
keytool -export -alias alice -file alice.crt -keystore alicestore.jks -storepass changeit
keytool -printcert -file alice.cer
rm *.pem *.p12
keytool -import -noprompt -trustcacerts -alias alice -file alice.cer -keystore cacerts.jks -storepass changeit


http://java.net/jira/browse/WSIT-789
http://java.net/jira/browse/WSIT-676
Apply the Fix for Issue 676 (By dropping hook.jar in GF) then even the STS should use JSR 196 Callbacks and then there is no question of specifying the Truststore and Keystore location and password attributes.

http://java.net/jira/browse/WSIT-1410
Keystore configuration not read when using @WebServiceProvider and WSDL first.

WSP:
keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore curewspm2-keystore.jks -srcstorepass changeit
keytool -trustcacerts -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore curewspm2-cacerts.jks -srcstorepass changeit 
WSC:
keytool -importkeystore -deststorepass changeit -destkeystore keystore.jks -srckeystore curewscm2-keystore.jks -srcstorepass changeit
keytool -importkeystore -deststorepass changeit -destkeystore cacerts.jks -srckeystore curewscm2-cacerts.jks -srcstorepass changeit 

-trustcacerts

Install Certs
Change domain.xml

Using the Java language NamespaceContext object with XPath
http://www.ibm.com/developerworks/library/x-nmspccontext/
The Java XPath API
http://www.ibm.com/developerworks/library/x-javaxpathapi/



    SAML Assertion validation against STS
            String stsEndpoint = "http://localhost:8080/jaxws-fs-sts/sts/validate";
            String stsMexAddress = "http://localhost:8080/jaxws-fs-sts/sts/mex";
            DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(stsEndpoint, stsMexAddress);
            Status status = null;
            try{
                IssuedTokenManager manager = IssuedTokenManager.getInstance();
                IssuedTokenContext ctx = manager.createIssuedTokenContext(config, null);
                ctx.setTarget(new GenericToken(assertion));
                manager.validateIssuedToken(ctx);
                status = (Status)ctx.getOtherProperties().get(IssuedTokenContext.STATUS);
            }catch(Exception ex){
                throw new SAMLValidationException(ex);
            }            
            if (!status.isValid()){
                throw new SAMLValidationException(status.getReason());
            }


Glassfish configuration
http://java.dzone.com/articles/putting-glassfish-v3

asadmin set configs.config.server-config.network-config.transports.transport.tcp.enable-snoop=true
asadmin set configs.config.server-config.http-service.access-logging-enabled=true


http://metro.java.net/2.1.1/guide/Handling_Token_and_Key_Requirements_at_Run_Time.html

http://weblogs.java.net/blog/ramapulavarthi/archive/2007/02/useful_goodies.html
http://weblogs.java.net/blog/ramapulavarthi/archive/2006/08/monitoring_soap.html
    -Dcom.sun.xml.internal.ws.transport.http.client.HttpTransportPipe.dump=true


Certificate changes:

curewsp     -> curewspm2
metrowsp    -> curewspm2
ha50wsp     -> ha50wspm2
netwsp      -> ha50wspm2

curewsc     -> curewscm2
metrowsc    -> curewscm2
ha50wsc     -> ha50wscm2
netwsc      -> ha50wscm2

cureidp     -> cureidpm2
metroidp    -> cureidpm2
ha50idp     -> ha50idpm2
netidp      -> ha50idpm2

Deleted net.gfipm.trustfabric.gfipm-trust-fabric-model2-sample-signed.xml from 

set M=m1
for F in 'wsc wsp'; do
 openssl pkcs8 -topk8 -nocrypt -in metro$F$M.key -inform PEM -out metro$F$M.key.der -outform DER
 openssl x509 -in metro$F$M.crt -inform PEM -out metro$F$M.crt.der -outform DER
 java ImportKey metro$F$M.key.der metro$F$M.crt.der cure$F$M cure$F$M-keystore.jks
 rm metro$F$M.crt.der metro$F$M.crt.der
done

cd m2wsc; mvn cargo:undeploy; cd - ; cd m2wsp; mvn cargo:undeploy; cd - ; cd m2sts; mvn cargo:undeploy; cd -
cd m2wsc;mvn cargo:deploy;cd - ;cd m2wsp;mvn cargo:deploy;cd -;cd m2sts;mvn cargo:deploy; cd -


Redirecting WSC requests:
//REDIRECTING_WSC_REQUEST
model2\svn\m2wsc\src\main\resources\META-INF\CommercialVehicleCollisionWebserviceIntf.xml
model2\svn\m2wsc\src\main\java\gov\niem\ws\sample\cvc\client\CommercialVehicleCollisionWSCClient.java
model2\svn\m2wsc\src\main\java\gov\niem\ws\sample\cvc\client\GFIPMWSCSamlCallbackHandler.java

xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:gfipm="http://gfipm.net/standards/metadata/2.0/entity" xmlns:gfipmws="http://gfipm.net/standards/metadata/2.0/webservices"



Try: 
>            <sp:EndorsingSupportingTokens>
>                  <wsp:Policy>
>                        <sp:SamlToken
>                              sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToRecipient">
>                              <wsp:Policy>
>                                    <sp:WssSamlV20Token11 />
>                              </wsp:Policy>
>                        </sp:SamlToken>
>                  </wsp:Policy>
>            </sp:EndorsingSupportingTokens>

            <sp:EndorsingSupportingTokens xmlns:sp="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy">
                    <wsp:Policy>
                            <sp:IssuedToken sp:IncludeToken="http://schemas.xmlsoap.org/ws/2005/07/securitypolicy/IncludeToken/AlwaysToRecipient">
                                    <sp:RequestSecurityTokenTemplate>
                                            <t:TokenType xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</t:TokenType>
                                            <t:KeyType xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">http://schemas.xmlsoap.org/ws/2005/02/trust/SymmetricKey</t:KeyType>
                                            <t:KeySize xmlns:t="http://schemas.xmlsoap.org/ws/2005/02/trust">256</t:KeySize>
                                    </sp:RequestSecurityTokenTemplate>
                                    <wsp:Policy>
                                            <sp:RequireDerivedKeys/>
                                            <sp:RequireInternalReference/>
                                    </wsp:Policy>
                            </sp:IssuedToken>
                    </wsp:Policy>
            </sp:EndorsingSupportingTokens>


(P001)	<wsp:Policy>
(P002)	  <sp:SupportingTokens>
(P003)	    <wsp:Policy>
(P004)	      <sp:SamlToken sp:IncludeToken=�AlwaysToRecpt�>
(P005)	        <wsp:Policy>
(P006)	          <sp:WssSamlV20Token11/>
(P007)	        </wsp:Policy>
(P008)	      </sp:SamlToken>
(P009)	    </wsp:Policy>
(P010)	  </sp:SupportingTokens>
(P011)	</wsp:Policy>

        DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration();
        config.setOBOToken(samlToken);
        STSIssuedTokenFeature stsIssuedTokenFeature = new STSIssuedTokenFeature(config);
        cvcPort = cvsWebService.getCommercialVehicleCollisionPort(new WebServiceFeature[]{stsIssuedTokenFeature, mtomFeature});



http://java.sun.com/webservices/docs/1.6/wsi-sampleapp/index.html
6.0 Configuring Logging
The Java WSDP supports the Java Logging API [9]. By default, the WS-I sample application in the Java WSDP has its logging level set to "INFO". The following levels are available, in ascending order of granularity and are used in the application as shown below.
Logging Level
Usage
SEVERE Server-side or client-side exception
WARNING Non-blocking error conditions
INFO (default) Basic flow of application
CONFIG Logging entries from the LoggingFacility
FINE SOAP request and response messages
FINER Entry and exit points of primary methods
FINEST Display intermediate steps from the primary methods, if any

To change the default logging level (INFO) on server-side and client-side to a different level:

    Edit JAVA_HOME/jre/lib/logging.properties file.
    Add the following on a new line

    com.sun.wsi.scm.level=LEVEL

    where LEVEL is one of the seven logging levels mentioned above.
    Set the default logging level and logging level for ConsoleHandler to the new level as

    .level=LEVEL
    java.util.logging.ConsoleHandler.level=LEVEL

    Note: You may need to either edit or add these lines depending upon your specific logging.properties file.
    Restart the container and re-run the client.
        For Sun Java System Web Server
            Edit the https-localhost/config/server.xml. 
            Change the level attribute of LOG element to FINE, FINER or FINEST to see more detailed log entries on the server side.



TODO : copy delegation information on STS. 


To create a DOM Element representing the Assertion :
 Element element = com.sun.xml.wss.util.SAMLUtil.createSAMLAssertion(xmlStreamReader);
 
If you would like to create a com.sun.xml.wss.saml.Assertion then here are the steps.
 
import com.sun.xml.wss.saml.SAMLAssertionFactory;
 
//assuming the assertion was a SAML 2.0 assertion
 SAMLAssertionFactory factory = SAMLAssertionFactory.getInstance(SAMLAssertionFactory.SAML2_0);
 Assertion assertion = factory.createAssertion(xmlStreamReader);

TODO:
Fix AuthnContextClassRef, transfer from previous token, Auth instance is not transfered right now.
Fix Delegate information - transfer from previous token
ServiceImpl - replace System.out with log
refactor TF library
GFIPMCertfiicateValidator = validation of the certificate chain from here was not tested (search for "//validation of the certificate chain")
//FIXME add handling of OnBehalfOf (search for "String idName = isActAs ? "ActAs" : NAME_IDENTIFIER;")\
//FIXME add chained delegation based on the content of the Delegation element ("Create SAML assertion and the reference to the SAML assertion")
//FIXME modify to handle conditions with AudienceRestriction ("List<ConditionAbstractType> conditionOrAudienceRestrictionOrOneTimeUseList =")
//FIXME handle https for WSDL ("http://stackoverflow.com/questions/1511674/how-do-a-send-an-https-request-through-a-proxy-in-java")
//FIXME add friendly name to the Attribute ("attrEle = createAttribute(doc, null, samlNS, samlPrefix, attrKey);")


Change TF initialization: TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");

Signature defaults to sha1 for SignatureMethod and DigestMethod, should default to SHA256

keytool -genkeypair -keystore test.p12 -storetype pkcs12 -storepass changeit -alias myalias -keypass changeit -keysize 2048 -keyalg RSA -sigalg sha256withrsa -dname "cn = cureidpm2, o = cure , L = Rome, S = GA, c = US" -validity 3650 -v


gov.niem.ws.util.level = FINEST
gov.niem.ws.util.jaxb.level = FINEST
gov.niem.ws.util.jaxb.delegate.level = FINEST
gov.niem.ws.sample.cvc.client.level = FINEST
gov.niem.ws.sample.cvc.handlers.level = FINEST
gov.niem.ws.sample.cvc.sts.level = FINEST
gov.niem.ws.sample.cvc.service.level = FINEST


When notified by the NIEF Program Office of a change in the Trust Fabric that needs to be incorporated into the local trust store, first load the old trust fabric file, removing all certificates from the trust store, then load the new certificate and add all certificates to the trust store.



========================================
Server is running on 8080, however client is trying to connect to 8888, use any soap monitor to view message, for example SOAP Membrane.

http://localhost:8080/m1wsp/services/cvc?wsdl=1
http://localhost:8888/m1wsp/services/cvc?wsdl=1

Add         
    <jvm-options>-DWSIT_HOME=${com.sun.aas.instanceRoot}</jvm-options>
    to domain.xml    
    
Policy should also work with <sp:RequireIssuerSerialReference/> 

                        <sp:MustSupportRefKeyIdentifier/>
                        <sp:MustSupportRefIssuerSerial/>
                        <sp:MustSupportRefThumbprint/>
                        <sp:MustSupportRefEncryptedKey/>
                        <sp:RequireSignatureConfirmation/>


Problem connected with SHA-1 used by Metro as default instead of required SHA-256 specified by WSDL. 
New WSDL policy requires an additional attribute signatureAlgorithm for Metro to use SHA-256 as following: 
<sp:AlgorithmSuite signatureAlgorithm="SHA256withRSA"> <wsp:Policy> <sp:Basic256Sha256/> </wsp:Policy> </sp:AlgorithmSuite> 
As it turned out SHA-256 is supported only in Java with versions higher than 1.6.22 and requires Metro 2.1 with Glassfish 3.1. 
See the following posts for details: 
    http://blogs.sun.com/gfsecurity/entry/what_s_new_in_metro 
    http://blogs.sun.com/SureshMandalapu/entry/support_of_rsa_sha256_and 
    
Currently uses XML encryption with XML Signatures. 

Metro uses <sp:RequireThumbprintReference/> as default:
<sp:RecipientToken> <wsp:Policy> <sp:X509Token sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/Never"> <wsp:Policy> <sp:RequireThumbprintReference/> <sp:WssX509V3Token11/> </wsp:Policy> </sp:X509Token> </wsp:Policy> </sp:RecipientToken> 
.NET uses <sp:RequireThumbprintReference/> as default: 
<sp:RecipientToken> <wsp:Policy> <sp:X509Token sp:IncludeToken="http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/IncludeToken/AlwaysToInitiator"> <wsp:Policy> <sp:RequireThumbprintReference/> <sp:WssX509V3Token11/> </wsp:Policy> </sp:X509Token> </wsp:Policy> </sp:RecipientToken> Resolved issue with MTOM: .NET is able to accept only MTOM or plain XML, not both, Metro client was trying to use both. 

Moved our implementation to SOAP 1.2 from SOAP 1.1, since .NET service defaults it to SOAP 1.2 We need to test the following transport binding for SOAP 1.2 <soap:binding transport="http://www.w3.org/2003/05/soap/bindings/HTTP/" style="document" /> Right now we have: <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/> 
Metro specifies first binding as the default for SOAP 1.2, i'm not sure thought if it's default for WSDL 2.0. 

.NET publishes modified GFIPM-Test-Contract-CommercialVehicleCollisionWebservice WSDL, which throws off precompiled Metro client. Provided a hack to use local version of the WSDL for WS-MetadataExchange requests for Metro client. 

Resolved <sp:EncryptBeforeSigning/> Default behavior is SignBeforeEncrypt, however .NET decided to implement EncryptBeforeSigning as default for the service. 


http://docs.google.com/viewer?a=v&q=cache:OguV5xffKQIJ:developer.connectopensource.org/download/attachments/32768055/Asynchrous%2BCommunication%2BDesign.docx+&hl=en&gl=us&pid=bl&srcid=ADGEESj9t3TdPL1znlz7BntKcYL7NkDkiaXNUYMwELkcbBvTVwCB_7ojgNznvsGx8N84pclJ2i7u4faP-YwLu6OzDCXDD2qHk3WMfeVF9Tt3d6N4bI5uwZuXv-JiaA5K0HY_VAN4nB8Q&sig=AHIEtbQX5nrYbtXHQJWPXEUlpfqyIjKVVw&pli=1


http://www.w3.org/TR/soap12-part1/
http://www.w3.org/TR/soap12-part2/
http://www.w3.org/TR/ws-addr-wsdl/

http://wsit.java.net/status-notes/status-notes-2-1-FCS.html


Non-standard WSIT configuration file locations for Metro
Configuring multiple WSIT web services or clients at once
Pass configuration file location into WSIT
http://blogs.sun.com/ritzmann/entry/non_standard_wsit_configuration_file

http://blogs.sun.com/trustjdg/entry/handling_token_and_key_requirements
http://blogs.sun.com/trustjdg/entry/handling_token_and_key_requirements3
http://blogs.sun.com/trustjdg/entry/handling_token_and_key_requirements2
========================================