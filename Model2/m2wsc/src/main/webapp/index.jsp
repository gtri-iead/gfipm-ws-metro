<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>Test page for Commercial Vehicle Collision Service</title>
    </head>
    <body>
        <h1>Test page for Commercial Vehicle Collision Service</h1>
        <p>All services are available <a href="/m1wsp/services/cvc?wsdl"> here </a>.</p>
        
        <p>
            <ul>
                <li>SAML subject confirmation methods: holder-of-key vs. sender-vouches http://www.jroller.com/gmazza/entry/saml_subject_confirmation_methods_holder</li>
                <li>SAML Sender Vouches with Certificates http://download.oracle.com/docs/cd/E19575-01/820-1072/ahidc/index.html</li>
                <li>SAML Holder of Key http://download.oracle.com/docs/cd/E19575-01/820-1072/ahidd/index.html</li>
                <li>Metro Guide: 12.3. Security Mechanisms http://metro.java.net/guide/Security_Mechanisms.html</li>
                <li>Metro Guide: 12.9 Example Applications http://metro.java.net/guide/Example_Applications.html</li>
                <li>http://htotapally.blogspot.com/2010/08/web-service-security-wss-sender-vouches_06.html</li>
                http://biemond.blogspot.com/2009/10/securing-web-services-with-saml-sender.html
                
                http://download.oracle.com/docs/cd/E17802_01/webservices/webservices/reference/tutorials/wsit/doc/WSIT_Security9.html#wp140996
                Example: SAML Sender Vouches with Certificates (SV) 
                
                http://blogs.oracle.com/enterprisetechtips/entry/security_token_service_and_identity
                !Security Token Service and Identity Delegation with Metro
                
                http://blogs.oracle.com/enterprisetechtips/entry/supporting_tokens_and_issued_token
                Supporting Tokens and Issued Token Delegation in WSIT 
                
!!!                
http://metro.1045641.n5.nabble.com/Need-clarification-on-SAML-Sender-Vouches-vs-Holder-of-Key-methods-td1060355.html
Hello, I'm trying to understand more about the SAML holder-of-key vs. sender vouches subject confirmation methods as discussed in the OASIS specs[1][2] and on a few other websites.  I have a few questions to help solidify my understanding of this:
1.) Does the SAML Holder-of-Key subject confirmation method tend to imply that the SOAP client making the request is adding SAML assertions to its own request, while the SAML sender vouches method imply that a third web service, such as an STS, is producing the SAML assertions and adding them to the SOAP client's request?
2.) Does the SAML HOK subject confirmation method imply that the SOAP client is directly calling the web service provider (having either obtained earlier or created the SAML assertions itself), while the SAML SV method imply that the SOAP client called the external web service that added the SAML assertions and then that external web service forwarded the SOAP request to the web service provider?
3.) Is there any correlation between usage of an STS and either subject confirmation method--does one subject confirmation method imply usage of an STS while the other does not, or do both tend to imply usage of an STS?
4.) Why in the OASIS SAML Token Profile specification's SAML sender-vouches example (Either line 707 of the 1.0[1] or 926 of 1.1[2]), is there no need for a reference to the Urn:oasis:names:tc:SAML:1.0:cm:sendervouches URN, like there is a reference to the Urn:oasis:names:tc:SAML:1.0:cm:holder-of-key URN in both the sender-vouches example and in the holder-of-key example immediately preceding it (Line 576 of [1] or Line 814 of [2])?  Do you ever need to have a reference to the Urn:oasis:names:tc:SAML:1.0:cm:sendervouches URN in the SOAP request when using the SV subject confirmation method?
[1] http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0.pdf
[2] http://www.oasis-open.org/committees/download.php/16768/wss-v1.1-spec-os-SAMLTokenProfile.pdf
-------------
A = end user, B = Web service client,  C = Web servcie. 
D = SAML assertion belong to A 
1. If A = B, the holder of key. 
2. If A != B, and B send request to C on behalf of A. Sender-Voucher. B need to sign D to vouch A.
It doesn't matter who issued the SAML assertions. 
--------------
Here is the scenarios: 
A=end user, B=web service client, C=STS, D=web service 
1. A=B, 
B calls C to get an SAML assertion for himself to access D. So B supplies its own certificate to C and C authenticate the certificate of B, create an SAML assertion with
 B's idenntity and put either an Symmetric Key or the Certificate of B into the assertion, and C also signs the assertion. The B send the assertion to D and use the key associated with the assertion to secure the message. This is Holder-Of-Key case.
2. A != B: 
B calls C to get an SAML assertion on behalf of A to access D. So B supplies its own certificate to C as well and also put the username/password of A in a sub-element OnBehalfOf in the request message, C create an SAML assertion with
 C's identity in the assertion, and C also signs the assertion. The B send the assertion to D and use server's certificate and/or B's certificate to secure the message. This is Sender-Vouch case.

 
                http://forums.java.net/node/693978
                Configure STS service to generate SAML token directly

                ------------------------
                http://www.jroller.com/gmazza/entry/metro_and_wstrust
                Implementing WS-Trust with GlassFish Metro on Tomcat
                http://www.jroller.com/gmazza/?cat=Web+Services&date=20100421
                Analysis of Metro STS calls
                
            </ul>
        </p>
    </body>
</html>
