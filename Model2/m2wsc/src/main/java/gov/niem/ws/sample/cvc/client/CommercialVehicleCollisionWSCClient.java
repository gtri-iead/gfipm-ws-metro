/*
 * Copyright (c) 2012, Georgia Institute of Technology. All Rights Reserved.
 * This code was developed by Georgia Tech Research Institute (GTRI) under
 * a grant from the U.S. Dept. of Justice, Bureau of Justice Assistance.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package gov.niem.ws.sample.cvc.client;

import com.sun.xml.ws.Closeable;
import com.sun.xml.ws.api.security.trust.client.STSIssuedTokenConfiguration;
import com.sun.xml.ws.security.Token;
import com.sun.xml.ws.security.trust.GenericToken;
import com.sun.xml.ws.security.trust.STSIssuedTokenFeature;
import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;
import com.sun.xml.wss.impl.XMLUtil;
import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.SAMLException;
import gov.niem.ws.sample.cvc.jaxb.msg.GetDocumentRequestType;
import gov.niem.ws.sample.cvc.jaxb.msg.GetDocumentResponseType;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionPortType;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionWebService;
import gov.niem.ws.util.GFIPMUtil;
import gov.niem.ws.sample.cvc.handlers.ClientHandlers;
import gov.niem.ws.sample.cvc.jaxb.msg.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.WebServiceException;
import javax.xml.ws.WebServiceFeature;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.soap.MTOMFeature;
import org.w3c.dom.Element;

/**
 *
 * @author shrom
 */
public class CommercialVehicleCollisionWSCClient {

    private static final Logger logger = Logger.getLogger(CommercialVehicleCollisionWSCClient.class.getName());
    private static final boolean DEBUG = true;
    //WORKAROUND
    //see WSIT tutorial for detals : http://docs.sun.com/app/docs/doc/820-1072/6ncp48v40?a=view#ahicy
    //or https://jax-ws.dev.java.net/guide/HTTPS_HostnameVerifier.html
//    static {
//        javax.net.ssl.HttpsURLConnection.setDefaultHostnameVerifier(
//                new javax.net.ssl.HostnameVerifier() {
//                    
//                    @Override
//                    public boolean verify(String hostname,
//                            javax.net.ssl.SSLSession sslSession) {
//                        System.out.println("Veryfing hostname: " + hostname);
////                        if (hostname.equals("xwssecurityserver")) {
////                            return true;
////                        }
////                        return false;
//                        return true;
//                    }
//                });
//
//        //http://java.sun.com/javase/javaseforbusiness/docs/TLSReadme.html
////        java.lang.System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
//    }
    //REDIRECTING_WSC_REQUEST_TO_DIFFERENT_WSP
    //.NET
//    public static String wsdlUrlString = "https://ha50wspm2:8553/Model2/CommercialVehicleCollisionWsp.svc?wsdl";
//    public static String sepUrlString  = "https://ha50wspm2:8553/Model2/CommercialVehicleCollisionWsp.svc";    
    //Metro
    public static String wsdlUrlString = "https://curewspm2:8181/m2wsp/services/cvc?wsdl";
    public static String sepUrlString = "https://curewspm2:8181/m2wsp/services/cvc";
    
    public static URL wsdlUrl ;
    static{
        try {
            wsdlUrl = new URL(wsdlUrlString);
        } catch (MalformedURLException ex) {
            Logger.getLogger(CommercialVehicleCollisionWSCClient.class.getName()).log(Level.SEVERE, "Unable to create URL using " + wsdlUrlString, ex);
        }
    }

    public String getIncidentText(WebServiceContext context){
        String incidentString;
        CommercialVehicleCollisionPortType cvcPort = getCVCPort(context);
        gov.niem.ws.sample.cvc.jaxb.msg.ObjectFactory msgOF = new gov.niem.ws.sample.cvc.jaxb.msg.ObjectFactory();
        gov.niem.ws.sample.cvc.jaxb.iepd.ObjectFactory iepdOF = new gov.niem.ws.sample.cvc.jaxb.iepd.ObjectFactory();

        //Document exchange
        GetDocumentRequestType getDocumentRequestType = msgOF.createGetDocumentRequestType();
        JAXBElement<String> documentFileControlID = iepdOF.createDocumentFileControlID("58525656:Request from Metro WSC");
        getDocumentRequestType.setDocumentFileControlID(documentFileControlID);

        GetDocumentResponseType getDocumentResponseType = cvcPort.getDocument(getDocumentRequestType);
        ((Closeable) cvcPort).close();
        incidentString = getDocumentResponseType.getCommercialVehicleCollisionDocument().getValue().getIncidentText().getValue();

        if (DEBUG) {
            logger.log(Level.FINEST, "WSC: Obtained the following incident string from WSP: " + incidentString);
        }

        return incidentString;
    }
    
    public UploadPhotoResponseType uploadPhoto(WebServiceContext context, UploadPhotoRequestType parameters) {
        CommercialVehicleCollisionPortType cvcPort = getCVCPort(context);
        return cvcPort.uploadPhoto(parameters);
    }    
    
    public DownloadDataResponseType downloadData(WebServiceContext context, DownloadDataRequestType parameters) {
        CommercialVehicleCollisionPortType cvcPort = getCVCPort(context);
        return cvcPort.downloadData(parameters);
    }
    
    /*
    private static DefaultSTSIssuedTokenConfiguration getDefaultSTSIssuedTokenConfiguration() {

        //.NET
        String stsEndpoint = "https://ha50idpm2:8543/Model2Ads/Issue.svc";
        String stsWSDLLocation="https://cureidpm2:8181/m2sts/services/sts?wsdl";
        String stsServiceName = "SecurityTokenService";
        String stsPortName = "ISecurityTokenService_Port";
        String stsNamespace = "http://tempuri.org/";

        DefaultSTSIssuedTokenConfiguration stsIssuedTokenConfiguration = new DefaultSTSIssuedTokenConfiguration(
                STSIssuedTokenConfiguration.PROTOCOL_13,
                stsEndpoint,
                stsWSDLLocation,
                stsServiceName,
                stsPortName,
                stsNamespace);

        //http://metro.java.net/2.1/guide/Handling_Token_and_Key_Requirements_at_Run_Time.html        
//        stsIssuedTokenConfiguration.setKeyType("http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey");        
//        stsIssuedTokenConfiguration.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey");
//        stsIssuedTokenConfiguration.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
//        stsIssuedTokenConfiguration.setProtocol(STSIssuedTokenConfiguration.PROTOCOL_13);
//        stsIssuedTokenConfiguration.setTokenType(WSTrustConstants.SAML20_WSS_TOKEN_TYPE);
//        stsIssuedTokenConfiguration.setCanonicalizationAlgorithm(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
//        stsIssuedTokenConfiguration.setEncryptionAlgorithm(MessageConstants.AES_BLOCK_ENCRYPTION_256);          
//        stsIssuedTokenConfiguration.setKeySize(256);

        return stsIssuedTokenConfiguration;
    } 
     */
    private CommercialVehicleCollisionPortType getCVCPort(WebServiceContext context) {
        
        CommercialVehicleCollisionPortType cvcPort;
        CommercialVehicleCollisionWebService cvsWebService;
        
        if(wsdlUrl == null){
            throw new WebServiceException("WSP SEP is not configured correctly, please check WSDL URL: " + wsdlUrlString);
        }

        //Shows example of setting different location for WSDL and actuall end point address for the web service
        cvsWebService = new CommercialVehicleCollisionWebService(
                wsdlUrl,
                new QName("urn:examples.com:techniques:iepd:commercialVehicleCollision:ws:2.0",
                "CommercialVehicleCollisionWebService"));

        final Token samlToken = new GenericToken(GFIPMUtil.getSAMLAssertion(context));
        MTOMFeature mtomFeature = new MTOMFeature(true);

        //Sender-Vouches
        cvcPort = cvsWebService.getCommercialVehicleCollisionPort(new WebServiceFeature[]{mtomFeature});
        Map<String, Object> requestContext = ((BindingProvider) cvcPort).getRequestContext();
        //put initial SAML assertion obtained from STS back into request for GFIPMWSCSamlCallbackHandler
        requestContext.put("userSAMLAssertion", samlToken.getTokenValue());

        //Holder-of-Key, Bearer        
//        DefaultSTSIssuedTokenConfiguration stsIssuedTokenConfiguration = getDefaultSTSIssuedTokenConfiguration();
//        stsIssuedTokenConfiguration.setOBOToken(samlToken);
//        STSIssuedTokenFeature stsIssuedTokenFeature = new STSIssuedTokenFeature(stsIssuedTokenConfiguration);
//        cvcPort = cvsWebService.getCommercialVehicleCollisionPort(new WebServiceFeature[]{stsIssuedTokenFeature, mtomFeature});        

        // add Client-side handlers if necessary
//        ClientHandlers.SOAPHandler sh = new ClientHandlers.SOAPHandler();
//        List<Handler> handlerChain = new ArrayList<Handler>();
//        handlerChain.add(sh);
//        ((BindingProvider) cvcPort).getBinding().setHandlerChain(handlerChain);                

        //set Service Endpoint
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, sepUrlString);

        if (DEBUG) {
            String urlUsed = (String) requestContext.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY);
            logger.log(Level.FINEST, "WSC: Using Service End Point URL: " + urlUsed);
        }

        //add schema validation through Service feature / include ErrorHandler from the server side to the library if necessary
//        WebServiceFeature feature = new SchemaValidationFeature(gov.niem.ws.sample.jaxwsspr.server.handler.ErrorHandler.class);
//        cvcPort = new CommercialVehicleCollisionWebService().getCommercialVehicleCollisionPort(feature);

        return cvcPort;
    }
}
