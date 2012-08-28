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
import com.sun.xml.ws.developer.StreamingDataHandler;
import com.sun.xml.ws.security.trust.STSIssuedTokenFeature;
import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;
import gov.niem.ws.sample.cvc.jaxb.msg.*;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionPortType;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionWebService;
import gov.niem.ws.util.GFIPMUtil;
import java.awt.Image;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.activation.DataHandler;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.WebServiceFeature;
import javax.xml.ws.soap.MTOMFeature;

/**
 *
 * @author shrom
 */
public class CommercialVehicleCollisionClient {

    private static final Logger logger = Logger.getLogger(CommercialVehicleCollisionClient.class.getName());

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
//                        logger.log(Level.INFO,"Veryfing hostname: " + hostname);
////                        if (hostname.equals("xwssecurityserver")) {
////                            return true;
////                        }
////                        return false;
//                        return true;
//                    }
//                });
//        //http://java.sun.com/javase/javaseforbusiness/docs/TLSReadme.html
//        //java.lang.System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
//    }
    
    //.NET WSC Cert Alias:            ha50wspm2
//    public static String wsdlUrl = "http://ha50wscm2:8089/Model2/Service.svc?wsdl";
//    public static String sepUrl  = "https://ha50wscm2:8643/Model2/Service.svc";    
    //Metro WSC Cert Alias:            curewscm2
//    public static String wsdlUrl = "http://curewscm2:8080/m2wsc/services/cvc?wsdl";
//    public static String sepUrl = "http://curewscm2:8080/m2wsc/services/cvc";
    public static String wsdlUrl = "https://curewscm2:8181/m2wsc/services/cvc?wsdl";
    public static String sepUrl = "https://curewscm2:8181/m2wsc/services/cvc";

//    public static String wsdlUrl = "http://curewspm2:8080/m2wsp/services/cvc?wsdl";
//    public static String sepUrl = "http://curewspm2:8080/m2wsp/services/cvc";
//    public static String wsdlUrl = "https://curewspm2:8181/m2wsp/services/cvc?wsdl";
//    public static String sepUrl = "https://curewspm2:8181/m2wsp/services/cvc";
    private static DefaultSTSIssuedTokenConfiguration getDefaultSTSIssuedTokenConfiguration() {

//        String stsEndpoint = "https://cureidpm2:8181/m2sts/services/sts";
//        String stsMexAddress = "https://cureidpm2:8181/m2sts/services/sts/mex";

//        DefaultSTSIssuedTokenConfiguration stsIssuedTokenConfiguration = new DefaultSTSIssuedTokenConfiguration(
//                STSIssuedTokenConfiguration.PROTOCOL_13, 
//                stsEndpoint, 
//                stsMexAddress);  
        //Metro Username Token
        String stsEndpoint = "https://cureidpm2:8181/m2sts/services/idp";
        String stsWSDLLocation = "https://cureidpm2:8181/m2sts/services/idp?wsdl";
        String stsServiceName = "IdentityProviderService";
        String stsPortName = "IIdentityProviderService_Port";
        String stsNamespace = "http://tempuri.org/";

        //Metro Certificate 
        //To be able to use Client (alice) certificate on STS either uncomment GFIPMCertificateValidator from sts.wsdl 
        // or remove Trust Fabric validation check ( if((entityId == null) || (!tf.isWebServiceConsumer(entityId))) )
        // in GFIPMCertificateValidator.java on STS.
//        String stsEndpoint = "http://cureidpm2:8080/m2sts/services/sts";
//        String stsWSDLLocation = "http://cureidpm2:8080/m2sts/services/sts?wsdl";
//        String stsServiceName = "SecurityTokenService";
//        String stsPortName = "ISecurityTokenService_Port";
//        String stsNamespace = "http://tempuri.org/";

        //.NET
//        String stsEndpoint = "https://ha50idpm2:8544/Model2UserSts/Issue.svc";
//        String stsWSDLLocation = "https://ha50idpm2:8544/Model2UserSts/Issue.svc?wsdl";
//        String stsServiceName = "SecurityTokenService";
//        String stsPortName = "CustomBinding_IWSTrust13Sync";
//        String stsNamespace = "http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice";

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

    //NOTE: don't forget to modify main/resources/META-INF/CommercialVehicleCollisionWebserviceIntf.xml to use proper Trust certificates/stores.
    public static void execute() throws MalformedURLException, Exception {

        CommercialVehicleCollisionPortType cvcPort;
        CommercialVehicleCollisionWebService cvsWebService;

//        References: http://metro.java.net/2.1/guide/Handling_Token_and_Key_Requirements_at_Run_Time.html        

        DefaultSTSIssuedTokenConfiguration stsIssuedTokenConfiguration = getDefaultSTSIssuedTokenConfiguration();
        STSIssuedTokenFeature stsIssuedTokenFeature = new STSIssuedTokenFeature(stsIssuedTokenConfiguration);
        MTOMFeature mtomFeature = new MTOMFeature(true);
        cvsWebService = new CommercialVehicleCollisionWebService(
                new URL(wsdlUrl),
                new QName("urn:examples.com:techniques:iepd:commercialVehicleCollision:ws:2.0",
                "CommercialVehicleCollisionWebService"));

        //cvcPort = cvsWebService.getCommercialVehicleCollisionPort();
        //cvcPort = cvsWebService.getCommercialVehicleCollisionPort(mtomFeature);
        cvcPort = cvsWebService.getCommercialVehicleCollisionPort(new WebServiceFeature[]{stsIssuedTokenFeature, mtomFeature});

        // add Client-side handlers if necessary
//        ClientHandlers.LogicalHandler lh = new ClientHandlers.LogicalHandler();
//        ClientHandlers.SOAPHandler sh = new ClientHandlers.SOAPHandler();
//        List<Handler> handlerChain = new ArrayList<Handler>();
//        handlerChain.add(lh);
//        handlerChain.add(sh);
//        ((BindingProvider) cvcPort).getBinding().setHandlerChain(handlerChain);        

        Map<String, Object> requestContext = ((BindingProvider) cvcPort).getRequestContext();

        //Username / pwd could be configured through here...
//        requestContext.put(BindingProvider.USERNAME_PROPERTY, "bob");
//        requestContext.put(BindingProvider.PASSWORD_PROPERTY, "bob"); 

        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, sepUrl);
//        requestContext.put(RequestContextConstants.SERVICE_CERT_SUBJECT_KEY,"com.example.common.security.certificate.service");

        logger.log(Level.INFO,"Using following SEP: " + requestContext.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY));

        //It is possible to add schema validation through Service feature / include ErrorHandler from the server side to the library
//        WebServiceFeature feature = new SchemaValidationFeature(gov.niem.ws.sample.jaxwsspr.server.handler.ErrorHandler.class);
//        cvcPort = new CommercialVehicleCollisionWebService().getCommercialVehicleCollisionPort(feature);

        gov.niem.ws.sample.cvc.jaxb.msg.ObjectFactory msgOF = new gov.niem.ws.sample.cvc.jaxb.msg.ObjectFactory();
        gov.niem.ws.sample.cvc.jaxb.iepd.ObjectFactory iepdOF = new gov.niem.ws.sample.cvc.jaxb.iepd.ObjectFactory();

        //Document exchange
        GetDocumentRequestType getDocumentRequestType = msgOF.createGetDocumentRequestType();
        JAXBElement<String> documentFileControlID = iepdOF.createDocumentFileControlID("abcd");
        getDocumentRequestType.setDocumentFileControlID(documentFileControlID);
        GetDocumentResponseType getDocumentResponseType = cvcPort.getDocument(getDocumentRequestType);
        logger.log(Level.INFO,"Done requesting the document: Incident text = " + getDocumentResponseType.getCommercialVehicleCollisionDocument().getValue().getIncidentText().getValue());


        //binary upload (image)
        UploadPhotoRequestType uploadPhotoRequestType = msgOF.createUploadPhotoRequestType();
        JAXBElement<Image> photo = iepdOF.createPhoto(getImage("java.jpg"));
        uploadPhotoRequestType.setPhoto(photo);
        UploadPhotoResponseType uploadPhotoResponseType = cvcPort.uploadPhoto(uploadPhotoRequestType);
        logger.log(Level.INFO,"Done uploading image: Photo control ID =" + uploadPhotoResponseType.getPhotoControlID().getValue());

        //donload 1Mb
        int size = 1000000;//1MB
        DownloadDataRequestType downloadDataRequestType = msgOF.createDownloadDataRequestType();
        JAXBElement<Integer> sizeJAXBElement = iepdOF.createSize(new Integer(size));
        downloadDataRequestType.setSize(sizeJAXBElement);
        DownloadDataResponseType downloadDataResponseType = cvcPort.downloadData(downloadDataRequestType);
        DataHandler dh = downloadDataResponseType.getData().getValue();
        validateDataHandler(size, dh);
        logger.log(Level.INFO,"Done downloading data.");

        ((Closeable) cvcPort).close();
    }

    /*
     * DefaultSTSIssuedTokenConfiguration stsConfig;
     *
     * //
     * http://social.msdn.microsoft.com/Forums/en/Geneva/thread/adb0eca4-d466-4b24-a756-1a12fc3b6e52
     * // http://java.net/jira/browse/METRO-16
     * stsConfig.getOtherOptions().put(BindingProvider.USERNAME_PROPERTY,
     * "domain1.local\\dev01");
     * stsConfig.getOtherOptions().put(BindingProvider.PASSWORD_PROPERTY,
     * "pass@word1");
     * stsConfig.getOtherOptions().put(com.sun.xml.wss.XWSSConstants.USERNAME_PROPERTY,
     * "domain1.local\\dev01");
     * stsConfig.getOtherOptions().put(com.sun.xml.wss.XWSSConstants.PASSWORD_PROPERTY,
     * "pass@word1");
     *
     * Token actAsToken = new GenericToken(samlAssertion);
     * stsConfig.getOtherOptions().put(STSIssuedTokenConfiguration.ACT_AS,
     * actAsToken); STSIssuedTokenFeature feature = new
     * STSIssuedTokenFeature(stsConfig);
     *
     * stsConfig.getOtherOptions().put(IssuedTokenContext.CONFIRMATION_METHOD,
     * SAML_SENDER_VOUCHES_2_0);
     * ctx.getOtherProperties().put(IssuedTokenContext.CONFIRMATION_METHOD,
     * SAML_SENDER_VOUCHES_2_0);
     */
    private static void validateDataHandler(int expTotal, DataHandler dh)
            throws IOException {

        // readOnce() doesn't store attachment on the disk in some cases
        // for e.g when only one attachment is in the message
//        StreamingDataHandler sdh = (StreamingDataHandler)dh;
//        InputStream in = sdh.readOnce();
        InputStream in;
        if (dh instanceof StreamingDataHandler) {
            in = ((StreamingDataHandler) dh).readOnce();
        } else {
            in = dh.getInputStream();
        }

        byte[] buf = new byte[8192];
        int total = 0;
        int len;
        while ((len = in.read(buf, 0, buf.length)) != -1) {
            for (int i = 0; i < len; i++) {
                if ((byte) ('A' + (total + i) % 26) != buf[i]) {
                    logger.log(Level.SEVERE,"FAIL: DataHandler data is different");
                }
            }
            total += len;
            if (total % (8192 * 250) == 0) {
                logger.log(Level.INFO,"Total so far=" + total);
            }
        }
        logger.log(Level.INFO,"Total Received=" + total);
        if (total != expTotal) {
            logger.log(Level.SEVERE,"FAIL: DataHandler data size is different. Expected=" + expTotal + " Got=" + total);
        }
        in.close();
//        sdh.close();
    }

    private static Image getImage(String imageName) throws Exception {
        String location = getDataDir() + imageName;
        logger.log(Level.INFO,"Loading image: " + location);
        return javax.imageio.ImageIO.read(new File(location));
    }

    private static String getDataDir() {
        String userDir = System.getProperty("user.dir");
        String sepChar = System.getProperty("file.separator");
        return userDir + sepChar + "src/test/";
    }

    public static void main(String[] args) throws Exception {

        //Logging
        GFIPMUtil.configureTrace(false);

        String currentDirAbsolutePath = System.getProperty("user.dir");
//        http://www.coderanch.com/t/372437/java/java/javax-net-ssl-keyStore-system        
        System.setProperty("javax.net.ssl.keyStore", currentDirAbsolutePath + "/src/main/resources/META-INF/cure-client-keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", currentDirAbsolutePath + "/src/main/resources/META-INF/cure-client-cacerts.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        CommercialVehicleCollisionClient.execute();
    }
}
