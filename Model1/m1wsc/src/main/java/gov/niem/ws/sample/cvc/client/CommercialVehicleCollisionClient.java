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

import com.sun.xml.ws.developer.StreamingDataHandler;
import gov.niem.ws.sample.cvc.jaxb.msg.*;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionPortType;
import gov.niem.ws.sample.cvc.jaxws.CommercialVehicleCollisionWebService;
import java.awt.Image;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Map;
import javax.activation.DataHandler;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.soap.MTOMFeature;

public class CommercialVehicleCollisionClient {

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
//        //java.lang.System.setProperty("sun.security.ssl.allowUnsafeRenegotiation", "true");
//    }
    //.NET Alias:  ha50wsp
//    private static String sepUrl = "https://ha50wspm1:8443/Model1/CommercialVehicleCollisionPortType.svc"
    //Metro Alias:  curewsp
    private static String wsdlUrl = "https://curewspm1:8181/m1wsp/services/cvc?wsdl";
    private static String sepUrl = "https://curewspm1:8181/m1wsp/services/cvc";

    //NOTE: modify main/resources/META-INF/CommercialVehicleCollisionWebserviceIntf.xml to use proper Trust certificates/stores for aliases.
    public static void execute() throws MalformedURLException, Exception {

        CommercialVehicleCollisionPortType cvcPort;
        CommercialVehicleCollisionWebService cvsWebService;

        cvsWebService = new CommercialVehicleCollisionWebService(
                new URL(wsdlUrl),
                new QName("urn:examples.com:techniques:iepd:commercialVehicleCollision:ws:2.0",
                "CommercialVehicleCollisionWebService"));
        cvcPort = cvsWebService.getCommercialVehicleCollisionPort(new MTOMFeature(true));
        Map<String, Object> requestContext = ((BindingProvider) cvcPort).getRequestContext();
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, sepUrl);
        System.out.println("Using following SEP: " + requestContext.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY));
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
        System.out.println("Incident text " + getDocumentResponseType.getCommercialVehicleCollisionDocument().getValue().getIncidentText().getValue());
        System.out.println("Done requesting the document. \n");


        //binary upload (image)
        UploadPhotoRequestType uploadPhotoRequestType = msgOF.createUploadPhotoRequestType();
        JAXBElement<Image> photo = iepdOF.createPhoto(getImage("java.jpg"));
        uploadPhotoRequestType.setPhoto(photo);
        UploadPhotoResponseType uploadPhotoResponseType = cvcPort.uploadPhoto(uploadPhotoRequestType);
        System.out.println("Done uploading image. \n" + uploadPhotoResponseType.getPhotoControlID().getValue());

        //donload 1Mb
        int size = 1000000;//1MB
        DownloadDataRequestType downloadDataRequestType = msgOF.createDownloadDataRequestType();
        JAXBElement<Integer> sizeJAXBElement = iepdOF.createSize(new Integer(size));
        downloadDataRequestType.setSize(sizeJAXBElement);
        DownloadDataResponseType downloadDataResponseType = cvcPort.downloadData(downloadDataRequestType);
        DataHandler dh = downloadDataResponseType.getData().getValue();
        validateDataHandler(size, dh);
        System.out.println("Done downloading data. \n");

    }

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
                    System.out.println("FAIL: DataHandler data is different");
                }
            }
            total += len;
            if (total % (8192 * 250) == 0) {
                System.out.println("Total so far=" + total);
            }
        }
        System.out.println("Total Received=" + total);
        if (total != expTotal) {
            System.out.println("FAIL: DataHandler data size is different. Expected=" + expTotal + " Got=" + total);
        }
        in.close();
//        sdh.close();
    }

    private static Image getImage(String imageName) throws Exception {
        String location = getDataDir() + imageName;
        System.out.println("Loading image: " + location);
        return javax.imageio.ImageIO.read(new File(location));
    }

    private static String getDataDir() {
        String userDir = System.getProperty("user.dir");
        String sepChar = System.getProperty("file.separator");
        return userDir + sepChar + "src/test/";
    }

    public static void main(String[] args) throws Exception {

        //Logs
        if (false) {
            System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", "true");
            //http://metro.java.net/guide/Logging.html
            System.setProperty("com.sun.xml.ws.assembler.jaxws.TerminalTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.HandlerTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.ValidationTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.MustUnderstandTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.MonitoringTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.AddressingTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.tx.runtime.TxTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.rx.rm.runtime.RmTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.rx.mc.runtime.McTubeFactory", "true");
            System.setProperty("com.sun.xml.wss.provider.wsit.SecurityTubeFactory", "true");//enable this to check messages
            System.setProperty("com.sun.xml.ws.dump.ActionDumpTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.rx.testing.PacketFilteringTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.dump.MessageDumpingTubeFactory", "true");
            System.setProperty("com.sun.xml.ws.assembler.jaxws.TransportTubeFactory", "true");
        }

        String currentDirAbsolutePath = System.getProperty("user.dir");
//        http://www.coderanch.com/t/372437/java/java/javax-net-ssl-keyStore-system        
        System.setProperty("javax.net.ssl.keyStore", currentDirAbsolutePath + "/src/main/resources/META-INF/curewscm1-keystore.jks");
        System.setProperty("javax.net.ssl.keyStorePassword", "changeit");
        System.setProperty("javax.net.ssl.trustStore", currentDirAbsolutePath + "/src/main/resources/META-INF/curewscm1-cacerts.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");

        CommercialVehicleCollisionClient.execute();

    }
}
