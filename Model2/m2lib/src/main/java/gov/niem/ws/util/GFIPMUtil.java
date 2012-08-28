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
package gov.niem.ws.util;

import com.sun.xml.wss.SubjectAccessor;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.XWSSecurityRuntimeException;
import com.sun.xml.wss.saml.util.SAMLUtil;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import javax.security.auth.Subject;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.WebServiceContext;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Auxiliary methods.
 */
public class GFIPMUtil {
    
    public static final String SAML_SENDER_VOUCHES_2_0 = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches";

    public static void configureTrace(Boolean enable) {

//            http://blogs.oracle.com/arungupta/entry/totd_1_soap_messaging_logging
//                -Dcom.sun.xml.ws.transport.http.HttpAdapter.dump=true:
//                -Dcom.sun.xml.ws.transport.http.client.HttpTransportPipe.dump=true        

        //Server
        System.setProperty("com.sun.xml.ws.transport.http.HttpAdapter.dump", enable.toString());
        //Client
        System.setProperty("com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump", enable.toString());
        //http://metro.java.net/guide/Logging.html
        System.setProperty("com.sun.xml.ws.assembler.jaxws.TerminalTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.HandlerTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.ValidationTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.MustUnderstandTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.MonitoringTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.AddressingTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.tx.runtime.TxTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.rx.rm.runtime.RmTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.rx.mc.runtime.McTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.wss.provider.wsit.SecurityTubeFactory", enable.toString());//enable this to check messages
        System.setProperty("com.sun.xml.ws.dump.ActionDumpTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.rx.testing.PacketFilteringTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.dump.MessageDumpingTubeFactory", enable.toString());
        System.setProperty("com.sun.xml.ws.assembler.jaxws.TransportTubeFactory", enable.toString());
    }

    /*
     * Helper function @param Node - DOM node to be converted to the string.
     */
    public static String putOutAsString(Node node) {
        String resultStr = "Unable to create a string for the node";
        if(node == null)
            return resultStr + ": it's null";
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            StringWriter writer = new StringWriter();
            Result result = new StreamResult(writer);
            transformer.transform(new DOMSource(node), result);
            resultStr = writer.toString();
        } catch (TransformerConfigurationException ex) {
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.SEVERE, "putOutAsString: unable to convert to a string", ex);
        } catch (TransformerException ex) {
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.SEVERE, "putOutAsString: unable to convert to a string", ex);
        }
        return resultStr;
    }
    
    public static String getWSDL(String wsdlUrl) {

        HttpURLConnection conn;
        URL url;
        StringBuilder wsdlStringBuffer = new StringBuilder();
        
        try {
            url = new URL(wsdlUrl);
            //See samples at http://stackoverflow.com/questions/1511674/how-do-a-send-an-https-request-through-a-proxy-in-java
            if (wsdlUrl.startsWith("https")) {
                SSLSocketFactory sslsocketfactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                HttpsURLConnection.setDefaultSSLSocketFactory(sslsocketfactory);
            }
            conn = (HttpURLConnection) url.openConnection();
            InputStream inputstream = conn.getInputStream();
            InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
            BufferedReader bufferedreader = new BufferedReader(inputstreamreader);
            String string;
            while ((string = bufferedreader.readLine()) != null) {
                wsdlStringBuffer.append(string);
            }   
        } catch (IOException ioEx) {
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.WARNING, "Unable to get WSDL from URL: " + wsdlUrl, ioEx);
        }       
        return wsdlStringBuffer.toString();
        
    }    
    
    public static Element getSAMLAssertion(WebServiceContext context) {
        Element samlAssertion = null;
        try {
            Subject subj = SubjectAccessor.getRequesterSubject(context);
            Set<Object> set = subj.getPublicCredentials();
            for (Object obj : set) {
                if (obj instanceof XMLStreamReader) {
                    XMLStreamReader reader = (XMLStreamReader) obj;
                    //To create a DOM Element representing the Assertion :
                    samlAssertion = SAMLUtil.createSAMLAssertion(reader);
                    break;
                } else if (obj instanceof Element) {
                    samlAssertion = (Element) obj;
                    break;
                } else {
                    Logger.getLogger(GFIPMUtil.class.getName()).log(Level.SEVERE, "Unable to identify samlAssertion object in WebServiceContext :" + obj.getClass().getCanonicalName());
                }
            }
        } catch (XMLStreamException ex) {
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.SEVERE, "XMLStreamException: unable to get SAML assertion", ex);
            throw new XWSSecurityRuntimeException(ex);
        } catch (XWSSecurityException ex) {
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.SEVERE, "XWSSecurityRuntimeException: security exception", ex);
            throw new XWSSecurityRuntimeException(ex);
        }
        return samlAssertion;
    }
    
    public static void printMap(String header,Map map) {
        if(map == null){
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\n" + header + " is null");
            return;
        }        
        Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\n" + header + " Map Size = " + map.size());
        for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
            Map.Entry e = (Map.Entry) it.next();
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\tKey/Value : " + e.getKey() + "/" + e.getValue());
        }
    }
    
    public static void printSet(String header,Set set) {
        if(set == null){
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\n" + header + " is null");
            return;
        }
        Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\n" + header + " Set Size = " + set.size());
        for (Iterator it = set.iterator(); it.hasNext();) {
            Object e = it.next();
            Logger.getLogger(GFIPMUtil.class.getName()).log(Level.INFO,"\t Object " + e.getClass().getCanonicalName() + " content: " + e.toString());
        }
    }        
}
