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

package gov.niem.ws.sample.cvc.handlers;

/**
 *
 * @author http://www.jroller.com/gmazza/entry/jaxws_handler_tutorial
 * http://jax-ws.java.net/articles/MessageContext.html
 *
 */
import com.sun.xml.wss.impl.XMLUtil;
import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.io.StringWriter;
import java.net.URI;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.Element;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.handler.MessageContext;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

public class HandlerUtils {

    private static final Logger logger = Logger.getLogger(HandlerUtils.class.getName());

    public static void printMessageContext(String whereFrom, Map<String, Object> propertyMap) {
        logger.log(Level.INFO, "*************** Full MessageContext from " + whereFrom);
        outputMap("propertyMap",propertyMap);
        logger.log(Level.INFO, "***************");
        printMessageContext(propertyMap);
        logger.log(Level.INFO, "*************** End for MessageContext *******************");
    }

    public static void printMessageContext(Map<String, Object> propertyMap) {

        try {
            outputBoolean("Message Outbound Property", (Boolean) propertyMap.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY));
//             outputMap("HTTP Request Headers", (Map<String,List<String>>)propertyMap.get(MessageContext.HTTP_REQUEST_HEADERS));
            outputString("HTTP Request Method", (String) propertyMap.get(MessageContext.HTTP_REQUEST_METHOD));
            outputString("Path Info", (String) propertyMap.get(MessageContext.PATH_INFO));
            outputString("Query String", (String) propertyMap.get(MessageContext.QUERY_STRING));
            // outputMap("HTTP Response Headers", (Map<String,List<String>>) propertyMap.get(MessageContext.HTTP_RESPONSE_HEADERS));
            outputInteger("HTTP Response Code", (Integer) propertyMap.get(MessageContext.HTTP_RESPONSE_CODE));
            outputArrayList("Reference Parameters", (ArrayList<Element>) propertyMap.get(MessageContext.REFERENCE_PARAMETERS));
//            outputURI("WSDL Description", ((URI) propertyMap.get(MessageContext.WSDL_DESCRIPTION)));
//            outputWSDL("WSDL Description", propertyMap.get(MessageContext.WSDL_DESCRIPTION));
            outputQName("WSDL Interface", (QName) propertyMap.get(MessageContext.WSDL_INTERFACE));
            outputQName("WSDL Operation", (QName) propertyMap.get(MessageContext.WSDL_OPERATION));
            outputQName("WSDL Port", (QName) propertyMap.get(MessageContext.WSDL_PORT));
            outputQName("WSDL Service", (QName) propertyMap.get(MessageContext.WSDL_SERVICE));
            outputString("User SAML Assertion", XMLUtil.print((org.w3c.dom.Element) propertyMap.get("userSAMLAssertion")));

        } catch (Exception e) {
            logger.log(Level.SEVERE, null, e);
        }
        // outputString("Servlet Context", ( )
        //    propertyMap.get(MessageContext.SERVLET_CONTEXT));
        // outputString("Servlet Request", ( )
        //    propertyMap.get(MessageContext.SERVLET_REQUEST));
        // outputString("Servlet Response", ( )
        //    propertyMap.get(MessageContext.SERVLET_RESPONSE));
    }
    
    private static void outputMap(String title, Map<String, Object> propertyMap){
        logger.log(Level.INFO, title);
        for (Iterator it = propertyMap.entrySet().iterator(); it.hasNext();) {
            Map.Entry e = (Map.Entry) it.next();
            logger.log(Level.INFO, "\n\tKey : " + e.getKey() + " ; Value : " + e.getValue() + " ; Class : " + e.getClass());
        }        
    }
    
    private static void outputString(String key, String value) {
        logger.log(Level.INFO, key + " = " + value);
    }

    private static void outputBoolean(String key, Boolean value) {
        logger.log(Level.INFO, key + " = " + ((value == null) ? "null" : value.toString()));
    }

    private static void outputInteger(String key, Integer value) {
        logger.log(Level.INFO, key + " = " + ((value == null) ? "null" : value.toString()));
    }

    private static void outputURI(String key, URI value) {
        logger.log(Level.INFO, key + " = " + ((value == null) ? "null" : value.toString()));
    }

    private static void outputQName(String key, QName value) {
        logger.log(Level.INFO, key + " = " + ((value == null) ? "null" : value.toString()));
    }

    private static void outputArrayList(String key, ArrayList<Element> list) {
        logger.log(Level.INFO, key + ":" + ((list == null) ? "(null)" : ""));
        if (list != null) {
            for (Element e : list) {
                logger.log(Level.INFO, "   " + e.toString());
            }
        }
    }

    private static void outputWSDL(String key, Object wsdlInput) {
        String wsdlString = "Unable to get the WSDL";
        try {
            //We need a Document
            DocumentBuilderFactory dbfac = DocumentBuilderFactory.newInstance();
            dbfac.setNamespaceAware(true);
            DocumentBuilder docBuilder = dbfac.newDocumentBuilder();
            Document doc = null;
            if (wsdlInput instanceof InputSource) {
                doc = docBuilder.parse((InputSource) wsdlInput);
            } else if (wsdlInput instanceof URI) {
                doc = docBuilder.parse((InputStream) ((URI) wsdlInput).toURL().openStream());
            }
            //set up a transformer
            TransformerFactory transfac = TransformerFactory.newInstance();
            Transformer trans = transfac.newTransformer();
            trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            trans.setOutputProperty(OutputKeys.INDENT, "yes");
            //create string from xml tree
            StringWriter sw = new StringWriter();
            StreamResult result = new StreamResult(sw);
            DOMSource source = new DOMSource(doc);
            trans.transform(source, result);
            wsdlString = sw.toString();
        } catch (TransformerConfigurationException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (TransformerException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (SAXException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            logger.log(Level.SEVERE, null, ex);
        } catch (ParserConfigurationException ex) {
            logger.log(Level.SEVERE, null, ex);
        } finally {
            InputStream is = ((InputSource) wsdlInput).getByteStream();
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
            Reader r = ((InputSource) wsdlInput).getCharacterStream();
            if (r != null) {
                try {
                    r.close();
                } catch (IOException ex) {
                    logger.log(Level.SEVERE, null, ex);
                }
            }
        }
        logger.log(Level.INFO, key + " :: \n" + ((wsdlString == null) ? "null" : wsdlString));
    }
}
