/*
 * Copyright 2012  Georgia Tech Research Institute
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
 * @author http://www.jroller.com/gmazza/entry/jaxws_handler_tutorial
 * http://jax-ws.java.net/articles/handlers_introduction/SOAPLoggingHandler.java
 *
 */
import java.io.ByteArrayOutputStream;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.namespace.QName;
import javax.xml.soap.*;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

public class SOAPHandler implements javax.xml.ws.handler.soap.SOAPHandler<SOAPMessageContext> {

    private static final Logger logger = Logger.getLogger(SOAPHandler.class.getName());
    private static final boolean DEBUG = true;

    @Override
    public Set<QName> getHeaders() {
        if (DEBUG) {
            logger.log(Level.INFO, "SOAP Handler : getHeaders");
        }
        return null;
    }

    @Override
    public void close(MessageContext mc) {
        if (DEBUG) {
            logger.log(Level.INFO, "SOAP Handler : close message context");
        }
    }

    @Override
    public boolean handleFault(SOAPMessageContext mc) {
        return true;
    }

    @Override
    public boolean handleMessage(SOAPMessageContext mc) {
        HandlerUtils.printMessageContext(" Service SOAPHandler ", mc);

        //Inquire incoming or outgoing message.
        Boolean outbound = (Boolean) mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        String direction = (outbound ? "Outbound" : "Inbound");
        if (DEBUG) {
            logger.log(Level.INFO, "Processing an " + direction + " message;");
        }

//        SOAPMessage msg = ((SOAPMessageContext) mc).getMessage();
        SOAPMessage msg = mc.getMessage();

        try {
            if (outbound) {
                // get SOAP-Part
                SOAPPart sp = msg.getSOAPPart();
                // edit Envelope
                SOAPEnvelope env = sp.getEnvelope();
                // add namespaces
//                env.addNamespaceDeclaration("xsd", "http://www.w3.org/2001/XMLSchema");
//                env.addNamespaceDeclaration("xsi", "http://www.w3.org/2001/XMLSchema-instance");
//                env.addNamespaceDeclaration("soap", "http://schemas.xmlsoap.org/soap/envelope");
                // add the Header with additional Elements sample
//                SOAPElement soapElement2 = env.getHeader().addHeaderElement(new QName("http://www.testuri.org", "HeaderElementName")); 
//                soapElement2.addTextNode("header element text");                
                // get the SOAP-Body just in case you'd like to do anything with it...
                SOAPBody body = env.getBody();
//                NodeList nodeList = body.getElementsByTagNameNS("http://docs.oasis-open.org/ws-sx/ws-trust/200512", "OnBehalfOf");
                dumpSOAPMessage(msg, direction);
            } else {
                dumpSOAPMessage(msg, direction);
            }

        } catch (Exception e) {
            //All other unhandled problems.
            if (DEBUG) {
                logger.log(Level.WARNING, "Unknow exception in SOAPHandler: ", e);
            }
        }

//      if (Boolean.FALSE.equals(mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY))) {
//         SOAPMessage sm = mc.getMessage();
//         try {
//            SOAPHeader sh = sm.getSOAPHeader();
//            // Note in real use validity checking should be done
//            // (really two terms present? namespaces? etc.)
//            NodeList termNodes = sh.getElementsByTagName("term");
//            mc.put("termOne", termNodes.item(0).getTextContent());
//            mc.put("termTwo", termNodes.item(1).getTextContent());
//            // default scope is HANDLER (i.e., not readable by SEI
//            // implementation)
//            mc.setScope("termTwo", MessageContext.Scope.APPLICATION);
//         } catch (SOAPException e) {
//            throw new ProtocolException(e);
//         }
//      }
        return true;
    }

//     private void generateSOAPFaultMessage(SOAPMessage msg, String reason) {
//       try {
//          SOAPBody soapBody = msg.getSOAPPart().getEnvelope().getBody();
//          SOAPFault soapFault = soapBody.addFault();
//          soapFault.setFaultString(reason);
//          throw new SOAPFaultException(soapFault); 
//       }
//       catch(SOAPException e) { }
//    }
    /**
     * Dump SOAP Message
     *
     * @param msg
     */
    public static void dumpSOAPMessage(SOAPMessage msg, String messageDirection) {
        if (msg == null) {
            if (DEBUG) {
                logger.log(Level.INFO, "SOAP Message is null");
            }
            return;
        }
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            msg.writeTo(baos);
            if (DEBUG) {
                logger.log(Level.INFO,
                        "\n------- " + messageDirection + " SOAP message -------\n"
                        + baos.toString(getMessageEncoding(msg))
                        + "\n------ end " + messageDirection + " SOAP message--------\n");
            }
//            String body = msg.getSOAPBody().getTextContent();
        } catch (Exception e) {
            logger.log(Level.WARNING, "Unable to dump SOAP Message", e);
        }

    }

    /**
     * Returns the message encoding
     *
     * @param msg
     * @return
     * @throws javax.xml.soap.SOAPException
     */
    public static String getMessageEncoding(SOAPMessage msg) throws SOAPException {
        String encoding = "utf-8";
        if (msg.getProperty(SOAPMessage.CHARACTER_SET_ENCODING) != null) {
            encoding = msg.getProperty(SOAPMessage.CHARACTER_SET_ENCODING).toString();
        }
        return encoding;
    }
}
