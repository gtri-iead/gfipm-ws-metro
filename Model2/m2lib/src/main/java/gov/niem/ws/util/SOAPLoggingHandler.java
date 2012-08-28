
package gov.niem.ws.util;

/**
 *
 * @author http://metro.1045641.n5.nabble.com/Retrieve-SOAP-Body-td3047194.html
 */
import java.io.ByteArrayInputStream; 
import java.io.ByteArrayOutputStream; 
import java.io.IOException; 
import java.util.Set; 

import javax.xml.namespace.QName; 
import javax.xml.soap.SOAPMessage; 
import javax.xml.transform.OutputKeys; 
import javax.xml.transform.Result; 
import javax.xml.transform.Source; 
import javax.xml.transform.Transformer; 
import javax.xml.transform.TransformerConfigurationException; 
import javax.xml.transform.TransformerFactory; 
import javax.xml.transform.stream.StreamResult; 
import javax.xml.transform.stream.StreamSource; 
import javax.xml.ws.handler.MessageContext; 
import javax.xml.ws.handler.soap.SOAPHandler; 
import javax.xml.ws.handler.soap.SOAPMessageContext; 
import java.util.logging.Level;
import java.util.logging.Logger;

public class SOAPLoggingHandler implements SOAPHandler<SOAPMessageContext> { 

        private static final Logger log = Logger.getLogger(SOAPLoggingHandler.class.getName());

        
        private TransformerFactory transFactory = TransformerFactory.newInstance();
         private Transformer transformer; 

        public SOAPLoggingHandler() { 
                super(); 
                try { 
                        transformer = transFactory.newTransformer(); 
                        transformer.setOutputProperty( 
                                        "{http://xml.apache.org/xslt}indent-amount", "3");
                         // The following property is used to create the element in different
                         // lines of the xml 
                        transformer.setOutputProperty(OutputKeys.INDENT, "Yes");
                         transformer 
                                        .setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "No");
                 } catch (TransformerConfigurationException e) { 
                        log.log(Level.WARNING, "Unable to log the message", e);
                } 

        } 

        @Override 
        public Set<QName> getHeaders() { 
                return null; 
        } 

        @Override 
        public void close(MessageContext context) { 
                log.log(Level.INFO, "invoke");
        } 

        @Override 
        public boolean handleFault(SOAPMessageContext context) { 
                log(context); 
                return true; 
        } 

        @Override 
        public boolean handleMessage(SOAPMessageContext context) { 
                log(context); 
                return true; 
        } 

        /* 
         * Check the MESSAGE_OUTBOUND_PROPERTY in the context to see if this is an
          * outgoing or incoming message. Write a brief message to the print stream
          * and output the message. The writeTo() method can throw SOAPException or
          * IOException 
         */ 
        private void log(SOAPMessageContext smc) { 
                Boolean outboundProperty = (Boolean) smc 
                                .get(MessageContext.MESSAGE_OUTBOUND_PROPERTY); 

                if (outboundProperty.booleanValue()) { 
                        log.log(Level.INFO,"\nOutbound message:"); 
                } else { 
                        log.log(Level.INFO,"\nInbound message:"); 
                } 

                SOAPMessage message = smc.getMessage(); 
                ByteArrayOutputStream outPrint = null; 
                ByteArrayInputStream in = null; 
                ByteArrayOutputStream out = new ByteArrayOutputStream(2048); 
                try { 
                        
                        message.writeTo(out); 
                        if (transformer != null) { 
                                in = new ByteArrayInputStream(out.toByteArray());
                                 outPrint = new ByteArrayOutputStream(2048); 
                                
                                Source input = new StreamSource(in); // passing the instance of
                                 // Document 
                                Result output = new StreamResult(outPrint); // passing the
                                                                                                                         // instance
                                 // of 
                                // OutputStream 
                                transformer.transform(input, output); 
                                log.log(Level.INFO,outPrint.toString()); 
                        } else { 
                                log.log(Level.INFO,out.toString()); 
                        } 
                } catch (Exception e) { 
                        log.log(Level.WARNING,"Exception in handler: " + e.getMessage(), e); 
                        log.log(Level.WARNING,out.toString()); 

                } finally { 
                        try { 
                                log.log(Level.INFO,"invoke"); 
                                out.close(); 
                                if(outPrint != null) { 
                                        outPrint.close(); 
                                } 
                                if(in != null) { 
                                        in.close(); 
                                } 
                                
                        } catch (IOException e) { 
                                log.log(Level.WARNING,e.getMessage(), e); 
                        } 
                } 
        } 
} 
