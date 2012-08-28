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
 */
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.namespace.QName;
import javax.xml.soap.Name;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.LogicalMessage;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.LogicalMessageContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPMessageContext;

//import org.example.schema.doubleit.DoubleIt;
//import org.example.schema.doubleit.ObjectFactory;

public class ClientHandlers {

   public static class LogicalHandler implements
         javax.xml.ws.handler.LogicalHandler<LogicalMessageContext> {

      @Override
      public void close(MessageContext mc) {
      }

      @Override
      public boolean handleFault(LogicalMessageContext messagecontext) {
         return true;
      }

      @Override
      public boolean handleMessage(LogicalMessageContext mc) {
         LogicalMessage msg = mc.getMessage();
         HandlerUtils.printMessageContext("Client LogicalHandler", mc);

         if (Boolean.TRUE.equals(mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY))) {
//            Integer maxValue = new Integer((String) mc.get("MAX_VALUE"));
//            try {
//               JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
//               Object payload = msg.getPayload(jaxbContext);
//               if (payload instanceof DoubleIt) {
//                  DoubleIt req = (DoubleIt) payload;
//                  if (req.getNumberToDouble() > maxValue.intValue()) {
//                     req.setNumberToDouble(maxValue.intValue());
//                     msg.setPayload(req, jaxbContext);
//                  }
//                  if (req.getNumberToDouble() == 20) {
//                     throw new ProtocolException("Doubling 20 is not allowed by the SOAP client.");
//                  }
//               }
//            } catch (JAXBException ex) {
//               throw new ProtocolException(ex);
//            }
         }
         return true;
      }

   }

   public static class SOAPHandler implements
         javax.xml.ws.handler.soap.SOAPHandler<SOAPMessageContext> {

      @Override
      public Set<QName> getHeaders() {
         return null;
      }

      @Override
      public void close(MessageContext mc) {
      }

      @Override
      public boolean handleFault(SOAPMessageContext mc) {
         return true;
      }

      @Override
      public boolean handleMessage(SOAPMessageContext mc) {
         if (Boolean.TRUE.equals(mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY))) {
            HandlerUtils.printMessageContext("Client SOAPHandler", mc);
            SOAPMessage sm = mc.getMessage();
            gov.niem.ws.sample.cvc.handlers.SOAPHandler.dumpSOAPMessage(sm, null);

//            try {
//               SOAPFactory sf = SOAPFactory.newInstance();
//               SOAPHeader sh = sm.getSOAPHeader();
//               if (sh == null) {
//                  sh = sm.getSOAPPart().getEnvelope().addHeader();
//               }
//
//               Name twoTermName = sf.createName("TwoTerms", "samp", "http://www.example.org");
//               SOAPHeaderElement shElement = sh.addHeaderElement(twoTermName);
//               SOAPElement firstTerm = shElement.addChildElement("term");
//               firstTerm.addTextNode("Apple");
//               shElement.addChildElement(firstTerm);
//               SOAPElement secondTerm = shElement.addChildElement("term");
//               secondTerm.addTextNode("Orange");
//               shElement.addChildElement(secondTerm);
//            } catch (SOAPException e) {
//               throw new ProtocolException(e);
//            }
         }

         return true;
      }
   }
}
