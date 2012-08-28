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
 */
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.ws.LogicalMessage;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.LogicalMessageContext;
import javax.xml.ws.handler.MessageContext;

public class LogicalHandler implements javax.xml.ws.handler.LogicalHandler<LogicalMessageContext> {

    private static final Logger logger = Logger.getLogger(LogicalHandler.class.getName());

   @Override
   public void close(MessageContext mc) {
   }

   @Override
   public boolean handleFault(LogicalMessageContext messagecontext) {
      return true;
   }

   @Override
   public boolean handleMessage(LogicalMessageContext mc) {
      HandlerUtils.printMessageContext("Service LogicalHandler", mc);
      if (Boolean.FALSE.equals(mc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY))) {
//         try {
//            LogicalMessage msg = mc.getMessage();
//            JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
//            Object payload = msg.getPayload(jaxbContext);
//            if (payload instanceof DoubleIt) {
//               DoubleIt req = (DoubleIt) payload;
//               if (req.getNumberToDouble() == 30) {
//                  throw new ProtocolException(
//                        "Doubling 30 is not allowed by the web service provider.");
//               }
//            }
//         } catch (JAXBException ex) {
//            throw new ProtocolException(ex);
//         }
      }
      return true;
   }

}
