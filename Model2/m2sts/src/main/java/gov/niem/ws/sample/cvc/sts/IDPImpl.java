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
package gov.niem.ws.sample.cvc.sts;

import com.sun.xml.ws.security.trust.sts.BaseSTSImpl;
import gov.niem.ws.util.jaxb.delegate.DelegateUtil;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.annotation.Resource;
import javax.xml.transform.Source;
import javax.xml.ws.*;
import javax.xml.ws.handler.MessageContext;

//@MessageDumping(storeMessages=true)
@WebServiceProvider(wsdlLocation = "WEB-INF/wsdl/idp.wsdl",
portName = "IIdentityProviderService_Port",
serviceName = "IdentityProviderService",
targetNamespace = "http://tempuri.org/")
//@BindingType(SOAPBinding.SOAP12HTTP_BINDING)  
//@BindingType(SOAPBinding.SOAP11HTTP_BINDING)
//@BindingType("http://schemas.xmlsoap.org/wsdl/soap/http?addressing=1.0")
//@WebServiceProvider(wsdlLocation = "WEB-INF/wsdl/sts.wsdl")
@ServiceMode(value = Service.Mode.PAYLOAD)
public class IDPImpl extends BaseSTSImpl implements Provider<Source> {

//public class IDPImpl extends com.sun.xml.ws.trust.impl.IssueSamlTokenContractImpl    
    @Resource
    protected WebServiceContext context;
    private static final Logger logger = Logger.getLogger(IDPImpl.class.getName());
    private static final boolean DEBUG = true;

    static {
        DelegateUtil.initDelegateJAXBContext();
//        com.sun.xml.ws.transport.http.HttpAdapter.dump = true;
//        com.sun.xml.ws.transport.http.client.HttpTransportPipe.dump = true;
        if (DEBUG) {
            logger.log(Level.FINEST, "IDP: IDPImpl : initialized");
        }
    }

    public Source invoke(Source rstElement) {
        return super.invoke(rstElement);
    }

    @Override
    protected MessageContext getMessageContext() {
        if (DEBUG) {
            logger.log(Level.FINEST, "IDP: Inside IDPImpl::getMessageContext");
        }
        MessageContext msgCtx = context.getMessageContext();
        return msgCtx;
    }
//    @Override
//    public Source invoke(final Source rstElement ){
//        //http://blogs.oracle.com/ritzmann/entry/printing_soap_messages_ii
//        if (context != null) {
//            // We need to get access to the MessageDumpingFeature object. This is a little tricky,
//            // we need to work our way through some JAX-WS implementation classes.
//            WSWebServiceContext dumpContext = (WSWebServiceContext) context;
//            Packet packet = dumpContext.getRequestPacket();
//            WSEndpoint endpoint = packet.endpoint;
//            WSBinding binding = endpoint.getBinding();
//            // Got it finally
//            MessageDumpingFeature messageDump = binding.getFeature(MessageDumpingFeature.class);
//            if (messageDump != null) {
//                // The first time this method is invoked, it will return the SOAP request. All other invocations will
//                // return the SOAP response of the previous invocation.
//                String previousResponse = messageDump.nextMessage();
//                if(DEBUG) logger.log(Level.FINEST,"\n\n\nIDP: Previous Response \n" + previousResponse);
//                // The first time this method is invoked, it will return null. All other invocations will return the
//                // current SOAP request.
//                String request = messageDump.nextMessage();
//                if(DEBUG) logger.log(Level.FINEST,"\n\n\nIDP: Request \n" + request);
//            }
//        }
//        
//        return super.invoke(rstElement);
//    }
}
