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

import com.sun.xml.ws.api.security.trust.client.IssuedTokenManager;
import com.sun.xml.ws.api.security.trust.client.STSIssuedTokenConfiguration;
import com.sun.xml.ws.security.IssuedTokenContext;
import com.sun.xml.ws.security.Token;
import com.sun.xml.ws.security.trust.WSTrustConstants;
import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.MessageConstants;
import com.sun.xml.wss.impl.callback.SAMLCallback;
import com.sun.xml.wss.logging.impl.misc.LogStringsMessages;
import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.AssertionUtil;
import com.sun.xml.wss.saml.SAMLException;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import org.w3c.dom.Element;

/*
 * This callback handler is not used, included only for sample purposes.
 * 
 * SAML 2.0 Holder Of Key Callback Handler for example see
 * https://xwss.dev.java.net/files/documents/4864/50700/SamlCallbackHandler.java
 * http://metro.java.net/guide/Example_Applications.html#ahiev
 */
public class GFIPMSamlCallbackHandler implements CallbackHandler {

    private UnsupportedCallbackException unsupported = new UnsupportedCallbackException(null, "Unsupported Callback Type Encountered");
    private static final Logger logger = Logger.getLogger(GFIPMSamlCallbackHandler.class.getName());
    private static final boolean DEBUG = true;

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback samlCallback = (SAMLCallback) callbacks[i];
                Element samlAssertion = null;

                if (DEBUG) {
                    logger.log(Level.INFO, "GFIPMSamlCallbackHandler confirmation method in the samlCallback: " + samlCallback.getConfirmationMethod());
                }

                Map<String, Object> runtimeProps = samlCallback.getRuntimeProperties();
                if (DEBUG) {
                    logger.log(Level.INFO, "GFIPMSamlCallbackHandler : content of samlCallback");
                    for (Map.Entry<String, Object> entry : runtimeProps.entrySet()) {
                        logger.log(Level.INFO, "\t\tKey:" + entry.getKey() + "  Value: " + entry.getValue());
                    }
                }

                samlAssertion = getSAMLAssertionFromSTS();
                
                if(true) {
                    samlCallback.setAssertionElement(samlAssertion);
                    return;
                }
                
                Assertion assertion;
                try {
                    assertion = AssertionUtil.fromElement(samlAssertion);
                    samlAssertion = assertion.toElement(null);
//                    samlAssertion = getElement(assertionString);
//                    samlAssertion = XMLUtil.toDOMDocument(assertionString).getDocumentElement();
                } catch (XWSSecurityException ex) {
                    logger.log(Level.INFO, "Unable to covert from assertion");
                    Logger.getLogger(GFIPMSamlCallbackHandler.class.getName()).log(Level.SEVERE, "Unable to covert from assertion !!!", ex);
                } catch (SAMLException ex) {
                    logger.log(Level.INFO, "Unable to covert to assertion");
                    Logger.getLogger(GFIPMSamlCallbackHandler.class.getName()).log(Level.SEVERE, "Unable to convert to Assertion !!!", ex);
                }
                //TODO see if it's possible to use setAssertionReader(XMLStreamReader samlAssertion) to improve performance instead of setAssertionElement()
                //See http://weblogs.java.net/blog/2009/06/01/security-token-configuration-metro
                samlCallback.setAssertionElement(samlAssertion);

                //TODO process claims
//                TokenPolicyMetaData metaData = new TokenPolicyMetaData(runtimeProps);
//                metaData.getClaims()                
            } else {
                logger.log(Level.SEVERE, LogStringsMessages.WSS_1504_UNSUPPORTED_CALLBACK_TYPE());
                throw unsupported;
            }

        }
    }

    //REDIRECTING_ADS_REQUEST
    private Element getSAMLAssertionFromSTS() {

        //Using stsEndpoint and stsMexAddress
//        String stsEndpoint = "https://cureidpm2:8181/m2sts/services/sts";
//        String stsMexAddress = "https://cureidpm2:8181/m2sts/services/sts/mex";
//        DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(
//                STSIssuedTokenConfiguration.PROTOCOL_13, 
//                stsEndpoint, 
//                stsMexAddress);


        //.NET
        String stsEndpoint = "https://ha50idpm2:8544/Model2UserSts/Issue.svc";
        String stsWSDLLocation = "https://ha50idpm2:8544/Model2UserSts/Issue.svc?wsdl";
        String stsServiceName = "SecurityTokenService";
        String stsPortName = "CustomBinding_IWSTrust13Sync";
        String stsNamespace = "http://schemas.microsoft.com/ws/2008/06/identity/securitytokenservice";

        //Metro username/password
//        String stsEndpoint = "https://cureidpm2:8181/m2sts/services/idp";
//        String stsWSDLLocation = "https://cureidpm2:8181/m2sts/services/idp?wsdl";
//        String stsServiceName = "IdentityProviderService";
//        String stsPortName = "IIdentityProviderService_Port";
//        String stsNamespace = "http://tempuri.org/";

        DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(
                STSIssuedTokenConfiguration.PROTOCOL_13,
                stsEndpoint,
                stsWSDLLocation,
                stsServiceName,
                stsPortName,
                stsNamespace);

        config.setTokenType(WSTrustConstants.SAML20_WSS_TOKEN_TYPE);

        config.setKeyType("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");
        config.setProtocol(STSIssuedTokenConfiguration.PROTOCOL_13);
        config.setCanonicalizationAlgorithm(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        config.setEncryptionAlgorithm(MessageConstants.AES_BLOCK_ENCRYPTION_256);          
        config.setKeySize(0);        

        try {
            IssuedTokenManager manager = IssuedTokenManager.getInstance();
            // CommercialVehicleCollisionWSCClient.sepUrl - appliesTo
            IssuedTokenContext ctx = manager.createIssuedTokenContext(config, CommercialVehicleCollisionClient.sepUrl);
            manager.getIssuedToken(ctx);
            Token issuedToken = ctx.getSecurityToken();
            //byte[] proofKey = ctx.getProofKey();            
            //Used in token validation against STS
//            Status status = (Status)ctx.getOtherProperties().get(IssuedTokenContext.STATUS);
            Element samlToken = (Element) issuedToken.getTokenValue();
            return samlToken;
        } catch (Exception ex) {
            logger.log(Level.WARNING, "WSC: Unable to get SAML Assertion from STS", ex);
            throw new RuntimeException(ex);
        }
    }
}
