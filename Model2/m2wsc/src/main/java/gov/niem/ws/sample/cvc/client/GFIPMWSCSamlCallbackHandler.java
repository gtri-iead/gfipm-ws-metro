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
import com.sun.xml.ws.security.trust.GenericToken;
import com.sun.xml.ws.security.trust.WSTrustConstants;
import com.sun.xml.ws.security.trust.impl.client.DefaultSTSIssuedTokenConfiguration;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.XMLUtil;
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
import net.gfipm.trustfabric.TrustFabric;
import net.gfipm.trustfabric.TrustFabricFactory;
import org.w3c.dom.Element;

/*
 * SAML 2.0 Holder Of Key Callback Handler for example see
 * https://xwss.dev.java.net/files/documents/4864/50700/SamlCallbackHandler.java
 * http://metro.java.net/guide/Example_Applications.html#ahiev
 */
public class GFIPMWSCSamlCallbackHandler implements CallbackHandler {

    private UnsupportedCallbackException unsupported = new UnsupportedCallbackException(null, "Unsupported Callback Type Encountered");
    private static final Logger logger = Logger.getLogger(GFIPMWSCSamlCallbackHandler.class.getName());
    private static final boolean DEBUG = true;
    private static TrustFabric tf;

    static {
        tf = TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof SAMLCallback) {
                SAMLCallback samlCallback = (SAMLCallback) callbacks[i];
                Element samlAssertion = null;

                if (DEBUG) {
                    logger.log(Level.FINEST, "WSC GFIPMWSCSamlCallbackHandler confirmation method in the samlCallback: " + samlCallback.getConfirmationMethod());
                }

                Map<String, Object> runtimeProps = samlCallback.getRuntimeProperties();
                if (DEBUG) {
                    logger.log(Level.FINEST, "WSC GFIPMWSCSamlCallbackHandler: content of samlCallback");
                    for (Map.Entry<String, Object> entry : runtimeProps.entrySet()) {
                        logger.log(Level.FINEST, "\t\tKey:" + entry.getKey() + "  Value: " + entry.getValue());
                    }
                }

                samlAssertion = (Element) runtimeProps.get("userSAMLAssertion");
                samlAssertion = getSAMLAssertionFromSTS(samlAssertion);
                if (DEBUG) {
                    logger.log(Level.FINEST, "Got the following NEW SAML Assertion from STS:\n" + XMLUtil.print(samlAssertion) + "\n");
                }

                // Code below providea a workaround for using http vs https for STS calls. 
                // If http is used samlCallback.setAssertionElement(samlAssertion); could be called righ away.
                Assertion assertion = null;
                try {
                    assertion = AssertionUtil.fromElement(samlAssertion);
                    samlAssertion = assertion.toElement(null);
                } catch (XWSSecurityException ex) {
                    logger.log(Level.WARNING, "Unable to covert from assertion");
                    Logger.getLogger(GFIPMWSCSamlCallbackHandler.class.getName()).log(Level.SEVERE, "Unable to covert from assertion !!!", ex);
                } catch (SAMLException ex) {
                    logger.log(Level.WARNING, "Unable to covert to assertion");
                    Logger.getLogger(GFIPMWSCSamlCallbackHandler.class.getName()).log(Level.SEVERE, "Unable to convert to Assertion !!!", ex);
                }

                if (DEBUG) {
                    logger.log(Level.FINEST, "Setting the STS token to :\n" + XMLUtil.print(samlAssertion) + "\n");
                }

                //it's possible to use setAssertionReader(XMLStreamReader samlAssertion) to improve performance instead of setAssertionElement()
                //See http://weblogs.java.net/blog/2009/06/01/security-token-configuration-metro
                samlCallback.setAssertionElement(samlAssertion);

                //process claims if necessary
//                TokenPolicyMetaData metaData = new TokenPolicyMetaData(runtimeProps);
//                metaData.getClaims()                
            } else {
                logger.log(Level.SEVERE, LogStringsMessages.WSS_1504_UNSUPPORTED_CALLBACK_TYPE());
                throw unsupported;
            }

        }
    }

    //REDIRECTING_ADS_REQUEST
    private Element getSAMLAssertionFromSTS(Element samlAssertion) {

        String issuerEntityId = ((Element) samlAssertion.getElementsByTagNameNS("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer").item(0)).getTextContent();
        if (DEBUG) {
            logger.log(Level.FINEST, "SAML Assertion Issuer: " + issuerEntityId);
        }
        String stsEndpoint = tf.getDelegatedTokenServiceEndpointAddress (issuerEntityId);
        String stsWSDLLocation = tf.getWsdlUrlAddress (issuerEntityId);
//        String stsMexAddress = tf.getMetadataExchangeEndpointAddress(issuerEntityId);

        //Using stsEndpoint and stsMexAddress
//        DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(
//                STSIssuedTokenConfiguration.PROTOCOL_13, 
//                stsEndpoint, 
//                stsMexAddress);

        //.NET configuration
//        String stsServiceName = "SecurityTokenService";
//        String stsPortName = "ISecurityTokenService_Port";
//        String stsNamespace = "http://tempuri.org/";        

        //Metro configuration
        String stsServiceName = "SecurityTokenService";
        String stsPortName = "ISecurityTokenService_Port";
        String stsNamespace = "http://tempuri.org/";

        DefaultSTSIssuedTokenConfiguration config = new DefaultSTSIssuedTokenConfiguration(
                STSIssuedTokenConfiguration.PROTOCOL_13,
                stsEndpoint,
                stsWSDLLocation,
                stsServiceName,
                stsPortName,
                stsNamespace);

        config.setTokenType(WSTrustConstants.SAML20_WSS_TOKEN_TYPE);

        config.setOBOToken(new GenericToken(samlAssertion));

        try {
            IssuedTokenManager manager = IssuedTokenManager.getInstance();
            // CommercialVehicleCollisionWSCClient.sepUrlString - appliesTo
            IssuedTokenContext ctx = manager.createIssuedTokenContext(config, CommercialVehicleCollisionWSCClient.sepUrlString);
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
