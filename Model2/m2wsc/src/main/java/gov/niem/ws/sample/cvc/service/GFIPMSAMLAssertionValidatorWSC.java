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
package gov.niem.ws.sample.cvc.service;

import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.callback.SAMLValidator;
import com.sun.xml.wss.saml.util.SAMLUtil;
import gov.niem.ws.util.GFIPMUtil;
import gov.niem.ws.util.SecurityUtil;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * This class provides a minimal SAML Assertion validation and does not cover GFIPM S2S requirements.  
 * For the full SAML Assertion validation see GFIPMSAMLAssertionValidatorWSP class in the WSP module.
 * 
 */
public class GFIPMSAMLAssertionValidatorWSC implements SAMLValidator {

    private static final boolean DEBUG = true;
    private static final Logger logger = Logger.getLogger(GFIPMSAMLAssertionValidatorWSC.class.getName());

    @Override
    public void validate(Element elmnt, Map map, Subject sbjct) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet.1");
    }

    @Override
    public void validate(XMLStreamReader xmlStreamerReader, Map map, Subject sbjct) throws SAMLValidationException {

        if (DEBUG) {
            logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<WSC: Validating SAML Assertion>>>>>>>>>>>>>>>");
        }

        try {

            Element domSamlAssertion = SAMLUtil.createSAMLAssertion(xmlStreamerReader);

            if (DEBUG) {
                logger.log(Level.FINEST, "\n Received SAML Assertion " + GFIPMUtil.putOutAsString(domSamlAssertion));
            }

            //Do a SAML:Conditions validation to make sure the SAML assertion is Valid
            if (!(SAMLUtil.validateTimeInConditionsStatement(domSamlAssertion))) {
                logger.log(Level.WARNING, "Invalid time conditions");
                throw new SAMLValidationException("Invalid time conditions");
            }

            if (DEBUG) {
                logger.log(Level.FINEST, "WSC: validated time conditions - passed");
            }

            PublicKey signingKey = null;
            try {
                signingKey = SecurityUtil.getSignaturePublicKey(domSamlAssertion.getOwnerDocument());
            } catch (ParserConfigurationException ex) {
                logger.log(Level.WARNING, null, ex);
                throw new SAMLValidationException(ex);
            } catch (SAXException ex) {
                logger.log(Level.WARNING, null, ex);
                throw new SAMLValidationException(ex);
            } catch (IOException ex) {
                logger.log(Level.WARNING, null, ex);
                throw new SAMLValidationException(ex);
            }
            if (signingKey != null) {
                if (!(SAMLUtil.verifySignature(domSamlAssertion, signingKey))) {
                    logger.log(Level.WARNING, "Unable to verify signature on SAML assertion.");
                    throw new SAMLValidationException("Unable to verify signature on SAML assertion.");
                }
                if (DEBUG) {
                    logger.log(Level.FINEST, "WSC: done verifying signature on the attached SAML assertion - valid");
                }
            } else {
                logger.log(Level.WARNING, "Unable to obtain signing key from SAML assertion.");
                throw new SAMLValidationException("Unable to obtain signing key from SAML assertion.");
            }

            if (DEBUG) {
                logger.log(Level.FINEST, "WSC: validated delegation - passed");
            }

            //If we want to be able to access the saml assertion in the client through 
            //SubjectAccessor.getRequesterSubject(context); we have to add it here
            sbjct.getPublicCredentials().add(domSamlAssertion);

            if (DEBUG) {
                logger.log(Level.FINEST, "\n Finished processing SAML Assertion " + GFIPMUtil.putOutAsString(domSamlAssertion));
            }

        } catch (XWSSecurityException ex) {
            logger.log(Level.SEVERE, null, ex);
            throw new SAMLValidationException(ex);
        } catch (XMLStreamException ex) {
            logger.log(Level.SEVERE, null, ex);
            throw new SAMLValidationException(ex);
        }

        if (DEBUG) {
            logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<<WSC:SAML Validation Successful>>>>>>>>>>>>>>>");
        }

    }

    public void validate(Element elmnt) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet.3");
    }

    public void validate(XMLStreamReader reader) throws SAMLValidationException {
        throw new UnsupportedOperationException("Not supported yet.4");
    }
}
