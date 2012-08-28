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

import com.sun.xml.ws.api.security.trust.Claims;
import com.sun.xml.ws.api.security.trust.STSAttributeProvider;
import com.sun.xml.wss.saml.*;
import java.security.Principal;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import org.w3c.dom.Element;

public class GFIPMSTSAttributeProvider implements STSAttributeProvider {

    private static final Logger logger =
            Logger.getLogger(GFIPMSTSAttributeProvider.class.getName());
    private static final boolean DEBUG = true;

    @Override
    public Map<QName, List<String>> getClaimedAttributes(Subject subject, String appliesTo, String tokenType, Claims claims) {

        if (DEBUG) {
            logger.log(Level.FINEST, "STS Attribute Provider:: Processing getClaimedAttributes");
        }

        //Code sample how OnBehalfOf token could be obtained through PublicCredentials
        if (DEBUG) {
            Set<Object> publicCredential = subject.getPublicCredentials();
            Element onBehalfOfElement = null;
            for (Object obj : publicCredential) {
                if (obj instanceof XMLStreamReader) {
                    logger.log(Level.FINEST, "STS Attribute Provider:: object is an XMLStreamReader");
//                    XMLStreamReader reader = (XMLStreamReader) obj;
                    //To create a DOM Element representing the Assertion :
//                    onBehalfOfElement = SAMLUtil.createSAMLAssertion(reader);
//                    break;
                } else if (obj instanceof Element) {
                    onBehalfOfElement = (Element) obj;
                    logger.log(Level.FINEST, "STS Attribute Provider:: retrieved OnBehalfOf from Subject's PublicCredentials");
//                    if(onBehalfOfElement != null) 
//                        logger.log(Level.FINEST,"STS Attribute Provider:: Element " + GFIPMUtil.putOutAsString(onBehalfOfElement));
                    break;
                } else {
                    logger.log(Level.FINEST, "STS Attribute Provider:: object is an " + obj.getClass().getCanonicalName());
                }
            }
        }

        Map<QName, List<String>> attrs = new HashMap<QName, List<String>>();

        String name = null;
        Set<Principal> principals = subject.getPrincipals();
        if (principals != null) {
            final Iterator iterator = principals.iterator();
            while (iterator.hasNext()) {
                String cnName = principals.iterator().next().getName();
                int pos = cnName.indexOf("=");
                name = cnName.substring(pos + 1);
                break;
            }
        }
        if (DEBUG) {
            logger.log(Level.FINEST, "STS Attribute Provider:: name = " + name);
        }
        // Add a NameID
        addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", STSAttributeProvider.NAME_IDENTIFIER, name);

        // Add attributes either from STS here or copy them from token supplied within OnBehalfOf or ActAs
        // For details on OnBehalfOf/ActAs implementation see
        // com.sun.xml.ws.security.trust.impl.WSTrustContractImpl.java in ws-sx-wssx-impl

        // Check if it is the ActAs or OnBehalfOf case
        // OnBehalfOf token could be obtained also through claims -> Supporting Properties -> Subject -> Public Credentials
        if (("true".equals(claims.getOtherAttributes().get(new QName("ActAs"))))
                || ("true".equals(claims.getOtherAttributes().get(new QName("OnBehalfOf"))))) {
            // Get the ActAs or OnBehalfOf token
            if (DEBUG) {
                logger.log(Level.FINEST, "STS Attribute Provider:: ActAs or OnBehalfOf case");
            }
            Element token = null;
            for (Object obj : claims.getSupportingProperties()) {
                if (obj instanceof Subject) {
                    token = (Element) ((Subject) obj).getPublicCredentials().iterator().next();
                    if (DEBUG) {
                        logger.log(Level.FINEST, "STS Attribute Provider:: retrieved OnBehalfOf from claims");
                    }
                    break;
                }
            }
            try {
                if (token != null) {
                    addAttributes(token, attrs, true);
                }
            } catch (SAMLException ex) {
                logger.log(Level.SEVERE, "STS Attribute Provider unknown failure", ex);
                throw new RuntimeException(ex);
            }
        } else {
            // Add attributes
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "user:EmployerName", "Dundler Mifflin");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "user:SurName", "Scott");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "user:GivenName", "Michael");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:EmployerName", "Dundler Mifflin");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:SurName", "Scott");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:GivenName", "Michael");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:SwornLawEnforcementOfficerIndicator", "true");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CitizenshipCode", "US");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:SecurityClearanceLevelCode", "Secret");
            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:SecurityClearanceExpirationDate", "05/30/2012");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CriminalInvestigativeDataSelfSearchHomePrivilegeIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CriminalIntelligenceDataSelfSearchHomePrivilegeIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:EmployerSubUnitName", "Scranton Branch Office");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:IdentityProofingAssuranceLevelCode", "NISTLEVEL3");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CriminalJusticeDataSelfSearchHomePrivilegeIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:ElectronicAuthenticationAssuranceLevelCode", "NISTLEVEL2");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:GovernmentDataSelfSearchHomePrivilegeIndicator", "true");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:NCICCertificationIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:EmployerOrganizationGeneralCategoryCode", "Private Industry");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:IdentityProviderId", "GFIPM:IDP:ExampleIDP");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:FederationId", "GFIPM:IDP:ExampleIDP:USER:ms01");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:TelephoneNumber", "404-555-9876");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:EmailAddressText", "ms01@gfipm.net");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:PublicSafetyOfficerIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CriminalHistoryDataSelfSearchHomePrivilegeIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:LocalId", "ms01");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:28CFRPrivilegeIndicator", "false");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:EmployerORI", "GA01234");
//            addAttribute(attrs, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", "gfipm:2.0:user:CounterTerrorismDataSelfSearchHomePrivilegeIndicator", "false");

        }

        return attrs;
    }

    private void addAttribute(Map<QName, List<String>> attrs, String nameFormat, String name, String value) {
        QName testQName = new QName(nameFormat, name);
        List<String> valueAttrs = new ArrayList<String>();
        valueAttrs.add(value);
        attrs.put(testQName, valueAttrs);
    }

    private void addAttributes(Element token, Map<QName, List<String>> attrs, boolean isActAs) throws SAMLException {
        // only handle the case of UsernameToken and SAML assertion here
        String name = null;
        String nameNS = null;
        String tokenName = token.getLocalName();
        if ("UsernameToken".equals(tokenName)) {
            // an UsernameToken: get the user name
            name = token.getElementsByTagNameNS("*", "Username").item(0).getFirstChild().getNodeValue();
        } else if ("Assertion".equals(tokenName)) {
            // an SAML assertion
            Assertion assertion = AssertionUtil.fromElement(token);

            com.sun.xml.wss.saml.Subject subject = null;
            NameID nameID = null;

            // SAML 2.0
            try {
                subject = assertion.getSubject();
            } catch (Exception ex) {
                subject = null;
            }

            if (subject != null) {
                nameID = subject.getNameId();
            }

            List<Object> statements = assertion.getStatements();
            for (Object s : statements) {
                if (s instanceof AttributeStatement) {
                    List<Attribute> samlAttrs = ((AttributeStatement) s).getAttributes();
                    for (Attribute samlAttr : samlAttrs) {
                        String attrName = samlAttr.getName();
                        String attrNS = samlAttr.getNameFormat();
                        List<Object> samlAttrValues = samlAttr.getAttributes();
                        List<String> attrValues = new ArrayList<String>();
                        for (Object samlAttrValue : samlAttrValues) {
                            if (samlAttrValue instanceof String) {
                                attrValues.add((String) samlAttrValue);
                            } else {
                                attrValues.add(((Element) samlAttrValue).getFirstChild().getNodeValue());
                            }
                        }
                        attrs.put(new QName(attrNS, attrName), attrValues);
                    }

                    // for SAML 1.0, 1.1
                    if (subject == null) {
                        subject = ((AttributeStatement) s).getSubject();
                    }
                } else if (s instanceof AuthenticationStatement) {
                    subject = ((AuthenticationStatement) s).getSubject();
                }
            }

            // Get the user identifier in the Subject:
            if (nameID != null) {
                //SAML 2.0 case
                name = nameID.getValue();
                nameNS = nameID.getNameQualifier();
            } else {
                // SAML 1.0, 1.1. case
                NameIdentifier nameIdentifier = subject.getNameIdentifier();
                if (nameIdentifier != null) {
                    name = nameIdentifier.getValue();
                    nameNS = nameIdentifier.getNameQualifier();
                }
            }
        }

        String idName = isActAs ? "ActAs" : NAME_IDENTIFIER;
        List<String> nameIds = new ArrayList<String>();
        if (name != null) {
            nameIds.add(name);
        }
        attrs.put(new QName(nameNS, idName), nameIds);
    }
}
