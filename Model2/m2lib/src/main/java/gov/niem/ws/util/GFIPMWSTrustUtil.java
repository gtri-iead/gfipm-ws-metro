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
package gov.niem.ws.util;

import com.sun.xml.ws.api.security.trust.STSAttributeProvider;
import com.sun.xml.ws.api.security.trust.WSTrustException;
import com.sun.xml.ws.security.trust.util.WSTrustUtil;
import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import java.text.SimpleDateFormat;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;

/**
 * Class is based on com.sun.xml.ws.security.trust.util.WSTrustUtil.java
 * Includes several fixes for Metro bugs.
 */
public class GFIPMWSTrustUtil {

    private GFIPMWSTrustUtil() {
    }


    public static Assertion addSamlAttributes(Assertion assertion, Map<QName, List<String>> claimedAttrs) throws WSTrustException {
        try {
            SAMLAssertionFactory samlFac = null;

            samlFac = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML2_0);

            Element assertionEle = assertion.toElement(null);
            String samlNS = assertionEle.getNamespaceURI();
            String samlPrefix = assertionEle.getPrefix();
            NodeList asList = assertionEle.getElementsByTagNameNS(samlNS, "AttributeStatement");
            Node as = null;
            if (asList.getLength() > 0) {
                as = asList.item(0);
            }
            createAttributeStatement(as, claimedAttrs, samlNS, samlPrefix);

            return samlFac.createAssertion(assertionEle);
        } catch (Exception ex) {
            throw new WSTrustException(ex.getMessage());
        }
    }

    private static Node createAttributeStatement(Node as, Map<QName, List<String>> claimedAttrs, String samlNS, String samlPrefix) throws WSTrustException {
        try {
            Document doc = null;
            if (as != null) {
                doc = as.getOwnerDocument();
            } else {
                doc = newDocument();
                as = doc.createElementNS(samlNS, samlPrefix + ":AttributeStatement");
                doc.appendChild(as);
            }            

            final Set<Map.Entry<QName, List<String>>> entries = claimedAttrs.entrySet();
            for (Map.Entry<QName, List<String>> entry : entries) {
                final QName attrKey = entry.getKey();
                final List<String> values = entry.getValue();
                if (values.size() > 0) {
                    Element attrEle = null;
                    if (false && STSAttributeProvider.NAME_IDENTIFIER.equals(attrKey.getLocalPart())) {
                        // create an "actor" attribute
                        attrEle = createActorAttribute(doc, samlNS, samlPrefix, values.get(0));

                    } else {
//                        attrEle = createAttribute(doc, friendlyName, samlNS, samlPrefix, attrKey);
                        attrEle = createAttribute(doc, null, samlNS, samlPrefix, attrKey);
                        Iterator valueIt = values.iterator();
                        while (valueIt.hasNext()) {
                            Element attrValueEle = doc.createElementNS(samlNS, samlPrefix + ":AttributeValue");
                            attrValueEle.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "xs:string");
                            Text text = doc.createTextNode((String) valueIt.next());
                            attrValueEle.appendChild(text);
                            attrEle.appendChild(attrValueEle);
                        }
                    }
                    as.appendChild(attrEle);
                }
            }

            return as;
        } catch (Exception ex) {
            throw new WSTrustException(ex.getMessage());
        }
    }

    private static Element createAttribute(Document doc, String friendlyName, String samlNS, String samlPrefix, QName attrKey) throws Exception {
        Element attrEle = doc.createElementNS(samlNS, samlPrefix + ":Attribute");
//        attrEle.setAttribute("AttributeName", attrKey.getLocalPart());
//        attrEle.setAttribute("AttributeNamespace", attrKey.getNamespaceURI());
//        if (WSTrustConstants.SAML20_ASSERTION_TOKEN_TYPE.equals(samlNS)){
        attrEle.setAttribute("Name", attrKey.getLocalPart());
        attrEle.setAttribute("NameFormat", attrKey.getNamespaceURI());
        if ((friendlyName != null) && (!friendlyName.trim().isEmpty())) {
            attrEle.setAttribute("FriendlyName", friendlyName);
        }
//        }
        return attrEle;
    }

    private static Element createActorAttribute(Document doc, String samlNS, String samlPrefix, String name) throws Exception {
        // Create Attribute of the form:
        // <saml:Attribute AttributeName="actor" 
        //          AttributeNamespace="http://schemas.xmlsoap.com/ws/2009/09/identity/claims">
        //      ...
        // </saml:Attribute>
        Element actorEle = createAttribute(doc, null, samlNS, samlPrefix, new QName("actor", "http://schemas.xmlsoap.com/ws/2009/09/identity/claims"));
        Element attrValueEle = doc.createElementNS(samlNS, samlPrefix + ":AttributeValue");
        actorEle.appendChild(attrValueEle);

        // Create inner Attribute of the form:
        // <saml:Attribute AttributeName="name"
        //          AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"       			                  AttributeNamespace="http://schemas.xmlsoap.org/ws/2005/05/identity/claims"    	                  xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion">
        //    <saml:AttributeValue>name</saml:AttributeValue>
        // </saml:Attribute>
        Element nameEle = createAttribute(doc, null, samlNS, samlPrefix, new QName("name", "http://schemas.xmlsoap.com/ws/2005/05/identity/claims"));
        attrValueEle.appendChild(nameEle);
        Element nameAttrValueEle = doc.createElementNS(samlNS, samlPrefix + ":AttributeValue");
        nameEle.appendChild(nameAttrValueEle);
        Text text = doc.createTextNode(name);
        nameAttrValueEle.appendChild(text);

        return actorEle;
    }

    public static Element getCondition(String delegationNameID) throws DatatypeConfigurationException {
        Element condition;
        Document doc = newDocument();
        condition = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:Condition");

        //http://codeidol.com/java/java-xml-for-web/Working-with-DOM/Advanced-DOM/
        condition.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:del",
                "urn:oasis:names:tc:SAML:2.0:conditions:delegation");

        condition.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:xsi",
                "http://www.w3.org/2001/XMLSchema-instance");

        condition.setAttributeNS(
                "http://www.w3.org/2001/XMLSchema-instance",
                "xsi:type",
                "del:DelegationRestrictionType");

        condition.setAttributeNS(
                "http://www.w3.org/2000/xmlns/",
                "xmlns:saml2",
                "urn:oasis:names:tc:SAML:2.0:assertion");        

        doc.appendChild(condition);        
        
        Element delegate;
        delegate = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:conditions:delegation","del:Delegate");
        //ConfirmationMethod is not needed
//        delegate.setAttribute("ConfirmationMethod", "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches");  
        
        final SimpleDateFormat calendarFormatter
            = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'.'SSS'Z'");
        long currentTime = WSTrustUtil.getCurrentTimeWithOffset();
        String issueInstString = calendarFormatter.format(currentTime);
        delegate.setAttribute("DelegationInstant", issueInstString);
                                       
        Element nameID;
        nameID = doc.createElementNS("urn:oasis:names:tc:SAML:2.0:assertion", "saml2:NameID");
        delegate.appendChild(nameID);
        Text text = doc.createTextNode(delegationNameID);
        nameID.appendChild(text);        
        condition.appendChild(delegate);
                
        return condition;

    }

    public static Document newDocument() {
        Document doc;
        try {
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder db = dbf.newDocumentBuilder();
            doc = db.newDocument();
        } catch (Exception ex) {
            throw new RuntimeException(ex.getMessage(), ex);
        }

        return doc;
    }
    
}
