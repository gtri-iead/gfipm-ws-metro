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
package gov.niem.ws.util.jaxb.delegate;

import com.sun.xml.wss.logging.LogDomainConstants;
import com.sun.xml.wss.saml.SAMLException;
import com.sun.xml.wss.saml.util.SAML20JAXBUtil;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;

/**
 * This is an implementation of the <code>Delegate</code> class.
 */
public class Delegate extends DelegateType {
    // implements com.sun.xml.wss.saml.AudienceRestriction
    
    protected static final Logger log = Logger.getLogger(
            LogDomainConstants.WSS_API_DOMAIN,
            LogDomainConstants.WSS_API_DOMAIN_BUNDLE);

    /**
     * Constructs an instance of <code>Delegate</code>.
     *
     * @param ConfirmationMethod String representing the confirmation method.
     * @param DelegationInstant String representing the delegation instant.
     */
//    public Delegate(String confirmationMethod, String delegationInstant) {
//        setConfirmationMethod(confirmationMethod);
//        setDelegationInstant(delegationInstant);
//    }    
    
    /**
     * Constructs an <code>Delegate</code> element from an
     * existing XML block.
     *
     * @param DelegateElement A
     *        <code>org.w3c.dom.Element</code> representing DOM tree for
     *        <code>Delegate</code> object.
     * @exception SAMLException if it could not process the
     *            <code>org.w3c.dom.Element</code> properly, implying that there
     *            is an error in the sender or in the element definition.
     */
    public static DelegateType fromElement(org.w3c.dom.Element element)
        throws SAMLException {
        try {
            JAXBContext jc = SAML20JAXBUtil.getJAXBContext();
            javax.xml.bind.Unmarshaller u = jc.createUnmarshaller();
            javax.xml.bind.JAXBElement o = (javax.xml.bind.JAXBElement)u.unmarshal(element);
            DelegateType delegateType = (DelegateType) o.getValue();
            return delegateType;
        } catch ( Exception ex) {
            throw new SAMLException(ex.getMessage());
        }
    }
}
