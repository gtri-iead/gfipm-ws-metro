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

import com.sun.xml.wss.saml.SAMLException;
import com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition;
import com.sun.xml.wss.saml.util.SAML20JAXBUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;

//@XmlRootElement(name = "Condition", namespace = "urn:oasis:names:tc:SAML:2.0:assertion")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DelegationRestrictionType", namespace = "urn:oasis:names:tc:SAML:2.0:conditions:delegation", propOrder = {
    "delegate"
})

/*
<?xml version="1.0" encoding="UTF-8"?>
<saml2:Conditions xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:oasis:names:tc:SAML:2.0:conditions:delegation sstc-saml-delegation.xsd" xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" NotBefore="2011-08-07T19:57:07.703Z" NotOnOrAfter="2011-08-07T20:02:07.703Z">
	<saml2:AudienceRestriction>
		<saml2:Audience>http://localhost:8080/calc/services/cvc</saml2:Audience>
	</saml2:AudienceRestriction>
	<saml2:Condition xmlns:del="urn:oasis:names:tc:SAML:2.0:conditions:delegation" xsi:type="del:DelegationRestrictionType">
		<del:Delegate ConfirmationMethod="urn:oasis:names:tc:SAML:2.0:cm:sender-vouches" DelegationInstant="2010-05-13T12:50:30.846Z">
			<saml2:NameID>john.doe@email.com</saml2:NameID>
		</del:Delegate>
	</saml2:Condition>
</saml2:Conditions>
 */

public class DelegationRestrictionType
        //    extends com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition 
        extends Condition implements com.sun.xml.wss.saml.Condition {
//    extends ConditionAbstractType {
//    implements com.sun.xml.wss.saml.Condition {

    private static final Logger logger =
            Logger.getLogger(DelegationRestrictionType.class.getName());
    @XmlElement(name = "Delegate", required = true)
    protected List<DelegateType> delegate;

    /**
     * Gets the value of the audience property.
     *
     * <p> This accessor method returns a reference to the live list, not a
     * snapshot. Therefore any modification you make to the returned list will
     * be present inside the JAXB object. This is why there is not a
     * <CODE>set</CODE> method for the audience property.
     *
     * <p> For example, to add a new item, do as follows:
     * <pre>
     *    getDelegate().add(newItem);
     * </pre>
     *
     *
     * <p> Objects of the following type(s) are allowed in the list
     * {@link DelegateType }
     *
     *
     */
    public List<DelegateType> getDelegate() {
        if (delegate == null) {
            delegate = new ArrayList<DelegateType>();
        }
        return this.delegate;
    }

    @SuppressWarnings("unchecked")
    public void setDelegate(List delegate) {
        this.delegate = delegate;
    }

    /**
     * Constructs an
     * <code>Condition</code> element from an existing XML block
     *
     * @param element representing a DOM tree element
     * @exception SAMLException if there is an error in the sender or in the
     * element definition.
     */
    public static DelegationRestrictionType fromElement(org.w3c.dom.Element element) throws SAMLException {
        try {
//            JAXBContext jc = SAML20JAXBUtil.getJAXBContext("gov.niem.ws.sample.cvc.sts");
            JAXBContext jc = SAML20JAXBUtil.getJAXBContext();
            javax.xml.bind.Unmarshaller u = jc.createUnmarshaller();
            javax.xml.bind.JAXBElement o = (javax.xml.bind.JAXBElement) u.unmarshal(element);
//            System.out.println("Inside of DelegationRestrictionType: " + o.getName() + " : " + o.getDeclaredType() + " : " + o.getClass() + " : " + o.getScope() + " : " + o.getValue());
//            System.out.println("Converted JAXB Element is: ");
//            GFIPMWSTrustUtil.printJAXBElement(o);
            DelegationRestrictionType delegationRestrictionType = (DelegationRestrictionType) o.getValue();
//            ConditionAbstractType conditionAbstractType = (ConditionAbstractType) o.getValue();
//            return conditionAbstractType;
            return delegationRestrictionType;
        } catch (Exception ex) {
            logger.log(Level.SEVERE, null, ex);
            throw new SAMLException(ex.getMessage());
        }
    }
//    com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition
//    static class Adapter extends XmlAdapter<Condition, com.sun.xml.wss.saml.Condition> {
//
//        @Override
//        public com.sun.xml.wss.saml.Condition unmarshal(Condition v) {
//            return v;
//        }
//
//        @Override
//        public Condition marshal(com.sun.xml.wss.saml.Condition v) {
//            return (Condition) v;
//        }
//    }
}
