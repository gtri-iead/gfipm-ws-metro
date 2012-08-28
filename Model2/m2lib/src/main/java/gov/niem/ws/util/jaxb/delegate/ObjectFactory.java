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

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the gov.niem.ws.util.jaxb.delegate package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

//    private final static QName _Condition_QNAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "Condition");
//    private final static QName _NameID_QNAME = new QName("urn:oasis:names:tc:SAML:2.0:assertion", "NameID");
    private final static QName _Delegate_QNAME = new QName("urn:oasis:names:tc:SAML:2.0:conditions:delegation", "Delegate");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: gov.niem.ws.sample.cvc.sts
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link DelegationRestrictionType }
     * 
     */
    public DelegationRestrictionType createDelegationRestrictionType() {
        return new DelegationRestrictionType();
    }    
    
    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DelegationRestrictionType }{@code >}}
     * 
     */
//    @XmlElementDecl(namespace = "urn:oasis:names:tc:SAML:2.0:assertion", name = "Condition")
//    public JAXBElement<DelegationRestrictionType> createDelegationRestriction(DelegationRestrictionType value) {
//        return new JAXBElement<DelegationRestrictionType>(_Condition_QNAME, DelegationRestrictionType.class, null, value);
//    }    

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DelegationRestrictionType }{@code >}}
     * 
     */
//    @XmlElementDecl(scope=com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition.class, namespace = "urn:oasis:names:tc:SAML:2.0:assertion", name = "Condition")
//    public JAXBElement<DelegationRestrictionType> createCondition(DelegationRestrictionType value) {
//        return new JAXBElement<DelegationRestrictionType>(_Condition_QNAME, DelegationRestrictionType.class, null, value);
//    }

    
    /**
     * Create an instance of {@link DelegateType }
     * 
     */
    public DelegateType createDelegateType() {
        return new DelegateType();
    }    
    
    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DelegateType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "urn:oasis:names:tc:SAML:2.0:conditions:delegation", name = "Delegate")
    public JAXBElement<DelegateType> createDelegate(DelegateType value) {
        return new JAXBElement<DelegateType>(_Delegate_QNAME, DelegateType.class, null, value);
    }    
}
