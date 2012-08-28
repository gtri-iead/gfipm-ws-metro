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

package net.gfipm.trustfabric;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import javax.xml.xpath.XPathExpressionException;

/**
 * Trust Fabric Interface
 * @author shrom
 */
public interface TrustFabricIntf {

    /**
     * Get a list of all the GFIPM entities in the trust document and returns a
     * list of GFIPMCertificate instances (id, types, key use, certificate).
     *
     * @param collectDuplicates Flag to determine if duplicate certificate
     * strings should be added, even if the certificate is duplicated in the
     * trust fabric document.
     *
     * @return List<GFIPMCertificate>
     *
     */
    List<GFIPMCertificate> getAllEntityCertificates(boolean collectDuplicates);

    /**
     * Get entity Id from GFIPM CTF using a Public Key of that entity.
     * @param public key of the certificate.
     * @return entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     */
    String getEntityId(PublicKey publicKey);

    /**
     * Get entity Id from GFIPM CTF using X509Certificate of that entity.
     * @param X509 Certificate of the entity
     * @return entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     */
    String getEntityId(X509Certificate cert);

    /**
     * Get entity id from GFIPM CTF using Service Endpoint of that entity. 
     * @param Service Endpoint URL String of the entity
     * @return entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     */
    String getEntityIdBySEP(String sepString);

    /**
     * Get the value of a GFIPM trust fabric document Organization Extensions
     * attribute in a specific entity.
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     * @param attrname The name of a GFIPM metadata entity attribute. Ex.:
     * gfipm:2.0:entity:OwnerAgencyORI
     *
     */
    String getGfipmEntityAttribute(String entityId, String attrname);

    /**
     * Get all entity attributes in the GFIPM CTF for entity by entity Id
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     * @return hash maps of the entity attribute values.
     */
    HashMap<String, String> getGfipmEntityAttributes(String entityId);

    /**
     * Get entity type specified in the EntityDescriptor/RoleDescriptor element
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     * @return GFIPMCertificate.RoleDescriptorType Role Descriptor Type in a GFIPM
     * trust fabric document. Null if not found.
     */
    GFIPMCertificate.RoleDescriptorType getRoleDescriptorType(String entityId);

    /**
     * Check if an entity with entity is an assertion delegate service
     * 
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     * @return boolean true if an entity is an assertion delegate service
     */
    boolean isAssertionDelegateService(String entityId);

    /**
     * Check if an entity with entity is a web service consumer 
     * 
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     * @return boolean true if an entity is a web service consumer
     */
    boolean isWebServiceConsumer(String entityId);

    /**
     * Check if an entity with entity is a web service provider 
     * 
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     * @return boolean true if an entity is a web service provider
     */
    boolean isWebServiceProvider(String entityId);

    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value.
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     * @param entityType One of "IDP" or "SP" or possibly other values later.
     *
     * @param keyUse The use of the certificate. One of "signing" or
     * "encryption" or null.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    String retrieveEntityCertificate(String entityId, String entityType, String keyUse);

    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value. The key use will try
     * "signing" or "encryption" or null.
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     * @param entityType One of "IDP" or "SP" or possibly other values later.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    String retrieveEntityCertificate(String entityId, String entityType);

    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value. For entity type, this
     * method will try both IDP and SP. The key use will try "signing" or
     * "encryption" or null.
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    String retrieveEntityCertificate(String entityId);
        
    /**
     * Retrieve Web Service Endpoint Address from the GFIPM Trust Document for an Entity with entityId
     * @param entityId
     * @return Returns URL Address string
     */
    String getWebServiceEndpointAddress(String entityId);
    
    /**
     * Retrieve Delegated Token Service Endpoint Address from the GFIPM Trust Document for an Entity with entityId
     * @param entityId
     * @return Returns URL Address string
     */
    String getDelegatedTokenServiceEndpointAddress(String entityId);

    /**
     * Retrieve WSDL URL Address from the GFIPM Trust Document for an Entity with entityId
     * @param entityId
     * @return Returns URL Address string
     */
    String getWsdlUrlAddress(String entityId);

    /**
     * Retrieve Metadata Exchange Endpoint Address from the GFIPM Trust Document for an Entity with entityId
     * @param entityId
     * @return Returns URL Address string
     */
    String getMetadataExchangeEndpointAddress(String entityId);    
}
