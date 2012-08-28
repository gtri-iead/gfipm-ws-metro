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

/**
 *
 * Class to store the interesting contents of a certificate from the GFIPM
 * trust fabric document. This class has instance variables for holding data
 * and passing it around and a few useful methods for manipulating a certificate.
 * This class is used by the GFIPMKeystore, TrustFabric, and GFIPMTrust classes.
 * 
 * @author Stefan Roth
 *
 */
public class GFIPMCertificate {

    private static final long serialVersionUID = 6617L;

    // The entity ID from the GFIPM Trust Fabric document.
    private String entityID = null;
    
    // Service endpoint from GFIPM Trust Fabric document.
    private String serviceEndpoint = null;

    // type is "IDP" or "SP" or ... :
    private String entityType = null;
    
    public enum RoleDescriptorType { WSP, WSC, ADS };

    // key use is "signing" or "encryption" or null:
    private String keyUse = null;

    // The actual certificate ("MIIB6AKSDL...") in base64:
    private String certificate = null;

    // These are the valid characters in base 64 encoding:
    private String validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";


    // ======================================================================
    /**
     * Generic constructor for creating the class.
     * Callers must fill in values for entity id, entity type, key use, and certificate
     * after calling this constructor or use the other constructor instead.
     *
     */
    public GFIPMCertificate() {

    }

    
    // ======================================================================
    /**
     * Constructor for filling all the fields in the instance.
     *
     * @param entityID
     * The entityID from the GFIPM Trust Fabric document.
     *
     * @param entityType
     * The entity type (such as "IDP" or "SP") from the GFIPM Trust Fabric document.
     *
     * @param keyUse
     * The keyDescriptor use= as specified in the GFIPM Trust Fabric document.
     * Valid values are signing, encryption, and null.
     *
     * @param certificate
     * The X509Certificate from the GFIPM Trust Fabric document for the above specified
     * entity ID, type and keyUse.  Must be a Base64 encoded string.
     *
     */
    public GFIPMCertificate(String entityID, String entityType,
                            String keyUse, String certificate) {
        this.entityID = entityID;
        this.entityType = entityType;
        this.keyUse = keyUse;
        if (certificate != null)
            this.certificate = certificate.trim();
        else
            this.certificate = null;
    }

    // ======================================================================
    /**
     * Builds a string representation of the certificate, suitable for displaying
     * to the user such as for verbose or debugging outputs, but not suitable as
     * as unique identitifier.
     *
     * @return 
     * a string suitable for displaying or printing
     *
     */
    @Override
    public String toString () {
        StringBuilder result = new StringBuilder();
        result.append(entityID);
        result.append(", ");
        if (entityType == null)
            result.append("nul");
        else if(entityType.equals("SP"))
            result.append("SP ");
        else result.append(entityType);
        result.append(", ");
        if (keyUse == null)
            result.append("null      ");
        else if(keyUse.equals("signing"))
            result.append("signing   ");
        else
            result.append(keyUse);
        result.append(", ");
        if (certificate != null) {
            int len = certificate.length();
            if (len < 21)
                result.append(certificate);
            else {
                result.append("[");
                result.append(removeEOL(certificate.substring(0, 10)));
                result.append("..(");
                result.append(len);
                result.append(")..");
                result.append(removeEOL(certificate.substring(len - 10, len)));
                result.append("]");
            }

        } else
            result.append("null");

        return result.toString();
    }

    // ======================================================================
    /**
     * Remove all End-Of-Line characters(\n and \r) from the string.
     *
     * @param str
     * str will have all its eol characters replaced with spaces.
     *
     * @return
     * Returns the modified string.
     */
    private String removeEOL(String str) {
        if (str == null)
            return null;
        if (str.indexOf('\n') >= 0) {
            str = str.replace('\n', ' ');
        }
        if (str.indexOf('\r') >= 0) {
            str = str.replace('\r', ' ');
        }
        return str;
    }


    // ======================================================================
    /**
     * Compares the certificates in two GFIPMCertificate instances (this and
     * cert) and returns true if the certificates are the same. Returns
     * false otherwise.
     * <p>
     * Performs comparison on the base 64 encoded certificates.
     * Only looks at legal base 64 encoding characters; ignores whitespace.
     *
     * @param cert
     * Compare this certificate to cert.
     *
     * @return
     * Returns true if the two certificates are equal; false otherwise.
     *
     */
    @Override
    public boolean equals(Object cert) {

        if (! (cert instanceof GFIPMCertificate))
            return false;

        GFIPMCertificate cert2 = (GFIPMCertificate)cert;
        
        String certstr2 = cert2.getCertificate();

        int len1 = certificate.length();
        int len2 = certstr2.length();
        int i1 = 0, i2 = 0;

        while ((i1 < len1) && (i2 < len2)) {
            if (validChars.indexOf(certificate.charAt(i1)) < 0) {
                i1++;
                continue;
            }
            if (validChars.indexOf(certstr2.charAt(i2)) < 0) {
                i2++;
                continue;
            }
            if (certificate.charAt(i1) == certstr2.charAt(i2)) {
                i1++;
                i2++;
            } else
                return false;

        }  // end while
        
        return true;
    
    }  // end equals


    // ======================================================================
    @Override
    /**
     * Generates a hash code for this instance.
     */
    public int hashCode() {
        int hash = 3;
        hash = 83 * hash + (this.certificate != null ? this.certificate.hashCode() : 0);
        return hash;
    }

    // ======================================================================
    /**
     * Returns the service endpoint.
     *
     * @return
     * the service endpoint string.
     *
     */
    public String getServiceEndpoint() {
        return serviceEndpoint;
    }

    // ======================================================================
    /**
     * Sets service endpoint .
     *
     * @param 
     * the certificate string, a base 64 encoded certificate.
     *
     */
    public void setServiceEndpoint(String serviceEndpoint) {
        this.serviceEndpoint = serviceEndpoint;
    }

    // ======================================================================
    /**
     * Returns the actual certificate string, a base 64 encoded certificate.
     *
     * @return
     * the certificate string, a base 64 encoded certificate.
     *
     */
    public String getCertificate() {
        return certificate;
    }

    // ======================================================================
    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    // ======================================================================
    /**
     * Returns the entity ID as used in the GFIPM trust fabric document entity
     * descriptor entityID.
     *
     * @return
     * Return a string with the entity id.
     *
     */
    public String getEntityID() {
        return entityID;
    }

    // ======================================================================
    public void setEntityID(String entityID) {
        this.entityID = entityID;
    }

    // ======================================================================
    /**
     * Returns the entity type, either IDP or SP or possibly something else.
     *
     * @return
     * a string for the entity type, such as "IDP" or "SP".
     *
     */
    public String getEntityType() {
        return entityType;
    }

    // ======================================================================
    public void setEntityType(String entityType) {
        this.entityType = entityType;
    }

    // ======================================================================
    /**
     * Returns the certificate's use, as specified in the GFIPM trust
     * fabric document entity descriptor keyDescriptor use=.
     *
     * @return
     * a string for the key use; one of "signing" or "encryption".
     * 
     */
    public String getKeyUse() {
        return keyUse;
    }

    // ======================================================================
    public void setKeyUse(String keyUse) {
        this.keyUse = keyUse;
    }

}  // end class
