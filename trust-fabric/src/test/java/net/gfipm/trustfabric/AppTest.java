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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.xml.sax.SAXException;

/**
 * Unit test for simple App.
 */
public class AppTest
        extends TestCase {
    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AppTest(String testName) {
        super(testName);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AppTest.class);
    }

    /**
     * Rigourous Tests :-)
     */
    public void testDefault() throws IOException, SAXException, ParserConfigurationException, XPathExpressionException, CertificateException {
        String filename = "src/test/resources/metroidpm2.crt";
        // Source: http://download.oracle.com/javase/1.5.0/docs/api/java/security/cert/X509Certificate.html
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();                
        TrustFabric tf = new TrustFabric();
//        tf.printAllEntityIDs();
        tf.getAllEntityCertificates(true);
        tf.getAllEntityCertificates(false);
        String entityId = tf.getEntityId(cert);
        assertTrue(entityId == null);
    }

    public void testGetEntityIdBySEP() throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");

        String entityId = tf.getEntityIdBySEP("https://cureidpm2:8181/m2sts/services/sts");
        assertTrue("cureidpm2".equals(entityId));

        entityId = tf.getEntityIdBySEP("https://curewspm2:8181/m2wsp/services/cvc");
        assertTrue("curewspm2".equals(entityId));
        
        entityId = tf.getEntityIdBySEP("https://ha50wspm2:8553/Model2/CommercialVehicleCollisionWsp.svc");
        assertTrue("ha50wspm2".equals(entityId));
        
        entityId = tf.getEntityIdBySEP("https://curewspm2:8181/m2wsp/services/cvc/mex");
        assertTrue(entityId==null);

        entityId = tf.getEntityIdBySEP("https://curewspm2:8181/m2wsp/services");
        assertTrue(entityId==null);
    }

    public void testGetWebServiceEndpointAddress()  throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("classpath:net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        String entitySEP = tf.getWebServiceEndpointAddress("curewspm2");
        assertTrue("https://curewspm2:8181/m2wsp/services/cvc".equals(entitySEP));
    }        

    public void testGetDelegatedTokenServiceEndpointAddress()  throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("classpath:net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        String entitySEP = tf.getDelegatedTokenServiceEndpointAddress("cureidpm2");
        assertTrue("https://cureidpm2:8181/m2sts/services/sts".equals(entitySEP));
    }        

    public void testGetWsdlUrlAddress()  throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("classpath:net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        String entitySEP = tf.getWsdlUrlAddress("cureidpm2");
        assertTrue("https://cureidpm2:8181/m2sts/services/sts?wsdl".equals(entitySEP));
    }        

    public void testGetMetadataExchangeEndpointAddress()  throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("classpath:net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        String entitySEP = tf.getMetadataExchangeEndpointAddress("cureidpm2");
        assertTrue("https://cureidpm2:8181/m2sts/services/sts/mex".equals(entitySEP));
    }        

    /*
     * Source: http://download.oracle.com/javase/1.5.0/docs/api/java/security/cert/X509Certificate.html
     */
    public void testMetroCert() throws FileNotFoundException, CertificateException, IOException, SAXException, XPathExpressionException, ParserConfigurationException {
        String filename = "src/test/resources/metroidpm2.crt";
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        String entityId = tf.getEntityId(cert);
        HashMap hm = tf.getGfipmEntityAttributes(entityId);
        assertTrue(("cureidpm2".compareTo(entityId)==0));
    }   
    
    public void testIsWSP() throws IOException, SAXException, ParserConfigurationException{
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
        assertTrue(tf.isWebServiceProvider("curewspm2"));
    }

    public void testNetCert() throws FileNotFoundException, CertificateException, IOException, SAXException, XPathExpressionException, ParserConfigurationException {
        String filename = "src/test/resources/netwscm2.crt";
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");        
        String entityId = tf.getEntityId(cert);
        HashMap hm = tf.getGfipmEntityAttributes(entityId);
        assertTrue(("ha50wscm2".compareTo(entityId)==0));
    }   
    
    public void testEntityAttributesSize() throws IOException, SAXException, ParserConfigurationException, XPathExpressionException {
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");        
//        tf.setDebugOut(true);
//        tf.setVerboseOut(true);
        List<GFIPMCertificate> entityCertificates;
        entityCertificates = tf.getAllEntityCertificates(true);
        assert(entityCertificates.size() == 22);
        entityCertificates = tf.getAllEntityCertificates(false);
        assert(entityCertificates.size() == 11);
    }

    public void testGetEntityPublicKey() throws FileNotFoundException, CertificateException, IOException, SAXException, XPathExpressionException, ParserConfigurationException {
        String filename = "src/test/resources/netwscm2.crt";
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");        
        String entityId = tf.getEntityId(cert.getPublicKey());
        assertTrue(("ha50wscm2".compareTo(entityId)==0));
    }   
    
    public void testEntityAttributes() throws FileNotFoundException, CertificateException, IOException, SAXException, XPathExpressionException, ParserConfigurationException {
        String filename = "src/test/resources/netwscm2.crt";
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(inStream);
        inStream.close();
        TrustFabric tf = new TrustFabric("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");        
        String entityId = tf.getEntityId(cert.getPublicKey());
//        tf.setDebugOut(true);
//        tf.setVerboseOut(true);
        String ownerAgencyCountryCode = tf.getGfipmEntityAttribute(entityId, "gfipm:2.0:entity:OwnerAgencyCountryCode");
        assertTrue(("US".compareTo(ownerAgencyCountryCode)==0));
    }   
            
    public static void printMap(Map map) {
        System.out.println("\nMap: " + map + "\nSize = " + map.size() + ", ");
        for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
            Map.Entry e = (Map.Entry) it.next();
            System.out.println("Key/Value : " + e.getKey() + "/" + e.getValue());
        }
    }    
}
