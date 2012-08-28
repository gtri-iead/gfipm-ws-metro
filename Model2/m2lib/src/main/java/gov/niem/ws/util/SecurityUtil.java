/*
 * Copyright 2010 University of Chicago
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * NOTE: This is a _PROTOTYPE_ implementation and is not intended for
 *       production use.
 * @src https://svn.cagrid.org/trunk/cagrid/restsecurity/cagrid-restsecurity-common/src/main/java/org/cagrid/security/rest/util/SecurityUtil.java
 */

package gov.niem.ws.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.TrustedCertificateEntry;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Iterator;
import java.util.logging.Logger;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.codec.binary.Base64;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.slf4j.Logger;
//import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public class SecurityUtil {

    private static final Logger log =
        Logger.getLogger(SecurityUtil.class.getCanonicalName());
        
//    static {
//        Security.addProvider(new BouncyCastleProvider());
//    }
    
    static XMLSignatureFactory signatureFactory = null;
    static XPathExpression subjectConfirmationKeyInfoPath = null;
    static XPathExpression signatureKeyInfoPath = null;
    static XPathExpression x509Path = null;
    static XPathExpression keyModulusPath = null;
    static XPathExpression keyExponentPath = null;
    
    static CertificateFactory certFactory = null;
    static KeyFactory rsaKeyFactory = null;
    
    static NamespaceContext namespaceCtx = new NamespaceContext() {
        public String getNamespaceURI(String prefix) {
            String uri;
            if (prefix.equals("saml2"))
                uri = "urn:oasis:names:tc:SAML:2.0:assertion";
            else if (prefix.equals("ds"))
                uri = "http://www.w3.org/2000/09/xmldsig#";
            else
                uri = null;
            return uri;
        }

        public Iterator getPrefixes(String val) {
            return null;
        }

        public String getPrefix(String uri) {
            return null;
        }
    };
    
    static DocumentBuilderFactory builderFactory =
                                        DocumentBuilderFactory.newInstance(); 
    
    static {
        builderFactory.setNamespaceAware(true);
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(namespaceCtx);

        try {
            rsaKeyFactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        try {
            subjectConfirmationKeyInfoPath = xpath.compile(
                "//saml2:Assertion/saml2:Subject/saml2:SubjectConfirmation"
                 + "/saml2:SubjectConfirmationData/ds:KeyInfo");
            signatureKeyInfoPath = xpath.compile(
                "//saml2:Assertion/ds:Signature/ds:KeyInfo");
            x509Path = xpath.compile(
                "ds:X509Data/ds:X509Certificate");
            keyModulusPath = xpath.compile(
                "ds:KeyValue/ds:RSAKeyValue/ds:Modulus");
            keyExponentPath = xpath.compile(
                "ds:KeyValue/ds:RSAKeyValue/ds:Exponent");
        } catch (XPathExpressionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            certFactory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }
    static {
        try {
            signatureFactory = XMLSignatureFactory.getInstance("DOM");
        } catch (Exception err) {
            // TODO Auto-generated catch block
            err.printStackTrace();
        }
    }   

    public static KeyManager[] createKeyManagers(KeyPair clientKey,
                                          X509Certificate clientCert)
                            throws GeneralSecurityException, IOException {
        // Create a new empty key store.
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null);
    
        Certificate[] chain = { clientCert };
    
        // The KeyStore requires a password for key entries.
        char[] password = { ' ' };
    
        // Since we never write out the key store, we don't bother protecting
        // the key.
        ks.setEntry("client-key",
                new KeyStore.PrivateKeyEntry(clientKey.getPrivate(), chain),
                new KeyStore.PasswordProtection(password));
    
        // Shove the key store in a KeyManager.
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                                    KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, password);
        return kmf.getKeyManagers();
    }

//    public static TrustManager[] createTrustManagers(String trustedCAFile)
//                            throws GeneralSecurityException, IOException {
//        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
//        ks.load(null);
//    
//        // Read the cert(s). The file must contain only certs, a cast
//        // Exception will be thrown if it contains anything else.
//        // TODO: wrap in friendly exception, it's a user error not a
//        // programming error if the file contains a non-cert.
//        FileReader fileReader = new FileReader(trustedCAFile);
//        X509Certificate[] certs = PEMUtil.readCertificateChain(fileReader);
//        int i = 0;
//        for (X509Certificate cert : certs) {
//            ks.setEntry("server-ca" + i,
//                    new KeyStore.TrustedCertificateEntry(cert), null);
//            //System.out.println("trusted cert subject: "
//            //        + cert.getSubjectX500Principal());
//            //System.out.println("trusted cert issuer: "
//            //        + cert.getIssuerX500Principal());
//        }
//    
//        // Shove the key store in a TrustManager.
//        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
//                                    TrustManagerFactory.getDefaultAlgorithm());
//        tmf.init(ks);
//        return tmf.getTrustManagers();
//    }

    /**
     * Encode data with DEFLATE and then Base64 without chunking, so it can
     * safely be placed in an HTTP header.
     * 
     * @param data
     * @return the compressed, b64 encoded data
     * @throws DataFormatException
     */
    public static String encodeHeader(byte[] data) throws DataFormatException {
        // TODO: length limit on encoded?      
        ByteArrayOutputStream out = new ByteArrayOutputStream(data.length);
        Deflater deflater = new Deflater();
        deflater.setInput(data);
        deflater.finish();
        byte[] buffer = new byte[1024];
        while (!deflater.finished()) {
            int count = deflater.deflate(buffer);
            if (count == 0)
                break;
            out.write(buffer, 0, count);
        }
        
        try {
            deflater.end();
            out.close();
        } catch (IOException e) {}
              
        return new String(Base64.encodeBase64(out.toByteArray(), false));
    }

    /**
     * Decode data by Base64 decoding, then decompressing with the DEFLATE
     * algorithm; reverses encodeHeader.
     * 
     * @param encoded
     * @return the decoded, decompressed data
     * @throws DataFormatException
     */
    public static String decodeHeader(byte[] encoded) throws DataFormatException {
        // TODO: length limit on encoded?
        byte[] compressedBytes = Base64.decodeBase64(encoded);
        ByteArrayOutputStream out = new ByteArrayOutputStream(
                                                        compressedBytes.length);
        Inflater inflater = new Inflater();
        inflater.setInput(compressedBytes);
        byte[] buffer = new byte[1024];
        while (!inflater.finished()) {
            int count = inflater.inflate(buffer);
            if (count == 0)
                break;
            out.write(buffer, 0, count);
        }
        
        try {
            inflater.end();
            out.close();
        } catch (IOException e) {
        }
        
        return new String(out.toByteArray());
    }

    public static boolean validateDocumentSignature(Document signedDoc,
                                                    Key publicKey)
    throws MarshalException, XMLSignatureException {
        if (signedDoc == null)
            throw new IllegalArgumentException("Signed Document is null");
        NodeList nl = signedDoc.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nl == null || nl.getLength() == 0) {
            throw new IllegalArgumentException("Cannot find Signature element");
        }
        if (publicKey == null)
            throw new IllegalArgumentException("Public Key is null");   
        
        DOMValidateContext valContext = new DOMValidateContext(publicKey, nl.item(0));
        XMLSignature signature = signatureFactory.unmarshalXMLSignature(valContext);
        boolean coreValidity = signature.validate(valContext);
        
        if (!coreValidity) {
            boolean sv = signature.getSignatureValue().validate(valContext);
            log.fine("Signature validation status: " + sv);
        }
    
        return coreValidity;
    }

    public static X509Certificate getCertificateFromKeyInfo(Node keyInfoNode)
            throws ParserConfigurationException, SAXException, IOException {
        X509Certificate cert = null;
    
        try {
            String s = x509Path.evaluate(keyInfoNode);
            if (s == null || s.length() == 0)
                return null;
            byte[] decoded = Base64.decodeBase64(s);
            cert = (X509Certificate) certFactory
                    .generateCertificate(new ByteArrayInputStream(decoded));
        } catch (XPathExpressionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        return cert;
    }

    public static PublicKey getPublicKeyFromKeyInfo(Node keyInfoNode)
            throws ParserConfigurationException, SAXException, IOException {
        PublicKey publicKey = null;       
    
        try {
            String modulusString = keyModulusPath.evaluate(keyInfoNode);
            String exponentString = keyExponentPath.evaluate(keyInfoNode);
            if (modulusString == null || exponentString == null) {
                return null;
            }
            byte[] modulusBytes = Base64.decodeBase64(modulusString);
            BigInteger modulus = new BigInteger(1, modulusBytes);
            byte[] exponentBytes = Base64.decodeBase64(exponentString);
            BigInteger exponent = new BigInteger(1, exponentBytes);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            publicKey = rsaKeyFactory.generatePublic(keySpec);
        } catch (XPathExpressionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return publicKey;
    }
    
    public static PublicKey getSignaturePublicKey(Document assertion)
    throws ParserConfigurationException, SAXException, IOException {
        Node keyInfoNode = null;
        try {
            keyInfoNode = (Node)signatureKeyInfoPath.evaluate(assertion,
                                                              XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return null;
        }
        if (keyInfoNode == null) {
            return null;
        }
        
        X509Certificate signatureCert = getCertificateFromKeyInfo(keyInfoNode);
        if (signatureCert != null) {
            return signatureCert.getPublicKey();
        }
        
        return getPublicKeyFromKeyInfo(keyInfoNode);
    }
    
    public static Document parseDocument(String xmlString)
    throws SAXException, IOException, ParserConfigurationException {
        DocumentBuilder builder = builderFactory.newDocumentBuilder();
        return builder.parse(new ByteArrayInputStream(xmlString.getBytes()));
    }

    /**
     * Check that the certificate in the holder of key assertion matches
     * the passed certificate, sent via another channel (e.g. SSL client auth).
     * The certificate must be validated separately, before making this call.
     * @param assertion SAML holder of key assertion.
     * @param presentedCert certificate claimed to be presented in the HoK.
     * @return
     * @throws IOException 
     * @throws SAXException 
     * @throws ParserConfigurationException 
     */
    public static boolean confirmHolderOfKey(Document assertion,
                                           X509Certificate presentedCert)
    throws ParserConfigurationException, SAXException, IOException {
        Node keyInfoNode = null;
        try {
            keyInfoNode = (Node)subjectConfirmationKeyInfoPath.evaluate(
                                            assertion, XPathConstants.NODE);
        } catch (XPathExpressionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            return false;
        }
        if (keyInfoNode == null) {
            System.out.println("key info not found in subject confirmation");
            return false;
        }
        X509Certificate assertionCert = getCertificateFromKeyInfo(keyInfoNode);
        if (assertionCert != null) {
            return assertionCert.equals(presentedCert);
        }
        
        PublicKey publicKey = getPublicKeyFromKeyInfo(keyInfoNode);
        if (publicKey != null) {
            return publicKey.equals(presentedCert.getPublicKey());
        }
        
        return false;
    }
}
