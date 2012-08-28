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

import com.sun.xml.ws.api.security.trust.WSTrustException;
import com.sun.xml.wss.impl.dsig.WSSPolicyConsumerImpl;
import com.sun.xml.wss.impl.dsig.WSSPolicyConsumerImpl.WSSProvider;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.CertificateException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import java.io.FileInputStream;
import java.security.*;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Document;

import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;

import com.sun.xml.wss.impl.policy.mls.AuthenticationTokenPolicy;
import com.sun.xml.wss.impl.policy.mls.SignaturePolicy;
import com.sun.xml.wss.impl.MessageConstants;
import com.sun.xml.wss.impl.SecurableSoapMessage;
import com.sun.xml.wss.impl.XMLUtil;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.core.ReferenceElement;
import com.sun.xml.wss.core.SecurityToken;
import com.sun.xml.wss.core.SecurityTokenReference;
import com.sun.xml.wss.core.X509SecurityToken;
import com.sun.xml.wss.core.reference.DirectReference;
import com.sun.xml.wss.core.reference.KeyIdentifier;
import com.sun.xml.wss.core.EncryptedKeyToken;
import com.sun.xml.wss.core.KeyInfoHeaderBlock;
import com.sun.xml.wss.core.SecurityContextTokenImpl;
import com.sun.xml.ws.security.SecurityContextToken;
import com.sun.xml.ws.security.trust.WSTrustElementFactory;
import com.sun.xml.ws.security.trust.elements.BinarySecret;
import com.sun.xml.wss.core.DerivedKeyTokenHeaderBlock;

import com.sun.xml.wss.impl.AlgorithmSuite;
import com.sun.xml.wss.impl.FilterProcessingContext;
import com.sun.xml.wss.impl.misc.DefaultSecurityEnvironmentImpl;
//import com.sun.xml.wss.impl.misc.Base64;

import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.util.SAMLUtil;

import java.math.BigInteger;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import com.sun.xml.wss.impl.policy.MLSPolicy;
import com.sun.xml.wss.impl.policy.mls.DerivedTokenKeyBinding;
import com.sun.xml.wss.impl.policy.mls.SymmetricKeyBinding;
import com.sun.xml.wss.impl.policy.mls.SecureConversationTokenKeyBinding;
import com.sun.xml.wss.impl.policy.mls.IssuedTokenKeyBinding;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import javax.xml.soap.SOAPElement;
import javax.xml.namespace.QName;

import com.sun.xml.wss.impl.PolicyTypeUtil;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.sun.xml.wss.impl.policy.SecurityPolicy;
import com.sun.xml.wss.impl.policy.mls.WSSPolicy;
import com.sun.xml.wss.impl.policy.mls.MessagePolicy;
import com.sun.xml.wss.impl.PolicyTypeUtil;
import com.sun.xml.wss.impl.misc.SecurityUtil;


import com.sun.xml.wss.logging.impl.dsig.LogStringsMessages;
import com.sun.xml.wss.saml.SAMLException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;

import com.sun.xml.ws.api.security.secconv.client.SCTokenConfiguration;
import com.sun.xml.wss.impl.FilterProcessingContext;
import com.sun.xml.wss.impl.policy.mls.AuthenticationTokenPolicy;
import com.sun.xml.wss.impl.policy.mls.SignaturePolicy;
import com.sun.xml.wss.logging.LogDomainConstants;
import com.sun.xml.wss.impl.MessageConstants;
import com.sun.xml.wss.impl.SecurableSoapMessage;
import com.sun.xml.wss.impl.XMLUtil;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.saml.AssertionUtil;
import com.sun.xml.wss.saml.SAMLException;
import com.sun.xml.wss.core.ReferenceElement;
import com.sun.xml.wss.core.SecurityToken;
import com.sun.xml.wss.core.SecurityTokenReference;
import com.sun.xml.wss.core.X509SecurityToken;
import com.sun.xml.wss.core.reference.DirectReference;
import com.sun.xml.wss.core.reference.KeyIdentifier;
import com.sun.xml.wss.core.EncryptedKeyToken;
import com.sun.xml.wss.core.KeyInfoHeaderBlock;
import com.sun.xml.wss.core.SecurityContextTokenImpl;
import com.sun.xml.ws.security.SecurityContextToken;
import com.sun.xml.wss.core.DerivedKeyTokenHeaderBlock;
import com.sun.xml.ws.security.impl.DerivedKeyTokenImpl;
import com.sun.xml.ws.security.DerivedKeyToken;

import com.sun.xml.ws.security.IssuedTokenContext;

import com.sun.xml.wss.impl.misc.DefaultSecurityEnvironmentImpl;
//import com.sun.xml.wss.impl.misc.Base64;

import com.sun.xml.wss.saml.Assertion;
import com.sun.xml.wss.saml.util.SAMLUtil;

import java.math.BigInteger;

import java.security.Key;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.crypto.AlgorithmMethod;
import javax.xml.crypto.KeySelector;
import javax.xml.crypto.KeySelectorException;
import javax.xml.crypto.KeySelectorResult;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.NodeSetData;
import javax.xml.crypto.URIDereferencer;
import javax.xml.crypto.URIReference;
import javax.xml.crypto.URIReferenceException;
import javax.xml.crypto.XMLCryptoContext;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.KeySelector.Purpose;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyName;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;
import com.sun.xml.wss.impl.policy.MLSPolicy;
import com.sun.xml.wss.impl.policy.mls.DerivedTokenKeyBinding;
import com.sun.xml.wss.impl.policy.mls.SymmetricKeyBinding;
import com.sun.xml.wss.impl.policy.mls.SecureConversationTokenKeyBinding;
import com.sun.xml.wss.impl.policy.mls.IssuedTokenKeyBinding;

import javax.xml.soap.SOAPElement;
import javax.xml.namespace.QName;

import com.sun.xml.wss.impl.policy.SecurityPolicy;
import com.sun.xml.wss.impl.policy.mls.WSSPolicy;
import com.sun.xml.wss.impl.policy.mls.MessagePolicy;
import com.sun.xml.wss.impl.PolicyTypeUtil;

import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.crypto.spec.SecretKeySpec;

import com.sun.xml.wss.impl.misc.SecurityUtil;
import com.sun.xml.wss.impl.AlgorithmSuite;

import com.sun.xml.ws.security.trust.elements.BinarySecret;
import com.sun.xml.ws.security.trust.WSTrustElementFactory;
import com.sun.xml.ws.api.security.trust.WSTrustException;
import com.sun.xml.ws.api.security.trust.client.IssuedTokenManager;

import com.sun.xml.wss.impl.misc.KeyResolver;
//import javax.security.auth.Subject;
import com.sun.xml.wss.saml.Subject;
import com.sun.xml.ws.runtime.dev.SessionManager;
import com.sun.xml.ws.security.SecurityContextTokenInfo;
import com.sun.xml.ws.security.secconv.WSSecureConversationException;
import com.sun.xml.ws.security.secconv.impl.client.DefaultSCTokenConfiguration;
import com.sun.xml.wss.core.SecurityHeader;
import com.sun.xml.wss.impl.dsig.KeySelectorImpl;
import com.sun.xml.wss.impl.dsig.SignatureProcessor;
import com.sun.xml.wss.logging.impl.dsig.LogStringsMessages;
import com.sun.xml.wss.saml.Conditions;
import com.sun.xml.wss.saml.NameID;
import com.sun.xml.wss.saml.SAMLAssertionFactory;
import com.sun.xml.wss.saml.SubjectConfirmation;
import java.io.FileOutputStream;
import java.io.OutputStream;
import java.net.URI;

import java.util.ArrayList;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.LinkedList;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBodyElement;
import org.w3c.dom.Document;
import javax.xml.soap.SOAPMessage;
import javax.xml.parsers.DocumentBuilderFactory;
import com.sun.xml.wss.impl.dsig.DSigResolver;

public class Validate {

    public static void main(String[] args) throws Exception {


        String fileName = args[0];
        String idString = args[1];

        // Instantiate the document to be validated
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        Document doc = dbf.newDocumentBuilder().parse(new FileInputStream(fileName));

        System.out.println("Loaded document from file " + fileName);

        // Load the KeyStore and get the signing key and certificate.
        KeyStore.PrivateKeyEntry keyEntry = getKeyEntry("curewscm2-keystore.jks", "changeit", "curewscm2");
        X509Certificate cert = (X509Certificate) keyEntry.getCertificate();

        // Create a DOM XMLSignatureFactory that will be used to generate the enveloped signature.
        XMLSignatureFactory facS = XMLSignatureFactory.getInstance("DOM");
        System.out.println("XMLSignatureFactory provider :" + facS.getProvider().getClass().getCanonicalName());

        //http://java.sun.com/developer/technicalArticles/xml/dig_signatures/
        DigestMethod digestMethod = facS.newDigestMethod(DigestMethod.SHA1, null);

        //WSSPolicyConsumerImpl.java
        Reference refS = null;
        if (true) {
            List<String> prefix = Collections.synchronizedList(new ArrayList<String>());
            prefix.add("saml2");
            prefix.add("ds");            
//            TransformParameterSpec transformParameterSpec = new ExcC14NParameterSpec(prefix);
//            TransformParameterSpec transformParameterSpec = new ExcC14NParameterSpec();
            TransformParameterSpec transformParameterSpec = null;
            
            Transform transform = facS.newTransform(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, transformParameterSpec);
            ArrayList transformList = new ArrayList(2);
            transformList.add(transform);
            refS = facS.newReference("#"+ idString, digestMethod, transformList, null, null);
        } else {
            refS = facS.newReference("#"+ idString, digestMethod);
        }


        //import javax.xml.crypto.dsig.spec.ExcC14NParameterSpec;
        CanonicalizationMethod cm = facS.newCanonicalizationMethod(MessageConstants.TRANSFORM_C14N_EXCL_OMIT_COMMENTS, (C14NMethodParameterSpec) null);
        SignatureMethod sm = facS.newSignatureMethod(SignatureMethod.RSA_SHA1, null);
        SignedInfo signedInfo = facS.newSignedInfo(cm, sm, Collections.singletonList(refS));

        //KeyInfoFactory keyFactory = KeyInfoFactory.getInstance();
        KeyInfoFactory keyFactory = facS.getKeyInfoFactory();
        KeyValue keyValue = keyFactory.newKeyValue(keyEntry.getCertificate().getPublicKey());

        //SecurityTokenReference tokenReference = new SecurityTokenReference();
        //DOMStructure domKeyInfo = new DOMStructure(tokenReference);

        KeyInfo keyInfo =
                keyFactory.newKeyInfo(Collections.singletonList(keyValue));
        XMLSignature signatureX = facS.newXMLSignature(signedInfo, keyInfo);

        // Create a DOMSignContext and set the signing Key to the DSA 
        // PrivateKey and specify where the XMLSignature should be inserted 
        // in the target document (in this case, the document root)
        DOMSignContext signContext = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement().getElementsByTagNameNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", "Security").item(0));
        //DOMSignContext signContext = new DOMSignContext(keyEntry.getPrivateKey(), doc.getDocumentElement());
//        signContext.setURIDereferencer(DSigResolver.getInstance());
//        signContext.setURIDereferencer(new URIResolverImpl());
//        signContext.setURIDereferencer(new com.sun.xml.wss.impl.resolver.URIResolver());
//        signContext.setURIDereferencer(facS.getURIDereferencer());

//        signContext.putNamespacePrefix(MessageConstants.DSIG_NS, MessageConstants.DSIG_PREFIX);
        signatureX.sign(signContext);

        Reference referenceX = (Reference) signatureX.getSignedInfo().getReferences().get(0);
        byte[] digestValue = referenceX.getDigestValue();
        String s = new sun.misc.BASE64Encoder().encode(digestValue);
        System.out.println("Digest value " + s);

        outputDocument(doc, fileName);

    }

    private static PrivateKeyEntry getKeyEntry(String keyStoreFileNameString, String pwd, String keyAlias) throws KeyStoreException, IOException, NoSuchAlgorithmException, UnrecoverableEntryException, CertificateException {
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(new FileInputStream(keyStoreFileNameString), pwd.toCharArray());
        KeyStore.PrivateKeyEntry keyEntry =
                (KeyStore.PrivateKeyEntry) ks.getEntry(keyAlias, new KeyStore.PasswordProtection(pwd.toCharArray()));
        return keyEntry;
    }

    public static void outputDocument(Node doc, String fileName) throws FileNotFoundException, TransformerConfigurationException, TransformerException {

        // Output the resulting document.
        OutputStream os = new FileOutputStream("signed" + fileName);
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        trans.transform(new DOMSource(doc), new StreamResult(os));

    }
}
