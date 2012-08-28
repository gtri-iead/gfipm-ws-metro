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

import com.sun.org.apache.xml.internal.security.keys.KeyInfo;
import com.sun.xml.ws.api.security.trust.STSAttributeProvider;
import com.sun.xml.ws.api.security.trust.STSTokenProvider;
import com.sun.xml.ws.api.security.trust.WSTrustException;
import com.sun.xml.ws.security.IssuedTokenContext;
import com.sun.xml.ws.security.trust.GenericToken;
import com.sun.xml.ws.security.trust.WSTrustConstants;
import com.sun.xml.ws.security.trust.WSTrustVersion;
import com.sun.xml.ws.security.trust.elements.str.SecurityTokenReference;
import com.sun.xml.ws.security.trust.impl.DefaultSAMLTokenProvider;
import com.sun.xml.ws.security.trust.logging.LogStringsMessages;
import com.sun.xml.ws.security.trust.util.WSTrustUtil;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.MessageConstants;
import com.sun.xml.wss.impl.dsig.WSSPolicyConsumerImpl;
import com.sun.xml.wss.saml.*;
import com.sun.xml.wss.saml.internal.saml20.jaxb20.AudienceRestrictionType;
import com.sun.xml.wss.saml.internal.saml20.jaxb20.ConditionAbstractType;
import com.sun.xml.wss.saml.util.SAMLUtil;
import gov.niem.ws.util.GFIPMUtil;
import gov.niem.ws.util.GFIPMWSTrustUtil;
import gov.niem.ws.util.SecurityUtil;
import gov.niem.ws.util.jaxb.delegate.DelegateType;
import gov.niem.ws.util.jaxb.delegate.DelegationRestrictionType;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.Subject;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import net.gfipm.trustfabric.TrustFabric;
import net.gfipm.trustfabric.TrustFabricFactory;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * Class provides implementation of the GFIPM SAML 2.0 Token Provider.
 *
 * @author shrom
 */
public class GFIPMSTSTokenProvider extends DefaultSAMLTokenProvider implements STSTokenProvider {

    private static final Logger logger =
            Logger.getLogger(GFIPMSTSTokenProvider.class.getName());
    private static final boolean DEBUG = true;
    private static TrustFabric tf;

    static {
        tf = TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
    }

    @Override
    public void generateToken(IssuedTokenContext ctx) throws WSTrustException {

        String issuer = ctx.getTokenIssuer();
        String appliesTo = ctx.getAppliesTo();
        String tokenType = ctx.getTokenType();
        String keyType = ctx.getKeyType();
        String oboString = (String) ctx.getOtherProperties().get("OnBehalfOf");
        String confirMethod = (String) ctx.getOtherProperties().get(IssuedTokenContext.CONFIRMATION_METHOD);

        if (DEBUG) {
            logger.log(Level.FINEST, "STS Token Provider:\n"
                    + "  \n\tIssuer: " + issuer
                    + "  \n\tappliesTo: " + appliesTo
                    + "  \n\ttokenType: " + tokenType
                    + "  \n\tkeyType: " + keyType
                    + "  \n\tOnBehalfOf: " + oboString
                    + "  \n\tConfirmation Method: " + confirMethod
                    + "  \n\tEncryption alg" + ctx.getEncryptionAlgorithm()
                    + "  \n\tSignature alg" + ctx.getSignatureAlgorithm()
                    + "  \n\tCanon alg" + ctx.getCanonicalizationAlgorithm());
        }

        if ((appliesTo == null) || appliesTo.isEmpty()) {
            throw new WSTrustException("STS Token Provider: AppliesTo must have a value.");
        }

        if (!(WSTrustConstants.SAML20_ASSERTION_TOKEN_TYPE.equals(tokenType)
                || WSTrustConstants.SAML20_WSS_TOKEN_TYPE.equals(tokenType))) {
            logger.log(Level.SEVERE, LogStringsMessages.WST_0031_UNSUPPORTED_TOKEN_TYPE(tokenType, appliesTo));
            throw new WSTrustException(LogStringsMessages.WST_0031_UNSUPPORTED_TOKEN_TYPE(tokenType, appliesTo));
        }

        //Enable Sender Vouches profile on STS. 
        //For details see Metro Sources wsit\ws-sx\wssx-impl\src\main\java\com\sun\xml\ws\security\trust\impl\WSTrustContractImpl.java
        //Also see bug http://java.net/jira/browse/WSIT-1401
        ctx.getOtherProperties().put(IssuedTokenContext.CONFIRMATION_METHOD, SAML_SENDER_VOUCHES_2_0);
        confirMethod = (String) ctx.getOtherProperties().get(IssuedTokenContext.CONFIRMATION_METHOD);
        if (DEBUG) {
            logger.log(Level.FINEST, "STS Token Provider: new subect confirmation method is set: " + confirMethod);
        }

//        if (DEBUG) {
//            Map<String, Object> otherPropertiesMap = ctx.getOtherProperties();
//            GFIPMUtil.printMap("IssuedTokenContext : Other Properties Map", otherPropertiesMap);
//        }

        int tokenLifeSpan = (int) (ctx.getExpirationTime().getTime() - ctx.getCreationTime().getTime());
        Map<QName, List<String>> claimedAttrs = (Map<QName, List<String>>) ctx.getOtherProperties().get(IssuedTokenContext.CLAIMED_ATTRUBUTES);
        WSTrustVersion wstVer = (WSTrustVersion) ctx.getOtherProperties().get(IssuedTokenContext.WS_TRUST_VERSION);
//         WSTrustElementFactory eleFac = WSTrustElementFactory.newInstance(wstVer);

        //EntityId which is requesting token
        String delegateId = null;
        Element onBehalfOfToken = null;
        Subject subj = ctx.getRequestorSubject();

        //could be simplified
//           Set<X509Certificate> subjectX509Certificate = subj.getPublicCredentials(X509Certificate.class);           
        Set<Object> publicCred = subj.getPublicCredentials();
        for (Iterator<Object> it = publicCred.iterator(); it.hasNext();) {
            Object publicCredentialsObject = it.next();
            if (publicCredentialsObject instanceof X509Certificate) {
                X509Certificate subjectX509Certificate = (X509Certificate) publicCredentialsObject;
                //Delegate ID is determined from Entity Certificate number.
                delegateId = tf.getEntityId(subjectX509Certificate);
                if (DEBUG) {
                    logger.log(Level.FINEST, "STS Token Provider: Got the following entity from public cert: " + delegateId + " Certificate " + subjectX509Certificate.getSubjectDN().getName());
                }
            } else if (publicCredentialsObject instanceof Element) {
                onBehalfOfToken = (Element) publicCredentialsObject;
                if (DEBUG) {
                    logger.log(Level.FINEST, "STS Token Provider:: Got the following OnBehalfOf token included: \n" + GFIPMUtil.putOutAsString(onBehalfOfToken));
                }
//            } else if ( publicCredentialsObject instanceof com.sun.enterprise.security.auth.login.DistinguishedPrincipalCredential ){
//                com.sun.enterprise.security.auth.login.DistinguishedPrincipalCredential distinguishedPrincipalCredential = (com.sun.enterprise.security.auth.login.DistinguishedPrincipalCredential) publicCredentialsObject;
            } else {
                if (DEBUG) {
                    logger.log(Level.FINEST, "Unknown object in public credentials " + publicCredentialsObject);
                }
            }
        }

        String authnCtx = (String) ctx.getOtherProperties().get(IssuedTokenContext.AUTHN_CONTEXT);

        //If we have OnBehalfOf request to ADS then we should use EntityId for appliesTo rather than entity SEP URL
        if (Boolean.parseBoolean(oboString)) {
            if (delegateId == null) {
                throw new WSTrustException("STS Token Provider: OnBehalfOf request specified from WSC that could not be located in GFIPM TF.");
            }
            Assertion assertionOnBehalfOfToken = validateOnBehafOfToken(onBehalfOfToken);
            X509Certificate x509CertificateTarget = (X509Certificate) ctx.getOtherProperties().get(IssuedTokenContext.TARGET_SERVICE_CERTIFICATE);
            String targetServiceId = tf.getEntityId(x509CertificateTarget);
            if (DEBUG) {
                logger.log(Level.FINEST, "STS: Target service Id = " + targetServiceId);
            }
            if (targetServiceId == null || (!tf.isWebServiceProvider(targetServiceId))) {
                throw new WSTrustException("STS Token Provider: OnBehalfOf request specified with AppliesTo that could not be located in GFIPM CTF or is not a WSP: " + appliesTo);
            }
            //Use Entity Id from CTF istead of URL so when this token is received back it could be verified with delegate Id based on the requestor certificate
            appliesTo = targetServiceId;

            //If authntication context is already provided from the incoming token copy it from there.            
            authnCtx = getAuthContextClassRef(assertionOnBehalfOfToken);
        }
        if (DEBUG) {
            logger.log(Level.FINEST, "STS: AppliesTo = " + appliesTo);
            logger.log(Level.FINEST, "STS: Authentication Context = " + authnCtx);
        }

        // Create the KeyInfo for SubjectConfirmation
//        final KeyInfo keyInfo = createKeyInfo(ctx);
        // We don't need keyInfo for SenderVouches.
        final KeyInfo keyInfo = null;

        // Create AssertionID
        final String assertionId = "uuid-" + UUID.randomUUID().toString();

        //Create SAML assertion and the reference to the SAML assertion
        Assertion assertion = null;
        SecurityTokenReference samlReference = null;
        assertion = createSAML20Assertion(wstVer, tokenLifeSpan, confirMethod, assertionId, issuer, appliesTo, keyInfo, claimedAttrs, keyType, authnCtx, delegateId);
        samlReference = WSTrustUtil.createSecurityTokenReference(assertionId, MessageConstants.WSSE_SAML_v2_0_KEY_IDENTIFIER_VALUE_TYPE);
        //set TokenType attribute for the STR as required in wss 1.1 saml token profile
        samlReference.setTokenType(WSTrustConstants.SAML20_WSS_TOKEN_TYPE);

        // Get the STS's certificate and private key
        final X509Certificate stsCert = (X509Certificate) ctx.getOtherProperties().get(IssuedTokenContext.STS_CERTIFICATE);
        final PrivateKey stsPrivKey = (PrivateKey) ctx.getOtherProperties().get(IssuedTokenContext.STS_PRIVATE_KEY);

        // Sign the assertion with STS's private key
        Element signedAssertion = null;
        try {
            XMLSignatureFactory fac = WSSPolicyConsumerImpl.getInstance().getSignatureFactory();
            signedAssertion = assertion.sign(fac.newDigestMethod(MessageConstants.SHA256, null), MessageConstants.RSA_SHA256_SIGMETHOD, stsCert, stsPrivKey, true);
            //if other methods are used then SignatureMethod defautls to SignatureMethod.RSA_SHA1 and DigestMethod to DigestMethod.SHA1
            //signedAssertion = assertion.sign(stsCert, stsPrivKey, true, ctx.getSignatureAlgorithm(), ctx.getCanonicalizationAlgorithm());
            //signedAssertion = assertion.sign(stsCert, stsPrivKey, true);            
            //signedAssertion = assertion.sign(stsCert, stsPrivKey);
        } catch (NoSuchAlgorithmException ex) {
            logger.log(Level.SEVERE,
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
            throw new WSTrustException(
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
        } catch (InvalidAlgorithmParameterException ex) {
            logger.log(Level.SEVERE,
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
            throw new WSTrustException(
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
        } catch (SAMLException ex) {
            logger.log(Level.SEVERE,
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
            throw new WSTrustException(
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
        }

        // put the SAML assertion and the references in the context
        ctx.setSecurityToken(new GenericToken(signedAssertion));
        ctx.setAttachedSecurityTokenReference(samlReference);
        ctx.setUnAttachedSecurityTokenReference(samlReference);
    }

    protected Assertion createSAML20Assertion(final WSTrustVersion wstVer,
            final int lifeSpan, String confirMethod,
            final String assertionId,
            final String issuer,
            final String appliesTo,
            final KeyInfo keyInfo,
            final Map<QName, List<String>> claimedAttrs,
            String keyType,
            String authnCtx,
            String delegateId)
            throws WSTrustException {

        if (DEBUG) {
            logger.log(Level.FINEST, "STS Token Provider: createSAML20Assertion :: \n"
                    + "\n\t WSTrustVersion = " + wstVer
                    + "\n\t lifeSpan = " + lifeSpan
                    + "\n\t confirMethod = " + confirMethod
                    + "\n\t assertionId = " + assertionId
                    + "\n\t issuer = " + issuer
                    + "\n\t appliesTo" + appliesTo
                    + "\n\t keyInfo = " + keyInfo
                    + "\n\t keyType = " + keyType
                    + "\n\t authnCtx = " + authnCtx
                    + "\n\t delegateId = " + delegateId);
        }

        Assertion assertion = null;
        try {
            final SAMLAssertionFactory samlFac = SAMLAssertionFactory.newInstance(SAMLAssertionFactory.SAML2_0);

            // Create Conditions
            final TimeZone utcTimeZone = TimeZone.getTimeZone("UTC");
            final GregorianCalendar issueInst = new GregorianCalendar(utcTimeZone);
            final GregorianCalendar notOnOrAfter = new GregorianCalendar(utcTimeZone);
            notOnOrAfter.add(Calendar.MILLISECOND, lifeSpan);

            List<AudienceRestriction> arc = null;
            if (appliesTo != null) {
                arc = new ArrayList<AudienceRestriction>();
                List<String> au = new ArrayList<String>();
                au.add(appliesTo);
                arc.add(samlFac.createAudienceRestriction(au));
            }
            KeyInfoConfirmationData keyInfoConfData = null;
            if (keyType.equals(wstVer.getBearerKeyTypeURI())) {
                confirMethod = SAML_BEARER_2_0;
            } else {
                if (confirMethod == null) {
                    confirMethod = SAML_HOLDER_OF_KEY_2_0;
                }
                if (keyInfo != null) {
                    keyInfoConfData = samlFac.createKeyInfoConfirmationData(keyInfo.getElement());
                }
            }

            //Create NameId for the subject confirmation
            NameID subjectConfirmationNameId = null;
            if (delegateId != null) {
                subjectConfirmationNameId = samlFac.createNameID(delegateId, null, null);
            }

            final SubjectConfirmation subjectConfirm = samlFac.createSubjectConfirmation(
                    subjectConfirmationNameId, keyInfoConfData, confirMethod);

            com.sun.xml.wss.saml.Subject subj = null;
            //final List<Attribute> attrs = new ArrayList<Attribute>();
            QName idName = null;
            String id = null;
            String idNS = null;
            if (DEBUG) {
                logger.log(Level.FINEST, "STS Token Provider:: claimed attrs");
            }
            final Set<Map.Entry<QName, List<String>>> entries = claimedAttrs.entrySet();
            for (Map.Entry<QName, List<String>> entry : entries) {
                final QName attrKey = entry.getKey();
                final List<String> values = entry.getValue();
                if (DEBUG) {
                    logger.log(Level.FINEST, " atrKey: " + attrKey.getLocalPart() + " attr values: " + values);
                }
                if (values != null) {
                    if ("ActAs".equals(attrKey.getLocalPart())) {
                        if (values.size() > 0) {
                            id = values.get(0);
                        } else {
                            id = null;
                        }
                        idNS = attrKey.getNamespaceURI();
                        idName = attrKey;

                        break;
                    } else if (STSAttributeProvider.NAME_IDENTIFIER.equals(attrKey.getLocalPart()) && subj == null) {
                        if (values.size() > 0) {
                            id = values.get(0);
                        }
                        idNS = attrKey.getNamespaceURI();
                        idName = attrKey;
                    }
                    //else{
                    //  final Attribute attr = samlFac.createAttribute(attrKey.getLocalPart(), attrKey.getNamespaceURI(), values);
                    //  attrs.add(attr);
                    //}
                }
            }

            NameID nameId = null;
            if (idName != null && id != null) {
                nameId = samlFac.createNameID(id, idNS, null);
                claimedAttrs.remove(idName);
            }
            subj = samlFac.createSubject(nameId, subjectConfirm);

            //This will not work due to a bug in com.sun.xml.wss.saml.assertion.saml20.jaxb20.Conditions.java
//            List <Condition> conditionList = new ArrayList<Condition>();
//            final Conditions conditions = samlFac.createConditions(issueInst, notOnOrAfter, conditionList, arc, null, null);
            //Instead we'll have to obtain and add list manually (see SAML20JAXBUtil, JAXBUtil for details)
            final Conditions conditions = samlFac.createConditions(issueInst, notOnOrAfter, null, arc, null, null);

            List<ConditionAbstractType> conditionOrAudienceRestrictionOrOneTimeUseList =
                    ((com.sun.xml.wss.saml.assertion.saml20.jaxb20.Conditions) conditions).getConditionOrAudienceRestrictionOrOneTimeUse();
            if (delegateId != null) {
                List<com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition> cond = null;
                cond = getCondition(delegateId);
                conditionOrAudienceRestrictionOrOneTimeUseList.addAll(cond);
            }

            final List<Object> statements = new ArrayList<Object>();

            //The default Metro behaviour is to produce either AuthnStatement or AttributeStatement, but not both. 
            //See bug: http://java.net/jira/browse/WSIT-1580
//            if (claimedAttrs.isEmpty()) {
//                System.out.println("STS: in claimedAttrs, authentication context: " + authnCtx);
//                AuthnContext ctx = samlFac.createAuthnContext(authnCtx, null);
//                SubjectLocality subjectLocality = samlFac.createSubjectLocality("10.50.12.20", "gtri.gatech.edu");
//                final AuthnStatement statement = samlFac.createAuthnStatement(issueInst, subjectLocality, ctx, null, null);
//                statements.add(statement);
//            } else {
//                System.out.println("STS: claimedAttrs are empty ");
//                final AttributeStatement statement = samlFac.createAttributeStatement(null);
//                statements.add(statement);
//            }

            AuthnContext ctx = samlFac.createAuthnContext(authnCtx, null);
            final AuthnStatement authnStatement = samlFac.createAuthnStatement(issueInst, null, ctx, null, null);
            statements.add(authnStatement);
            final AttributeStatement attributeStatement = samlFac.createAttributeStatement(null);
            statements.add(attributeStatement);

            final NameID issuerID = samlFac.createNameID(issuer, null, null);

            //Create Assertion
            assertion =
                    samlFac.createAssertion(assertionId, issuerID, issueInst, conditions, null, null, statements);
            if (!claimedAttrs.isEmpty()) {
//                assertion = WSTrustUtil.addSamlAttributes(assertion, claimedAttrs);
                assertion = GFIPMWSTrustUtil.addSamlAttributes(assertion, claimedAttrs);
            }
            ((com.sun.xml.wss.saml.assertion.saml20.jaxb20.Assertion) assertion).setSubject((com.sun.xml.wss.saml.internal.saml20.jaxb20.SubjectType) subj);
        } catch (SAMLException ex) {
            logger.log(Level.SEVERE,
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
            throw new WSTrustException(
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
        } catch (XWSSecurityException ex) {
            logger.log(Level.SEVERE,
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
            throw new WSTrustException(
                    LogStringsMessages.WST_0032_ERROR_CREATING_SAML_ASSERTION(), ex);
        }

        return assertion;
    }
//
//    @Override
//    public void isValideToken(IssuedTokenContext ctx) throws WSTrustException {
//        throw new UnsupportedOperationException("Not supported yet.");
//    }
//
//    @Override
//    public void renewToken(IssuedTokenContext ctx) throws WSTrustException {
//        throw new UnsupportedOperationException("Not supported yet.");
//    }
//
//    @Override
//    public void invalidateToken(IssuedTokenContext ctx) throws WSTrustException {
//        throw new UnsupportedOperationException("Not supported yet.");
//    }

//    private KeyInfo createKeyInfo(final IssuedTokenContext ctx) throws WSTrustException {
//        Element kiEle = (Element) ctx.getOtherProperties().get("ConfirmationKeyInfo");
//        if (kiEle != null && "KeyInfo".equals(kiEle.getLocalName())) {
//            try {
//                return new KeyInfo(kiEle, null);
//            } catch (com.sun.org.apache.xml.internal.security.exceptions.XMLSecurityException ex) {
//                logger.log(Level.SEVERE, LogStringsMessages.WST_0034_UNABLE_GET_CLIENT_CERT(), ex);
//                throw new WSTrustException(LogStringsMessages.WST_0034_UNABLE_GET_CLIENT_CERT(), ex);
//            }
//        }
//        final DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
//        Document doc = null;
//        try {
//            doc = docFactory.newDocumentBuilder().newDocument();
//        } catch (ParserConfigurationException ex) {
//            logger.log(Level.SEVERE,
//                    LogStringsMessages.WST_0039_ERROR_CREATING_DOCFACTORY(), ex);
//            throw new WSTrustException(LogStringsMessages.WST_0039_ERROR_CREATING_DOCFACTORY(), ex);
//        }
//
//        final String appliesTo = ctx.getAppliesTo();
//        final KeyInfo keyInfo = new KeyInfo(doc);
//        if (kiEle != null) {
//            keyInfo.addUnknownElement(kiEle);
//            return keyInfo;
//        }
//        String keyType = ctx.getKeyType();
//        WSTrustVersion wstVer = (WSTrustVersion) ctx.getOtherProperties().get(IssuedTokenContext.WS_TRUST_VERSION);
//        if (wstVer.getSymmetricKeyTypeURI().equals(keyType)) {
//            final byte[] key = ctx.getProofKey();
//            try {
//                final EncryptedKey encKey = WSTrustUtil.encryptKey(doc, key, (X509Certificate) ctx.getOtherProperties().get(IssuedTokenContext.TARGET_SERVICE_CERTIFICATE), null);
//                keyInfo.add(encKey);
//            } catch (Exception ex) {
//                logger.log(Level.SEVERE,
//                        LogStringsMessages.WST_0040_ERROR_ENCRYPT_PROOFKEY(appliesTo), ex);
//                throw new WSTrustException(LogStringsMessages.WST_0040_ERROR_ENCRYPT_PROOFKEY(appliesTo), ex);
//            }
//        } else if (wstVer.getPublicKeyTypeURI().equals(keyType)) {
//            final X509Data x509data = new X509Data(doc);
//            try {
//                x509data.addCertificate(ctx.getRequestorCertificate());
//            } catch (com.sun.org.apache.xml.internal.security.exceptions.XMLSecurityException ex) {
//                logger.log(Level.SEVERE, LogStringsMessages.WST_0034_UNABLE_GET_CLIENT_CERT(), ex);
//                throw new WSTrustException(LogStringsMessages.WST_0034_UNABLE_GET_CLIENT_CERT(), ex);
//            }
//            keyInfo.add(x509data);
//        }
//
//        return keyInfo;
//    }
    private List<com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition> getCondition(String delegateId) throws SAMLException {

        List<com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition> conditionList = new ArrayList<com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition>();
        Element element;
        try {
            element = GFIPMWSTrustUtil.getCondition(delegateId);
        } catch (DatatypeConfigurationException ex) {
            logger.log(Level.SEVERE,
                    "Unable to get DatatypeFactory for the XML Gregorian Calendar date", ex);
            throw new SAMLException(ex);
        }
        ConditionAbstractType conditionAbstractType = DelegationRestrictionType.fromElement(element);
        com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition condition = (com.sun.xml.wss.saml.assertion.saml20.jaxb20.Condition) conditionAbstractType;
        conditionList.add(condition);
        return conditionList;
    }

    private Assertion validateOnBehafOfToken(Element onBehalfOfToken) throws WSTrustException {

        if (DEBUG) {
            logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<ADS: Validating SAML Assertion supplied within OnBehalfOf >>>>>>>>>>>>>>>\n");
        }

        try {
            //Do a SAML:Conditions validation to make sure the SAML assertion is Valid
            if (!(SAMLUtil.validateTimeInConditionsStatement(onBehalfOfToken))) {
                logger.log(Level.WARNING, "Invalid time conditions");
                throw new WSTrustException("Invalid time conditions");
            } else {
                if (DEBUG) {
                    logger.log(Level.FINEST, "ADS: validated time conditions - passed");
                }
            }
        } catch (XWSSecurityException ex) {
            Logger.getLogger(GFIPMSTSTokenProvider.class.getName()).log(Level.SEVERE, null, ex);
            throw new WSTrustException("Invalid time conditions", ex);
        }

        PublicKey signingKey = null;
        try {
            signingKey = SecurityUtil.getSignaturePublicKey(onBehalfOfToken.getOwnerDocument());
        } catch (ParserConfigurationException ex) {
            logger.log(Level.WARNING, "ParseConfigurationException while obtaining Signature Public Key", ex);
            throw new WSTrustException("ParseConfigurationException while obtaining Signature Public Key", ex);
        } catch (SAXException ex) {
            logger.log(Level.WARNING, "SAXException while obtaining Signature Public Key", ex);
            throw new WSTrustException("SAXException while obtaining Signature Public Key", ex);
        } catch (IOException ex) {
            logger.log(Level.WARNING, "IOException while obtaining Signature Public Key", ex);
            throw new WSTrustException("IOException while obtaining Signature Public Key", ex);
        }

        if (signingKey != null) {
            try {
                if (!(SAMLUtil.verifySignature(onBehalfOfToken, signingKey))) {
                    logger.log(Level.WARNING, "Unable to verify signature on SAML assertion.");
                    throw new WSTrustException("Unable to verify signature on SAML assertion.");
                } else {
                    if (DEBUG) {
                        logger.log(Level.FINEST, "ADS: done verifying signature on the attached SAML assertion - valid");
                    }
                }
            } catch (XWSSecurityException ex) {
                Logger.getLogger(GFIPMSTSTokenProvider.class.getName()).log(Level.SEVERE, "Failure to verify signature on SAML assertion ", ex);
                throw new WSTrustException("Failure to verify signature on SAML assertion", ex);
            }
        } else {
            logger.log(Level.WARNING, "Unable to obtain signing key from SAML assertion.");
            throw new WSTrustException("Unable to obtain signing key from SAML assertion.");
        }

        String signingEntityId = tf.getEntityId(signingKey);

        if (signingEntityId == null) {
            logger.log(Level.WARNING, "Certificate used by the peer is not in the GFIPM Trust Fabric. Signing key is :\n" + signingKey);
            throw new WSTrustException("Certificate used by the peer is not in the GFIPM Trust Fabric");
        }

        if (tf.isAssertionDelegateService(signingEntityId)) {
            if (DEBUG) {
                logger.log(Level.FINEST, "ADS: SAML assertion was signed by the Assertion Delegate Service Entity in GFIPM Trust Fabric, Singing Entity ID: " + signingEntityId);
            }
        } else {
            throw new WSTrustException("User assertion was not signed by the Assertion Delegate Service Entity in GFIPM Trust Fabric, Singing Entity ID: " + signingEntityId);
        }

        Assertion assertion = null;
        try {
            assertion = AssertionUtil.fromElement(onBehalfOfToken);
        } catch (SAMLException ex) {
            Logger.getLogger(GFIPMSTSTokenProvider.class.getName()).log(Level.SEVERE, "Unable to create SAML Assertion from content of OnBehalfOfToken", ex);
            throw new WSTrustException("Unable to create SAML Assertion from content of OnBehalfOfToken", ex);
        }

        //check if it's SAML 2.0 assertion
        String assertionVersion = assertion.getVersion();
        if ((assertionVersion == null) || (!(assertionVersion.compareTo("2.0") == 0))) {
            logger.log(Level.WARNING, "Invalid version of the SAML assertion: " + assertionVersion);
            throw new WSTrustException("ADS: Invalid version of the SAML assertion.");
        } else {
            if (DEBUG) {
                logger.log(Level.FINEST, "ADS: Validated SAML Version : " + assertion.getVersion());
            }
        }

        com.sun.xml.wss.saml.Subject subject = assertion.getSubject();

        if (subject == null) {
            throw new WSTrustException("ADS: SAML Assertion is missing subject.");
        }

        Conditions conditions = assertion.getConditions();
        boolean isAudienceRestrictionValid = false;
        for (Object condition : conditions.getConditions()) {
            if (condition instanceof DelegationRestrictionType) {
                List<DelegateType> delegateList = ((DelegationRestrictionType) condition).getDelegate();
                if (delegateList.isEmpty()) {
                    throw new WSTrustException("ADS: Delegate restrictions element is present but the list is empty.");
                }
                for (DelegateType delegate : delegateList) {
                    String delegateNameId = delegate.getNameID().getValue();
                    if (tf.getRoleDescriptorType(delegateNameId) == null) {
                        throw new WSTrustException("ADS: Delegate restrictions list contains entities that does not belong to the GFIPM CTF.");
                    }
                }
            } else if (condition instanceof AudienceRestrictionType) {
                List<String> audienceList = ((AudienceRestrictionType) condition).getAudience();
                if (audienceList.isEmpty()) {
                    throw new WSTrustException("ADS: Audience restriction is empty.");
                } else {
                    isAudienceRestrictionValid = true;
                }
            }
        }//Conditions
        if (!isAudienceRestrictionValid) {
            throw new WSTrustException("ADS: Audience restriction was not set.");
        }

        String authnContextClassRef = getAuthContextClassRef(assertion);
        if (authnContextClassRef != null && !authnContextClassRef.isEmpty()) {
            if (DEBUG) {
                logger.log(Level.FINEST, "ADS: Authentication Context is valid : " + authnContextClassRef);
            }
        } else {
            throw new WSTrustException("ADS: Authentication Context is not valid or was not set.");
        }
        
        if (DEBUG) {
            logger.log(Level.FINEST, "<<<<<<<<<<<<<<<<<<ADS: SAML Assertion supplied within OnBehalfOf is VALID >>>>>>>>>>>>>>>");
        }

        
        return assertion;

    }

    private String getAuthContextClassRef(Assertion assertion) {
        String authnContextClassRef = null;
        for (Object statement : assertion.getStatements()) {
            if (statement instanceof AuthnStatement) {
                AuthnStatement authnStatement = (AuthnStatement) statement;
                authnContextClassRef = authnStatement.getAuthnContextClassRef();
            }
        }
        return authnContextClassRef;
    }
}
