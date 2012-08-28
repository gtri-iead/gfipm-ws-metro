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

import com.sun.xml.wss.SubjectAccessor;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.saml.*;
import gov.niem.ws.util.GFIPMUtil;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.ws.WebServiceContext;
import net.gfipm.trustfabric.TrustFabric;
import net.gfipm.trustfabric.TrustFabricFactory;
import org.w3c.dom.Element;

/**
 * Class provides a sample implementation of the authorization access control decisions
 * based on the WSC (requestor service) CTF GFIPM attributes, and user's
 * attributed included in the GFIPM SAML Assertion (user's on which behalf
 * service is making the request).
 *
 */
public class GFIPMAuthorizationProvider {

    private static final boolean DEBUG = true;
    private static final Logger logger = Logger.getLogger(GFIPMAuthorizationProvider.class.getName());
    private static TrustFabric tf;

    static {
        tf = TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");
    }

    public static boolean isServiceAuthorized(String methodName, WebServiceContext wsContext) {
        boolean isAuthorized = false;

        if (DEBUG) {
            logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isServiceAuthorized::Method:: " + methodName);
        }
        try {
            if (DEBUG) {
                logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isServiceAuthorized::Subject Accessor::" + SubjectAccessor.getRequesterSubject(wsContext));
            }
            if (SubjectAccessor.getRequesterSubject(wsContext) != null) {
                for (Iterator<Object> it = SubjectAccessor.getRequesterSubject(wsContext).getPublicCredentials().iterator(); it.hasNext();) {
                    Object publicCredentialsObject = it.next();
//                        logger.log(Level.FINEST, "\nPublic CredentialsObject::\n" + publicCredentialsObject +" class: " + publicCredentialsObject.getClass().getCanonicalName());
                    if (publicCredentialsObject instanceof X509Certificate) {
                        X509Certificate subjectX509Certificate = (X509Certificate) publicCredentialsObject;
                        //Delegate ID is determined from Entity Certificate.
                        String wscId = tf.getEntityId(subjectX509Certificate);
                        if (DEBUG) {
                            logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isServiceAuthorized::Got the following WSC entity :: " + wscId + " using public Certificate ::" + subjectX509Certificate.getSubjectDN().getName());
                        }
                        //Provide authorization decision for the WSC to execute method gov.niem.ws.sample.cvc.service.CommercialVehicleCollisionWebServiceImpl.getDocument
                        if (tf.isWebServiceConsumer(wscId) && "gov.niem.ws.sample.cvc.service.CommercialVehicleCollisionWebServiceImpl.getDocument".equals(methodName)) {
                            //In this example any WSC from the CTF is authorized to execute method: gov.niem.ws.sample.cvc.service.CommercialVehicleCollisionWebServiceImpl.getDocument
                            isAuthorized = true;
                        }
                    } else {
                        if (DEBUG) {
                            logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isServiceAuthorized::Object in public credentials :: " + publicCredentialsObject.getClass().getCanonicalName());
                        }
                    }
                }
            }
        } catch (XWSSecurityException ex) {
            logger.log(Level.SEVERE, "Unable to get UserPrincipal", ex);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Unknown exception", e);
        }

        return isAuthorized;
    }

    public static boolean isUserAuthorized(String methodName, Element userSAMLAssertion) {
        boolean isAuthorized = false;

        if (DEBUG) {
            logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isUserAuthorized::Method:: " + methodName);
            logger.log(Level.FINEST, "\nGFIPMAuthorizationProvider::isUserAuthorized::User's SAML Assertion ::\n" + GFIPMUtil.putOutAsString(userSAMLAssertion));
        }
        try {
            Assertion assertion = AssertionUtil.fromElement(userSAMLAssertion);
            HashMap<String, String> attributesHashMap = new HashMap<String, String>();
            List<Object> statements = assertion.getStatements();
            for (Object s : statements) {
                if (s instanceof AttributeStatement) {
                    List<Attribute> samlAttrs = ((AttributeStatement) s).getAttributes();
                    for (Attribute samlAttr : samlAttrs) {
                        String attrName = samlAttr.getName();
                        String attributeValue = (String) samlAttr.getAttributes().iterator().next();
                        attributesHashMap.put(attrName, attributeValue);
                        if (DEBUG) {
                            logger.log(Level.FINEST, "WSP: Attribute Name : " + attrName + " || Attr Value : " + attributeValue);
                        }
                    }
                } else if (s instanceof AuthenticationStatement) {
                    if (DEBUG) {
                        logger.log(Level.FINEST, "WSP: AuthenticationStatement : " + ((AuthenticationStatement) s).toString());
                    }
                }
            }
            
            isAuthorized = isAuthorized(attributesHashMap);

        } catch (SAMLException ex) {
            Logger.getLogger(GFIPMAuthorizationProvider.class.getName()).log(Level.SEVERE, "GFIPMAuthorizationProvider::isUserAuthorized::SAML Exception", ex);
        }


        return isAuthorized;
    }

    /**
     * Checks whether GFIPM user attributes are included and are of the certain values
     * @param attributesHashMap
     * @return true if all authorization requirements are met, false otherwise. 
     */
    private static Boolean isAuthorized(HashMap<String, String> attributesHashMap) {
        //Check gfipm:2.0:user:SwornLawEnforcementOfficerIndicator and gfipm:2.0:user:CitizenshipCode
        if (("true".compareToIgnoreCase(attributesHashMap.get("gfipm:2.0:user:SwornLawEnforcementOfficerIndicator")) == 0) &&
            ("US".compareToIgnoreCase(attributesHashMap.get("gfipm:2.0:user:CitizenshipCode")) == 0)) {
            return true;
        }
        return false;
    }
    
    public static String getCurrentMethodName() {
        StackTraceElement stackTraceElements[] = (new Throwable()).getStackTrace();
        return stackTraceElements[1].toString().split("\\(")[0];
    }
}
