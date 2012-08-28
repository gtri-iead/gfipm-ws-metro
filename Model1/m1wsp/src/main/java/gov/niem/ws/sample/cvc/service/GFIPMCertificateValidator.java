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

import com.sun.xml.ws.security.opt.impl.util.SOAPUtil;
import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.MessageConstants;
import com.sun.xml.wss.impl.XWSSecurityRuntimeException;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback.CertificateValidationException;
import com.sun.xml.wss.impl.callback.CertificateValidationCallback.CertificateValidator;
import com.sun.xml.wss.impl.callback.KeyStoreCallback;
import com.sun.xml.wss.impl.callback.ValidatorExtension;
import com.sun.xml.wss.impl.misc.SecurityUtil;
import com.sun.xml.wss.logging.LogStringsMessages;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.Principal;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import net.gfipm.trustfabric.TrustFabric;
import net.gfipm.trustfabric.TrustFabricFactory;

/**
 * GFIPM X509 Certificate validator is a modifed version of the Metro's x509 validator. 
 * Validator uses gfipm-security-env.properties properties file. 
 * For examples of the certficate validation see
 * com.sun.xml.wss.impl.misc.DefaultCallbackHandler and
 * com.sun.xml.wss.impl.misc.WSITProviderSecurityEnvironment 
 * 
 * References:
 * http://weblogs.java.net/blog/kumarjayanti/archive/2009/06/security_token_1.html
 * http://weblogs.java.net/blog/kumarjayanti/archive/2009/07/jsr_196_in_metr.html
 *
 * @author shrom
 */
public class GFIPMCertificateValidator implements CertificateValidator, ValidatorExtension {

    private static final Logger log =
            Logger.getLogger(GFIPMCertificateValidator.class.getName());
    private static final boolean DEBUG = true;
    public static final String resource = "gfipm-security-env.properties";
    public static final String KEYSTORE_URL = "keystore.url";
    public static final String KEYSTORE_TYPE = "keystore.type";
    public static final String KEYSTORE_PASSWORD = "keystore.password";
    public static final String KEY_PASSWORD = "key.password";
    public static final String MY_ALIAS = "my.alias";
    public static final String MY_USERNAME = "my.username";
    public static final String MY_PASSWORD = "my.password";
    public static final String MY_ITERATIONS = "my.iterations";
    public static final String TRUSTSTORE_URL = "truststore.url";
    public static final String TRUSTSTORE_TYPE = "truststore.type";
    public static final String TRUSTSTORE_PASSWORD = "truststore.password";
    public static final String PEER_ENTITY_ALIAS = "peerentity.alias";
    public static final String KEYSTORE_CBH = "keystore.callback.handler";
    public static final String TRUSTSTORE_CBH = "truststore.callback.handler";
    public static final String REVOCATION_ENABLED = "revocation.enabled";
    private TrustFabric tf;
    private Map runtimeProps = null;
    private KeyStore keyStore;
    private KeyStore trustStore;
    private CertStore certStore = null;
    private CallbackHandler keystoreHandler;
    private CallbackHandler truststoreHandler;
    private CallbackHandler certstoreHandler;
    private Class keystoreCbHandler;
    private Class truststoreCbHandler;
    protected boolean revocationEnabled = false;
    private String keyStoreURL;
    private String keyStorePassword;
    private String keyStoreType;
    private String myAlias;
    private String keyPwd;
    private char[] keyPassword = null;
    private String trustStoreURL;
    private String trustStorePassword;
    private String trustStoreType;
    private String peerEntityAlias;

    public GFIPMCertificateValidator() throws XWSSecurityException, InstantiationException, IllegalAccessException {
        Properties properties = new Properties();
        InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        if (in != null) {
            try {
                properties.load(in);
            } catch (IOException ex) {
                throw new XWSSecurityException(ex);
            }
        }

        this.keyStoreURL = properties.getProperty(KEYSTORE_URL);
        this.keyStoreType = properties.getProperty(KEYSTORE_TYPE);
        this.keyStorePassword = properties.getProperty(KEYSTORE_PASSWORD);
        this.keyPwd = properties.getProperty(KEY_PASSWORD);

        this.trustStoreURL = properties.getProperty(TRUSTSTORE_URL);
        this.trustStoreType = properties.getProperty(TRUSTSTORE_TYPE);
        this.trustStorePassword = properties.getProperty(TRUSTSTORE_PASSWORD);
        this.peerEntityAlias = properties.getProperty(PEER_ENTITY_ALIAS);

        if (properties.getProperty(REVOCATION_ENABLED) != null) {
            this.revocationEnabled = Boolean.parseBoolean(properties.getProperty(REVOCATION_ENABLED));
        }

        keystoreCbHandler = loadClass(properties.getProperty(KEYSTORE_CBH));
        truststoreCbHandler = loadClass(properties.getProperty(TRUSTSTORE_CBH));

        initTrustStore();
        initKeyStore();

        if (this.keystoreCbHandler != null) {
            this.keystoreHandler = (CallbackHandler) this.keystoreCbHandler.newInstance();
        }
        if (this.truststoreCbHandler != null) {
            this.truststoreHandler = (CallbackHandler) this.truststoreCbHandler.newInstance();
        }

        //Initialize CTF
        tf = TrustFabricFactory.getInstance("net/gfipm/trustfabric/gfipm-trust-fabric-model2-sample-signed.xml");

    }

    @Override
    public void setRuntimeProperties(Map propMap) {
        this.runtimeProps = propMap;

//        String isGF = System.getProperty("com.sun.aas.installRoot");
//        if (isGF != null) {            
//            try {
//                Properties props = new Properties();
//                populateConfigProperties(configAssertions, props);
//                String jmacHandler = props.getProperty(DefaultCallbackHandler.JMAC_CALLBACK_HANDLER);
//                if (jmacHandler != null) {
//                    handler = loadGFHandler(false, jmacHandler);
//                }
//                if (handler == null) {
//                   handler = loadGFHandler(false, jmacHandler); 
//                }
//                
//                secEnv = new WSITProviderSecurityEnvironment(handler, map, props);
//            }catch (XWSSecurityException ex) {
//                log.log(Level.SEVERE,
//                        LogStringsMessages.WSITPVD_0048_ERROR_POPULATING_SERVER_CONFIG_PROP(), ex);
//                throw new WebServiceException(
//                        LogStringsMessages.WSITPVD_0048_ERROR_POPULATING_SERVER_CONFIG_PROP(), ex);
//            }
//        }         
//
//
//        _handler = new PriviledgedHandler(handler);
    }

    @Override
    public boolean validate(X509Certificate certificate) throws CertificateValidationException {

        if (DEBUG) {
            log.log(Level.FINEST, "WSP: validate: Validating certificate with Subject DN: " + certificate.getSubjectDN());
        }

        if (!isAuthorized(certificate)){
            throw new CertificateValidationException ("Not authorized to access this WSP");
        }
        
        /*
         * use TrustStore and CertStore
         */
        try {
            certificate.checkValidity();
        } catch (CertificateExpiredException e) {
            log.log(Level.SEVERE, LogStringsMessages.WSS_0298_X_509_EXPIRED(), e);
            throw SOAPUtil.newSOAPFaultException(MessageConstants.WSSE_INVALID_SECURITY_TOKEN,
                    "X509Certificate Expired", e);
        } catch (CertificateNotYetValidException e) {
            log.log(Level.SEVERE, LogStringsMessages.WSS_0299_X_509_NOT_VALID(), e);
            throw SOAPUtil.newSOAPFaultException(MessageConstants.WSSE_INVALID_SECURITY_TOKEN,
                    "X509Certificate not yet valid", e);
        }

        // for self-signed certificate
        if (certificate.getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
            if (isTrustedSelfSigned(certificate, getTrustStore(this.runtimeProps))) {
                if (DEBUG) {
                    log.log(Level.FINEST, "WSP: self-signed certificate validated in truststore");
                }
                return true;
            } else {
                log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1533_X_509_SELF_SIGNED_CERTIFICATE_NOT_VALID());
                throw new CertificateValidationException("WSP: Validation of self-signed certificate failed");
            }
        }

        if (DEBUG) {
            log.log(Level.FINEST, "WSP: Cert is not self-signed, continuing validation");
        }

        // FIXME validation of the certificate chain from here was not tested
        //check keyUsage        
        X509CertSelector certSelector = new X509CertSelector();
        certSelector.setCertificate(certificate);

        PKIXBuilderParameters parameters;
        CertPathValidator certValidator = null;
        CertPath certPath = null;
        List<Certificate> certChainList = new ArrayList<Certificate>();
        boolean caFound = false;
        Principal certChainIssuer = null;
        int noOfEntriesInTrustStore = 0;
        boolean isIssuerCertMatched = false;

        try {
            KeyStore tStore = getTrustStore(this.runtimeProps);
            CertStore cStore = getCertStore(this.runtimeProps);
            parameters = new PKIXBuilderParameters(tStore, certSelector);
            parameters.setRevocationEnabled(revocationEnabled);
            if (cStore != null) {
                parameters.addCertStore(cStore);
            } else {
                //create a CertStore on the fly with CollectionCertStoreParameters since some JDK's
                //cannot build chains to certs only contained in a TrustStore
                CertStore cs = CertStore.getInstance("Collection",
                        new CollectionCertStoreParameters(Collections.singleton(certificate)));
                parameters.addCertStore(cs);
            }

            Certificate[] certChain = null;
            String certAlias = tStore.getCertificateAlias(certificate);
            if (certAlias != null) {
                certChain = tStore.getCertificateChain(certAlias);
            }
            if (certChain == null) {
                certChainList.add(certificate);
                certChainIssuer = certificate.getIssuerX500Principal();
                noOfEntriesInTrustStore = tStore.size();
            } else {
                certChainList = Arrays.asList(certChain);
            }
            while (!caFound && noOfEntriesInTrustStore-- != 0 && certChain == null) {
                Enumeration aliases = tStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = (String) aliases.nextElement();
                    Certificate cert = tStore.getCertificate(alias);
                    if (cert == null || !"X.509".equals(cert.getType()) || certChainList.contains(cert)) {
                        continue;
                    }
                    X509Certificate x509Cert = (X509Certificate) cert;
                    if (certChainIssuer.equals(x509Cert.getSubjectX500Principal())) {
                        certChainList.add(cert);
                        if (x509Cert.getSubjectX500Principal().equals(x509Cert.getIssuerX500Principal())) {
                            caFound = true;
                            break;
                        } else {
                            certChainIssuer = x509Cert.getIssuerDN();
                            if (!isIssuerCertMatched) {
                                isIssuerCertMatched = true;
                            }
                        }
                    } else {
                        continue;
                    }
                }
                if (!caFound) {
                    if (!isIssuerCertMatched) {
                        break;
                    } else {
                        isIssuerCertMatched = false;
                    }
                }
            }
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            certPath = cf.generateCertPath(certChainList);
            certValidator = CertPathValidator.getInstance("PKIX");

        } catch (Exception e) {
            log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1518_FAILEDTO_VALIDATE_CERTIFICATE(), e);
            throw new CertificateValidationCallback.CertificateValidationException(e.getMessage(), e);
        }

        try {
            certValidator.validate(certPath, parameters);
        } catch (Exception e) {
            log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1518_FAILEDTO_VALIDATE_CERTIFICATE(), e);
            throw new CertificateValidationCallback.CertificateValidationException(e.getMessage(), e);
        }

        return true;
    }

    /**
     *
     * @throws com.sun.xml.wss.XWSSecurityException
     */
    private void initTrustStore() throws XWSSecurityException {
        try {

            if (trustStoreURL == null) {
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.FINE, "Got NULL for TrustStore URL");
                }
                return;
            }
            if (this.trustStorePassword == null) {
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.FINE, "Got NULL for TrustStore Password");
                }
            }

            char[] trustStorePasswordChars = null;
            //check here if trustStorePassword is a CBH className
//            Class cbh = this.loadClassSilent(trustStorePassword);
//            if (cbh != null) {
//                CallbackHandler hdlr = (CallbackHandler) cbh.newInstance();
//                javax.security.auth.callback.PasswordCallback pc =
//                        new javax.security.auth.callback.PasswordCallback("TrustStorePassword", false);
//                Callback[] cbs = new Callback[]{pc};
//                hdlr.handle(cbs);
//                trustStorePasswordChars = ((javax.security.auth.callback.PasswordCallback) cbs[0]).getPassword();
//            } else {
            //the user supplied value is a Password for the truststore
            trustStorePasswordChars = trustStorePassword.toCharArray();
//            }

            trustStore = KeyStore.getInstance(trustStoreType);
            InputStream is = null;
            URL tURL = SecurityUtil.loadFromClasspath("META-INF/" + trustStoreURL);

            try {
                if (tURL != null) {
                    is = tURL.openStream();
                } else {
                    is = new FileInputStream(trustStoreURL);
                }
                trustStore.load(is, trustStorePasswordChars);
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1509_FAILED_INIT_TRUSTSTORE(), e);
            throw new RuntimeException(e);
        }
    }

    /**
     *
     * @throws com.sun.xml.wss.XWSSecurityException
     */
    private void initKeyStore() throws XWSSecurityException {
        try {
            if (keyStoreURL == null) {
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.FINE, "Got NULL for KeyStore URL");
                }
                return;
            }

            if (keyStorePassword == null) {
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.FINE, "Got NULL for KeyStore PASSWORD");
                }
                return;
            }

            char[] keyStorePasswordChars = null;
            //check here if keyStorePassword is a CBH className
//            Class cbh = this.loadClassSilent(keyStorePassword);
//            if (cbh != null) {
//                CallbackHandler hdlr = (CallbackHandler) cbh.newInstance();
//                javax.security.auth.callback.PasswordCallback pc =
//                        new javax.security.auth.callback.PasswordCallback("KeyStorePassword", false);
//                Callback[] cbs = new Callback[]{pc};
//                hdlr.handle(cbs);
//                keyStorePasswordChars = ((javax.security.auth.callback.PasswordCallback) cbs[0]).getPassword();
//            } else {
            //the user supplied value is a Password for the keystore
            keyStorePasswordChars = keyStorePassword.toCharArray();
//            }

            //now initialize KeyPassword if any ?
            if (this.keyPwd == null) {
                this.keyPassword = keyStorePasswordChars;
            } else {
                initKeyPassword();
            }

            keyStore = KeyStore.getInstance(keyStoreType);
            InputStream is = null;
            URL kURL = SecurityUtil.loadFromClasspath("META-INF/" + keyStoreURL);
            try {
                if (kURL != null) {
                    is = kURL.openStream();
                } else {
                    is = new FileInputStream(keyStoreURL);
                }
                keyStore.load(is, keyStorePasswordChars);
            } finally {
                if (is != null) {
                    is.close();
                }
            }
        } catch (Exception e) {
            log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1510_FAILED_INIT_KEYSTORE(), e);
            throw new RuntimeException(e);
        }
    }

    private void initKeyPassword() {
        //NOTE: this is called only when this.keyPwd is non-null
        // check if this.keyPwd is a CBH
//        try {
//            Class cbh = this.loadClassSilent(this.keyPwd);
//            if (cbh != null) {
//                CallbackHandler hdlr = (CallbackHandler) cbh.newInstance();
//                javax.security.auth.callback.PasswordCallback pc =
//                        new javax.security.auth.callback.PasswordCallback("KeyPassword", false);
//                Callback[] cbs = new Callback[]{pc};
//                hdlr.handle(cbs);
//                this.keyPassword = ((javax.security.auth.callback.PasswordCallback) cbs[0]).getPassword();
//            } else {
        //the user supplied value is a Password for the key alias
        this.keyPassword = this.keyPwd.toCharArray();
//            }
//        } catch (java.lang.InstantiationException ex) {
//            log.log(Level.SEVERE, LogStringsMessages.WSS_1528_FAILED_INITIALIZE_KEY_PASSWORD(), ex);
//            throw new RuntimeException(ex);
//        } catch (java.io.IOException e) {
//            log.log(Level.SEVERE, LogStringsMessages.WSS_1528_FAILED_INITIALIZE_KEY_PASSWORD(), e);
//            throw new RuntimeException(e);
//        } catch (java.lang.IllegalAccessException ie) {
//            log.log(Level.SEVERE, LogStringsMessages.WSS_1528_FAILED_INITIALIZE_KEY_PASSWORD(), ie);
//            throw new RuntimeException(ie);
//        } catch (javax.security.auth.callback.UnsupportedCallbackException ue) {
//            log.log(Level.SEVERE, LogStringsMessages.WSS_1528_FAILED_INITIALIZE_KEY_PASSWORD(), ue);
//            throw new RuntimeException(ue);
//        }
    }

    private KeyStore getTrustStore(Map runtimeProps) {
        if (trustStore != null) {
            return trustStore;
        }
        return getTrustStoreUsingCallback(runtimeProps);
    }

    /**
     *
     * @param runtimeProps
     * @return
     */
    private synchronized KeyStore getTrustStoreUsingCallback(Map runtimeProps) {

        if (trustStore == null && truststoreHandler != null) {
            try {
                KeyStoreCallback cb = new KeyStoreCallback();
                SecurityUtil.copy(cb.getRuntimeProperties(), runtimeProps);
                Callback[] cbs = new Callback[]{cb};
                this.truststoreHandler.handle(cbs);
                trustStore = cb.getKeystore();
                if (trustStore == null) {
                    log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1536_NO_TRUSTSTORE_SET_IN_TRUSTSTORECALLBACK());
                    throw new XWSSecurityRuntimeException("No TrustStore set in KeyStoreCallback by CallbackHandler");
                }
            } catch (IOException ex) {
                log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1537_ERROR_TRUSTSTORE_USING_CALLBACK(), ex);
                throw new XWSSecurityRuntimeException(ex);
            } catch (UnsupportedCallbackException ex) {
                log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1537_ERROR_TRUSTSTORE_USING_CALLBACK(), ex);
                throw new XWSSecurityRuntimeException(ex);
            }
        }
        return trustStore;
    }

    private CertStore getCertStore(Map runtimeProps) {
        if (this.certStore != null) {
            return certStore;
        }
        return getCertStoreUsingCallback(runtimeProps);
    }

    private synchronized CertStore getCertStoreUsingCallback(Map runtimeProps) {
        if (this.certstoreHandler != null) {
            //keep the certstore handy...
            com.sun.xml.wss.impl.callback.CertStoreCallback cb = new com.sun.xml.wss.impl.callback.CertStoreCallback();
            SecurityUtil.copy(cb.getRuntimeProperties(), runtimeProps);
            Callback[] callbacks = new Callback[]{cb};
            try {
                this.certstoreHandler.handle(callbacks);
                this.certStore = cb.getCertStore();
            } catch (UnsupportedCallbackException ex) {
                log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1529_EXCEPTION_IN_CERTSTORE_CALLBACK(), ex);
                throw new XWSSecurityRuntimeException(ex);
            } catch (IOException ex) {
                log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1529_EXCEPTION_IN_CERTSTORE_CALLBACK(), ex);
                throw new XWSSecurityRuntimeException(ex);
            }
        }
        return certStore;
    }

    private Class loadClass(String classname) throws XWSSecurityException {
        if (classname == null) {
            return null;
        }
        Class ret = null;
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        if (loader != null) {
            try {
                ret = loader.loadClass(classname);
                return ret;
            } catch (ClassNotFoundException e) {
                // ignore
                if (log.isLoggable(Level.FINE)) {
                    log.log(Level.FINE, "LoadClass: could not load class " + classname, e);
                }
            }
        }
        // if context classloader didnt work, try this
        loader = this.getClass().getClassLoader();
        try {
            ret = loader.loadClass(classname);
            return ret;
        } catch (ClassNotFoundException e) {
            // ignore
            if (log.isLoggable(Level.FINE)) {
                log.log(Level.FINE, "LoadClass: could not load class " + classname, e);
            }
        }
        log.log(Level.SEVERE, com.sun.xml.wss.logging.impl.misc.LogStringsMessages.WSS_1521_ERROR_GETTING_USER_CLASS());
        throw new XWSSecurityException("Could not find User Class " + classname);
    }

    private boolean isTrustedSelfSigned(X509Certificate cert, KeyStore trustStore) throws CertificateValidationException {
        if (trustStore == null) {
            return false;
        }

        try {
//            Callback[] callbacks = null;
//            CertStoreCallback csCallback = null;
//            TrustStoreCallback tsCallback = null;
//
//            if (tsCallback == null && csCallback == null) {
//                csCallback = new CertStoreCallback();
//                tsCallback = new TrustStoreCallback();
//                callbacks = new Callback[]{csCallback, tsCallback};
//            } else if (csCallback == null) {
//                csCallback = new CertStoreCallback();
//                callbacks = new Callback[]{csCallback};
//            } else if (tsCallback == null) {
//                tsCallback = new TrustStoreCallback();
//                callbacks = new Callback[]{tsCallback};
//            }

//            try {
//                _handler.handle(callbacks);
//            } catch (Exception e) {
//                log.log(Level.SEVERE, LogStringsMessages.WSS_0216_CALLBACKHANDLER_HANDLE_EXCEPTION("Validate an X509Certificate"),
//                        new Object[]{"Validate an X509Certificate"});
//                throw new CertificateValidationException(e);
//            }

//            if (tsCallback.getTrustStore() == null) {
//                return false;
//            }

            Enumeration aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = (String) aliases.nextElement();
                Certificate certificate = trustStore.getCertificate(alias);
                if (certificate == null || !"X.509".equals(certificate.getType())) {
                    continue;
                }
                X509Certificate x509Cert = (X509Certificate) certificate;
                if (x509Cert != null && x509Cert.equals(cert)) {
                    return true;
                }
            }
            return false;
        } catch (Exception e) {
            log.log(Level.SEVERE, LogStringsMessages.WSS_0223_FAILED_CERTIFICATE_VALIDATION(), e);
            throw SOAPUtil.newSOAPFaultException(MessageConstants.WSSE_INVALID_SECURITY_TOKEN,
                    e.getMessage(), e);
        }
    }
//    class PriviledgedHandler implements CallbackHandler {
//
//        CallbackHandler delegate = null;
//
//        public PriviledgedHandler(CallbackHandler handler) {
//            delegate = handler;
//        }
//
//        public void handle(final Callback[] callbacks) throws IOException, UnsupportedCallbackException {
//            AccessController.doPrivileged(new PrivilegedAction() {
//
//                public Object run() {
//                    try {
//                        delegate.handle(callbacks);
//                        return null;
//                    } catch (Exception ex) {
//                        throw new XWSSecurityRuntimeException(ex);
//                    }
//                }
//            });
//        }
//    }
//    protected CallbackHandler loadGFHandler(boolean isClientAuthModule, String jmacHandler) {
//
//        String classname = DefaultCallbackHandler.JMAC_CALLBACK_HANDLER;
//        if (jmacHandler != null) {
//            classname = jmacHandler;
//        }
//        Class ret = null;
//        try {
//
//            ClassLoader loader = Thread.currentThread().getContextClassLoader();
//            try {
//                if (loader != null) {
//                    ret = loader.loadClass(classname);
//                }
//            } catch (ClassNotFoundException e) {
//            }
//
//            if (ret == null) {
//                // if context classloader didnt work, try this
//                loader = this.getClass().getClassLoader();
//                ret = loader.loadClass(classname);
//            }
//
//            if (ret != null) {
//                CallbackHandler handler = (CallbackHandler) ret.newInstance();
//                return handler;
//            }
//        } catch (ClassNotFoundException e) {
//            // ignore
//        } catch (InstantiationException e) {
//        } catch (IllegalAccessException ex) {
//        }
//        log.log(Level.SEVERE,
//                com.sun.xml.wss.provider.wsit.logging.LogStringsMessages.WSITPVD_0023_COULD_NOT_LOAD_CALLBACK_HANDLER_CLASS(classname));
//        throw new RuntimeException(
//                com.sun.xml.wss.provider.wsit.logging.LogStringsMessages.WSITPVD_0023_COULD_NOT_LOAD_CALLBACK_HANDLER_CLASS(classname));
//    }

    /**
     * Provides authorization for the certificate owner to access this WSP
     * @param certificate
     * @return true if certificate owner is authorized, false if not
     */
    private boolean isAuthorized(X509Certificate certificate) {
        
        String entityId = tf.getEntityId(certificate);

        if (entityId == null) {
            log.log(Level.WARNING, "Certificate used by the peer is not in the GFIPM Trust Fabric: " + certificate.getSubjectDN());
            return false;
        }

        //GFIPM Entity (entityId) should belong to WSC only
        //Add access control decisions based on the GFIPM CTF entityAttributes
        if (tf.isWebServiceConsumer(entityId)) {
            String ownerAgencyCountryCode = tf.getGfipmEntityAttribute(entityId, "gfipm:2.0:entity:OwnerAgencyCountryCode");
            //As an example current WSP SLA currently allows only country codes US and VQ
            if (!(("VQ".compareToIgnoreCase(ownerAgencyCountryCode) != 0) || ("US".compareToIgnoreCase(ownerAgencyCountryCode) != 0))) {
                log.log(Level.WARNING, "WSP: WSC Entity connecting to this WSP should have OwnerAgencyCountryCode as VQ or US. Retrieved agency ID from TF is: " + ownerAgencyCountryCode);
                return false;
            }          
        } else {
            log.log(Level.WARNING, "Entity connecting to this WSP should be listed as WSC in the GFIPM Trust Fabric, entity id :" + entityId);
            return false;
        }
        
        return true;
    }
}
