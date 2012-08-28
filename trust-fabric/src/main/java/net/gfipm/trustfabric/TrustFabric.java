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

import com.sun.xml.wss.XWSSecurityException;
import com.sun.xml.wss.impl.misc.SecurityUtil;
import com.sun.xml.wss.saml.util.SAMLUtil;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.namespace.NamespaceContext;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * The TrustFabric class provides functionality to access and process the GFIPM
 * Trust Fabric document. Methods are provided to extract some or all of the
 * entity certificates or to get specific entity attibutes useful to GFIPM web
 * services or to evaluate any arbitrary XPath expression on the document. The
 * document is retrievable from any arbitrary web URL, but cannot be changed
 * with this class. The retrieved values are designed to be usable by the
 * GFIPMKeystore class through use of the GFIPMTrust main program.
 *
 * @author Stefan Roth
 * @author shrom
 */
public class TrustFabric implements TrustFabricIntf {

    public static final String DEFAULT_TRUST_DOCUMENT_URL = "https://ref.gfipm.net/gfipm-signed-ref-metadata.xml";
    // Production federation 
//    public static final String DEFAULT_TRUST_DOCUMENT_URL = "https://nief.gfipm.net/trust-fabric/nief-trust-fabric.xml";
    private static final Logger log = Logger.getLogger(TrustFabric.class.getName());
    private static final long serialVersionUID = 6612L;
    private static NamespaceContext namespaceContext;
    private Document trustDocument = null;
    private String topQuery = "/md:EntitiesDescriptor/md:EntityDescriptor";
    private List<Element> topElements = null;
    private boolean verboseOut = false;
    private boolean debugOut = false;

    static {
        namespaceContext = new GfipmNamespaceContext();
    }

    //Convert to use get URL from com.sun.xml.wss.imp.misc.SecurityUtil.loadFromClasspath()    
    // ======================================================================
    /**
     * Initializes various variables in the class instance. May also read from a
     * config file.
     *
     */
    public TrustFabric() throws IOException, SAXException, ParserConfigurationException {
        // FIXME Get value for trustDocumentURL from a config file. For now, set it here.
        initialize(DEFAULT_TRUST_DOCUMENT_URL);
    }  // end initializeClass

    /**
     * Initializes various variables in the class instance. May also read from a
     * config file.
     *
     * @param url The URL of the GFIPM trust document. Must be fully qualified,
     * i.e., https://host.gfipm.net/metadata-file.xml
     *
     */
    public TrustFabric(String trustDocumentURL) throws IOException, SAXException, ParserConfigurationException {
        initialize(trustDocumentURL);
    }

    private void initialize(String trustDocumentURL) throws IOException, SAXException, ParserConfigurationException {
        InputStream inputStream = openUrlInputStream(trustDocumentURL);
        trustDocument = loadTrustDocument(inputStream);
    }

    private Document loadTrustDocument(InputStream inputStream) throws SAXException, ParserConfigurationException, IOException {
        // create the xml document object
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document xmlDoc = builder.parse(inputStream);
        inputStream.close();
        return xmlDoc;
    }

    // ======================================================================
    /**
     * Sets the instance variable trustDocumentURL. Setting it to null does not
     * have any effect.
     *
     * @param url The URL of the GFIPM trust document. Must be fully qualified,
     * i.e., https://host.gfipm.net/metadata-file.xml
     *
     * @return Returns the new value of trustDocumentURL
     */
//    public String setTrustDocumentURL(String url) {
//        if (url != null) {
//            trustDocumentURL = url;
//        }
//        openUrlInputStream();
//        return trustDocumentURL;
//    }
    // ======================================================================
    /**
     * Gets the instance variable trustDocumentURL.
     *
     * @return Returns the value of trustDocumentURL
     */
//    public String getTrustDocumentURL() {
//
//        return trustDocumentURL;
//    }
    // ======================================================================
    /**
     * Given a URL (http or https), it opens an InputStream to that resource.
     * Not currently used. Works for http but not for https.
     *
     * @param urlstr is the URL string, such as
     * "http://ref.gfipm.net/...-metdata.xml
     *
     * @return Returns true if the open was successful, false otherwise.
     *
     * @throws nothing
     */
//    private boolean openUrlInputStreamOld() {
//
//        if (trustDocumentURL == null) {
//            System.err.println("ERROR: TrustFabric.openUrlInputStream: trustDocumentURL is null");
//            System.err.flush();
//            return false;
//        }
//
//        try {
//            URL urlobject = new URL(trustDocumentURL);
//
//            URLConnection urlconn = urlobject.openConnection();
//            if (urlconn == null) {
//                System.err.println("ERROR: TrustFabric.openUrlInputStream: URLConnection is null");
//                System.err.flush();
//                return false;
//            }
//
//            urlInputStream = urlconn.getInputStream();
//            if (urlInputStream == null) {
//                System.err.println("ERROR: TrustFabric.openUrlInputStream: InputStream to URL "
//                        + trustDocumentURL + " is null");
//                System.err.flush();
//                return false;
//
//            } else {
//                return true;
//            }
//        } catch (IOException e) {
//
//            System.err.println("ERROR: TrustFabric.openUrlInputStream failed: ");
//            System.err.println(e.toString());
//            System.err.flush();
//            return false;
//        }
//
//    }  // end openUrlInputStreamOld
    // ======================================================================
    /**
     * Given a URL (http or https), it opens an InputStream to that resource.
     *
     * @param urlstr is the URL string, such as
     * "http://ref.gfipm.net/...-metdata.xml or https://...xml
     *
     * @return Returns true if the open was successful, false otherwise.
     *
     * @throws nothing
     */
    //FIXME refactor to use logger, throw initialization exception
    private InputStream openUrlInputStream(String trustDocumentURL) throws IOException {

//        GetMethod httpGet = null;
        InputStream inputStream = null;

        if (trustDocumentURL == null) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.openUrlInputStream: trustDocumentURL is null");
            throw new IOException("ERROR: TrustFabric.openUrlInputStream: trustDocumentURL is null");
        }

        if (trustDocumentURL.startsWith("classpath:")) {
            try {
                URL url = new URL(null, trustDocumentURL, new net.gfipm.trustfabric.Handler(ClassLoader.getSystemClassLoader()));
                inputStream = url.openStream();
            } catch (IOException ex) {
                log.log(Level.SEVERE, "ERROR: TrustFabric.openUrlInputStream failed to open InputStream to URL " + trustDocumentURL, ex);
                throw ex;
            }
            return inputStream;
        } else if (trustDocumentURL.startsWith("http")) {
            inputStream = getInputStream(trustDocumentURL);
//            try {
//
//                HttpClient httpclient = new HttpClient();
//                httpGet = new GetMethod(trustDocumentURL);
//
//                httpclient.executeMethod(httpGet);
//
//                inputStream = httpGet.getResponseBodyAsStream();
//
//                if (inputStream == null) {
//                    throw new IOException("ERROR: TrustFabric.openUrlInputStream: InputStream to URL " + trustDocumentURL + " is null");
//                }
//
//            } catch (IOException e) {
//                log.log(Level.SEVERE, "ERROR: TrustFabric.openUrlInputStream: InputStream to URL " + trustDocumentURL + " is null", e);
//                closeInput(inputStream, httpGet);
//                throw e;
//            }
        } else {
            inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(trustDocumentURL);
        }

        return inputStream;

    }  // end openUrlInputStream

    // ======================================================================
    /**
     * Reads the GFIPM XML trust document from an InputStream into a String
     * object. Primarily for debugging purposes.
     *
     * @return The String object containing the XML trust document.
     *
     * @throws IOException
     */
//    private StringBuilder getTrustDocumentString() throws IOException {
//
//        if (urlInputStream == null) {
//            System.err.println("ERROR: TrustFabric.getTrustDocumentString: urlInputStream is null.");
//            return null;
//        }
//
//        final int charlen = 10000;
//        char[] cbuf = new char[charlen + 1];
//        int len = 0;
//
//        StringBuilder strbuf = new StringBuilder(charlen * 5);
//
//        InputStreamReader inreader = new InputStreamReader(urlInputStream);
//
//        if (!inreader.ready()) {
//            System.err.println("ERROR: InputStream is not ready before reading.");
//            System.err.flush();
//        } else {
//            if (verboseOut) {
//                System.out.println("TrustFabric: Reading characters:");
//            }
//        }
//
//        while (inreader.ready()) {
//            len = inreader.read(cbuf, 0, charlen);
//            if (verboseOut) {
//                System.out.print(" ");
//                System.out.print(len);
//            }
//            if (len > 0) {
//                strbuf.append(cbuf, 0, len);
//            }
//        }
//        if (verboseOut) {
//            System.out.println("");
//            System.out.flush();
//        }
//
//        return strbuf;
//    }  // end getTrustDocumentString
    // ======================================================================
    /**
     * Removes all spaces from the given String. If the string argument does not
     * contain any spaces, just returns the string argument. If it contains
     * spaces, a new string without spaces is built and returned. If str1 is
     * null, returns null.
     *
     * @param str1 The input String whose spaces are to be removed.
     *
     * @return A string without spaces. Returns a new string if str1 contained
     * spaces, otherwise returns original str1 argument.
     */
    private String removeSpaces(String str1) {
        int count = 0;
        StringBuilder strbuf = null;
        String rtnVal = null;

        if (str1 != null) {

            strbuf = new StringBuilder(str1.length() / 2);

            for (int i = 0; i < str1.length(); i++) {
                if ((str1.charAt(i) != ' ')
                        && (str1.charAt(i) != '\t')) {
                    strbuf.append(str1.charAt(i));
                } else {
                    count++;
                }
            }
            rtnVal = strbuf.toString();
        }

        if (debugOut) {
            System.out.println("TrustFabric.removeSpaces: " + count);
            System.out.flush();
        }
        return rtnVal;

    }  // end removeSpaces

    // ======================================================================
    /**
     * Opens the URL at trustDocumentURL. Loads the GFIPM Trust Fabric document
     * into an XML Document object.
     *
     * @return true if the loading of the trust doc succeeded; false otherwise.
     *
     */
//    private boolean loadTrustDocument(InputStream inputStream) throws IOException {
//
//        if (inputStream == null) {
//            throw new IOException("ERROR: TrustFabric.loadTrustDocument failed: inputStream is null");
//        }
//
//        SAXReader reader = new SAXReader();
//
//        try {
//            trustDocument = reader.read(inputStream);
//        } catch (DocumentException e) {
//            log.log(Level.SEVERE, "ERROR: TrustFabric.loadTrustDocument failed", e);
//            throw new IOException("ERROR: TrustFabric.loadTrustDocument failed");
//        }  finally {
//            closeInput(inputStream, null);
//        }
//
//        return true;
//    }
    // ======================================================================
    /**
     * Close the input stream in urlInputStream after finishing reading from it.
     *
     */
//    private void closeInput(InputStream inputStream, GetMethod httpGet) {
    private void closeInput(InputStream inputStream) {
        try {
            if (inputStream != null) {
                inputStream.close();
            }
//            if (httpGet != null) {
//                httpGet.releaseConnection();
//            }
        } catch (IOException e) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.closeInput failed: unable to close the connections or input streams ", e);
        }
    }

//    // ======================================================================
//    /**
//     * Opens the URL at trustDocumentURL. Loads the GFIPM Trust Fabric document
//     * into an XML Document object.
//     *
//     * @param url The String value to use for the URL of the trust document.
//     *
//     * @return true if the loading of the trust doc succeeded; false otherwise.
//     *
//     */
//    public boolean loadTrustDocument(String url) {
//        if (url != null) {
//            setTrustDocumentURL(url);
//        }
//        return loadTrustDocument();
//    }
    // ======================================================================
    /**
     * Takes a XPath query string and applies it to the GFIPM trust fabric
     * document. Can be used to evaluate any arbitrary expression against the
     * GFIPM trust document.
     *
     * @param xPathQuery A String with an XPath expression to be evaluated.
     *
     * @return A String with the value of the expression; null if there is no
     * value.
     */
    private String executeXPath(String xPathQuery) throws XPathExpressionException {

        if (trustDocument == null) {
            System.err.println("ERROR: TrustFabric.evaluateExpression: trustDocument is not loaded.");
            System.err.flush();
            return null;
        }

        String result = null;

        // setup the xPath objects
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(namespaceContext);
        try {
            // compile the xpath
            XPathExpression expression = xpath.compile(xPathQuery);
            // get the matching node
            result = (String) expression.evaluate(trustDocument, XPathConstants.STRING);
        } catch (javax.xml.xpath.XPathExpressionException ex) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.evaluateExpression failed for expression" + xPathQuery, ex);
            throw ex;
        }

        if ((result != null) && (result.trim().length() == 0)) {
            result = null;
        }

        return result;
    }  // end executeXPath

    // ======================================================================
    /**
     * Takes a XPath query string and applies it to the Node. Can be used to
     * evaluate any arbitrary expression against the Node.
     *
     * @param node A DOM Node with an XPath expression to be evaluated.
     * @param xPathQuery A String with an XPath expression to be evaluated.
     *
     * @return A String with the value of the expression; null if there is no
     * value.
     */
    private String executeXPath(Node node, String xPathQuery) throws XPathExpressionException {
        String result = null;
        // setup the xPath objects
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(namespaceContext);
        try {
            // compile the xpath
            XPathExpression expression = xpath.compile(xPathQuery);
            // get the matching node
            result = (String) expression.evaluate(node, XPathConstants.STRING);
        } catch (javax.xml.xpath.XPathExpressionException ex) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.executeXPath failed for expression" + xPathQuery, ex);
            throw ex;
        }
        return result;
    }

    private boolean getBooleanXPath(Node node, String xPathQuery) throws XPathExpressionException {
        Boolean result = false;

        // setup the xPath objects
        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(namespaceContext);
        try {
            // compile the xpath
            XPathExpression expression = xpath.compile(xPathQuery);
            // get the matching node
            result = (Boolean) expression.evaluate(node, XPathConstants.BOOLEAN);
        } catch (javax.xml.xpath.XPathExpressionException ex) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.executeXPath failed for expression" + xPathQuery, ex);
            throw ex;
        }

        return result;
    }

    // ======================================================================
    /**
     * Goes through the previously loaded trust document and extracts all
     * elements that match the query. Returns a list of all the Element objects
     * that match the xPathQuery.
     *
     * @param xPathQuery xPathQuery = "//md:EntityDescriptor" or
     * /md:EntitiesDescriptor/md:EntityDescriptor or ...
     *
     * @return Returns a list of Element objects.
     */
    //FIXME get rid of this method
//    private List<Element> parseDocument(String xPathQuery) {
    private List<Element> parseDocument(String xPathQuery) throws XPathExpressionException {

        NodeList nodelist;
        List<Element> elements = new ArrayList<Element>();

        XPath xpath = XPathFactory.newInstance().newXPath();
        xpath.setNamespaceContext(namespaceContext);
        try {
            // compile the xpath
            XPathExpression expression = xpath.compile(xPathQuery);
            // get the matching node
            nodelist = (NodeList) expression.evaluate(trustDocument.getDocumentElement(), XPathConstants.NODESET);

            for (int i = 0; i < nodelist.getLength(); i++) {
                if (nodelist.item(i) instanceof Element) {
                    elements.add((Element) nodelist.item(i));
                }
            }

        } catch (javax.xml.xpath.XPathExpressionException ex) {
            log.log(Level.SEVERE, "ERROR: TrustFabric.executeXPath failed for expression" + xPathQuery, ex);
            throw ex;
        }

        return elements;

    }  // end parseDocument

    // ======================================================================
    /**
     * Goes through the previously loaded trust document and extracts all
     * elements that match the query. Returns a list of all the Element objects,
     * which should be GFIPM entities. Stores the list in topElements for
     * possible later re-use.
     *
     * @return Returns a list of Element objects.
     *
     */
    private List<Element> collectEntities() throws XPathExpressionException {
        if (topElements != null) {
            return topElements;
        }

        topElements = parseDocument(topQuery);

        return topElements;
    }  // end collectEntities

    // ======================================================================
    /**
     * Builds an XPath query to be used to access the certificate in a GFIPM
     * trust doc entity. Assumes that the query environment is already the
     * element of the entity, i.e., below the md:EntityDescriptor (so that the
     * entityid is no longer needed).
     *
     * @param entitytype "SP" or "IDP" only
     *
     * @param keyuse "encryption" or "signing" or null only
     *
     * @return Returns a XPath query string: ./md:SPSSODescriptor or
     * ./md:IDPSSODescriptor ...
     *
     */
    private String buildXPathQueryForCertificate(String entitytype, String keyuse) {
        StringBuilder query = new StringBuilder();

        query.setLength(0);
        query.append("string(./md:");
        query.append("RoleDescriptor/md:KeyDescriptor");
//        query.append(entitytype);
//        query.append("SSODescriptor/md:KeyDescriptor");
        if (keyuse != null) {
            query.append("[@use='");
            query.append(keyuse);
            query.append("']");
        }
        query.append("/ds:KeyInfo/ds:X509Data/ds:X509Certificate)");

        return query.toString();
    }  // end buildXPathQueryForCertificate

    // ======================================================================
    /**
     * Builds an XPath query for an entity subnode (element) in the trust
     * document and performs the query to find the certificate for the specific
     * entity id, entity type, and key use. Only used by
     * getAllEntityCertificates.
     *
     * @param ele
     *
     * @param entityid
     *
     * @param entitytype
     *
     * @param keyuse
     *
     * @return Returns a GFIPMCertificate object if the certificate was found;
     * otherwise null.
     *
     */
    private GFIPMCertificate findCertificateInElement(Element ele, String entityid, String entitytype, String keyuse) throws XPathExpressionException {
        GFIPMCertificate newcert;
        String certstr, qstr;

        qstr = buildXPathQueryForCertificate(entitytype, keyuse);
        if (debugOut) {
            System.out.println("query: " + qstr);
        }
        certstr = executeXPath(ele, qstr);
        if ((certstr != null) && (certstr.trim().length() != 0)) {
            newcert = new GFIPMCertificate(entityid, entitytype, keyuse, certstr);
            if (debugOut) {
                System.out.print("TrustFabric.findCertificateInElement found: ");
                System.out.println(newcert.toString());
                System.out.flush();
            }
            return newcert;
        }
        return null;
    }  // end findCertificateInElement

    // ======================================================================
    /**
     * Checks if a duplicate certificate should be addded to the certificate
     * list and then does it. Called only by getAllEntityCertificates.
     *
     * @param collectDuplicates Flag to determine if duplicate certificate
     * strings should be added (even if the cert is duplicated in the trust doc)
     *
     * @param certificates Certificate list
     *
     * @param newcert the new certificate
     *
     * @return Returns true if the newcert was added to the list; false
     * otherwise.
     *
     */
    private boolean maybeAddCertificate(boolean collectDuplicates, List<GFIPMCertificate> certificates,
            GFIPMCertificate newcert) {
        if ((collectDuplicates) || (!certificates.contains((GFIPMCertificate) newcert))) {
            certificates.add(newcert);
            return true;

        } else {
            if (debugOut) {
                System.out.print("TrustFabric.getAllEntityCertificates already collected: ");
                System.out.println(newcert.toString());
                System.out.flush();
            }
        }
        return false;
    }  // end maybeAddCertificate    

    private static InputStream getInputStream(String wsdlUrl) throws MalformedURLException, IOException {
        HttpURLConnection conn;
        URL url;

        url = new URL(wsdlUrl);
        conn = (HttpURLConnection) url.openConnection();
        return conn.getInputStream();

    }

    // ======================================================================
    //              PUBLIC METHODS
    // ======================================================================
    public boolean setVerboseOut(boolean val) {
        verboseOut = val;

        return verboseOut;
    }

    // ======================================================================
    public boolean setDebugOut(boolean val) {
        debugOut = val;
        if (debugOut) {
            setVerboseOut(true);
        }
        return debugOut;
    }

    // ======================================================================
    /**
     * Get entity type specified in the EntityDescriptor/RoleDescriptor element
     *
     * @param entityId The entity ID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     */
    @Override
    public GFIPMCertificate.RoleDescriptorType getRoleDescriptorType(String entityId) {

        GFIPMCertificate.RoleDescriptorType roleDescriptorType = null;
        String roleDescriptionTypeString = null;

        String query = "string(/md:EntitiesDescriptor/md:EntityDescriptor[@entityID='" + entityId + "']/md:RoleDescriptor/@xsi:type)";
        try {
            roleDescriptionTypeString = executeXPath(query);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to get RoleDescriptor type for an Entity :" + entityId, ex);
            return null;
        }

        if (roleDescriptionTypeString != null && roleDescriptionTypeString.endsWith("GFIPMWebServiceProviderType")) {
            return GFIPMCertificate.RoleDescriptorType.WSP;
        } else if (roleDescriptionTypeString != null && roleDescriptionTypeString.endsWith("GFIPMWebServiceConsumerType")) {
            return GFIPMCertificate.RoleDescriptorType.WSC;
        } else if (roleDescriptionTypeString != null && roleDescriptionTypeString.endsWith("GFIPMAssertionDelegateServiceType")) {
            return GFIPMCertificate.RoleDescriptorType.ADS;
        }

        return roleDescriptorType;
    }

    @Override
    public boolean isWebServiceProvider(String entityId) {
        GFIPMCertificate.RoleDescriptorType roleDescriptorType = getRoleDescriptorType(entityId);
        if (roleDescriptorType != null && (roleDescriptorType.compareTo(roleDescriptorType.WSP) == 0)) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isWebServiceConsumer(String entityId) {
        GFIPMCertificate.RoleDescriptorType roleDescriptorType = getRoleDescriptorType(entityId);
        if (roleDescriptorType != null && (roleDescriptorType.compareTo(roleDescriptorType.WSC) == 0)) {
            return true;
        }
        return false;
    }

    @Override
    public boolean isAssertionDelegateService(String entityId) {
        GFIPMCertificate.RoleDescriptorType roleDescriptorType = getRoleDescriptorType(entityId);
        if (roleDescriptorType != null && (roleDescriptorType.compareTo(roleDescriptorType.ADS) == 0)) {
            return true;
        }
        return false;
    }

    // ======================================================================
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
    @Override
    public String getGfipmEntityAttribute(String entityId, String attrname) {

        String result = null;

        StringBuilder query = new StringBuilder();

        query.append("string(");
        query.append(topQuery);
        query.append("[@entityID='");
        query.append(entityId);
        query.append("']");

//        query.append("/md:Organization/md:Extensions");
        query.append("/md:RoleDescriptor/md:Extensions");
        if ((attrname == null) || (attrname.equals(""))) {
            // do nothing; collect all values
        } else {
            query.append("/gfipm:EntityAttribute[@Name='");
            query.append(attrname);
            query.append("']/gfipm:EntityAttributeValue");
        }
        query.append(")");

        if (debugOut) {
            System.out.println("TrustFabric.getGfipmEntityAttribute query: " + query.toString());
        }
        try {
            result = executeXPath(query.toString());
        } catch (XPathExpressionException ex) {
            log.log(Level.SEVERE, "TrustFabric.getGfipmEntityAttribute query: unable to execute query", ex);
        }

        if (result != null) {
            result = result.trim();
        }
        if (debugOut) {
            System.out.println("TrustFabric.getGfipmEntityAttribute value: " + result);
            System.out.flush();
        }

        return result;

    }  // end getGfipmEntityAttribute

    // ======================================================================
    /*
     * Searches for a specific entity in the GFIPM trust fabric document and
     * then extracts all the gfipm:EntityAttribute elements. Builds a HashMap of
     * the attribute names and values and returns it. Example attribute:
     * gfipm:2.0:entity:OwnerAgencyORI Example value: GA012345
     *
     * @param entityId The entityID of an EntityDescriptor in a GFIPM trust
     * fabric document.
     *
     * @return A HashMap of the GFIPM entity attribute names and values.
     *
     */
    //FIXME not tested.
    @Override
    public HashMap<String, String> getGfipmEntityAttributes(String entityId) {

        StringBuilder query = new StringBuilder();
        HashMap result = new HashMap<String, String>(20);    // returns this HashMap

        query.append(topQuery);
        query.append("[@entityID='");
        query.append(entityId);
        query.append("']");
//        query.append("/md:Organization/md:Extensions/gfipm:EntityAttribute");
        query.append("/md:RoleDescriptor/md:Extensions/gfipm:EntityAttribute");

        if (debugOut) {
            System.out.println("TrustFabric.getGfipmEntityAttributes: query: " + query.toString());
        }

        try {
            List<Element> elements = parseDocument(query.toString());
            if (verboseOut) {
                System.out.println("TrustFabric.getGfipmEntityAttributes: # GFIPM attributes found: "
                        + elements.size() + " (plus any SAML attributes)");
            }

            String attrname, value;
            int count = 0;
            for (Element ele : elements) {
                count++;
                attrname = executeXPath(ele, "string(@Name)");
                if (attrname != null) {
                    attrname = attrname.trim();
                    if (debugOut) {
                        System.out.println("   " + count + ") attr:  " + attrname);
                    }

                } else {
                    if (debugOut) {
                        System.out.println("   could not find attribute name " + count);
                    }
                }
                if (attrname.length() != 0) {
                    value = executeXPath(ele, "string(gfipm:EntityAttributeValue)");
                    if (value != null) {
                        value = value.trim();
                    }
                    result.put(attrname, value);
                    if (debugOut) {
                        System.out.println("   " + count + ") value: " + value);
                    }

                } else {
                    if (debugOut) {
                        System.out.println("   found bad attrname " + count + ": [" + attrname + "]");
                    }
                }
            }  // end for

            query.setLength(0);
            query.append("string(");
            query.append(topQuery);
            query.append("[@entityID='");
            query.append(entityId);
            query.append("']");
            query.append("/md:Organization/");
            int tempLength = query.length();

            attrname = "md:OrganizationName";
            query.append(attrname);
            query.append(")");
            value = executeXPath(query.toString());
            if (value != null) {
                value = value.trim();
                if (value.length() != 0) {
                    result.put(attrname, value);
                    count++;
                    if (debugOut) {
                        System.out.println("   " + count + ") attr:  " + attrname);
                        System.out.println("   " + count + ") value: " + value);
                    }
                }
            }

            query.setLength(tempLength);
            attrname = "md:OrganizationDisplayName";
            query.append(attrname);
            query.append(")");
            value = executeXPath(query.toString());
            if (value != null) {
                value = value.trim();
                if (value.length() != 0) {
                    result.put(attrname, value);
                    count++;
                    if (debugOut) {
                        System.out.println("   " + count + ") attr:  " + attrname);
                        System.out.println("   " + count + ") value: " + value);
                    }
                }
            }

            query.setLength(tempLength);
            attrname = "md:OrganizationURL";
            query.append(attrname);
            query.append(")");
            value = executeXPath(query.toString());
            if (value != null) {
                value = value.trim();
                if (value.length() != 0) {
                    result.put(attrname, value);
                    count++;
                    if (debugOut) {
                        System.out.println("   " + count + ") attr:  " + attrname);
                        System.out.println("   " + count + ") value: " + value);
                    }
                }
            }
        } catch (XPathExpressionException xpe) {
            log.log(Level.WARNING, "Invalid XPathExpression is used in getGfipmEntityAttributes.", xpe);
        }

        if (debugOut) {
            System.out.flush();
        }

        return result;

    }  // end getGfipmEntityAttributes

    @Override
    public String getEntityId(PublicKey publicKey) {
        String entityId = null;

        String certQuery = "/md:EntitiesDescriptor/md:EntityDescriptor[md:RoleDescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate]";

        try {

            List<Element> entityDescriptors = parseDocument(certQuery);
            for (Node entityDescriptor : entityDescriptors) {
                String certificateQuery = "string(./md:RoleDescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate)";
                String x509CertificateString = executeXPath(entityDescriptor, certificateQuery);

                StringBuilder certbuf = new StringBuilder();
                certbuf.append("-----BEGIN CERTIFICATE-----\n");
                certbuf.append(x509CertificateString);
                char ch = x509CertificateString.charAt(x509CertificateString.length() - 1);
                if ((ch != '\n') && (ch != '\r')) {
                    certbuf.append("\n");
                }
                certbuf.append("-----END CERTIFICATE-----\n");
                x509CertificateString = certbuf.toString();

                ByteArrayInputStream bisb = new ByteArrayInputStream(x509CertificateString.getBytes("UTF-8"));
                X509Certificate tfX509Certificate = null;
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    tfX509Certificate = (X509Certificate) certificateFactory.generateCertificate(bisb);
                } catch (CertificateException ce) {
                    log.log(Level.WARNING, "Unable to process certificate from the trust fabric for Entity ID = " + entityDescriptor.getAttributes().getNamedItem("ID"), ce);
                }
                bisb.close();
                if ((tfX509Certificate != null) && (tfX509Certificate.getPublicKey().equals(publicKey))) {
                    entityId = executeXPath(entityDescriptor, "string(@entityID)");
                    break;
                }
            }
        } catch (XPathExpressionException ex) {
            log.log(Level.WARNING, "Invalid XPathExpression is used to retrieve the Entity from the trust fabric.", ex);
        } catch (IOException ioe) {
            log.log(Level.WARNING, "Unable to convert certificate from the trust fabric", ioe);
        }

        return entityId;
    }

    @Override
    public String getEntityId(X509Certificate cert) {
        String entityId = null;

        String certQuery = "/md:EntitiesDescriptor/md:EntityDescriptor[md:RoleDescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate]";

        try {

            List<Element> entityDescriptors = parseDocument(certQuery);
            for (Node entityDescriptor : entityDescriptors) {
                String certificateQuery = "string(./md:RoleDescriptor/md:KeyDescriptor/ds:KeyInfo/ds:X509Data/ds:X509Certificate)";
                String x509CertificateString = executeXPath(entityDescriptor, certificateQuery);

                StringBuilder certbuf = new StringBuilder();
                certbuf.append("-----BEGIN CERTIFICATE-----\n");
                certbuf.append(x509CertificateString);
                char ch = x509CertificateString.charAt(x509CertificateString.length() - 1);
                if ((ch != '\n') && (ch != '\r')) {
                    certbuf.append("\n");
                }
                certbuf.append("-----END CERTIFICATE-----\n");
                x509CertificateString = certbuf.toString();

                ByteArrayInputStream bisb = new ByteArrayInputStream(x509CertificateString.getBytes("UTF-8"));
                X509Certificate tfX509Certificate = null;
                try {
                    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
                    tfX509Certificate = (X509Certificate) certificateFactory.generateCertificate(bisb);
                } catch (CertificateException ce) {
                    log.log(Level.WARNING, "Unable to process certificate from the trust fabric for Entity ID =" + entityDescriptor.getAttributes().getNamedItem("ID"), ce);
                }
                bisb.close();
                if ((tfX509Certificate != null) && (tfX509Certificate.equals(cert))) {
                    entityId = executeXPath(entityDescriptor, "string(@entityID)");
                    break;
                }
            }
        } catch (XPathExpressionException ex) {
            log.log(Level.WARNING, "Invalid XPathExpression is used to retrieve the Entity from the trust fabric.", ex);
        } catch (IOException ioe) {
            log.log(Level.WARNING, "Unable to convert certificate from the trust fabric", ioe);
        }

        return entityId;
    }

    // ======================================================================
    /**
     * Get a list of all the GFIPM entities in the trust document and prints the
     * entity ids of all the entities to System.out. For debugging use.
     *
     */
    public List<String> printAllEntityIDs() throws XPathExpressionException {

        List<Element> elements = collectEntities();
        List<String> elementStrings = new ArrayList<String>();
        String result;
        for (Element ele : elements) {
            result = executeXPath(ele, "string(@entityID)");
            elementStrings.add(result);
            System.out.println(result);
        }
        System.out.flush();
        return elementStrings;
    }  // end printAllEntityIDs

    // ======================================================================
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
    @Override
    public List<GFIPMCertificate> getAllEntityCertificates(boolean collectDuplicates) {

//        String SPquery = "count(./md:SPSSODescriptor) > 0";
//        String idpquery = "count(./md:IDPSSODescriptor) > 0";

        // This method will return this list:
        List<GFIPMCertificate> certificates = new ArrayList<GFIPMCertificate>();

        String entityIdQuery = "string(@entityID)";
        String entityTypeQuery = "string(./md:RoleDescriptor/@xsi:type)";
        // Results in GFIPMAssertionDelegateServiceType, GFIPMWebServiceProviderType, GFIPMWebServiceConsumerType       
        int count;              // the number of certs for an entity
        int eleCount = 0;       // the total number of elements or entities
        int certCount = 0;      // the total number of certificates found

        try {
            List<Element> elements = collectEntities();

            GFIPMCertificate newcert;

//        String entityid, entitytype;

            for (Element ele : elements) {
                eleCount++;

                String entityid, entitytype;

                entityid = executeXPath(ele, entityIdQuery);
                entitytype = executeXPath(ele, entityTypeQuery);

                //FIXME recode to enumerations
                if ((entitytype != null) && entitytype.endsWith("GFIPMAssertionDelegateServiceType")) {
                    entitytype = "IDP";
                } else if ((entitytype != null) && entitytype.endsWith("GFIPMWebServiceProviderType")) {
                    entitytype = "SP";
                } else if ((entitytype != null) && entitytype.endsWith("GFIPMWebServiceConsumerType")) {
                    entitytype = "SC";
                }

                count = 0;

                newcert = findCertificateInElement(ele, entityid, entitytype, "signing");
                if (newcert != null) {
                    maybeAddCertificate(collectDuplicates, certificates, newcert);
                    count++;
                    certCount++;
                }

                newcert = findCertificateInElement(ele, entityid, entitytype, "encryption");
                if (newcert != null) {
                    maybeAddCertificate(collectDuplicates, certificates, newcert);
                    count++;
                    certCount++;
                }

                if (count == 0) {   // Try null key use:
                    newcert = findCertificateInElement(ele, entityid, entitytype, null);
                    if (newcert != null) {
                        maybeAddCertificate(collectDuplicates, certificates, newcert);
                        count++;
                        certCount++;
                    }
                }

//            // Check for entity type = SP :
//            if (getBooleanXPath(ele, SPquery)) {
//                entitytype = "SP";
//                if (debugOut) {
//                    System.out.println("TrustFabric.getAllEntityCertificates checking: "
//                            + entityid + ", " + entitytype);
//                    System.out.flush();
//                }
//
//                count = 0;
//
//                newcert = findCertificateInElement(ele, entityid, entitytype, "signing");
//                if (newcert != null) {
//                    maybeAddCertificate(collectDuplicates, certificates, newcert);
//                    count++;
//                    certCount++;
//                }
//
//                newcert = findCertificateInElement(ele, entityid, entitytype, "encryption");
//                if (newcert != null) {
//                    maybeAddCertificate(collectDuplicates, certificates, newcert);
//                    count++;
//                    certCount++;
//                }
//
//                if (count == 0) {   // Try null key use:
//                    newcert = findCertificateInElement(ele, entityid, entitytype, null);
//                    if (newcert != null) {
//                        maybeAddCertificate(collectDuplicates, certificates, newcert);
//                        count++;
//                        certCount++;
//                    }
//                }
//            }
//
//            // Check for entity type = IDP :
//            if (getBooleanXPath(ele, idpquery)) {
//                entitytype = "IDP";
//                if (debugOut) {
//                    System.out.println("TrustFabric.getAllEntityCertificates checking: "
//                            + entityid + ", " + entitytype);
//                    System.out.flush();
//                }
//
//                count = 0;
//
//                newcert = findCertificateInElement(ele, entityid, entitytype, "signing");
//                if (newcert != null) {
//                    maybeAddCertificate(collectDuplicates, certificates, newcert);
//                    count++;
//                    certCount++;
//                }
//
//                newcert = findCertificateInElement(ele, entityid, entitytype, "encryption");
//                if (newcert != null) {
//                    maybeAddCertificate(collectDuplicates, certificates, newcert);
//                    count++;
//                    certCount++;
//                }
//
//                if (count == 0) {   // Try null key use:
//                    newcert = findCertificateInElement(ele, entityid, entitytype, null);
//                    if (newcert != null) {
//                        maybeAddCertificate(collectDuplicates, certificates, newcert);
//                        count++;
//                        certCount++;
//                    }
//                }
//            }                
            }
        } catch (XPathExpressionException xpe) {
            log.log(Level.WARNING, "Invalid XPathExpression is used in getAllEntityCertificates.", xpe);
        }

        if (verboseOut) {
            System.out.println("TrustFabric.getAllEntityCertificates found "
                    + eleCount + " entities and "
                    + certCount + " certificates.");
            System.out.flush();
        }

        return certificates;
    }  // end getAllEntityCertificates

// ======================================================================
    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value.
     *
     * @param entityId The entity ID as used in the Trust Fabric document.
     *
     * @param entityType One of "IDP" or "SP" or possibly other values later.
     *
     * @param keyUse The use of the certificate. One of "signing" or
     * "encryption" or null.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    @Override
    public String retrieveEntityCertificate(String entityId, String entityType, String keyUse) {

        // TO DO: Some entities do not have a keyUse attribute - fix this method.
        // Maybe all IDPs?

        if (debugOut) {
            System.out.print("TrustFabric: Trying to retrieve entity with: id=");
            System.out.print(entityId);
            System.out.print(", type=");
            System.out.print(entityType);
            System.out.print(", keyuse=");
            System.out.println(keyUse);
            System.out.flush();
        }

        if (entityId == null) {
            System.err.println("ERROR: TrustFabric.retrieveEntityCertificate: entityId is null");
            System.err.flush();
            return null;
        }

        if (entityType == null) {
            System.err.println("ERROR: TrustFabric.retrieveEntityCertificate: entityType is null");
            System.err.flush();
            return null;
        }

        String result = null;

        StringBuilder query = new StringBuilder();

        query.append("string(");
        query.append(topQuery);
        query.append("[@entityID='");
        query.append(entityId);
        query.append("']/");

//        if (entityType.equalsIgnoreCase("SP")) {
//            query.append("md:SPSSODescriptor");
//        } else if (entityType.equalsIgnoreCase("IDP")) {
//            query.append("md:IDPSSODescriptor");
//        }
        query.append("md:RoleDescriptor");

        query.append("/md:KeyDescriptor");
        if ((keyUse == null) || (keyUse.equals(""))) {
            // do nothing
        } else {
            query.append("[@use='");
            query.append(keyUse);
            query.append("']");
        }
        query.append("/ds:KeyInfo/ds:X509Data/ds:X509Certificate)");

        try {
            result = executeXPath(query.toString());

            if (result == null) {
                // If we didn't find an entity and the entity is an IDP and the key use
                // was specified, try again with key use = null:
                if ((entityType.equalsIgnoreCase("IDP")) && (keyUse != null)) {
                    result = retrieveEntityCertificate(entityId, "IDP", null);
                }
            } else {
                result = removeSpaces(result);
            }
        } catch (XPathExpressionException xpe) {
            log.log(Level.WARNING, "Invalid XPathExpression is used in retrieveEntityCertificate.", xpe);
        }

        if (debugOut) {
            System.out.println("Query: [" + query + "]");
            System.out.print("Certificate: ");
            System.out.println(result);
            System.out.flush();
        }
        return result;

    }  // end retrieveEntityCertificate (3 args)

    // ======================================================================
    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value. The key use will try
     * "signing" or "encryption" or null.
     *
     * @param entityId The entity ID as used in the Trust Fabric document.
     *
     * @param entityType One of "IDP" or "SP" or possibly other values later.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    @Override
    public String retrieveEntityCertificate(String entityId, String entityType) {
        String result;

        result = retrieveEntityCertificate(entityId, entityType, "signing");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, entityType, "encryption");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, entityType, null);
        if (result != null) {
            return result;
        }

        return null;
    }  // end retrieveEntityCertificate (2 args)

    // ======================================================================
    /**
     * Builds a query for an entity's certificate and performs the XPath query
     * on the GFIPM Trust Document and returns the value. For entity type, this
     * method will try both IDP and SP. The key use will try "signing" or
     * "encryption" or null.
     *
     * @param entityId The entity ID as used in the Trust Fabric document.
     *
     * @return Returns a String that is the public certificate with spaces and
     * tabs removed. Or null if not found.
     */
    @Override
    public String retrieveEntityCertificate(String entityId) {
        String result;

        result = retrieveEntityCertificate(entityId, "SP", "signing");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, "SP", "encryption");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, "SP", null);
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, "IDP", "signing");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, "IDP", "encryption");
        if (result != null) {
            return result;
        }

        result = retrieveEntityCertificate(entityId, "IDP", null);
        if (result != null) {
            return result;
        }

        return null;
    }  // end retrieveEntityCertificate (1 arg)    

    //optimize this query
    @Override
    public String getEntityIdBySEP(String sepString) {

        String entityIdString = null;

        StringBuilder query = new StringBuilder();

        query.append("string(");
        query.append(topQuery);
        // XPath 2.0 version could use this and compare function. 
        //                                      (gfipmws:WebServiceEndpoint|gfipmws:DelegatedTokenServiceEndpoint)
        query.append("[contains(./md:RoleDescriptor/gfipmws:*/wsa:EndpointReference/wsa:Address,'");
        query.append(sepString);
        query.append("') and contains('");
        query.append(sepString);
        query.append("', md:RoleDescriptor/gfipmws:*/wsa:EndpointReference/wsa:Address)]/@entityID)");

        try {
            entityIdString = executeXPath(query.toString());
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to find Service Endpoint Reference for " + entityIdString, ex);
        }

        return entityIdString;
    }

    public String getWsdlUrlAddress(String entityId) {
        String sepString = null;
        String query = getEndpointAddressQuery(entityId, "WSDLURL");
        try {
            sepString = executeXPath(query);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to find WSDL URL Endpoint Reference Address for " + entityId, ex);
        }
        return sepString;
    }

    public String getMetadataExchangeEndpointAddress(String entityId) {
        String sepString = null;
        String query = getEndpointAddressQuery(entityId, "MetadataExchangeEndpoint");
        try {
            sepString = executeXPath(query);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to find Delegated Token Service Endpoint Reference Address for " + entityId, ex);
        }
        return sepString;
    }

    public String getDelegatedTokenServiceEndpointAddress(String entityId) {
        String sepString = null;
        String query = getEndpointAddressQuery(entityId, "DelegatedTokenServiceEndpoint");
        try {
            sepString = executeXPath(query);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to find Delegated Token Service Endpoint Reference Address for " + entityId, ex);
        }
        return sepString;
    }

    public String getWebServiceEndpointAddress(String entityId) {
        String sepString = null;
        String query = getEndpointAddressQuery(entityId, "WebServiceEndpoint");
        try {
            sepString = executeXPath(query);
        } catch (XPathExpressionException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, "Unable to find Web Service Endpoint Reference Address for " + entityId, ex);
        }
        return sepString;
    }
    
    public static final String TRUSTSTORE_URL = "truststore.url";
    public static final String TRUSTSTORE_PASSWORD = "truststore.password";

    boolean isValid() {
        boolean isValid = false;

        String resource = "gfipm-security-env.properties";

        Properties properties = new Properties();
        InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
        if (in != null) {
            try {
                properties.load(in);
            } catch (IOException ex) {
                return false;
            }
        }


        String trustStoreURL = properties.getProperty(TRUSTSTORE_URL);
        String trustStorePassword = properties.getProperty(TRUSTSTORE_PASSWORD);
        char[] trustStorePasswordChars = trustStorePassword.toCharArray();

        KeyStore trustStore;

        try {
            trustStore = KeyStore.getInstance(KeyStore.getDefaultType());

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

            Enumeration<String> aliases = trustStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate aliasCertificate = trustStore.getCertificate(alias);
                PublicKey pk = aliasCertificate.getPublicKey();
                if (pk != null && SAMLUtil.verifySignature(trustDocument.getDocumentElement(), pk)) {
                    isValid = true;
                    if (verboseOut) {
                        System.out.println("GFIPM Trust Fabric Document was signed by " + alias);
                    }
                    break;
                }
            }

        } catch (IOException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, null, ex);
        } catch (KeyStoreException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, null, ex);
        } catch (XWSSecurityException ex) {
            Logger.getLogger(TrustFabric.class.getName()).log(Level.SEVERE, null, ex);
        }

        return isValid;
    }

    private String getEndpointAddressQuery(String entityIdString, String endpointTypeString) {
        StringBuilder query = new StringBuilder();
        query.append("string(");
        query.append(topQuery);
        query.append("[@entityID='");
        query.append(entityIdString);
        query.append("']/");
        query.append("md:RoleDescriptor/");
        query.append("gfipmws:");
        query.append(endpointTypeString);
        query.append("/");
        query.append("wsa:EndpointReference/");
        query.append("wsa:Address");
        query.append(")");
        return query.toString();
    }
}   // end class

