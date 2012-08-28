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

import java.util.Iterator;
import javax.xml.*;
import javax.xml.namespace.NamespaceContext;

/**
 * A class to return the appropriate Namespace context for xPath execution
 * against KML files
 */
public class GfipmNamespaceContext implements NamespaceContext {

    /**
     * A method to return the Namespace URI of a given namespace prefix
     *
     * @param prefix the prefix to math
     *
     * @return the matched namespace URI
     */
    public String getNamespaceURI(String prefix) {

        // determine which namespace to return
        if (prefix == null) {
            // no prefix specified
            throw new NullPointerException("Null prefix");
        } else if ("md".equals(prefix)) {
            return "urn:oasis:names:tc:SAML:2.0:metadata";
        } else if ("ds".equals(prefix)) {
            return "http://www.w3.org/2000/09/xmldsig#";
        } else if ("gfipmws".equals(prefix)) {
            return "http://gfipm.net/standards/metadata/2.0/webservices";
        } else if ("xsi".equals(prefix)) {
            return "http://www.w3.org/2001/XMLSchema-instance";            
        } else if ("wsa".equals(prefix)) {
            return "http://www.w3.org/2005/08/addressing";
        } else if ("gfipm".equals(prefix)) {
            return "http://gfipm.net/standards/metadata/2.0/entity";
        } else if ("xml".equals(prefix)) {
            // default namespace
            return XMLConstants.XML_NS_URI;
        } else {
            // default namespace
            return XMLConstants.XML_NS_URI;
        }
    }

    /**
     * This method isn't necessary for XPath processing.
     */
    public String getPrefix(String uri) {
        throw new UnsupportedOperationException();
    }

    /**
     * This method isn't necessary for XPath processing.
     */
    public Iterator getPrefixes(String uri) {
        throw new UnsupportedOperationException();
    }
}
