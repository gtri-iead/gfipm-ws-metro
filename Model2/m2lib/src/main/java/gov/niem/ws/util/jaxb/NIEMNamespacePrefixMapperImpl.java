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
package gov.niem.ws.util.jaxb;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

/**
 * Namespace prefix mapper for JAXB.
 * @author shrom
 */
public class NIEMNamespacePrefixMapperImpl extends NamespacePrefixMapper {

    public static final String XML_SCHEMA_INSTANCE_NAMESPACE = "http://www.w3.org/2001/XMLSchema-instance";
    public static final String IEPDEXT_NAMESPACE = "urn:examples.com:techniques:iepd:extension:2.0";
    public static final String IEPD_NAMESPACE = "urn:examples.com:techniques:iepd:commercialVehicleCollision:2.0";
    public static final String JXDM__NAMESPACE = "http://niem.gov/niem/domains/jxdm/4.0";
    public static final String NIEMCORE_NAMESPACE = "http://niem.gov/niem/niem-core/2.0";
    public static final String STRUCTURES_NAMESPACE = "http://niem.gov/niem/structures/2.0";
    public static final String APPINFO_NAMESPACE = "http://niem.gov/niem/appinfo/2.0";
    public static final String IMMIGRATION_NAMESPACE = "http://niem.gov/niem/domains/immigration/2.0";
    public static final String EMERGENCYMGMT_NAMESPACE = "http://niem.gov/niem/domains/emergencyManagement/2.0";
    public static final String SCREENING_NAMESPACE = "http://niem.gov/niem/domains/screening/2.0";
    public static final String XML_SCHEMA_PREFIX = "xsi";
    public static final String IEPDEXT_PREFIX = "ext";
    public static final String IEPD_PREFIX = "iepd";
    public static final String JXDM_PREFIX = "j";
    public static final String NC_PREFIX = "nc";
    public static final String S_PREFIX = "s";
    public static final String APPINFO_PREFIX = "i";
    public static final String IMMIGRATION_PREFIX = "im";
    public static final String EMERGENCYMGMT_PREFIX = "em";
    public static final String SCREENING_PREFIX = "scr";

    @Override
    public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {

        if (XML_SCHEMA_INSTANCE_NAMESPACE.equals(namespaceUri)) {
            return XML_SCHEMA_PREFIX;
        }
        if (IEPD_NAMESPACE.equals(namespaceUri)) {
            return IEPD_PREFIX;
        }
        if (IEPDEXT_PREFIX.equals(namespaceUri)) {
            return IEPDEXT_PREFIX;
        }
        if (STRUCTURES_NAMESPACE.equals(namespaceUri)) {
            return S_PREFIX;
        }
        if (APPINFO_NAMESPACE.equals(namespaceUri)) {
            return APPINFO_PREFIX;
        }
        if (JXDM__NAMESPACE.equals(namespaceUri)) {
            return JXDM_PREFIX;
        }
        if (NIEMCORE_NAMESPACE.equals(namespaceUri)) {
            return NC_PREFIX;
        }
        if (IMMIGRATION_NAMESPACE.equals(namespaceUri)) {
            return IMMIGRATION_PREFIX;
        }
        if (EMERGENCYMGMT_NAMESPACE.equals(namespaceUri)) {
            return EMERGENCYMGMT_PREFIX;
        }
        if (SCREENING_NAMESPACE.equals(namespaceUri)) {
            return SCREENING_PREFIX;
        }
        return suggestion;

    }
}
