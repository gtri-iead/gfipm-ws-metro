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
package gov.niem.ws.util.jaxb.delegate;

import com.sun.xml.wss.saml.util.SAML20JAXBUtil;
import gov.niem.ws.util.jaxb.WSConstants;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;

/**
 * Helper class to provide custom JAXBContext initialization for Delegation support.
 * @author shrom
 */
public class DelegateUtil {

    private static final Logger logger = Logger.getLogger(DelegateUtil.class.getName());
    private static final boolean DEBUG = true;
    private static JAXBContext jaxbContext = null;

    public static boolean initDelegateJAXBContext() {
        try {
            if (jaxbContext == null) {
                jaxbContext = SAML20JAXBUtil.getJAXBContext(WSConstants.DELEGATE_JAXB_CONTEXT_PACKAGE);
                if (DEBUG) {
                    logger.log(Level.FINEST, "DelegateUtil::initDelegateJAXBContext::JAXB got initialized for: " + WSConstants.DELEGATE_JAXB_CONTEXT_PACKAGE + " context ");
                }
            } else {
                if (DEBUG) {
                    logger.log(Level.FINEST, "DelegateUtil::initDelegateJAXBContext::JAXB is already initialized");
                }
            }
        } catch (JAXBException ex) {
            logger.log(Level.SEVERE, null, ex);
            return false;
        }
        return true;
    }

    public static JAXBContext getJAXBContext() {
        if (jaxbContext == null) {
            initDelegateJAXBContext();
        }
        return jaxbContext;
    }
}
