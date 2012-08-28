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
import com.sun.xml.wss.saml.util.SAML20JAXBUtil;
import java.io.*;
import java.util.logging.Logger;
import javax.xml.XMLConstants;
import javax.xml.bind.*;
import javax.xml.bind.util.ValidationEventCollector;
import javax.xml.transform.Source;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import org.xml.sax.SAXException;

/**
 * JAXB Helper Class.
 * $Id$
 * @author shrom
 */
public class InstanceHelper {

    private static final Logger logger = Logger.getLogger(InstanceHelper.class.getName());

    //Settable properties
    private String schemaLocation = null;
    private String schemaNamespace = null;
    private NamespacePrefixMapper namespacePrefixMapper;

    //Initialized properties
//    private JAXBContext jaxbContext;
    private Schema validationSchema = null;

    public InstanceHelper() throws SAXException, JAXBException {
        initialize();
    }

    public InstanceHelper(String schemaLocation, String schemaNamespace) throws SAXException, JAXBException {
        setSchemaLocation(schemaLocation);
        setSchemaNamespace(schemaNamespace);
        initialize();
    }

    private void initialize()
            throws SAXException, JAXBException {

        if (schemaLocation != null) {

            // create a SchemaFactory capable of understanding WXS schemas
            SchemaFactory factory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);

            // load a WXS schema, represented by a Schema instance
            Source schemaSource = new StreamSource(this.schemaLocation);
            try {
                validationSchema = factory.newSchema(schemaSource);
            } catch (SAXException e) {
                logger.warning("Unable to load schema from following schema location:" + this.schemaLocation);
                logger.throwing(InstanceHelper.class.getName(), "initialize()", e);
                throw e;
            }
        }

        // create a JAXBContext capable of handling classes generated into the default package
//        jaxbContext = JAXBContext.newInstance(WSConstants.DELEGATE_JAXB_CONTEXT_PACKAGE);

    }

    public Unmarshaller getUnmarshaller() {
        Unmarshaller unmarshaller = null;
        try {
            unmarshaller = SAML20JAXBUtil.getJAXBContext().createUnmarshaller();
            if (validationSchema != null) {
                unmarshaller.setSchema(validationSchema);
                ValidationEventCollector vec = new ValidationEventCollector();
                unmarshaller.setEventHandler(vec);
            }
        } catch (JAXBException ex) {
            logger.throwing(InstanceHelper.class.getName(), "getUnmarshaller()", ex);
        }
        return unmarshaller;
    }

    public Marshaller getMarshaller() {
        Marshaller marshaller = null;
        try {
            marshaller = SAML20JAXBUtil.getJAXBContext().createMarshaller();
            marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
            if (namespacePrefixMapper != null) {
                marshaller.setProperty(WSConstants.NAMESPACE_PREFIX_PROP, namespacePrefixMapper);
            }
            if (validationSchema != null) {
                marshaller.setSchema(validationSchema);
                //TODO add validation of schema location to the empty string
                marshaller.setProperty(Marshaller.JAXB_SCHEMA_LOCATION,
                        this.schemaNamespace + " " + (this.schemaLocation == null ? this.schemaNamespace : this.schemaLocation));
            }
        } catch (JAXBException ex) {
            logger.throwing(InstanceHelper.class.getName(), "getMarshaller", ex);
        }
        return marshaller;
    }

    public JAXBElement<?> getJAXBElement(String fileName) {
        JAXBElement<?> jaxbElement = null;
        try {
            FileInputStream fileInputStream = new FileInputStream(fileName);
            jaxbElement = getJAXBElement(fileInputStream);
        } catch (FileNotFoundException fnfe) {
            logger.warning("File not found : " + fileName);
            logger.throwing(InstanceHelper.class.getName(), "getJAXBElement(String fileName)", fnfe);
        }
        return jaxbElement;
    }

    public JAXBElement<?> getJAXBElement(InputStream inputStream) {
        JAXBElement<?> jaxbElement = null;
        Unmarshaller unmarshaller;
        try {
            if (inputStream != null && inputStream.available() != 0) {
                unmarshaller = getUnmarshaller();
                jaxbElement = (JAXBElement<?>) unmarshaller.unmarshal(inputStream);
                if (validationSchema != null) {
                    ValidationEvent[] validationEvent = ((ValidationEventCollector) unmarshaller.getEventHandler()).getEvents();
                    if (validationEvent.length != 0) {
                        StringBuffer validationErrorMessages = new StringBuffer();
                        for (int i = 0; i < validationEvent.length; i++) {
                            validationErrorMessages.append(validationEvent[i].getMessage());
                            validationErrorMessages.append(" on line ");
                            validationErrorMessages.append(validationEvent[i].getLocator().getLineNumber());
                            validationErrorMessages.append("\n");
                            throw new JAXBException(validationErrorMessages.toString());
                        }
                    }
                }
            }
        } catch (JAXBException je) {
            logger.throwing(InstanceHelper.class.getName(), "getJAXBElement(InputStream inputStream)", je);
        } catch (IOException e) {
            logger.warning("InputStream is not available");
            logger.throwing(InstanceHelper.class.getName(), "getJAXBElement(InputStream inputStream)", e);
        }
        return jaxbElement;
    }

    public String getString(JAXBElement<?> jaxbElement) {
        // marshall a tree of Java content objects back to a string
        if (jaxbElement == null) {
            logger.fine("Input JAXBElement is null");
            return "";
        } else {
            logger.finest("JAXB element is : " + jaxbElement.getName());
        }
        StringWriter sw = new StringWriter();
        try {
            getMarshaller().marshal(jaxbElement, sw);
        } catch (JAXBException e) {
            logger.fine("Error getting String from JAXBElement");
            logger.throwing(InstanceHelper.class.getName(), "getString(JAXBElement<?> jaxbElement)", e);
            return "";
        }
        return sw.getBuffer().toString();
    }

    public void setSchemaLocation(String schemaLocation) {
        this.schemaLocation = schemaLocation;
    }

    public void setSchemaNamespace(String schemaNamespace) {
        this.schemaNamespace = schemaNamespace;
    }

    public void setNamespacePrefixMapper(NamespacePrefixMapper namespacePrefixMapper) {
        this.namespacePrefixMapper = namespacePrefixMapper;
    }
}
