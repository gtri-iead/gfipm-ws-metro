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

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;

/**
 *
 * @author shrom
 */
public class TrustFabricFactory {

    private static TrustFabric trustFabric;

    public static final TrustFabric getInstance() {
        if (trustFabric == null) {
            try {
                trustFabric = new TrustFabric();
            } catch (IOException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            } catch (SAXException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            } catch (ParserConfigurationException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            }
        }
        return trustFabric;
    }

    public static final TrustFabric getInstance(String url) {
        if (trustFabric == null) {
            try {
                trustFabric = new TrustFabric(url);
            } catch (IOException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            } catch (SAXException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            } catch (ParserConfigurationException ex) {
                Logger.getLogger(TrustFabricFactory.class.getName()).log(Level.SEVERE, "Unable to initialize GFIPM Trust Fabric", ex);
            }
        }
        return trustFabric;
    }
}
