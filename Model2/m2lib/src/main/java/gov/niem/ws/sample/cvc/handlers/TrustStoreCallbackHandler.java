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

package gov.niem.ws.sample.cvc.handlers;

/**
 * Class that supports TrustStoreCallback handler
//
//<wsp:Policy wsu:Id="NewWebServicePortBindingPolicy">
// <wsp:ExactlyOne>
// <wsp:All>
// <sc:KeyStore
// xmlns:sc="http://schemas.sun.com/2006/03/wss/client" wspp:visibility="private"
// callbackHandler="test.KeyStoreCallbackHandler" alias="xws-security-client"/>
// <sc:TrustStore
// xmlns:sc="http://schemas.sun.com/2006/03/wss/client" wspp:visibility="private"
// callbackHandler="test.TrustStoreCallbackHandler" peeralias="xws-security-server"/>
// </wsp:All>
// </wsp:ExactlyOne>
// </wsp:Policy>
//
*/

import com.sun.xml.wss.impl.callback.KeyStoreCallback;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Iterator;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;


public class TrustStoreCallbackHandler implements CallbackHandler {

    KeyStore keyStore = null;
    String password = "changeit";
    public TrustStoreCallbackHandler() {
            System.out.println("Truststore CBH.CTOR Called..........");
            InputStream is = null;
            try {
                keyStore = KeyStore.getInstance("JKS");
                //InputStream inputStream = this.getClass().getClassLoader().getResourceAsStream("META-INF/system.properties");  
                URL keystoreURL =  this.getClass().getResource("cureidpm2-cacerts.jks"); 
                is = new FileInputStream(new File(keystoreURL.getFile()));
                keyStore.load(is, "changeit".toCharArray());
            } catch (IOException ex) {
                Logger.getLogger(KeyStoreCallbackHandler.class.getName()).log(Level.SEVERE, null, ex);
                 throw new RuntimeException(ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(KeyStoreCallbackHandler.class.getName()).log(Level.SEVERE, null, ex);
                 throw new RuntimeException(ex);
            } catch (CertificateException ex) {
                Logger.getLogger(KeyStoreCallbackHandler.class.getName()).log(Level.SEVERE, null, ex);
                 throw new RuntimeException(ex);
            } catch (KeyStoreException ex) {
                Logger.getLogger(KeyStoreCallbackHandler.class.getName()).log(Level.SEVERE, null, ex);
                 throw new RuntimeException(ex);
            } finally {
                try {
                    is.close();
                } catch (IOException ex) {
                    Logger.getLogger(KeyStoreCallbackHandler.class.getName()).log(Level.SEVERE, null, ex);
                }
            }
    }
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        System.out.println("Truststore CBH.handle() Called..........");
         for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof KeyStoreCallback) {
                KeyStoreCallback cb = (KeyStoreCallback) callbacks[i];
                print(cb.getRuntimeProperties());
                cb.setKeystore(keyStore);
            } else {
                throw new UnsupportedCallbackException(callbacks[i]);
            }
        }
    }
    private void print(Map context) {
         Iterator it = context.keySet().iterator();
         while (it.hasNext()) {
             System.out.println("Prop " + it.next());
         }
     }
}
