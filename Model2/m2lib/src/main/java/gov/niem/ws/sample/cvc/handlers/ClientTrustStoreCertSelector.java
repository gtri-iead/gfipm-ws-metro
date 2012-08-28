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

import java.security.Principal;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class ClientTrustStoreCertSelector implements CertSelector {

    private Map context;
    private String serviceCert;

    public ClientTrustStoreCertSelector(Map contextParam) {
        this.context = contextParam;
        if (context != null) {
            this.serviceCert = (String) context.get("com.example.common.security.certificate.service");
        }
    }

    public boolean match(Certificate certificate) {
        boolean result = false;
        if ((this.serviceCert != null) && (this.serviceCert.length() > 0)
                && (certificate instanceof X509Certificate)) {
            // The certificate's subject name must match what has been specified
            String certSubj = getCertificateSubject((X509Certificate) certificate);
            result = this.serviceCert.equals(certSubj);
        }
        return result;
    }

    @Override
    public Object clone() {
        return new ClientTrustStoreCertSelector(new HashMap(this.context));
    }

    private String getCertificateSubject(X509Certificate certificate) {
        String result = null;
        Principal subject = certificate.getSubjectDN();
        if (subject != null) {
            result = subject.getName();
        }
        return result;
    }
}
