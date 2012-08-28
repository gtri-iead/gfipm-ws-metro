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

package gov.niem.ws.sample.cvc.client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import javax.security.auth.callback.*;

public class GFIPMUsernamePasswordCallbackHandler implements CallbackHandler {

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        for (int i = 0; i < callbacks.length; i++) {
            Callback callback = callbacks[i];
            if (callback instanceof NameCallback) {
                handleUsernameCallback((NameCallback) callback);
            } else if (callback instanceof PasswordCallback) {
                handlePasswordCallback((PasswordCallback) callback);
            } else {
                throw new UnsupportedCallbackException(callback, "Unknown callback type for username or password");
            }
        }
    }

    private void handleUsernameCallback(NameCallback cb) throws IOException {
        System.err.print(">Please Enter Your User Name: ");
        System.err.flush();
        cb.setName((new BufferedReader(new InputStreamReader(System.in))).readLine());
    }

    private void handlePasswordCallback(PasswordCallback cb) throws IOException {
        System.err.print(">Please Enter Your Password: ");
        System.err.flush();
        cb.setPassword((new BufferedReader(new InputStreamReader(System.in))).readLine().toCharArray());
    }
}
