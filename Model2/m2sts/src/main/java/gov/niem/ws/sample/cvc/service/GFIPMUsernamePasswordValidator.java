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

import com.sun.xml.wss.impl.callback.PasswordValidationCallback;
import java.util.logging.Level;
import java.util.logging.Logger;

public class GFIPMUsernamePasswordValidator implements PasswordValidationCallback.PasswordValidator {

    private static final Logger logger =
            Logger.getLogger(GFIPMUsernamePasswordValidator.class.getName());
    private static final boolean DEBUG = true;

    public boolean validate(PasswordValidationCallback.Request request)
            throws PasswordValidationCallback.PasswordValidationException {
//          PasswordValidationCallback.DigestPasswordRequest req = (PasswordValidationCallback.DigestPasswordRequest)request;        
        if (DEBUG) {
            logger.log(Level.FINEST, "GFIPMUsernamePasswordValidator: Request is of type " + request.getClass().getCanonicalName());
        }

        PasswordValidationCallback.PlainTextPasswordRequest plainTextRequest =
                (PasswordValidationCallback.PlainTextPasswordRequest) request;
        if (DEBUG) {
            logger.log(Level.FINEST, "GFIPMUsernamePasswordValidator: validating user : " + plainTextRequest.getUsername() + "::" + plainTextRequest.getPassword());
        }
        if ("alice".equals(plainTextRequest.getUsername())
                && "alice".equals(plainTextRequest.getPassword())) {
            if (DEBUG) {
                logger.log(Level.FINEST, "GFIPMUsernamePasswordValidator: logged in alice ");
            }
            return true;
        } else if ("bob".equals(plainTextRequest.getUsername())
                && "bob".equals(plainTextRequest.getPassword())) {
            if (DEBUG) {
                logger.log(Level.FINEST, "GFIPMUsernamePasswordValidator: logged in bob ");
            }
            return true;
        }
        if (DEBUG) {
            logger.log(Level.FINEST, "GFIPMUsernamePasswordValidator: login failed ");
        }
        return false;
    }
}
