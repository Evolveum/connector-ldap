/**
 * Copyright (c) 2020 Evolveum
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
package com.evolveum.polygon.connector.ldap.ad;

import org.identityconnectors.framework.common.exceptions.RetryableException;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Handling the strange (and mostly undocumented) errors with DSID identifier, e.g:
 *
 * unavailableCriticalExtension: 00000057: LdapErr: DSID-0C090850, comment: Error processing control, data 0, v2580? (12)
 *
 */
public class DsidError {

    private final static Pattern DSID_PATTERN = Pattern.compile("LdapErr: DSID-([0-0a-fA-F]+)");

    private final String message;
    private final Class<? extends RuntimeException> exceptionClass;

    public DsidError(String message, String originalDiagnosticMessage, Class<? extends RuntimeException> exceptionClass) {
        if (originalDiagnosticMessage == null) {
            this.message = message;
        } else {
            this.message = message + "(original message: " + originalDiagnosticMessage +" )";
        }
        this.exceptionClass = exceptionClass;
    }

    public String getMessage() {
        return message;
    }

    public Class<? extends RuntimeException> getExceptionClass() {
        return exceptionClass;
    }

    public static DsidError parseDiagnosticMessage(String diagnosticMessage) {
        if (diagnosticMessage == null) {
            return null;
        }
        Matcher matcher = DSID_PATTERN.matcher(diagnosticMessage);
        if (!matcher.find()) {
            return null;
        }
        String codeString = matcher.group(1).toUpperCase();
        switch (codeString) {
            case "0C090850":
                    // unavailableCriticalExtension: 00000057: LdapErr: DSID-0C090850, comment: Error processing control, data 0, v2580? (12)
                    //
                    // Not sure about this error. It looks like we have exceeded or depleted indexing resources on the server.
                    // It seems to be related to paging (SPR control).
                    // It happens sometimes (rarely) for operation that works perfectly other times.
                    // However, it seems to be a temporary error. The "unavailableCriticalExtension" would suggest a permanent error, therefore overriding the exception type.
                    // MID-6530
                    return new DsidError("Search or indexing limits (temporarily) exceeded?", diagnosticMessage, RetryableException.class);
        }
        return null;
    }
}
