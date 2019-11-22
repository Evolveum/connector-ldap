/**
 * Copyright (c) 2017-2018 Evolveum
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

import org.identityconnectors.framework.common.exceptions.UnknownUidException;

/**
 * Based on https://msdn.microsoft.com/en-us/library/windows/desktop/ms681390(v=vs.85).aspx
 *
 * @author semancik
 */
public enum WindowsErrorCode {

    ERROR_DS_NO_PARENT_OBJECT(0x2089, "The operation could not be performed because the object's parent is either uninstantiated or deleted.", UnknownUidException.class),
    ERROR_DS_OBJ_NOT_FOUND(0x208D, "Directory object not found.", UnknownUidException.class);

    private int code;
    private String message;
    private Class<? extends RuntimeException> exceptionClass;

    private WindowsErrorCode(int code, String message, Class<? extends RuntimeException> exceptionClass) {
        this.code = code;
        this.message = message;
        this.exceptionClass = exceptionClass;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

    public Class<? extends RuntimeException> getExceptionClass() {
        return exceptionClass;
    }

    public static WindowsErrorCode parseDiagnosticMessage(String diagnosticMessage) {
        if (diagnosticMessage == null) {
            return null;
        }
        int indexColon = diagnosticMessage.indexOf(':');
        if (indexColon < 1) {
            return null;
        }
        String codeString = diagnosticMessage.substring(0,  indexColon);
        int code;
        try {
            code = Integer.parseInt(codeString, 16);
        } catch (NumberFormatException e) {
            return null;
        }
        return getByCode(code);
    }

    private static WindowsErrorCode getByCode(int code) {
        for (WindowsErrorCode val: values()) {
            if (code == val.code) {
                return val;
            }
        }
        return null;
    }
}
