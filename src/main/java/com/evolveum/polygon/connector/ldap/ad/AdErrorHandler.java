/**
 * Copyright (c) 2015-2020 Evolveum
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

import com.evolveum.polygon.connector.ldap.ErrorHandler;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

public class AdErrorHandler extends ErrorHandler {

    private static final Log LOG = Log.getLog(AdErrorHandler.class);

    @Override
    public RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
        if (ldapResult.getResultCode() == ResultCodeEnum.UNWILLING_TO_PERFORM ||
                ldapResult.getResultCode() == ResultCodeEnum.OPERATIONS_ERROR) {
            AdErrorSubcode adErrorSubcode = AdErrorSubcode.parseDiagnosticMessage(ldapResult.getDiagnosticMessage());
            if (adErrorSubcode != null) {
                try {
                    Class<? extends RuntimeException> exceptionClass = adErrorSubcode.getExceptionClass();
                    Constructor<? extends RuntimeException> exceptionConstructor;
                    exceptionConstructor = exceptionClass.getConstructor(String.class);
                    String exceptionMessage = LdapUtil.sanitizeString(ldapResult.getDiagnosticMessage()) + ": " + adErrorSubcode.name() + ": " + adErrorSubcode.getMessage();
                    RuntimeException exception = exceptionConstructor.newInstance(exceptionMessage);
                    LdapUtil.logOperationError(connectorMessage, ldapResult, exceptionMessage);
                    if (exception instanceof InvalidAttributeValueException) {
                        ((InvalidAttributeValueException)exception).setAffectedAttributeNames(adErrorSubcode.getAffectedAttributes());
                    }
                    throw exception;
                } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
                    LOG.error("Error during LDAP error handling: {0}: {1}", e.getClass(), e.getMessage(), e);
                    // fallback
                    return super.processLdapResult(connectorMessage, ldapResult);
                }
            }

        }
        if (ldapResult.getResultCode() == ResultCodeEnum.OTHER) {
            RuntimeException otherExpression = processOtherError(connectorMessage, ldapResult.getDiagnosticMessage(), ldapResult, null);
            if (otherExpression != null) {
                return otherExpression;
            }
        }
        return super.processLdapResult(connectorMessage, ldapResult);
    }

    @Override
    public RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
        if (ldapException instanceof LdapOtherException) {
            RuntimeException otherExpression = processOtherError(connectorMessage, ldapException.getMessage(), null, (LdapOtherException) ldapException);
            if (otherExpression != null) {
                return otherExpression;
            }
        }
        return super.processLdapException(connectorMessage, ldapException);
    }


    /**
     * This is category of errors that we do not know anything just a string error message.
     * And we have to figure out what is going on just from the message.
     */
    private RuntimeException processOtherError(String connectorMessage, String diagnosticMessage, LdapResult ldapResult, LdapOperationException ldapException) {
        WindowsErrorCode errorCode = WindowsErrorCode.parseDiagnosticMessage(diagnosticMessage);
        if (errorCode == null) {
            return null;
        }
        try {
            Class<? extends RuntimeException> exceptionClass = errorCode.getExceptionClass();
            Constructor<? extends RuntimeException> exceptionConstructor;
            exceptionConstructor = exceptionClass.getConstructor(String.class);
            String exceptionMessage = LdapUtil.sanitizeString(diagnosticMessage) + ": " + errorCode.name() + ": " + errorCode.getMessage();
            RuntimeException exception = exceptionConstructor.newInstance(exceptionMessage);
            if (ldapResult != null) {
                LdapUtil.logOperationError(connectorMessage, ldapResult, exceptionMessage);
            } else {
                LdapUtil.logOperationError(connectorMessage, ldapException, exceptionMessage);
            }
            return exception;
        } catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
            LOG.error("Error during LDAP error handling: {0}: {1}", e.getClass(), e.getMessage(), e);
            // fallback
            return null;
        }
    }


}
