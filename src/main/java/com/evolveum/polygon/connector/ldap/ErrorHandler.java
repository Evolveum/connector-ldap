/*
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
package com.evolveum.polygon.connector.ldap;

import org.apache.directory.api.ldap.model.exception.*;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.framework.common.exceptions.*;

public class ErrorHandler {

    public RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
        // AD returns non-printable chars in the message. Remove them, otherwise we will havve problems
        // displaying the message in upper layers
        String exceptionMessage = null;
        if (ldapException.getMessage() != null) {
            exceptionMessage = ldapException.getMessage().replaceAll("\\p{C}", "?");
        }
        if (connectorMessage == null) {
            connectorMessage = "";
        } else {
            connectorMessage = connectorMessage + ": ";
        }
        RuntimeException re;
        if (ldapException instanceof LdapEntryAlreadyExistsException) {
            re = new AlreadyExistsException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapSchemaViolationException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapStrongAuthenticationRequiredException) {
            re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAdminLimitExceededException) {
            re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAffectMultipleDsaException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAliasDereferencingException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAliasException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAttributeInUseException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAuthenticationException) {
            re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapAuthenticationNotSupportedException) {
            re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapConfigurationException) {
            re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof InvalidConnectionException) {
            re = new ConnectionFailedException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapContextNotEmptyException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapInvalidAttributeTypeException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapInvalidAttributeValueException) {
            if (((LdapInvalidAttributeValueException)ldapException).getResultCode() == ResultCodeEnum.CONSTRAINT_VIOLATION) {
                // CONSTRAINT_VIOLATION is usually returned when uniqueness plugin is triggered
                re = new AlreadyExistsException(connectorMessage + exceptionMessage, ldapException);
            } else {
                re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
            }
        } else if (ldapException instanceof LdapInvalidDnException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapInvalidSearchFilterException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapLoopDetectedException) {
            re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapNoPermissionException) {
            re = new PermissionDeniedException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapNoSuchAttributeException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapNoSuchObjectException) {
            re = new UnknownUidException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapSchemaException) {
            re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapSchemaViolationException) {
            re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
        } else if (ldapException instanceof LdapUnwillingToPerformException) {
            re = new PermissionDeniedException(connectorMessage + exceptionMessage, ldapException);
        } else {
            re = new ConnectorIOException(connectorMessage + exceptionMessage, ldapException);
        }
        LdapUtil.logOperationError(connectorMessage, ldapException, connectorMessage);
        return re;
    }


    public RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
        ResultCodeEnum resultCode = ldapResult.getResultCode();
        RuntimeException re;
        switch (resultCode) {
            case SUCCESS :
                re = null;
                break;

            case ENTRY_ALREADY_EXISTS:
            case CONSTRAINT_VIOLATION:
                // CONSTRAINT_VIOLATION is usually returned when uniqueness plugin is triggered
                re =  new AlreadyExistsException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case OBJECT_CLASS_VIOLATION :
            case NOT_ALLOWED_ON_RDN :
            case OBJECT_CLASS_MODS_PROHIBITED :
            case NOT_ALLOWED_ON_NON_LEAF :
            case AFFECTS_MULTIPLE_DSAS :
            case ALIAS_DEREFERENCING_PROBLEM :
            case ALIAS_PROBLEM :
            case ATTRIBUTE_OR_VALUE_EXISTS :
            case UNDEFINED_ATTRIBUTE_TYPE :
            case INVALID_ATTRIBUTE_SYNTAX :
            case INVALID_DN_SYNTAX :
            case NAMING_VIOLATION :
            case INAPPROPRIATE_MATCHING :
            case NO_SUCH_ATTRIBUTE :
                re =  new InvalidAttributeValueException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case STRONG_AUTH_REQUIRED :
            case ADMIN_LIMIT_EXCEEDED :
            case INVALID_CREDENTIALS :
            case INAPPROPRIATE_AUTHENTICATION :
            case CONFIDENTIALITY_REQUIRED :
            case AUTH_METHOD_NOT_SUPPORTED:
                re =  new ConnectorSecurityException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case OTHER :
            case LOOP_DETECT :
                re =  new ConfigurationException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case INSUFFICIENT_ACCESS_RIGHTS :
            case UNWILLING_TO_PERFORM :
            case SIZE_LIMIT_EXCEEDED :
            case TIME_LIMIT_EXCEEDED :
                re =  new PermissionDeniedException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case NO_SUCH_OBJECT :
                re =  new UnknownUidException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            case OPERATIONS_ERROR :
            case PROTOCOL_ERROR :
                // Do not classify this as IO exception. The IO exception often means network error and therefore it is
                // the IDM will re-try. There is no point in re-try if there is a protocol error.
                re =  new ConnectorException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;

            default :
                re =  new ConnectorIOException(connectorMessage + ": " + LdapUtil.formatLdapMessage(ldapResult));
                break;
        }
        LdapUtil.logOperationError(connectorMessage, ldapResult, null);
        return re;
    }


}
