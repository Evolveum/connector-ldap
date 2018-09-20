/**
 * Copyright (c) 2017 Evolveum
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

import java.util.Arrays;
import java.util.Collection;

import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.InvalidPasswordException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

/**
 * Based on http://www.ldapwiki.com/wiki/WILL_NOT_PERFORM
 * 
 * @author semancik
 */
public enum WillNotPerform {
	
	INVALID_PRIMARY_GROUP(0x51c, "This security ID may not be assigned as the primary groupof an object", InvalidAttributeValueException.class),
	NO_IMPERSONATION_TOKEN(0x51d, "An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client", ConnectorSecurityException.class),
	CANT_DISABLE_MANDATORY(0x51e, "The group may not be disabled", PermissionDeniedException.class),
	NO_LOGON_SERVERS(0x51f, "There are currently no logon servers available to service the logon request", PermissionDeniedException.class),
	NO_SUCH_LOGON_SESSION(0x520, "A specified logon session does not exist. It may already have been terminated", PermissionDeniedException.class),
	NO_SUCH_PRIVILEGE(0x521, "A specified privilege does not exist", ConnectorSecurityException.class),
	PRIVILEGE_NOT_HELD(0x522, "A required privilege is not held by the client", PermissionDeniedException.class),
	INVALID_ACCOUNT_NAME(0x523, "The name provided is not a properly formed account name", InvalidAttributeValueException.class),
	USER_EXISTS(0x524, "The specified user already exists", AlreadyExistsException.class),
	NO_SUCH_USER(0x525, "The specified user does not exist", UnknownUidException.class),
	GROUP_EXISTS(0x526, "The specified group already exists", AlreadyExistsException.class),
	NO_SUCH_GROUP(0x527, "The specified group does not exist", UnknownUidException.class),
	MEMBER_IN_GROUP(0x528, "Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member", ConnectorException.class),
	MEMBER_NOT_IN_GROUP(0x529, "The specified user account is not a member of the specified group account", ConnectorException.class),
	LAST_ADMIN(0x52a, "The last remaining administration account cannot be disabled or deleted", PermissionDeniedException.class),
	WRONG_PASSWORD(0x52b, "Unable to update the password. The value provided as the current password is incorrect",
			InvalidAttributeValueException.class, OperationalAttributes.PASSWORD_NAME),
	ILL_FORMED_PASSWORD(0x52c, "Unable to update the password. The value provided for the new password contains values that are not allowed in passwords",
			InvalidAttributeValueException.class, OperationalAttributes.PASSWORD_NAME),
	PASSWORD_RESTRICTION(0x52d, "Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirement of the domain",
			InvalidAttributeValueException.class, OperationalAttributes.PASSWORD_NAME),
	LOGON_FAILURE(0x52e, "Logon failure unknown user name or bad password", PermissionDeniedException.class),
	ACCOUNT_RESTRICTION(0x52f, "Logon failure user account restriction. Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced", PermissionDeniedException.class),
	INVALID_LOGON_HOURS(0x530, "Logon failure account logon time restriction violation", PermissionDeniedException.class),
	INVALID_WORKSTATION(0x531, "Logon failure user not allowed to log on to this computer", PermissionDeniedException.class),
	PASSWORD_EXPIRED(0x532, "Logon failure the specified account password has expired", PermissionDeniedException.class),
	ACCOUNT_DISABLED(0x533, "Logon failure account currently disabled", PermissionDeniedException.class),
	NONE_MAPPED(0x534, "No mapping between account names and security IDs was done", PermissionDeniedException.class),
	TOO_MANY_LUIDS_REQUESTED(0x535, "Too many local user identifiers (LUIDs) were requested at one time", ConnectorException.class),
	LUIDS_EXHAUSTED(0x536, "No more local user identifiers (LUIDs) are available", ConnectorException.class),
	INVALID_SUB_AUTHORITY(0x537, "The subauthority part of a security ID is invalid for this particular use", ConnectorException.class),
	INVALID_ACL(0x538, "The access control list (ACL) structure is invalid", ConnectorException.class),
	INVALID_SID(0x539, "The security ID structure is invalid", ConnectorException.class),
	INVALID_SECURITY_DESCR(0x53a, "The security descriptor structure is invalid", ConnectorException.class);
	
	private int code;
	private String message;
	private Class<? extends RuntimeException> exceptionClass;
	private Collection<String> affectedAttributes;
	
	private WillNotPerform(int code, String message, Class<? extends RuntimeException> exceptionClass, String... affectedAttributes) {
		this.code = code;
		this.message = message;
		this.exceptionClass = exceptionClass;
		if (affectedAttributes != null && affectedAttributes.length != 0) {
			this.affectedAttributes = Arrays.asList(affectedAttributes);
		}
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
	
	public Collection<String> getAffectedAttributes() {
		return affectedAttributes;
	}

	public static WillNotPerform parseDiagnosticMessage(String diagnosticMessage) {
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

	private static WillNotPerform getByCode(int code) {
		for (WillNotPerform val: values()) {
			if (code == val.code) {
				return val;
			}
		}
		return null;
	}
}
