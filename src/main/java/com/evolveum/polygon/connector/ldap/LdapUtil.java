/**
 * Copyright (c) 2015 Evolveum
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

import java.util.ArrayList;
import java.util.List;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException;
import org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException;
import org.apache.directory.api.ldap.model.exception.LdapAliasDereferencingException;
import org.apache.directory.api.ldap.model.exception.LdapAliasException;
import org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException;
import org.apache.directory.api.ldap.model.exception.LdapConfigurationException;
import org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException;
import org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeTypeException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException;
import org.apache.directory.api.ldap.model.exception.LdapNoPermissionException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaViolationException;
import org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationOptions;

/**
 * @author semancik
 *
 */
public class LdapUtil {
	
	public static boolean isDnAttribute(String attributeName) {
		return LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME.equals(attributeName);
	}
	
	public static boolean isEntryUuidAttribute(String attributeName) {
		return LdapConfiguration.ATTRIBUTE_ENTRYUUID_NAME.equals(attributeName) 
				|| LdapConfiguration.ATTRIBUTE_NSUNIQUEID_NAME.equals(attributeName);
	}


	public static String getStringAttribute(Entry entry, String attrName) throws LdapInvalidAttributeValueException {
		Attribute attribute = entry.get(attrName);
		if (attribute == null) {
			return null;
		}
		return attribute.getString();
	}
	
	public static String[] getAttributesToGet(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			OperationOptions options, LdapConfiguration configuration, SchemaTranslator schemaTranslator, String... additionalAttributes) {
		String[] operationalAttributes = configuration.getOperationalAttributes();
		if (options == null || options.getAttributesToGet() == null) {
			String[] ldapAttrs = new String[2 + operationalAttributes.length + additionalAttributes.length];
			ldapAttrs[0] = "*";
			ldapAttrs[1] = configuration.getUidAttribute();
			int i = 2;
			for (String operationalAttribute: operationalAttributes) {
				ldapAttrs[i] = operationalAttribute;
				i++;
			}
			for (String additionalAttribute: additionalAttributes) {
				ldapAttrs[i] = additionalAttribute;
				i++;
			}
			return ldapAttrs;
		}
		String[] icfAttrs = options.getAttributesToGet();
		List<String> ldapAttrs = new ArrayList<String>(icfAttrs.length + operationalAttributes.length + 1);
		for (String icfAttr: icfAttrs) {
			if (Name.NAME.equals(icfAttr)) {
				continue;
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr);
			if (ldapAttributeType == null) {
				// No definition for this attribute. It is most likely operational attribute that is not in the schema.
				if (isOperationalAttribute(configuration, icfAttr)) {
					ldapAttrs.add(icfAttr);
				} else {
					throw new InvalidAttributeValueException("Unknown attribute '"+icfAttr+"' (in attributesToGet)");
				}
			} else {
				ldapAttrs.add(ldapAttributeType.getName());
			}
		}
		for (String operationalAttribute: operationalAttributes) {
			ldapAttrs.add(operationalAttribute);
		}
		for (String additionalAttribute: additionalAttributes) {
			ldapAttrs.add(additionalAttribute);
		}
		ldapAttrs.add(configuration.getUidAttribute());
		return ldapAttrs.toArray(new String[ldapAttrs.size()]);
	}

	public static boolean isOperationalAttribute(LdapConfiguration configuration, String icfAttr) {
		String[] operationalAttributes = configuration.getOperationalAttributes();
		if (operationalAttributes == null) {
			return false;
		}
		for (String opAt: operationalAttributes) {
			if (opAt.equals(icfAttr)) {
				return true;
			}
		}
		return false;
	}

	public static Entry fetchEntry(LdapNetworkConnection connection, String dn, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			OperationOptions options, LdapConfiguration configuration, SchemaTranslator schemaTranslator) {
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options, configuration, schemaTranslator);
		Entry entry = null;
		try {
			EntryCursor searchCursor = connection.search(dn, LdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT, attributesToGet);
			if (searchCursor.next()) {
				entry = searchCursor.get();
			}
			if (searchCursor.next()) {
				throw new IllegalStateException("Impossible has happened, 'base' search for "+dn+" returned more than one entry");
			}
			searchCursor.close();
		} catch (LdapException e) {
			throw processLdapException("Search for "+dn+" failed", e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Search for "+dn+" failed: "+e.getMessage(), e);
		}
		return entry;
	}

	public static RuntimeException processLdapException(String message, LdapException ldapException) {
    	if (message == null) {
    		message = "";
    	} else {
    		message = message + ": ";
    	}
		if (ldapException instanceof LdapEntryAlreadyExistsException) {
			throw new AlreadyExistsException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapSchemaViolationException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapStrongAuthenticationRequiredException) {
			throw new ConnectorSecurityException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAdminLimitExceededException) {
			throw new ConnectorSecurityException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAffectMultipleDsaException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAffectMultipleDsaException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAliasDereferencingException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAliasException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAttributeInUseException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAuthenticationException) {
			throw new ConnectorSecurityException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapAuthenticationNotSupportedException) {
			throw new ConnectorSecurityException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapConfigurationException) {
			throw new ConfigurationException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof InvalidConnectionException) {
			throw new ConnectionFailedException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapContextNotEmptyException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapInvalidAttributeTypeException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapInvalidAttributeValueException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapInvalidDnException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapInvalidSearchFilterException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapLoopDetectedException) {
			throw new ConfigurationException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapNoPermissionException) {
			throw new PermissionDeniedException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapNoSuchAttributeException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapNoSuchObjectException) {
			throw new UnknownUidException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapSchemaException) {
			throw new ConfigurationException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapSchemaViolationException) {
			throw new InvalidAttributeValueException(message + ldapException.getMessage(), ldapException);
		} else if (ldapException instanceof LdapUnwillingToPerformException) {
			throw new PermissionDeniedException(message + ldapException.getMessage(), ldapException);
		} else {
			return new ConnectorIOException(message + ldapException.getMessage(), ldapException);
		}
	}
	
	public static RuntimeException processLdapResult(String message, LdapResult ldapResult) {
		ResultCodeEnum resultCode = ldapResult.getResultCode();
		if (resultCode == ResultCodeEnum.SUCCESS) {
			return null;
		} else if (resultCode == ResultCodeEnum.ENTRY_ALREADY_EXISTS) {
			return new AlreadyExistsException(message + ": " + formatLdapMessage(ldapResult));
		} else if (resultCode == ResultCodeEnum.OBJECT_CLASS_VIOLATION || resultCode == ResultCodeEnum.NOT_ALLOWED_ON_RDN ||
				resultCode == ResultCodeEnum.OBJECT_CLASS_MODS_PROHIBITED || resultCode == ResultCodeEnum.NOT_ALLOWED_ON_NON_LEAF ||
				resultCode == ResultCodeEnum.AFFECTS_MULTIPLE_DSAS || resultCode == ResultCodeEnum.ALIAS_DEREFERENCING_PROBLEM ||
				resultCode == ResultCodeEnum.ALIAS_PROBLEM || resultCode == ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS || 
				resultCode == ResultCodeEnum.UNDEFINED_ATTRIBUTE_TYPE || resultCode == ResultCodeEnum.CONSTRAINT_VIOLATION ||
				resultCode == ResultCodeEnum.INVALID_ATTRIBUTE_SYNTAX || resultCode == ResultCodeEnum.INVALID_DN_SYNTAX ||
				resultCode == ResultCodeEnum.NAMING_VIOLATION || resultCode == ResultCodeEnum.INAPPROPRIATE_MATCHING ||
				resultCode == ResultCodeEnum.NO_SUCH_ATTRIBUTE) {
			return new InvalidAttributeValueException(message + ": " + formatLdapMessage(ldapResult));
		} else if (resultCode == ResultCodeEnum.STRONG_AUTH_REQUIRED || resultCode == ResultCodeEnum.ADMIN_LIMIT_EXCEEDED ||
				resultCode == ResultCodeEnum.INVALID_CREDENTIALS || resultCode == ResultCodeEnum.INAPPROPRIATE_AUTHENTICATION ||
				resultCode == ResultCodeEnum.CONFIDENTIALITY_REQUIRED || resultCode == ResultCodeEnum.AUTH_METHOD_NOT_SUPPORTED) {
			return new ConnectorSecurityException(message + ": " + formatLdapMessage(ldapResult));
		} else if (resultCode == ResultCodeEnum.OTHER || resultCode == ResultCodeEnum.LOOP_DETECT) {
			return new ConfigurationException(message + ": " + formatLdapMessage(ldapResult));
		} else if (resultCode == ResultCodeEnum.INSUFFICIENT_ACCESS_RIGHTS || resultCode == ResultCodeEnum.UNWILLING_TO_PERFORM ||
				resultCode == ResultCodeEnum.SIZE_LIMIT_EXCEEDED || resultCode == ResultCodeEnum.TIME_LIMIT_EXCEEDED) {
			return new PermissionDeniedException(message + ": " + formatLdapMessage(ldapResult));
		} else if (resultCode == ResultCodeEnum.NO_SUCH_OBJECT) {
			return new UnknownUidException(message + ": " + formatLdapMessage(ldapResult));
		} else {
			return new ConnectorIOException(message + ": " + formatLdapMessage(ldapResult));
		}
		
	}
	
	public static String formatLdapMessage(LdapResult ldapResult) {
		return ldapResult.getResultCode().getMessage() +
				": " + ldapResult.getDiagnosticMessage() + " ("+ ldapResult.getResultCode().getResultCode()+")";
	}

	public static Entry getRootDse(LdapNetworkConnection connection, String... attributesToGet) {
		try {
			return connection.getRootDse(attributesToGet);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error getting changelog data from root DSE: "+e.getMessage(), e);
		}
	}
	
	public static boolean isObjectClass(Entry entry,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		if (ldapObjectClass == null) {
			return true;
		}
		Attribute objectClassAttribute = entry.get(LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME); 
		for (Value<?> objectClassVal: objectClassAttribute) {
			if (ldapObjectClass.getName().equals(objectClassVal.getString())) {
				return true;
			}
		}
		return false;
	}
}
