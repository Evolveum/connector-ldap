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
package com.evolveum.polygon.connector.ldap.ad;

import java.io.UnsupportedEncodingException;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

/**
 * @author semancik
 *
 */
public class AdSchemaTranslator extends SchemaTranslator<AdLdapConfiguration> {
		
	private static final Log LOG = Log.getLog(AdSchemaTranslator.class);
	
	private static final String[] OPERATIONAL_ATTRIBUTE_NAMES = {
		"distinguishedname", "dscorepropagationdata", 
		"allowedattributes", "allowedattributeseffective", 
		"allowedchildclasses", "allowedchildclasseseffective",
		"replpropertymetadata", 
		"usnchanged", "usncreated",
		"whenchanged", "whencreated"};
	
	public AdSchemaTranslator(SchemaManager schemaManager, AdLdapConfiguration configuration) {
		super(schemaManager, configuration);
	}

	@Override
	protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		super.extendObjectClassDefinition(ocib, ldapObjectClass);
		if (isUserObjectClass(ldapObjectClass.getName()) || isGroupObjectClass(ldapObjectClass.getName())) {
			AttributeInfoBuilder samAccountNameAttr = new AttributeInfoBuilder(AdConstants.ATTRIBUTE_SAM_ACCOUNT_NAME_NAME);
			samAccountNameAttr.setType(String.class);
			ocib.addAttributeInfo(samAccountNameAttr.build());
		}
		
		AttributeInfoBuilder enableAb = new AttributeInfoBuilder(OperationalAttributes.ENABLE_NAME);
		enableAb.setType(boolean.class);
		ocib.addAttributeInfo(enableAb.build());
	}
	
	@Override
	public AttributeType toLdapAttribute(
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, String icfAttributeName) {
		if (icfAttributeName.equals(OperationalAttributes.ENABLE_NAME)) {
			return super.toLdapAttribute(ldapObjectClass, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME);
		} else {
			return super.toLdapAttribute(ldapObjectClass, icfAttributeName);
		}
	}
	
	@Override
	public Value<Object> toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME.equals(ldapAttributeType.getName())) {
			if (((Boolean)icfAttributeValue)) {
				// ENABLED
				return super.toLdapValue(ldapAttributeType, Integer.toString(AdConstants.USER_ACCOUNT_CONTROL_NORMAL));
			} else {
				// DISABLED
				return super.toLdapValue(ldapAttributeType, Integer.toString(
						AdConstants.USER_ACCOUNT_CONTROL_NORMAL + AdConstants.USER_ACCOUNT_CONTROL_DISABLED));
			}
		}
		return super.toLdapValue(ldapAttributeType, icfAttributeValue);
	}
	
	@Override
	protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
		super.extendConnectorObject(cob, entry, objectClassName);
		Integer userAccountControl = LdapUtil.getIntegerAttribute(entry, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, null);
		if (userAccountControl == null) {
			if (isUserObjectClass(objectClassName)) {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
			}
		} else {
			if ((userAccountControl & AdConstants.USER_ACCOUNT_CONTROL_DISABLED) == 0) {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
			} else {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
			}
		}
	}

	public boolean isUserObjectClass(String ldapObjectClass) {
		return getConfiguration().getUserObjectClass().equals(ldapObjectClass);
	}

	public boolean isGroupObjectClass(String ldapObjectClass) {
		return getConfiguration().getGroupObjectClass().equals(ldapObjectClass);
	}

	@Override
	protected Value<Object> toLdapPasswordValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		String password;
		if (icfAttributeValue instanceof String) {
				password = ((String)icfAttributeValue);
		} else if (icfAttributeValue instanceof GuardedString) {
			final String[] out = new String[1];
			((GuardedString)icfAttributeValue).access(new GuardedString.Accessor() {
				@Override
				public void access(char[] clearChars) {
					out[0] = new String(clearChars);
				}
			});
			password = out[0];
		} else {
			throw new IllegalArgumentException("Password must be string or GuardedString, but it was "+icfAttributeValue.getClass());
		}
		
		String quotedPassword = "\"" + password + "\"";
		byte[] utf16PasswordBytes;
		try {
			utf16PasswordBytes = quotedPassword.getBytes("UTF-16LE");
		} catch (UnsupportedEncodingException e) {
			throw new IllegalStateException("Error converting password to UTF-16: "+e.getMessage(), e);
		}
		
		try {
			return (Value)new BinaryValue(ldapAttributeType, utf16PasswordBytes);
		} catch (LdapInvalidAttributeValueException e) {
			throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
					+"; attributeType="+ldapAttributeType, e);
		}
	}

	@Override
	public boolean isBinaryAttribute(String attributeId) {
		if (AdConstants.ATTRIBUTE_NT_SECURITY_DESCRIPTOR.equalsIgnoreCase(attributeId)) {
			return true;
		}
		return super.isBinaryAttribute(attributeId);
	}
	
	public String formatGuidToDashedNotation(String uidValue) {
		if (uidValue == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append(uidValue.substring(6, 8));
		sb.append(uidValue.substring(4, 6));
		sb.append(uidValue.substring(2, 4));
		sb.append(uidValue.substring(0, 2));
		sb.append('-');
		sb.append(uidValue.substring(10, 12));
		sb.append(uidValue.substring(8, 10));
		sb.append('-');
		sb.append(uidValue.substring(14, 16));
		sb.append(uidValue.substring(12, 14));
		sb.append('-');
		sb.append(uidValue.substring(16, 20));
		sb.append('-');
		sb.append(uidValue.substring(20, 32));
		return sb.toString();
	}

	@Override
	protected boolean isOperational(AttributeType ldapAttribute) {
		if (super.isOperational(ldapAttribute)) {
			return true;
		}
		String attrName = ldapAttribute.getName().toLowerCase();
		if (attrName.startsWith("msds-")) {
			return true;
		}
		return ArrayUtils.contains(OPERATIONAL_ATTRIBUTE_NAMES, attrName);
	}
	
}
