/**
 * Copyright (c) 2015-2018 Evolveum
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
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class AdSchemaTranslator extends AbstractSchemaTranslator<AdLdapConfiguration> {
		
	private static final Log LOG = Log.getLog(AdSchemaTranslator.class);
	
	private static final String[] OPERATIONAL_ATTRIBUTE_NAMES = {
		"distinguishedname", "dscorepropagationdata", 
		"allowedattributes", "allowedattributeseffective", 
		"allowedchildclasses", "allowedchildclasseseffective",
		"replpropertymetadata", 
		"usnchanged", "usncreated",
		"whenchanged", "whencreated"};
	
	/**
	 * List of attributes in the top object class that are specified as
	 * mandatory but they are in fact optional.
	 */
	private static final String[] OPTIONAL_TOP_ATTRIBUTES = {
			"ntsecuritydescriptor", "instancetype", "objectcategory"
	};
	
	private AttributeType guidAttributeType = null;
	
	public AdSchemaTranslator(SchemaManager schemaManager, AdLdapConfiguration configuration) {
		super(schemaManager, configuration);
	}

	@Override
	protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		super.extendObjectClassDefinition(ocib, ldapObjectClass);
		if (getConfiguration().isTweakSchema()) {
			// Account and groups need samAccountName attribute. But it is not in the declared schema.
			if (isUserObjectClass(ldapObjectClass.getName()) || isGroupObjectClass(ldapObjectClass.getName())) {
				AttributeInfoBuilder samAccountNameAttr = new AttributeInfoBuilder(AdConstants.ATTRIBUTE_SAM_ACCOUNT_NAME_NAME);
				samAccountNameAttr.setType(String.class);
				ocib.addAttributeInfo(samAccountNameAttr.build());
			}
		}
		
		if (!getConfiguration().isRawUserAccountControlAttribute()) {
			AttributeInfoBuilder enableAb = new AttributeInfoBuilder(OperationalAttributes.ENABLE_NAME);
			enableAb.setType(boolean.class);
			ocib.addAttributeInfo(enableAb.build());
		}
	}
	
	
	
	@Override
	protected void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, String connidAttributeName,
			AttributeInfoBuilder aib) {
		super.setAttributeMultiplicityAndPermissions(ldapAttributeType, connidAttributeName, aib);
		if (ArrayUtils.contains(OPTIONAL_TOP_ATTRIBUTES, ldapAttributeType.getName().toLowerCase())) {
			aib.setRequired(false);
		}
	}

	@Override
	public AttributeType toLdapAttribute(
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, String icfAttributeName) {
		if (!getConfiguration().isRawUserAccountControlAttribute() && icfAttributeName.equals(OperationalAttributes.ENABLE_NAME)) {
			return super.toLdapAttribute(ldapObjectClass, AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME);
		} else {
			return super.toLdapAttribute(ldapObjectClass, icfAttributeName);
		}
	}
	
	@Override
	public Value toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (!getConfiguration().isRawUserAccountControlAttribute() && AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME.equals(ldapAttributeType.getName())) {
			if ((Boolean)icfAttributeValue) {
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
	public Value toLdapIdentifierValue(AttributeType ldapAttributeType, String icfAttributeValue) {
		if (isGuid(ldapAttributeType)) {
			icfAttributeValue = parseGuidFromDashedNotation(icfAttributeValue);
		}
		return super.toLdapIdentifierValue(ldapAttributeType, icfAttributeValue);
	}

	@Override
	public String toIcfIdentifierValue(Value ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
		String icfIdentifierValue = super.toIcfIdentifierValue(ldapValue, ldapAttributeName, ldapAttributeType);
		if (isGuid(ldapAttributeType)) {
			icfIdentifierValue = formatGuidToDashedNotation(icfIdentifierValue);
		}
		return icfIdentifierValue;
	}

	private boolean isGuid(AttributeType ldapAttributeType) {
		return ldapAttributeType.getName().equalsIgnoreCase(AdLdapConfiguration.ATTRIBUTE_OBJECT_GUID_NAME);
	}

	@Override
	protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
		super.extendConnectorObject(cob, entry, objectClassName);
		if (!getConfiguration().isRawUserAccountControlAttribute()) {
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
	}

	public boolean isUserObjectClass(String ldapObjectClass) {
		return getConfiguration().getUserObjectClass().equals(ldapObjectClass);
	}

	public boolean isGroupObjectClass(String ldapObjectClass) {
		return getConfiguration().getGroupObjectClass().equals(ldapObjectClass);
	}

	@Override
	protected Value toLdapPasswordValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		String password;
		if (icfAttributeValue instanceof String) {
				password = (String)icfAttributeValue;
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
			return new Value(ldapAttributeType, utf16PasswordBytes);
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
	
	public Dn getGuidDn(String uidValue) {
		// Yes, this is really how Active Directory DNs looks like. Yes, they are really DNs.
		// Insane, isn't it? Well, yes, it is AD after all.
		// We need to create this as schema-aware even though it has nothing to do with the
		// schema. But if the Dn parsing does not know about schemaManager it does not know
		// that we are in relaxed mode and it will fail with these crazy DNs.
		return toSchemaAwareDn("<GUID="+uidValue+">");
	}
	
	
	public String getGuidAsDashedString(Entry entry) {
		Attribute guidAttribute = entry.get(AdLdapConfiguration.ATTRIBUTE_OBJECT_GUID_NAME);
		String hexNotation = super.toIcfIdentifierValue(guidAttribute.get(), AdLdapConfiguration.ATTRIBUTE_OBJECT_GUID_NAME, 
				getGuidAttributeType());
		return formatGuidToDashedNotation(hexNotation);
	}
	
	private AttributeType getGuidAttributeType() {
		if (guidAttributeType == null) {
			guidAttributeType = getSchemaManager().getAttributeType(AdLdapConfiguration.ATTRIBUTE_OBJECT_GUID_NAME);
		}
		return guidAttributeType;
	}
	
	/**
	 * Returns dashed GUID notation formatted from simple hex-encoded binary.
	 * 
	 * E.g. "2f01c06bb1d0414e9a69dd3841a13506" -> "6bc0012f-d0b1-4e41-9a69-dd3841a13506"
	 */
	public String formatGuidToDashedNotation(String hexValue) {
		if (hexValue == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append(hexValue.substring(6, 8));
		sb.append(hexValue.substring(4, 6));
		sb.append(hexValue.substring(2, 4));
		sb.append(hexValue.substring(0, 2));
		sb.append('-');
		sb.append(hexValue.substring(10, 12));
		sb.append(hexValue.substring(8, 10));
		sb.append('-');
		sb.append(hexValue.substring(14, 16));
		sb.append(hexValue.substring(12, 14));
		sb.append('-');
		sb.append(hexValue.substring(16, 20));
		sb.append('-');
		sb.append(hexValue.substring(20, 32));
		return sb.toString();
	}

	/**
	 * Returns simple hex-encoded string parsed from dashed GUID notation.
	 * 
	 * E.g. "6bc0012f-d0b1-4e41-9a69-dd3841a13506" -> "2f01c06bb1d0414e9a69dd3841a13506"
	 */
	public String parseGuidFromDashedNotation(String guidDashedNotation) {
		if (guidDashedNotation == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		sb.append(guidDashedNotation.substring(6, 8));
		sb.append(guidDashedNotation.substring(4, 6));
		sb.append(guidDashedNotation.substring(2, 4));
		sb.append(guidDashedNotation.substring(0, 2));
		sb.append(guidDashedNotation.substring(11, 13));
		sb.append(guidDashedNotation.substring(9, 11));
		sb.append(guidDashedNotation.substring(16, 18));
		sb.append(guidDashedNotation.substring(14, 16));
		sb.append(guidDashedNotation.substring(19, 23));
		sb.append(guidDashedNotation.substring(24, 36));
		return sb.toString();
	}
	
	@Override
	public String getDn(Entry entry) {
		// distinguishedName attribute provides better DN format (some kind of Microsoft-cannonical form).
		// The usual entry DN will be formatted in the same way as it was in the request. Therefore if
		// name hint is used with midPoint, the normal DN will be all lowercase. This may break some things,
		// e.g. it may interfere with names in older shadows.
		// So use distinguishedName attribute if available.
		Attribute distinguishedNameAttr = entry.get(AdConstants.ATTRIBUTE_DISTINGUISHED_NAME_NAME);
		if (distinguishedNameAttr != null) {
			try {
				return distinguishedNameAttr.getString();
			} catch (LdapInvalidAttributeValueException e) {
				LOG.warn("Error getting sting value from {0}, falling back to entry DN: {1}", 
						distinguishedNameAttr, e.getMessage(), e);
				return super.getDn(entry);
			}
		}
		return super.getDn(entry);
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
