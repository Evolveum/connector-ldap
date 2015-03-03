/**
 * Copyright (c) 2014 Evolveum
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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;

/**
 * @author semancik
 *
 */
public class SchemaTranslator {
	
	private static final Log LOG = Log.getLog(SchemaTranslator.class);
	private static final Map<String, Class<?>> SYNTAX_MAP = new HashMap<String,Class<?>>();
	private static final String SYNTAX_GENERALIZED_TIME_OID = "TODO"; 
	
	private SchemaManager schemaManager;
	private LdapConfiguration configuration;
	private Schema icfSchema = null;
	
	public SchemaTranslator(SchemaManager schemaManager, LdapConfiguration configuration) {
		super();
		this.schemaManager = schemaManager;
		this.configuration = configuration;
	}

	public Schema translateSchema() {
		SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
		LOG.ok("Translating LDAP schema from {0}", schemaManager);
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
			LOG.ok("Found LDAP schema object class {0}", ldapObjectClass.getName());
			ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
			ocib.setType(ldapObjectClass.getName());
			List<AttributeInfo> attrInfoList = new ArrayList<AttributeInfo>();
			addAttributeTypes(attrInfoList, ldapObjectClass);
			ocib.addAllAttributeInfo(attrInfoList);
			schemaBuilder.defineObjectClass(ocib.build());
		}
		icfSchema = schemaBuilder.build();
		return icfSchema;
	}
	
	private void addAttributeTypes(List<AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		addAttributeTypesFromLdapSchema(attrInfoList, ldapObjectClass);
		addExtraOperationalAttributes(attrInfoList, ldapObjectClass);
	}
	
	private void addExtraOperationalAttributes(List<AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		for (String operationalAttributeLdapName: configuration.getOperationalAttributes()) {
			if (containsAttribute(attrInfoList, operationalAttributeLdapName)) {
				continue;
			}
			AttributeInfoBuilder aib = new AttributeInfoBuilder(operationalAttributeLdapName);
			aib.setRequired(false);
			
			AttributeType attributeType = null;
			try {
				String operationalAttributeLdapOid = schemaManager.getAttributeTypeRegistry().getOidByName(operationalAttributeLdapName);
				attributeType = schemaManager.getAttributeTypeRegistry().get(operationalAttributeLdapOid);
			} catch (LdapException e) {
				// Ignore. We want this attribute even if it is not in the LDAP schema
			}
			
			if (attributeType != null) {
				aib.setType(toIcfType(attributeType.getSyntax(), operationalAttributeLdapName));
				if (attributeType.isSingleValued()) {
					aib.setMultiValued(false);
				} else {
					aib.setMultiValued(true);
				}
				if (attributeType.isReadOnly()) {
					aib.setCreateable(false);
					aib.setUpdateable(false);
				}
			} else {
				aib.setType(String.class);
				aib.setMultiValued(false);
			}
			aib.setReturnedByDefault(false);
			
			attrInfoList.add(aib.build());
		}
		
	}
	
	private void addAttributeTypesFromLdapSchema(List<AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		addAttributeTypes(attrInfoList, ldapObjectClass.getMustAttributeTypes(), true);
		addAttributeTypes(attrInfoList, ldapObjectClass.getMayAttributeTypes(), false);
		
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> superiors = ldapObjectClass.getSuperiors();
		if (superiors != null) {
			for (org.apache.directory.api.ldap.model.schema.ObjectClass superior: superiors) {
				addAttributeTypesFromLdapSchema(attrInfoList, superior);
			}
		}
	}

	private void addAttributeTypes(List<AttributeInfo> attrInfoList, List<AttributeType> attributeTypes, boolean isRequired) {
		for (AttributeType ldapAttribute: attributeTypes) {
			String icfAttributeName = toIcfAttributeName(ldapAttribute.getName());
			if (containsAttribute(attrInfoList, icfAttributeName)) {
				continue;
			}
			AttributeInfoBuilder aib = new AttributeInfoBuilder(icfAttributeName);
			aib.setRequired(isRequired);
			aib.setType(toIcfType(ldapAttribute.getSyntax(), icfAttributeName));
			if (ldapAttribute.isOperational()) {
				aib.setReturnedByDefault(false);
			}
			if (ldapAttribute.isSingleValued()) {
				aib.setMultiValued(false);
			} else {
				aib.setMultiValued(true);
			}
			if (ldapAttribute.isReadOnly()) {
				aib.setCreateable(false);
				aib.setUpdateable(false);
			}
			attrInfoList.add(aib.build());
		}
	}
	
	private boolean containsAttribute(List<AttributeInfo> attrInfoList, String icfAttributeName) {
		for (AttributeInfo attrInfo: attrInfoList) {
			if (icfAttributeName.equals(attrInfo.getName())) {
				return true;
			}
		}
		return false;
	}

	private String toIcfAttributeName(String ldapAttributeName) {
		if (ldapAttributeName.equals(configuration.getPasswordAttribute())) {
			return OperationalAttributeInfos.PASSWORD.getName();
		}
		return ldapAttributeName;
	}

	public org.apache.directory.api.ldap.model.schema.ObjectClass toLdapObjectClass(ObjectClass icfObjectClass) {
		String ldapObjectClassName;
		if (icfObjectClass.is(ObjectClass.ACCOUNT_NAME)) {
			ldapObjectClassName = configuration.getMagicAccountObjectClass();
		} else {
			ldapObjectClassName = icfObjectClass.getObjectClassValue();
		}
		String ldapObjectClassOid;
		try {
			ldapObjectClassOid = schemaManager.getObjectClassRegistry().getOidByName(ldapObjectClassName);
		} catch (LdapException e) {
			throw new IllegalArgumentException("Unknown object class "+icfObjectClass+": "+e.getMessage(), e);
		}
		try {
			return schemaManager.getObjectClassRegistry().lookup(ldapObjectClassOid);
		} catch (LdapException e) {
			throw new IllegalArgumentException("Unknown object class "+icfObjectClass+": "+e.getMessage(), e);
		}
	}

	/**
	 * Throws exception if the attribute is illegal.
	 * Return null if the attribute is legal, but we do not have any definition for it.
	 */
	public AttributeType toLdapAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			String icfAttributeName) {
		if (Name.NAME.equals(icfAttributeName)) {
			return null;
		}
		String ldapAttributeName;
		if (Uid.NAME.equals(icfAttributeName)) {
			ldapAttributeName = configuration.getUidAttribute();
		} else if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			ldapAttributeName = configuration.getPasswordAttribute();
		} else {
			ldapAttributeName = icfAttributeName;
		}
		try {
			String attributeOid = schemaManager.getAttributeTypeRegistry().getOidByName(ldapAttributeName);
			return schemaManager.getAttributeTypeRegistry().lookup(attributeOid);
		} catch (LdapException e) {
			if (ArrayUtils.contains(configuration.getOperationalAttributes(), ldapAttributeName)) {
				return null;
			} else {
				throw new IllegalArgumentException("Unknown LDAP attribute "+ldapAttributeName+" (translated from ICF attribute "+icfAttributeName+")");
			}
		}
	}

	public Class<?> toIcfType(LdapSyntax syntax, String icfAttributeName) {
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			return GuardedString.class;
		}
    	Class<?> type = SYNTAX_MAP.get(syntax.getName());
    	if (type == null) {
    		LOG.warn("No type mapping for syntax {0}, using string", syntax.getName());
    		return String.class;
    	} else {
    		return type;
    	}
	}

	public List<Value<Object>> toLdapValues(AttributeType ldapAttributeType, List<Object> icfAttributeValues) {
		List<Value<Object>> ldapValues = new ArrayList<Value<Object>>(icfAttributeValues.size());
		for (Object icfValue: icfAttributeValues) {
			ldapValues.add(toLdapValue(ldapAttributeType, icfValue));
		}
		return ldapValues;
	}
	
	public Value<Object> toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (icfAttributeValue == null) {
			return null;
		}
		if (ldapAttributeType == null) {
			// We have no definition for this attribute. Assume string.
			try {
				return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString());
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		}
		String syntaxOid = ldapAttributeType.getSyntaxOid();
		if (SYNTAX_GENERALIZED_TIME_OID.equals(syntaxOid)) {
			// TODO: convert time
			return null;
		} else {
			try {
				return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString());
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		}
	}
	
	public Value<Object> toLdapValue(AttributeType ldapAttributeType, List<Object> icfAttributeValues) {
		if (icfAttributeValues == null || icfAttributeValues.isEmpty()) {
			return null;
		}
		if (icfAttributeValues.size() > 1) {
			throw new IllegalArgumentException("More than one value specified for LDAP attribute "+ldapAttributeType.getName());
		}
		return toLdapValue(ldapAttributeType, icfAttributeValues.get(0));
	}
	
	private Object toIcfValue(String icfAttributeName, Value<?> ldapValue) {
		if (ldapValue == null) {
			return null;
		}
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			return new GuardedString(ldapValue.getString().toCharArray());
		} else {
			AttributeType ldapAttributeType = ldapValue.getAttributeType();
			String syntaxOid = ldapAttributeType.getSyntaxOid();
			if (SYNTAX_GENERALIZED_TIME_OID.equals(syntaxOid)) {
				// TODO: convert time
				return null;
			} else {
				return ldapValue.getString();
			}
		}
	}


	public ConnectorObject toIcfObject(ObjectClass icfObjectClass, Entry entry) {
		ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
		String dn = entry.getDn().getName();
		cob.setName(dn);
		cob.setObjectClass(icfObjectClass);
		ObjectClassInfo icfObjectClassInfo = null;
		if (icfSchema != null) {
			icfObjectClassInfo = icfSchema.findObjectClassInfo(icfObjectClass.toString());
		}
		String uidAttributeName = configuration.getUidAttribute();
		String uid;
		if (LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME.equals(uidAttributeName)) {
			uid = dn;
		} else {
			org.apache.directory.api.ldap.model.entry.Attribute uidAttribute = entry.get(uidAttributeName);
			if (uidAttribute == null) {
				throw new IllegalArgumentException("LDAP entry "+dn+" does not have UID attribute "+uidAttributeName);
			}
			if (uidAttribute.size() > 1) {
				throw new IllegalArgumentException("LDAP entry "+dn+" has more than one value for UID attribute "+uidAttributeName);
			}
			try {
				uid = uidAttribute.getString();
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("LDAP entry "+dn+" has non-string value for UID attribute "+uidAttributeName, e);
			}
		}
		cob.setUid(uid);
		
		Iterator<org.apache.directory.api.ldap.model.entry.Attribute> iterator = entry.iterator();
		while (iterator.hasNext()) {
			org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute = iterator.next();
			AttributeType attributeType = ldapAttribute.getAttributeType();
			String ldapAttributeName = attributeType.getName();
			if (!uidAttributeName.equals(ldapAttributeName)) {
				cob.addAttribute(toIcfAttribute(ldapAttribute));
			}
		}
		
		return cob.build();
	}
	
	private Attribute toIcfAttribute(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
		AttributeBuilder ab = new AttributeBuilder();
		AttributeType ldapAttributeType = ldapAttribute.getAttributeType();
		String icfAttributeName = toIcfAttributeName(ldapAttributeType.getName());
		ab.setName(icfAttributeName);
		Iterator<Value<?>> iterator = ldapAttribute.iterator();
		while (iterator.hasNext()) {
			Value<?> ldapValue = iterator.next();
			ab.addValue(toIcfValue(icfAttributeName, ldapValue));
		}
		return ab.build();
	}

	static {
		SYNTAX_MAP.put("TODO",String.class);
		SYNTAX_MAP.put(SYNTAX_GENERALIZED_TIME_OID, long.class);
	}


}
