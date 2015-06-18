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
package com.evolveum.polygon.connector.ldap.schema;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
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
import org.identityconnectors.framework.common.objects.OperationOptionInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.operations.SearchOp;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;

/**
 * @author semancik
 *
 */
public class SchemaTranslator {
	
	public static final String SYNTAX_AUTH_PASSWORD = "1.3.6.1.4.1.4203.1.1.2";
	public static final String SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION = "1.3.6.1.4.1.26027.1.3.4";
	public static final String SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR = "1.3.6.1.4.1.26027.1.3.6";
	
	private static final Log LOG = Log.getLog(SchemaTranslator.class);
	private static final Map<String, Class<?>> SYNTAX_MAP = new HashMap<String,Class<?>>();
	
	private SchemaManager schemaManager;
	private LdapConfiguration configuration;
	private Schema icfSchema = null;
	
	public SchemaTranslator(SchemaManager schemaManager, LdapConfiguration configuration) {
		super();
		this.schemaManager = schemaManager;
		this.configuration = configuration;
	}
	
	public Schema getIcfSchema() {
		return icfSchema;
	}

	public Schema translateSchema(LdapNetworkConnection connection) {
		SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
		LOG.ok("Translating LDAP schema from {0}", schemaManager);
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
			LOG.ok("Found LDAP schema object class {0}", ldapObjectClass.getName());
			ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
			ocib.setType(ldapObjectClass.getName());
			List<AttributeInfo> attrInfoList = new ArrayList<AttributeInfo>();
			addAttributeTypes(attrInfoList, ldapObjectClass);
			ocib.addAllAttributeInfo(attrInfoList);
			if (ldapObjectClass.isAuxiliary()) {
				ocib.setAuxiliary(true);
			}
			schemaBuilder.defineObjectClass(ocib.build());
		}
		
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAllowPartialResults(), SearchOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildContainer(), SearchOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildScope(), SearchOp.class);
		List<String> supportedControls;
		try {
			supportedControls = connection.getSupportedControls();
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error getting supported controls", e);
		}
		if (supportedControls.contains(PagedResults.OID) || supportedControls.contains(VirtualListViewRequest.OID)) {
			schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPageSize(), SearchOp.class);
			schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPagedResultsCookie(), SearchOp.class);
		}
		if (supportedControls.contains(VirtualListViewRequest.OID)) {
			schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildPagedResultsOffset(), SearchOp.class);
		}
		if (supportedControls.contains(SortRequest.OID)) {
			schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildSortKeys(), SearchOp.class);
		}
		
		icfSchema = schemaBuilder.build();
		LOG.ok("Translated schema {0}", icfSchema);
		return icfSchema;
	}
	
	/**
	 * Make sure that we have icfSchema 
	 */
	public void prepareIcfSchema(LdapNetworkConnection connection) {
		if (icfSchema == null) {
			translateSchema(connection);
		}
	}
	
	private void addAttributeTypes(List<AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		
		// ICF UID
		String uidAttribudeLdapName = configuration.getUidAttribute();
		AttributeInfoBuilder uidAib = new AttributeInfoBuilder(Uid.NAME);
		uidAib.setNativeName(uidAttribudeLdapName);
		uidAib.setRequired(false); // Must be optional. It is not present for create operations
		AttributeType uidAttributeLdapType = null;
		try {
			uidAttributeLdapType = schemaManager.getAttributeTypeRegistry().lookup(uidAttribudeLdapName);
		} catch (LdapException e) {
			// We can live with this
			LOG.ok("Got exception looking up UID atribute {0}: {1} ({2}) (probabably harmless)", uidAttribudeLdapName,
					e.getMessage(), e.getClass());
		}
		if (uidAttributeLdapType != null) {
			uidAib.setType(toIcfType(uidAttributeLdapType.getSyntax(), Uid.NAME));
			setAttributeMultiplicityAndPermissions(uidAttributeLdapType, uidAib);
		} else {
			uidAib.setType(String.class);
			uidAib.setCreateable(false);
			uidAib.setUpdateable(false);
			uidAib.setReadable(true);
		}
		attrInfoList.add(uidAib.build());
		
		// ICF NAME
		AttributeInfoBuilder nameAib = new AttributeInfoBuilder(Name.NAME);
		nameAib.setType(String.class);
		nameAib.setNativeName(LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME);
		nameAib.setRequired(true);
		attrInfoList.add(nameAib.build());
		
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
			aib.setNativeName(operationalAttributeLdapName);
			
			AttributeType attributeType = null;
			try {
				String operationalAttributeLdapOid = schemaManager.getAttributeTypeRegistry().getOidByName(operationalAttributeLdapName);
				attributeType = schemaManager.getAttributeTypeRegistry().get(operationalAttributeLdapOid);
			} catch (LdapException e) {
				// Ignore. We want this attribute even if it is not in the LDAP schema
			}
			
			if (attributeType != null) {
				aib.setType(toIcfType(attributeType.getSyntax(), operationalAttributeLdapName));
				setAttributeMultiplicityAndPermissions(attributeType, aib);
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
			if (ldapAttribute.getName().equals(LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME)) {
				continue;
			}
			String icfAttributeName = toIcfAttributeName(ldapAttribute.getName());
			if (containsAttribute(attrInfoList, icfAttributeName)) {
				continue;
			}
			AttributeInfoBuilder aib = new AttributeInfoBuilder(icfAttributeName);
			aib.setRequired(isRequired);
			aib.setType(toIcfType(ldapAttribute.getSyntax(), icfAttributeName));
			aib.setNativeName(ldapAttribute.getName());
			if (ldapAttribute.isOperational()) {
				aib.setReturnedByDefault(false);
			}
			setAttributeMultiplicityAndPermissions(ldapAttribute, aib);
			attrInfoList.add(aib.build());
		}
	}
	
	private void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, AttributeInfoBuilder aib) {
		if (ldapAttributeType.isSingleValued()) {
			aib.setMultiValued(false);
		} else {
			aib.setMultiValued(true);
		}
		aib.setReadable(true);
		if (ldapAttributeType.isReadOnly() || !ldapAttributeType.isUserModifiable()) {
			aib.setCreateable(false);
			aib.setUpdateable(false);
		} else {
			aib.setCreateable(true);
			aib.setUpdateable(true);			
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

	public List<org.apache.directory.api.ldap.model.schema.ObjectClass> toLdapObjectClasses(ObjectClass[] icfObjectClasses) {
		if (icfObjectClasses == null) {
			return new ArrayList<>(0);
		}
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> ldapObjectClasses = new ArrayList<>(icfObjectClasses.length);
		for (ObjectClass icfObjectClass: icfObjectClasses) {
			ldapObjectClasses.add(toLdapObjectClass(icfObjectClass));
		}
		return ldapObjectClasses;
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
		if (syntax == null) {
			// We may be in a quirks mode. Server schema may not be consistent (e.g. 389ds schema).
			// Therefore syntax may be null. Fall back to default in that case.
			return String.class;
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
		if (SchemaConstants.GENERALIZED_TIME_SYNTAX.equals(syntaxOid)) {
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
	
	private Object toIcfValue(String icfAttributeName, Value<?> ldapValue, AttributeType ldapAttributeType) {
		if (ldapValue == null) {
			return null;
		}
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			return new GuardedString(ldapValue.getString().toCharArray());
		} else {
			String syntaxOid = ldapAttributeType.getSyntaxOid();
			if (SchemaConstants.GENERALIZED_TIME_SYNTAX.equals(syntaxOid)) {
				try {
					GeneralizedTime gt = new GeneralizedTime(ldapValue.getString());
					return gt.getCalendar().getTimeInMillis();
				} catch (ParseException e) {
					throw new InvalidAttributeValueException("Wrong generalized time format in LDAP attribute "+ldapAttributeType.getName()+": "+e.getMessage(), e);
				}
			} else {
				return ldapValue.getString();
			}
		}
	}
	
	public ObjectClassInfo findObjectClassInfo(ObjectClass icfObjectClass) {
		return icfSchema.findObjectClassInfo(icfObjectClass.getObjectClassValue());
	}

	public ConnectorObject toIcfObject(ObjectClass icfObjectClass, Entry entry) {
		ObjectClassInfo icfObjectClassInfo = findObjectClassInfo(icfObjectClass);
		if (icfObjectClassInfo == null) {
			throw new InvalidAttributeValueException("No definition for object class "+icfObjectClass);
		}
		return toIcfObject(icfObjectClassInfo, entry);
	}

	public ConnectorObject toIcfObject(ObjectClassInfo icfStructuralObjectClassInfo, Entry entry) {
		LdapObjectClasses ldapObjectClasses = processObjectClasses(entry);
		if (icfStructuralObjectClassInfo == null) {
			icfStructuralObjectClassInfo = icfSchema.findObjectClassInfo(ldapObjectClasses.getLdapLowestStructuralObjectClass().getName());
		}
		ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
		String dn = entry.getDn().getName();
		cob.setName(dn);
		cob.setObjectClass(new ObjectClass(icfStructuralObjectClassInfo.getType()));
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapAuxiliaryObjectClass: ldapObjectClasses.getLdapAuxiliaryObjectClasses()) {
			cob.addAuxiliaryObjectClass(new ObjectClass(ldapAuxiliaryObjectClass.getName()));
		}
		String uidAttributeName = configuration.getUidAttribute();
		String uid;
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
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
			AttributeType attributeType = schemaManager.getAttributeType(ldapAttribute.getId());
			String ldapAttributeName = attributeType.getName();
			if (uidAttributeName.equals(ldapAttributeName)) {
				continue;
			}
			Attribute icfAttribute = toIcfAttribute(ldapAttribute);
			AttributeInfo attributeInfo = SchemaUtil.findAttributeInfo(icfStructuralObjectClassInfo, icfAttribute);
			if (attributeInfo != null) {
				// Avoid sending unknown attributes (such as createtimestamp)
				cob.addAttribute(icfAttribute);
			}
			
		}
		
		return cob.build();
	}
	
	private LdapObjectClasses processObjectClasses(Entry entry) {
		LdapObjectClasses ocs = new LdapObjectClasses();
		org.apache.directory.api.ldap.model.entry.Attribute objectClassAttribute = entry.get(LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME);
		if (objectClassAttribute == null) {
			throw new InvalidAttributeValueException("No object class attribute in entry "+entry.getDn());
		}
		for (Value<?> objectClassVal: objectClassAttribute) {
			String objectClassString = objectClassVal.getString();
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
			try {
				ldapObjectClass = schemaManager.getObjectClassRegistry().lookup(objectClassString);
			} catch (LdapException e) {
				throw new InvalidAttributeValueException(e.getMessage(), e);
			}
			if (ldapObjectClass.isStructural()) {
				ocs.getLdapStructuralObjectClasses().add(ldapObjectClass);
			} else if (ldapObjectClass.isAuxiliary()) {
				ocs.getLdapAuxiliaryObjectClasses().add(ldapObjectClass);
			}
		}
		if (ocs.getLdapStructuralObjectClasses().isEmpty()) {
			throw new InvalidAttributeValueException("Entry "+entry.getDn()+" has no structural object classes");
		}
		if (ocs.getLdapStructuralObjectClasses().size() == 1) {
			ocs.setLdapLowestStructuralObjectClass(ocs.getLdapStructuralObjectClasses().get(0));
		} else {
			for (org.apache.directory.api.ldap.model.schema.ObjectClass structObjectClass: ocs.getLdapStructuralObjectClasses()) {
	//			LOG.ok("Trying {0} ({1})", structObjectClass.getName(), structObjectClass.getOid());
				boolean isSuper = false;
				for (org.apache.directory.api.ldap.model.schema.ObjectClass otherObjectClass: ocs.getLdapStructuralObjectClasses()) {
					if (structObjectClass.getOid().equals(otherObjectClass.getOid())) {
						continue;
					}
	//				LOG.ok("  with {0} ({1})", otherObjectClass.getName(), structObjectClass.getOid());
	//				LOG.ok("    superiorOids: {0}", otherObjectClass.getSuperiorOids());
					if (otherObjectClass.getSuperiorOids().contains(structObjectClass.getOid()) || otherObjectClass.getSuperiorOids().contains(structObjectClass.getName())) {
	//					LOG.ok("    isSuper");
						isSuper = true;
						break;
					}
				}
	//			LOG.ok("    isSuper={0}", isSuper);
				if (!isSuper) {
					ocs.setLdapLowestStructuralObjectClass(structObjectClass);
					break;
				}
			}
			if (ocs.getLdapLowestStructuralObjectClass() == null) {
				throw new InvalidAttributeValueException("Cannot determine lowest structural object class for set of object classes: "+objectClassAttribute);
			}
		}
		return ocs;
	}

	private Attribute toIcfAttribute(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
		AttributeBuilder ab = new AttributeBuilder();
		AttributeType ldapAttributeType = schemaManager.getAttributeType(ldapAttribute.getId());
		String icfAttributeName = toIcfAttributeName(ldapAttributeType.getName());
		ab.setName(icfAttributeName);
		Iterator<Value<?>> iterator = ldapAttribute.iterator();
		while (iterator.hasNext()) {
			Value<?> ldapValue = iterator.next();
			ab.addValue(toIcfValue(icfAttributeName, ldapValue, ldapAttributeType));
		}
		return ab.build();
	}

	static {
		SYNTAX_MAP.put(SchemaConstants.NAME_OR_NUMERIC_ID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NUMERIC_OID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ATTRIBUTE_TYPE_USAGE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NUMBER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OID_LEN_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OBJECT_NAME_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ACI_ITEM_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ACCESS_POINT_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ATTRIBUTE_TYPE_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.AUDIO_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.BINARY_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.BIT_STRING_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.BOOLEAN_SYNTAX, Boolean.class);
		SYNTAX_MAP.put(SchemaConstants.CERTIFICATE_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.CERTIFICATE_LIST_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.CERTIFICATE_PAIR_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.COUNTRY_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DN_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DATA_QUALITY_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DELIVERY_METHOD_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DIRECTORY_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DIT_CONTENT_RULE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DIT_STRUCTURE_RULE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DL_SUBMIT_PERMISSION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DSA_QUALITY_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DSE_TYPE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ENHANCED_GUIDE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.FAX_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.GENERALIZED_TIME_SYNTAX, long.class);
		SYNTAX_MAP.put(SchemaConstants.GUIDE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.IA5_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.INTEGER_SYNTAX, int.class);
		SYNTAX_MAP.put(SchemaConstants.JPEG_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.MATCHING_RULE_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.MATCHING_RULE_USE_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.MAIL_PREFERENCE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.MHS_OR_ADDRESS_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NAME_AND_OPTIONAL_UID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NAME_FORM_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NUMERIC_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OBJECT_CLASS_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OTHER_MAILBOX_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.OCTET_STRING_SYNTAX, byte[].class);
		SYNTAX_MAP.put(SchemaConstants.POSTAL_ADDRESS_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.PROTOCOL_INFORMATION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.PRESENTATION_ADDRESS_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.PRINTABLE_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUBTREE_SPECIFICATION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUPPLIER_INFORMATION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUPPLIER_OR_CONSUMER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUPPLIER_AND_CONSUMER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUPPORTED_ALGORITHM_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.TELEPHONE_NUMBER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.TELETEX_TERMINAL_IDENTIFIER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.TELEX_NUMBER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.UTC_TIME_SYNTAX, long.class);
		SYNTAX_MAP.put(SchemaConstants.LDAP_SYNTAX_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.MODIFY_RIGHTS_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.LDAP_SCHEMA_DEFINITION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.LDAP_SCHEMA_DESCRIPTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SUBSTRING_ASSERTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.ATTRIBUTE_CERTIFICATE_ASSERTION_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.UUID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.CSN_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.CSN_SID_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.JAVA_BYTE_SYNTAX, byte.class);
		SYNTAX_MAP.put(SchemaConstants.JAVA_CHAR_SYNTAX, char.class);
		SYNTAX_MAP.put(SchemaConstants.JAVA_SHORT_SYNTAX, short.class);
		SYNTAX_MAP.put(SchemaConstants.JAVA_LONG_SYNTAX, long.class);
		SYNTAX_MAP.put(SchemaConstants.JAVA_INT_SYNTAX, int.class);
		SYNTAX_MAP.put(SchemaConstants.COMPARATOR_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.NORMALIZER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SYNTAX_CHECKER_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.SEARCH_SCOPE_SYNTAX, String.class);
		SYNTAX_MAP.put(SchemaConstants.DEREF_ALIAS_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_AUTH_PASSWORD, String.class);
		SYNTAX_MAP.put(SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR, String.class);
		SYNTAX_MAP.put(SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION, String.class);
	}

}
