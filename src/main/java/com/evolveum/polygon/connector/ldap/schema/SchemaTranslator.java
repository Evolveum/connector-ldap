/**
 * Copyright (c) 2014-2016 Evolveum
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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.BinaryValue;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.UsageEnum;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
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
import org.identityconnectors.framework.common.objects.PredefinedAttributeInfos;
import org.identityconnectors.framework.common.objects.PredefinedAttributes;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;

/**
 * @author semancik
 *
 */
public class SchemaTranslator<C extends AbstractLdapConfiguration> {
	
	public static final String SYNTAX_AUTH_PASSWORD = "1.3.6.1.4.1.4203.1.1.2";
	public static final String SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION = "1.3.6.1.4.1.26027.1.3.4";
	public static final String SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR = "1.3.6.1.4.1.26027.1.3.6";
	private static final String SYNTAX_NIS_NETGROUP_TRIPLE_SYNTAX = "1.3.6.1.1.1.0.0";
	private static final String SYNTAX_NIS_BOOT_PARAMETER_SYNTAX = "1.3.6.1.1.1.0.1";
	private static final String SYNTAX_AD_DN_WITH_BINARY_SYNTAX = "1.2.840.113556.1.4.903";
	private static final String SYNTAX_AD_DN_WITH_STRING_SYNTAX = "1.2.840.113556.1.4.904";
	private static final String SYNTAX_AD_CASE_IGNORE_STRING_SYNTAX = "1.2.840.113556.1.4.905";
	private static final String SYNTAX_AD_INTEGER8_SYNTAX = "1.2.840.113556.1.4.906";
	private static final String SYNTAX_AD_SECURITY_DESCRIPTOR_SYNTAX = "1.2.840.113556.1.4.907";
	
	private static final Log LOG = Log.getLog(SchemaTranslator.class);
	private static final Map<String, Class<?>> SYNTAX_MAP = new HashMap<String,Class<?>>();
	private static final Collection<String> STRING_ATTRIBUTE_NAMES = new ArrayList<String>();
	
	private SchemaManager schemaManager;
	private C configuration;
	private Schema icfSchema = null;
	
	public SchemaTranslator(SchemaManager schemaManager, C configuration) {
		super();
		this.schemaManager = schemaManager;
		this.configuration = configuration;
	}
	
	public Schema getIcfSchema() {
		return icfSchema;
	}

	public SchemaManager getSchemaManager() {
		return schemaManager;
	}

	public C getConfiguration() {
		return configuration;
	}

	public Schema translateSchema(ConnectionManager<C> connection) throws InvalidConnectionException {
		SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
		LOG.ok("Translating LDAP schema from {0}", schemaManager);
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
			if (shouldTranslateObjectClass(ldapObjectClass.getName())) {
				LOG.ok("Found LDAP schema object class {0}, translating", ldapObjectClass.getName());
				ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
				ocib.setType(toIcfObjectClassType(ldapObjectClass));
				List<AttributeInfo> attrInfoList = new ArrayList<AttributeInfo>();
				addAttributeTypes(attrInfoList, ldapObjectClass);
				ocib.addAllAttributeInfo(attrInfoList);
				if (ldapObjectClass.isAuxiliary()) {
					ocib.setAuxiliary(true);
				}
				extendObjectClassDefinition(ocib, ldapObjectClass);
				schemaBuilder.defineObjectClass(ocib.build());
			} else {
				LOG.ok("Found LDAP schema object class {0}, skipping", ldapObjectClass.getName());
			}
		}
		
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAttributesToGet(), SearchOp.class, SyncOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildReturnDefaultAttributes(), SearchOp.class, SyncOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildAllowPartialResults(), SearchOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildContainer(), SearchOp.class);
		schemaBuilder.defineOperationOption(OperationOptionInfoBuilder.buildScope(), SearchOp.class);
		
		List<String> supportedControls;
		try {
			supportedControls = connection.getDefaultConnection().getSupportedControls();
		} catch (InvalidConnectionException e) {
			throw e;
		} catch (LdapException e) {
			if (e.getCause() instanceof InvalidConnectionException) {
				throw (InvalidConnectionException)e.getCause();
			}
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

	protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		// Nothing to do. Expected to be overridden in subclasses.
	}

	protected boolean shouldTranslateObjectClass(String ldapObjectClassName) {
		return true;
	}
	
	protected String toIcfObjectClassType(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		return ldapObjectClass.getName();
	}
	
	protected String toLdapObjectClassName(ObjectClass icfObjectClass) {
		return icfObjectClass.getObjectClassValue();
	}

	/**
	 * Make sure that we have icfSchema  
	 */
	public void prepareIcfSchema(ConnectionManager<C> connectionManager) throws InvalidConnectionException {
		if (icfSchema == null) {
			translateSchema(connectionManager);
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
			// UID must be string. It is hardcoded in the framework.
			uidAib.setType(String.class);
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
		
		// AUXILIARY_OBJECT_CLASS
		attrInfoList.add(PredefinedAttributeInfos.AUXILIARY_OBJECT_CLASS);
		
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
		LOG.ok("  ... translating attributes from {0}:\n{1}\nMUST\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMustAttributeTypes());
		addAttributeTypes(attrInfoList, ldapObjectClass.getMustAttributeTypes(), true);
		LOG.ok("  ... translating attributes from {0}:\n{1}\nMAY\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMayAttributeTypes());
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
			if (!shouldTranslateAttribute(ldapAttribute.getName())) {
				LOG.ok("Skipping translation of attribute {0} because it should not be translated", ldapAttribute.getName());
				continue;
			}
			if (ldapAttribute.getName().equals(LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME)) {
				continue;
			}
			if (ldapAttribute.getName().equals(getConfiguration().getUidAttribute())) {
				// This is handled separately as __UID__ attribute
				continue;
			}
			String icfAttributeName = toIcfAttributeName(ldapAttribute.getName());
			if (containsAttribute(attrInfoList, icfAttributeName)) {
				LOG.ok("Skipping translation of attribute {0} because it is already translated", ldapAttribute.getName());
				continue;
			}
			AttributeInfoBuilder aib = new AttributeInfoBuilder(icfAttributeName);
			aib.setRequired(isRequired);
			
			LdapSyntax ldapSyntax = getSyntax(ldapAttribute);
			if (ldapSyntax == null) {
				LOG.warn("No syntax for attribute: {0}", ldapAttribute.getName());
			}
			
			Class<?> icfType = toIcfType(ldapSyntax, icfAttributeName);
			aib.setType(icfType);
			aib.setNativeName(ldapAttribute.getName());
			if (isOperational(ldapAttribute)) {
				aib.setReturnedByDefault(false);
			}
			setAttributeMultiplicityAndPermissions(ldapAttribute, aib);
			LOG.ok("Translating {0} -> {1} ({2} -> {3})", ldapAttribute.getName(), icfAttributeName, 
					ldapSyntax==null?null:ldapSyntax.getOid(), icfType);
			attrInfoList.add(aib.build());
		}
	}
	
	protected boolean isOperational(AttributeType ldapAttribute) {
		return ldapAttribute.isOperational();
	}

	protected void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, AttributeInfoBuilder aib) {
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
	
	public org.apache.directory.api.ldap.model.schema.ObjectClass toLdapObjectClass(ObjectClass icfObjectClass) {
		String ldapObjectClassName = toLdapObjectClassName(icfObjectClass);
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
		
		if (ldapAttributeType.getName().equals(configuration.getPasswordAttribute())) {
			return toLdapPasswordValue(ldapAttributeType, icfAttributeValue);
		}
		
		return wrapInLdapValueClass(ldapAttributeType, icfAttributeValue);
	}
	
	protected Value<Object> wrapInLdapValueClass(AttributeType ldapAttributeType, Object icfAttributeValue) {
		String syntaxOid = ldapAttributeType.getSyntaxOid();
		if (SchemaConstants.GENERALIZED_TIME_SYNTAX.equals(syntaxOid)) {
			if (icfAttributeValue instanceof Long) {
				try {
					return (Value)new StringValue(ldapAttributeType, LdapUtil.toGeneralizedTime((Long)icfAttributeValue, acceptsFractionalGeneralizedTime()));
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
			} else {
				try {
					return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString());
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}				
			}
		} else if (icfAttributeValue instanceof Boolean) {
			LOG.ok("Converting to LDAP: {0} ({1}): boolean", ldapAttributeType.getName(), syntaxOid);
			try {
				return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString().toUpperCase());
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		} else if (icfAttributeValue instanceof GuardedString) {
			try {
				return (Value)new GuardedStringValue(ldapAttributeType, (GuardedString) icfAttributeValue);
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		} else if (isBinarySyntax(syntaxOid)) {
			LOG.ok("Converting to LDAP: {0} ({1}): explicit binary", ldapAttributeType.getName(), syntaxOid);
			if (icfAttributeValue instanceof byte[]) {
				try {
					// Do NOT set attributeType in the Value in this case.
					// The attributeType might not match the Value class
					// e.g. human-readable jpegPhoto attribute will expect StringValue
					return (Value)new BinaryValue(null, (byte[])icfAttributeValue);
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
			} else if (icfAttributeValue instanceof String) {
				// this can happen for userPassword
				byte[] bytes;
				try {
					bytes = ((String)icfAttributeValue).getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
					throw new IllegalArgumentException("Cannot encode attribute value to UTF-8 for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
				try {
					// Do NOT set attributeType in the Value in this case.
					// The attributeType might not match the Value class
					// e.g. human-readable jpegPhoto attribute will expect StringValue
					return (Value)new BinaryValue(null, bytes);
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
			} else {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": expected byte[] but got "+icfAttributeValue.getClass()
						+"; attributeType="+ldapAttributeType);
			}
		} else if (isStringSyntax(syntaxOid)) {
			LOG.ok("Converting to LDAP: {0} ({1}): explicit string", ldapAttributeType.getName(), syntaxOid);
			try {
				return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString());
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		} else {
			if (icfAttributeValue instanceof byte[]) {
				LOG.ok("Converting to LDAP: {0} ({1}): detected binary", ldapAttributeType.getName(), syntaxOid);
				try {
					return (Value)new BinaryValue(ldapAttributeType, (byte[])icfAttributeValue);
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
			} else {
				LOG.ok("Converting to LDAP: {0} ({1}): detected string", ldapAttributeType.getName(), syntaxOid);
				try {
					return (Value)new StringValue(ldapAttributeType, icfAttributeValue.toString());
				} catch (LdapInvalidAttributeValueException e) {
					throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
							+"; attributeType="+ldapAttributeType, e);
				}
			}
		}
	}
	
	protected Value<Object> toLdapPasswordValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (configuration.getPasswordHashAlgorithm() != null 
				&& !LdapConfiguration.PASSWORD_HASH_ALGORITHM_NONE.equals(configuration.getPasswordHashAlgorithm())) {
			icfAttributeValue = hashLdapPassword(icfAttributeValue);
		}
		return wrapInLdapValueClass(ldapAttributeType, icfAttributeValue);
	}

	protected boolean acceptsFractionalGeneralizedTime() {
		return true;
	}

	/**
	 * Used to parse __UID__ and __NAME__.
	 */
	public Value<Object> toLdapIdentifierValue(AttributeType ldapAttributeType, String icfAttributeValue) {
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
		if (SchemaConstants.OCTET_STRING_SYNTAX.equals(syntaxOid)) {
			// Expect hex-encoded value (see toIcfIdentifierValue())
			byte[] bytes = LdapUtil.hexToBinary(icfAttributeValue);
			try {
				// Do NOT set attributeType in the Value in this case.
				// The attributeType might not match the Value class
				return (Value)new BinaryValue(null, bytes);
			} catch (LdapInvalidAttributeValueException e) {
				throw new IllegalArgumentException("Invalid value for attribute "+ldapAttributeType.getName()+": "+e.getMessage()
						+"; attributeType="+ldapAttributeType, e);
			}
		} else {
			try {
				return (Value)new StringValue(ldapAttributeType, icfAttributeValue);
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
			} else if (SchemaConstants.BOOLEAN_SYNTAX.equals(syntaxOid)) {
				return Boolean.parseBoolean(ldapValue.getString());
			} else if (isIntegerSyntax(syntaxOid)) {
				return Integer.parseInt(ldapValue.getString());
			} else if (isLongSyntax(syntaxOid)) {
				return Long.parseLong(ldapValue.getString());
			} else if (isBinarySyntax(syntaxOid)) {
				LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit binary", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
				return ldapValue.getBytes();
			} else if (isStringSyntax(syntaxOid)) {
				LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit string", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
				return ldapValue.getString();
			} else {
				if (ldapValue instanceof StringValue) {
					LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected string", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
					return ldapValue.getString();
				} else {
					LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected binary", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
					return ldapValue.getBytes();
				}
			}
		}
	}

	protected boolean isIntegerSyntax(String syntaxOid) {
		return SchemaConstants.INTEGER_SYNTAX.equals(syntaxOid);
	}
	
	protected boolean isLongSyntax(String syntaxOid) {
		return SchemaConstants.JAVA_LONG_SYNTAX.equals(syntaxOid) ||
				SYNTAX_AD_INTEGER8_SYNTAX.equals(syntaxOid);
	}


	protected boolean isStringSyntax(String syntaxOid) {
		return SchemaConstants.DIRECTORY_STRING_SYNTAX.equals(syntaxOid) 
				|| SchemaConstants.IA5_STRING_SYNTAX.equals(syntaxOid)				
				|| SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.DN_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.PRINTABLE_STRING_SYNTAX.equals(syntaxOid);
	}

	protected boolean isBinarySyntax(String syntaxOid) {
		return SchemaConstants.OCTET_STRING_SYNTAX.equals(syntaxOid) 
				|| SchemaConstants.JPEG_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.BINARY_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.BIT_STRING_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.CERTIFICATE_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.CERTIFICATE_LIST_SYNTAX.equals(syntaxOid)
				|| SchemaConstants.CERTIFICATE_PAIR_SYNTAX.equals(syntaxOid);				
	}
	
	public boolean isBinaryAttribute(String attributeId) {
		String ldapAttributeName = getLdapAttributeName(attributeId);
		AttributeType attributeType = schemaManager.getAttributeType(ldapAttributeName);
		if (attributeType == null) {
			if (STRING_ATTRIBUTE_NAMES.contains(attributeId.toLowerCase())) {
				return false;
			}
			LOG.warn("Uknown attribute {0}, cannot determine if it is binary", ldapAttributeName);
			return false;
		}
		LdapSyntax syntax = getSyntax(attributeType);
		if (syntax == null) {
			// OpenLDAP does not define some syntaxes that it uses
			return false;
		}
		String syntaxOid = attributeType.getSyntaxOid();
		if (isBinarySyntax(syntaxOid)) {
			return true;
		}
		if (isStringSyntax(syntaxOid)) {
			return false;
		}
		return !syntax.isHumanReadable();
	}
	
	LdapSyntax getSyntax(AttributeType attributeType) {
		LdapSyntax syntax = attributeType.getSyntax();
		if (syntax == null && attributeType.getSyntaxOid() != null) {
			// HACK to support ugly servers (such as AD) that do not declare 
			// ldapSyntaxes in the schema
			syntax = new LdapSyntax(attributeType.getSyntaxOid());
		}
		return syntax;
	}

	/**
	 * Used to format __UID__ and __NAME__.
	 */
	public String toIcfIdentifierValue(Value<?> ldapValue, AttributeType ldapAttributeType) {
		if (ldapValue == null) {
			return null;
		}
		String syntaxOid = ldapAttributeType.getSyntaxOid();
		if (isBinarySyntax(syntaxOid)) {
			LOG.ok("Converting identifier to ICF: {0} (syntax {1}, value {2}): explicit binary", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
			byte[] bytes;
			if (ldapValue instanceof BinaryValue) {
				bytes = ldapValue.getBytes();
			} else if (ldapValue instanceof StringValue) {
				// Binary value incorrectly detected as string value. Conversion to Java string has broken the data.
				// We need to do some magic to fix it.
				LOG.ok("UID: string: {0}, bytes", ldapValue.getString());
				ByteArrayOutputStream bout = new ByteArrayOutputStream();
				try {
					ObjectOutputStream oos = new ObjectOutputStream(bout);
					oos.writeUTF(ldapValue.getString());
					oos.close();
					bout.close();
				} catch (IOException e) {
					throw new IllegalStateException(e.getMessage(), e);
				}
				bytes = bout.toByteArray();
			} else {
				throw new IllegalStateException("Unexpected value type "+ldapValue.getClass());
			}
			// Assume that identifiers are short. It is more readable to use hex representation than base64.
			return LdapUtil.binaryToHex(bytes);
		} else {
			LOG.ok("Converting identifier to ICF: {0} (syntax {1}, value {2}): implicit string", ldapAttributeType.getName(), syntaxOid, ldapValue.getClass());
			return ldapValue.getString();
		}
	}
	
	public ObjectClassInfo findObjectClassInfo(ObjectClass icfObjectClass) {
		return icfSchema.findObjectClassInfo(icfObjectClass.getObjectClassValue());
	}
	
	public boolean hasUidAttribute(Entry entry) {
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
			return true;
		} else {
			org.apache.directory.api.ldap.model.entry.Attribute uidAttribute = entry.get(uidAttributeName);
			return uidAttribute != null;
		}
	}

	public ConnectorObject toIcfObject(LdapNetworkConnection connection, ObjectClass icfObjectClass, Entry entry, AttributeHandler attributeHandler) {
		ObjectClassInfo icfObjectClassInfo = findObjectClassInfo(icfObjectClass);
		if (icfObjectClassInfo == null) {
			throw new InvalidAttributeValueException("No definition for object class "+icfObjectClass);
		}
		return toIcfObject(connection, icfObjectClassInfo, entry, null, attributeHandler);
	}

	public ConnectorObject toIcfObject(LdapNetworkConnection connection, ObjectClassInfo icfStructuralObjectClassInfo, Entry entry) {
		return toIcfObject(connection, icfStructuralObjectClassInfo, entry, null, null);
	}
	
	public ConnectorObject toIcfObject(LdapNetworkConnection connection, ObjectClassInfo icfStructuralObjectClassInfo, Entry entry, String dn) {
		return toIcfObject(connection, icfStructuralObjectClassInfo, entry, dn, null);
	}
	
	public ConnectorObject toIcfObject(LdapNetworkConnection connection, ObjectClassInfo icfStructuralObjectClassInfo, Entry entry, String dn, AttributeHandler attributeHandler) {
		LdapObjectClasses ldapObjectClasses = processObjectClasses(entry);
		if (icfStructuralObjectClassInfo == null) {
			icfStructuralObjectClassInfo = icfSchema.findObjectClassInfo(ldapObjectClasses.getLdapLowestStructuralObjectClass().getName());
		}
		ConnectorObjectBuilder cob = new ConnectorObjectBuilder();
		if (dn == null) {
			dn = entry.getDn().getName();
		}
		cob.setName(dn);
		cob.setObjectClass(new ObjectClass(icfStructuralObjectClassInfo.getType()));
		
		List<ObjectClassInfo> icfAuxiliaryObjectClassInfos = new ArrayList<>(ldapObjectClasses.getLdapAuxiliaryObjectClasses().size());
		if (!ldapObjectClasses.getLdapAuxiliaryObjectClasses().isEmpty()) {
			AttributeBuilder auxAttrBuilder = new AttributeBuilder();
			auxAttrBuilder.setName(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME);
			for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapAuxiliaryObjectClass: ldapObjectClasses.getLdapAuxiliaryObjectClasses()) {
				auxAttrBuilder.addValue(ldapAuxiliaryObjectClass.getName());
				icfAuxiliaryObjectClassInfos.add(icfSchema.findObjectClassInfo(ldapAuxiliaryObjectClass.getName()));
			}
			cob.addAttribute(auxAttrBuilder.build());
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
			AttributeType attributeType = schemaManager.getAttributeType(uidAttribute.getId());
			uid = toIcfIdentifierValue(uidAttribute.get(), attributeType);
		}
		cob.setUid(uid);
		
		Iterator<org.apache.directory.api.ldap.model.entry.Attribute> iterator = entry.iterator();
		while (iterator.hasNext()) {
			org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute = iterator.next();
			String ldapAttrName = getLdapAttributeName(ldapAttribute);
			if (!shouldTranslateAttribute(ldapAttrName)) {
				continue;
			}
			AttributeType attributeType = schemaManager.getAttributeType(ldapAttrName);
			if (attributeType == null) {
				throw new InvalidAttributeValueException("Unknown attribute " + ldapAttrName);
			}
			String ldapAttributeName = attributeType.getName();
			if (uidAttributeName.equals(ldapAttributeName)) {
				continue;
			}
			Attribute icfAttribute = toIcfAttribute(connection, entry, ldapAttribute, attributeHandler);
			if (icfAttribute == null) {
				continue;
			}
			AttributeInfo attributeInfo = SchemaUtil.findAttributeInfo(icfStructuralObjectClassInfo, icfAttribute);
			if (attributeInfo == null) {
				for (ObjectClassInfo icfAuxiliaryObjectClassInfo: icfAuxiliaryObjectClassInfos) {
					attributeInfo = SchemaUtil.findAttributeInfo(icfAuxiliaryObjectClassInfo, icfAttribute);
					if (attributeInfo != null) {
						break;
					}
				}
			}
			if (attributeInfo != null) {
				// Avoid sending unknown attributes (such as createtimestamp)
				cob.addAttribute(icfAttribute);
			}
			
		}
		
		extendConnectorObject(cob, entry, icfStructuralObjectClassInfo.getType());
		
		return cob.build();
	}
	
	public String getLdapAttributeName(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
		return getLdapAttributeName(ldapAttribute.getId());
	}
	
	public String getLdapAttributeName(String attributeId) {
		int iSemicolon = attributeId.indexOf(';');
		if (iSemicolon < 0) {
			return attributeId;
		}
		return attributeId.substring(0, iSemicolon);
	}

	protected boolean shouldTranslateAttribute(String attrName) {
		return true;
	}

	protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
		// Nothing to do here. This is supposed to be overriden by subclasses.
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
	
	private Object hashLdapPassword(Object icfAttributeValue) {
		if (icfAttributeValue == null) {
			return null;
		}
		byte[] bytes;
		if (icfAttributeValue instanceof String) {
			try {
				bytes = ((String)icfAttributeValue).getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		} else if (icfAttributeValue instanceof GuardedString) {
			final String[] out = new String[1];
			((GuardedString)icfAttributeValue).access(new GuardedString.Accessor() {
				@Override
				public void access(char[] clearChars) {
					out[0] = new String(clearChars);
				}
			});
			try {
				bytes = out[0].getBytes("UTF-8");
			} catch (UnsupportedEncodingException e) {
				throw new IllegalStateException(e.getMessage(), e);
			}
		} else if (icfAttributeValue instanceof byte[]) {
			bytes = (byte[])icfAttributeValue;
		} else {
			throw new InvalidAttributeValueException("Unsupported type of password attribute: "+icfAttributeValue.getClass());
		}
		return hashBytes(bytes, configuration.getPasswordHashAlgorithm(), 0);
	}
	
	private String hashBytes(byte[] clear, String alg, long seed) {
        MessageDigest md = null;
        
    	try {
            if (alg.equalsIgnoreCase("SSHA") || alg.equalsIgnoreCase("SHA")) {
            		md = MessageDigest.getInstance("SHA-1");
            } else if ( alg.equalsIgnoreCase("SMD5") || alg.equalsIgnoreCase("MD5") ) {
                md = MessageDigest.getInstance("MD5");
            }
    	} catch (NoSuchAlgorithmException e) {
            throw new ConnectorException("Could not find MessageDigest algorithm: "+alg);
        }
        
        if (md == null) {
            throw new ConnectorException("Unsupported MessageDigest algorithm: " + alg);
        }

        byte[] salt = {};
        if (alg.equalsIgnoreCase("SSHA") || alg.equalsIgnoreCase("SMD5")) {
            Random rnd = new Random();
            rnd.setSeed(System.currentTimeMillis() + seed);
            salt = new byte[8];
            rnd.nextBytes(salt);
        }

        md.reset();
        md.update(clear);
        md.update(salt);
        byte[] hash = md.digest();

        byte[] hashAndSalt = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, hashAndSalt, 0, hash.length);
        System.arraycopy(salt, 0, hashAndSalt, hash.length, salt.length);

        StringBuilder resSb = new StringBuilder(alg.length() + hashAndSalt.length);
        resSb.append('{');
        resSb.append(alg);
        resSb.append('}');
        resSb.append(Base64.encode(hashAndSalt));

        return resSb.toString();
    }

	private Attribute toIcfAttribute(LdapNetworkConnection connection, Entry entry, org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute, AttributeHandler attributeHandler) {
		AttributeBuilder ab = new AttributeBuilder();
		String ldapAttributeName = getLdapAttributeName(ldapAttribute);
		AttributeType ldapAttributeType = schemaManager.getAttributeType(ldapAttributeName);
		String icfAttributeName = toIcfAttributeName(ldapAttributeType.getName());
		ab.setName(icfAttributeName);
		if (attributeHandler != null) {
			attributeHandler.handle(connection, entry, ldapAttribute, ab);
		}
		Iterator<Value<?>> iterator = ldapAttribute.iterator();
		boolean hasValidValue = false;
		while (iterator.hasNext()) {
			Value<?> ldapValue = iterator.next();
			Object icfValue = toIcfValue(icfAttributeName, ldapValue, ldapAttributeType);
			if (icfValue != null) {
				ab.addValue(icfValue);
				hasValidValue = true;
			}
		}
		if (!hasValidValue) {
			// Do not even try to build. The build will fail.
			return null;
		}
		try {
			return ab.build();
		} catch (IllegalArgumentException e) {
			throw new IllegalArgumentException(e.getMessage() + ", attribute "+icfAttributeName+" (ldap: "+ldapAttributeName+")", e);
		}
	}
	
	public Dn toDn(Attribute attribute) {
		if (attribute == null) {
			return null;
		}
		return toDn(SchemaUtil.getSingleStringNonBlankValue(attribute));
	}
	
	public Dn toDn(Uid icfUid) {
		if (icfUid == null) {
			return null;
		}
		return toDn(icfUid.getUidValue());
	}

	public Dn toDn(String stringDn) {
		if (stringDn == null) {
			return null;
		}
		try {
			return new Dn(schemaManager, stringDn);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Invalid DN '"+stringDn+"': "+e.getMessage(), e);
		}
	}
	
	// This may seems strange. But it converts non-schema-aware DNs to schema-aware DNs.
	public Dn toDn(Dn dn) {
		if (dn == null) {
			return null;
		}
		if (dn.isSchemaAware()) {
			return dn;
		}
		try {
			dn.apply(schemaManager);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Invalid DN '"+dn+"': "+e.getMessage(), e);
		}
		return dn;
	}

	/**
	 * Find an attribute that is part of the specified object class definition.
	 * Returns the first attribute from the list of candidate attributes that matches.
	 */
	public String selectAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			List<String> candidates) {
		for (String candidate: candidates) {
			if (getConfiguration().getUidAttribute().equalsIgnoreCase(candidate)) {
				return candidate;
			}
			if (hasAttribute(ldapObjectClass, candidate)) {
				return candidate;
			}
		}
		return null;
	}

	private boolean hasAttribute(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			String attributeName) {
		if (hasAttribute(ldapObjectClass.getMustAttributeTypes(), attributeName) ||
				hasAttribute(ldapObjectClass.getMayAttributeTypes(), attributeName)) {
			return true;
		}
		for (org.apache.directory.api.ldap.model.schema.ObjectClass superior: ldapObjectClass.getSuperiors()) {
			if (superior.getName().equalsIgnoreCase(AbstractLdapConfiguration.OBJECTCLASS_TOP_NAME)) {
				// Do not even try top object class. Standard top objectclass has nothing to offer.
				// And some non-standard (e.g. AD) definitions will only screw everything up as they
				// contain definition for attributes that are not really meaningful.
				continue;
			}
			if (hasAttribute(superior, attributeName)) {
				return true;
			}
		}
		return false;
	}

	private boolean hasAttribute(List<AttributeType> attrTypeList, String attributeName) {
		for (AttributeType attrType: attrTypeList) {
			for (String name: attrType.getNames()) {
				if (attributeName.equalsIgnoreCase(name)) {
					return true;
				}
			}			
		}
		return false;
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
		SYNTAX_MAP.put(SYNTAX_NIS_NETGROUP_TRIPLE_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_NIS_BOOT_PARAMETER_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_AD_CASE_IGNORE_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_AD_DN_WITH_STRING_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_AD_DN_WITH_BINARY_SYNTAX, String.class);
		SYNTAX_MAP.put(SYNTAX_AD_INTEGER8_SYNTAX, long.class);
		SYNTAX_MAP.put(SYNTAX_AD_SECURITY_DESCRIPTOR_SYNTAX, byte[].class);
		
		// AD strangeness
		SYNTAX_MAP.put("OctetString", byte[].class);
		
		// Make sure that these attributes are always resolved as string attributes
		// These are mostly root DSE attributes
		// WARNING: all attribute names must be in lowercase
		STRING_ATTRIBUTE_NAMES.add("namingcontexts");
		STRING_ATTRIBUTE_NAMES.add("defaultnamingcontext");
		STRING_ATTRIBUTE_NAMES.add("schemanamingcontext");
		STRING_ATTRIBUTE_NAMES.add("supportedcontrol");
		STRING_ATTRIBUTE_NAMES.add("configurationnamingcontext");
		STRING_ATTRIBUTE_NAMES.add("rootdomainnamingcontext");
		STRING_ATTRIBUTE_NAMES.add("supportedldapversion");
		STRING_ATTRIBUTE_NAMES.add("supportedldappolicies");
		STRING_ATTRIBUTE_NAMES.add("supportedsaslmechanisms");
		STRING_ATTRIBUTE_NAMES.add("highestcommittedusn");
		STRING_ATTRIBUTE_NAMES.add("ldapservicename");
		STRING_ATTRIBUTE_NAMES.add("supportedcapabilities");
		STRING_ATTRIBUTE_NAMES.add("issynchronized");
		STRING_ATTRIBUTE_NAMES.add("isglobalcatalogready");
		STRING_ATTRIBUTE_NAMES.add("domainfunctionality");
		STRING_ATTRIBUTE_NAMES.add("forestfunctionality");
		STRING_ATTRIBUTE_NAMES.add("domaincontrollerfunctionality");
		STRING_ATTRIBUTE_NAMES.add("currenttime");
		STRING_ATTRIBUTE_NAMES.add("dsservicename");
		STRING_ATTRIBUTE_NAMES.add(AbstractLdapConfiguration.ATTRIBUTE_389DS_FIRSTCHANGENUMBER.toLowerCase());
		STRING_ATTRIBUTE_NAMES.add(AbstractLdapConfiguration.ATTRIBUTE_389DS_LASTCHANGENUMBER.toLowerCase());
		
	}

}
