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

import javax.naming.directory.SchemaViolationException;

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
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.AttributeValueCompleteness;
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
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import com.evolveum.polygon.connector.ldap.LdapConstants;
import com.evolveum.polygon.connector.ldap.LdapUtil;

/**
 * @author semancik
 *
 */
public abstract class AbstractSchemaTranslator<C extends AbstractLdapConfiguration> {
	
	private static final Log LOG = Log.getLog(AbstractSchemaTranslator.class);
	private static final Collection<String> STRING_ATTRIBUTE_NAMES = new ArrayList<>();
	private static final Map<String, TypeSubType> SYNTAX_MAP = new HashMap<>();
	
	private SchemaManager schemaManager;
	private C configuration;
	private Schema icfSchema = null;
	
	public AbstractSchemaTranslator(SchemaManager schemaManager, C configuration) {
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

	@SuppressWarnings("unchecked")
	public Schema translateSchema(ConnectionManager<C> connection) throws InvalidConnectionException {
		SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
		LOG.ok("Translating LDAP schema from {0}", schemaManager);
		
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
			if (shouldTranslateObjectClass(ldapObjectClass.getName())) {
				LOG.ok("Found LDAP schema object class {0}, translating", ldapObjectClass.getName());
				ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
				ocib.setType(toIcfObjectClassType(ldapObjectClass));
				Map<String, AttributeInfo> attrInfoList = new HashMap<>();
				addAttributeTypes(attrInfoList, ldapObjectClass);
				ocib.addAllAttributeInfo(attrInfoList.values());
				
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
	
	private void addAttributeTypes(Map<String, AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		
		// ICF UID
		String uidAttribudeLdapName = configuration.getUidAttribute();
		AttributeInfoBuilder uidAib = new AttributeInfoBuilder(Uid.NAME);
		uidAib.setNativeName(uidAttribudeLdapName);
		uidAib.setRequired(false); // Must be optional. It is not present for create operations
		AttributeType uidAttributeLdapType = null;
		
		try {
			uidAttributeLdapType = schemaManager.lookupAttributeTypeRegistry(uidAttribudeLdapName);
		} catch (LdapException e) {
			// We can live with this
			LOG.ok("Got exception looking up UID atribute {0}: {1} ({2}) (probabably harmless)", uidAttribudeLdapName,
					e.getMessage(), e.getClass());
		}

        // UID must be string. It is hardcoded in the framework.
        uidAib.setType(String.class);

		if (uidAttributeLdapType != null) {
			uidAib.setSubtype(toIcfSubtype(String.class, uidAttributeLdapType, Uid.NAME));
			setAttributeMultiplicityAndPermissions(uidAttributeLdapType, Uid.NAME, uidAib);
		} else {
			uidAib.setCreateable(false);
			uidAib.setUpdateable(false);
			uidAib.setReadable(true);
		}
		
		AttributeInfo attributeInfo = uidAib.build();
		attrInfoList.put(attributeInfo.getName(), attributeInfo);
		
		// ICF NAME
		AttributeInfoBuilder nameAib = new AttributeInfoBuilder(Name.NAME);
		nameAib.setType(String.class);
		nameAib.setNativeName(LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME);
		nameAib.setSubtype(AttributeInfo.Subtypes.STRING_LDAP_DN);
		nameAib.setRequired(true);
        attributeInfo = nameAib.build();
        attrInfoList.put(attributeInfo.getName(), attributeInfo);
		
		// AUXILIARY_OBJECT_CLASS
		attrInfoList.put(PredefinedAttributeInfos.AUXILIARY_OBJECT_CLASS.getName(), PredefinedAttributeInfos.AUXILIARY_OBJECT_CLASS);
		
		addAttributeTypesFromLdapSchema(attrInfoList, ldapObjectClass);
		addExtraOperationalAttributes(attrInfoList);
	}
	
	private void addExtraOperationalAttributes(Map<String, AttributeInfo> attrInfoList) {
		for (String operationalAttributeLdapName: configuration.getOperationalAttributes()) {
			if (containsAttribute(attrInfoList, operationalAttributeLdapName)) {
				continue;
			}
			AttributeInfoBuilder aib = new AttributeInfoBuilder(operationalAttributeLdapName);
			aib.setRequired(false);
			aib.setNativeName(operationalAttributeLdapName);
			
			AttributeType attributeType = null;
			try {
				attributeType = schemaManager.lookupAttributeTypeRegistry(operationalAttributeLdapName);
			} catch (LdapException e) {
				// Ignore. We want this attribute even if it is not in the LDAP schema
			}
			
			if (attributeType != null) {
				LdapSyntax ldapSyntax = getSyntax(attributeType);
				Class<?> icfType = toIcfType(ldapSyntax, operationalAttributeLdapName);
				aib.setType(icfType);
				aib.setSubtype(toIcfSubtype(icfType, attributeType, operationalAttributeLdapName));
				LOG.ok("Translating {0} -> {1} ({2} -> {3}) (operational)", operationalAttributeLdapName, operationalAttributeLdapName, 
						ldapSyntax==null?null:ldapSyntax.getOid(), icfType);
				setAttributeMultiplicityAndPermissions(attributeType, operationalAttributeLdapName, aib);
			} else {
				LOG.ok("Translating {0} -> {1} ({2} -> {3}) (operational, not defined in schema)", operationalAttributeLdapName, operationalAttributeLdapName, 
						null, String.class);
				aib.setType(String.class);
				aib.setMultiValued(false);
			}
			aib.setReturnedByDefault(false);
			
			AttributeInfo attributeInfo = aib.build();
			attrInfoList.put(attributeInfo.getName(), attributeInfo);
		}
		
	}
	
	private void addAttributeTypesFromLdapSchema(Map<String, AttributeInfo> attrInfoList, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		LOG.ok("  ... translating attributes from {0}:\n{1}\nMUST\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMustAttributeTypes());
		addAttributeTypes(attrInfoList, ldapObjectClass.getMustAttributeTypes(), true);
		LOG.ok("  ... translating attributes from {0}:\n{1}\nMAY\n{2}", ldapObjectClass.getName(), ldapObjectClass, ldapObjectClass.getMayAttributeTypes());
		addAttributeTypes(attrInfoList, ldapObjectClass.getMayAttributeTypes(), false);
		
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> superiors = ldapObjectClass.getSuperiors();
		if ((superiors != null) && (superiors.size() > 0)) {
			for (org.apache.directory.api.ldap.model.schema.ObjectClass superior: superiors) {
				addAttributeTypesFromLdapSchema(attrInfoList, superior);
			}
		}
	}

	private void addAttributeTypes(Map<String, AttributeInfo> attrInfoList, List<AttributeType> attributeTypes, boolean isRequired) {
		for (AttributeType ldapAttribute: attributeTypes) {
			if (!shouldTranslateAttribute(ldapAttribute.getName())) {
				LOG.ok("Skipping translation of attribute {0} because it should not be translated", ldapAttribute.getName());
				continue;
			}
			
			// Compare the name *or* the OID (the name may be null)
			if ((SchemaConstants.OBJECT_CLASS_AT.equalsIgnoreCase( ldapAttribute.getName()))
			    || SchemaConstants.OBJECT_CLASS_AT_OID.equals( ldapAttribute.getOid() )) {
				continue;
			}
			if (ldapAttribute.getName().equalsIgnoreCase(getConfiguration().getUidAttribute())) {
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
			aib.setSubtype(toIcfSubtype(icfType, ldapAttribute, icfAttributeName));
			aib.setNativeName(ldapAttribute.getName());
			if (isOperational(ldapAttribute)) {
				aib.setReturnedByDefault(false);
			}
			setAttributeMultiplicityAndPermissions(ldapAttribute, icfAttributeName, aib);
			LOG.ok("Translating {0} -> {1} ({2} -> {3})", ldapAttribute.getName(), icfAttributeName, 
					ldapSyntax==null?null:ldapSyntax.getOid(), icfType);
			AttributeInfo attributeInfo = aib.build();
			attrInfoList.put(attributeInfo.getName(), attributeInfo);
		}
	}
	
	protected boolean isOperational(AttributeType ldapAttribute) {
		return ldapAttribute.isOperational();
	}

	protected void setAttributeMultiplicityAndPermissions(AttributeType ldapAttributeType, String icfAttributeName, AttributeInfoBuilder aib) {
		if (ldapAttributeType.isSingleValued()) {
			aib.setMultiValued(false);
		} else {
			aib.setMultiValued(true);
		}
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			switch (configuration.getPasswordReadStrategy()) {
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_READABLE:
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_INCOMPLETE_READ:
					aib.setReadable(true);
					break;
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_UNREADABLE:
					aib.setReturnedByDefault(false);
					aib.setReadable(false);
					break;
				default:
					throw new ConfigurationException("Unknown passoword read strategy "+configuration.getPasswordReadStrategy());
			}
		} else {
			aib.setReadable(true);
		}
		if (ldapAttributeType.isReadOnly() || !ldapAttributeType.isUserModifiable()) {
			aib.setCreateable(false);
			aib.setUpdateable(false);
		} else {
			aib.setCreateable(true);
			aib.setUpdateable(true);			
		}
	}
	
	private boolean containsAttribute(Map<String, AttributeInfo> attrInfoList, String icfAttributeName) {
	    return attrInfoList.containsKey( icfAttributeName );
	}

	private String toIcfAttributeName(String ldapAttributeName) {
		if (ldapAttributeName.equalsIgnoreCase(configuration.getPasswordAttribute())) {
			return OperationalAttributeInfos.PASSWORD.getName();
		}
		return ldapAttributeName;
	}
	
	public org.apache.directory.api.ldap.model.schema.ObjectClass toLdapObjectClass(ObjectClass icfObjectClass) {
		String ldapObjectClassName = toLdapObjectClassName(icfObjectClass);
		try {
			return schemaManager.lookupObjectClassRegistry(ldapObjectClassName);
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
			AttributeType attributeType = schemaManager.lookupAttributeTypeRegistry(ldapAttributeName);
			if (attributeType == null && configuration.isAllowUnknownAttributes()) {
				// Create fake attribute type
				attributeType = createFauxAttributeType(ldapAttributeName);
			}
			return attributeType;
		} catch (LdapException e) {
			if (ArrayUtils.contains(configuration.getOperationalAttributes(), ldapAttributeName) || configuration.isAllowUnknownAttributes()) {
				// Create fake attribute type
				AttributeType attributeType = new AttributeType(ldapAttributeName);
				attributeType.setNames(ldapAttributeName);
				return attributeType;
			} else {
				throw new IllegalArgumentException("Unknown LDAP attribute "+ldapAttributeName+" (translated from ICF attribute "+icfAttributeName+")", e);
			}
		}
	}
	
	public AttributeType createFauxAttributeType(String attributeName) {
		MutableAttributeType mutableLdapAttributeType = new MutableAttributeType(attributeName);
		mutableLdapAttributeType.setNames(attributeName);
		mutableLdapAttributeType.setSyntaxOid(SchemaConstants.DIRECTORY_STRING_SYNTAX);
		return mutableLdapAttributeType;
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
    	Class<?> type = null;
        TypeSubType typeSubtype = SYNTAX_MAP.get( syntax.getName() );

    	if (typeSubtype != null) {
    	    type = typeSubtype.type;
    	    if (type == Date.class) {
    	    	if (AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_UNIX_EPOCH.equals(getConfiguration().getTimestampPresentation())) {
    	    		type = long.class;
    	    	} else {
    	    		type = String.class;
    	    	}
    	    }
    	}
    	
    	if (type == null) {
    		LOG.warn("No type mapping for syntax {0}, using string", syntax.getName());
    		return String.class;
    	} else {
    		return type;
    	}
	}
	
	public String toIcfSubtype(Class<?> icfType, AttributeType ldapAttribute, String icfAttributeName) {
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			return null;
		}
		if (ldapAttribute == null) {
			return null;
		}
		if (hasEqualityMatching(ldapAttribute, SchemaConstants.CASE_IGNORE_MATCH_MR, SchemaConstants.CASE_IGNORE_MATCH_MR_OID)) {
			return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
		}
		if (hasEqualityMatching(ldapAttribute, SchemaConstants.CASE_IGNORE_IA5_MATCH_MR, SchemaConstants.CASE_IGNORE_IA5_MATCH_MR_OID)) {
			return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
		}
		if (hasEqualityMatching(ldapAttribute, SchemaConstants.UUID_MATCH_MR, SchemaConstants.UUID_MATCH_MR_OID)) {
			return AttributeInfo.Subtypes.STRING_UUID.toString();
		}
		String syntaxOid = ldapAttribute.getSyntaxOid();		
		if (syntaxOid == null) {
			return null;
		} 
		if (SYNTAX_MAP.get(syntaxOid) == null) {
			if (icfType == String.class) {
				return AttributeInfo.Subtypes.STRING_CASE_IGNORE.toString();
			} else {
				return null;
			}
		}
		return SYNTAX_MAP.get(syntaxOid).subtype;
	}

	private boolean hasEqualityMatching(AttributeType ldapAttribute, String matchingRuleName,
			String matchingRuleOid) {
		if (ldapAttribute == null) {
			return false;
		}
		if (ldapAttribute.getEquality() != null && matchingRuleOid.equalsIgnoreCase(ldapAttribute.getEquality().getOid())) {
			return true;
		}
		if (matchingRuleOid.equalsIgnoreCase(ldapAttribute.getEqualityOid())) {
			return true;
		}
		if (matchingRuleName.equalsIgnoreCase(ldapAttribute.getEqualityName())) {
			return true;
		}
		if (ldapAttribute.getSuperior() != null) {
			if (hasEqualityMatching(ldapAttribute.getSuperior(), matchingRuleName, matchingRuleOid)) {
				return true;
			}
		}
		return false;
	}

	public List<Value<Object>> toLdapValues(AttributeType ldapAttributeType, List<Object> icfAttributeValues) {
		List<Value<Object>> ldapValues = new ArrayList<>(icfAttributeValues.size());
		for (Object icfValue: icfAttributeValues) {
			ldapValues.add(toLdapValue(ldapAttributeType, icfValue));
		}
		return ldapValues;
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public Value<Object> toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (icfAttributeValue == null) {
			return null;
		}
		if (ldapAttributeType == null) {
			// We have no definition for this attribute. Assume string.
			return (Value)new StringValue(icfAttributeValue.toString());
		}
		
		if (ldapAttributeType.getName().equalsIgnoreCase(configuration.getPasswordAttribute())) {
			return toLdapPasswordValue(ldapAttributeType, icfAttributeValue);
		}
		
		return wrapInLdapValueClass(ldapAttributeType, icfAttributeValue);
	}
	
	@SuppressWarnings({ "unchecked", "rawtypes" })
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
		} else if (!isBinaryAttribute(syntaxOid)) {
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
	@SuppressWarnings({ "unchecked", "rawtypes" })
	public Value<Object> toLdapIdentifierValue(AttributeType ldapAttributeType, String icfAttributeValue) {
		if (icfAttributeValue == null) {
			return null;
		}
		if (ldapAttributeType == null) {
			// We have no definition for this attribute. Assume string.
			return (Value)new StringValue(icfAttributeValue);
		}
		
		String syntaxOid = ldapAttributeType.getSyntaxOid();
		if (SchemaConstants.OCTET_STRING_SYNTAX.equals(syntaxOid)) {
			// Expect hex-encoded value (see toIcfIdentifierValue())
			byte[] bytes = LdapUtil.hexToBinary(icfAttributeValue);
			// Do NOT set attributeType in the Value in this case.
			// The attributeType might not match the Value class
			return (Value)new BinaryValue(bytes);
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
	
	private Object toIcfValue(String icfAttributeName, Value<?> ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
		if (ldapValue == null) {
			return null;
		}
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			return new GuardedString(ldapValue.getString().toCharArray());
		} else {
			String syntaxOid = null;
			if (ldapAttributeType != null) {
				syntaxOid = ldapAttributeType.getSyntaxOid();
			}
			if (SchemaConstants.GENERALIZED_TIME_SYNTAX.equals(syntaxOid)) {
				if (AbstractLdapConfiguration.TIMESTAMP_PRESENTATION_UNIX_EPOCH.equals(getConfiguration().getTimestampPresentation())) {
					try {
						GeneralizedTime gt = new GeneralizedTime(ldapValue.getString());
						return gt.getCalendar().getTimeInMillis();
					} catch (ParseException e) {
						throw new InvalidAttributeValueException("Wrong generalized time format in LDAP attribute "+ldapAttributeName+": "+e.getMessage(), e);
					}
				} else {
					return ldapValue.getString();
				}
			} else if (SchemaConstants.BOOLEAN_SYNTAX.equals(syntaxOid)) {
				return Boolean.parseBoolean(ldapValue.getString());
			} else if (isIntegerSyntax(syntaxOid)) {
				return Integer.parseInt(ldapValue.getString());
			} else if (isLongSyntax(syntaxOid)) {
				return Long.parseLong(ldapValue.getString());
			} else if (isBinarySyntax(syntaxOid)) {
				LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit binary", ldapAttributeName, syntaxOid, ldapValue.getClass());
				return ldapValue.getBytes();
			} else if (isStringSyntax(syntaxOid)) {
				LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): explicit string", ldapAttributeName, syntaxOid, ldapValue.getClass());
				return ldapValue.getString();
			} else {
				if (ldapValue instanceof StringValue) {
					LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected string", ldapAttributeName, syntaxOid, ldapValue.getClass());
					return ldapValue.getString();
				} else {
					LOG.ok("Converting to ICF: {0} (syntax {1}, value {2}): detected binary", ldapAttributeName, syntaxOid, ldapValue.getClass());
					return ldapValue.getBytes();
				}
			}
		}
	}

	protected boolean isIntegerSyntax(String syntaxOid) {
		return false;
	}
	
	protected boolean isLongSyntax(String syntaxOid) {
		return SchemaConstants.JAVA_LONG_SYNTAX.equals(syntaxOid) ||
				LdapConstants.SYNTAX_AD_INTEGER8_SYNTAX.equals(syntaxOid);
	}


    /**
     * Tells if the given Syntax OID is String. It checks only a subset of
     * know syntaxes :
     * <ul>
     *   <li>DIRECTORY_STRING_SYNTAX</li>
     *   <li>IA5_STRING_SYNTAX</li>
     *   <li>OBJECT_CLASS_TYPE_SYNTAX</li>
     *   <li>DN_SYNTAX</li>
     *   <li>PRINTABLE_STRING_SYNTAX</li>
     *   <li>INTEGER_SYNTAX</li>
     * </ul>  
     * @param syntaxOid The Syntax OID
     * @return <tt>true</tt> if the syntax OID is one of the listed syntaxes
     */
    protected boolean isStringSyntax(String syntaxOid) {
    	if (syntaxOid == null) {
    		// If there is no syntax information we assume that is is string type
    		return true;
    	}
        switch (syntaxOid) {
            case SchemaConstants.DIRECTORY_STRING_SYNTAX : 
            case SchemaConstants.IA5_STRING_SYNTAX :
            case SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX :
            case SchemaConstants.DN_SYNTAX :
            case SchemaConstants.PRINTABLE_STRING_SYNTAX :
            case SchemaConstants.INTEGER_SYNTAX :
                return true;
            default :
                return false;
        }
    }

    /**
     * Tells if the given Syntax OID is binary. It checks only a subset of
     * know syntaxes :
     * <ul>
     *   <li>OCTET_STRING_SYNTAX</li>
     *   <li>JPEG_SYNTAX</li>
     *   <li>BINARY_SYNTAX</li>
     *   <li>BIT_STRING_SYNTAX</li>
     *   <li>CERTIFICATE_SYNTAX</li>
     *   <li>CERTIFICATE_LIST_SYNTAX</li>
     *   <li>CERTIFICATE_PAIR_SYNTAX</li>
     * </ul>  
     * @param syntaxOid The Syntax OID
     * @return <tt>true</tt> if the syntax OID is one of the listed syntaxes
     */
    protected boolean isBinarySyntax(String syntaxOid) {
    	if (syntaxOid == null) {
    		return false;
    	}
        switch (syntaxOid) {
            case SchemaConstants.OCTET_STRING_SYNTAX :
            case SchemaConstants.JPEG_SYNTAX :
            case SchemaConstants.BINARY_SYNTAX :
            case SchemaConstants.BIT_STRING_SYNTAX :
            case SchemaConstants.CERTIFICATE_SYNTAX :
            case SchemaConstants.CERTIFICATE_LIST_SYNTAX :
            case SchemaConstants.CERTIFICATE_PAIR_SYNTAX :
                return true;
            default :
                return false;
        }
    }

	/**
	 * Check if an Attribute is binary or String. We use either the H/R flag, if present,
	 * or a set of static syntaxes. In this case, here are the statically defined matches :
	 * <ul>
     *   <li>
     *     Binary syntaxes :
     *     <ul>
     *       <li>BINARY_SYNTAX</li>
     *       <li>BIT_STRING_SYNTAX</li>
     *       <li>CERTIFICATE_LIST_SYNTAX</li>
     *       <li>CERTIFICATE_PAIR_SYNTAX</li>
     *       <li>CERTIFICATE_SYNTAX</li>
     *       <li>JPEG_SYNTAX</li>
     *       <li>OCTET_STRING_SYNTAX</li>
     *     </ul>
     *   </li>
     *   <li>
     *     String syntaxes :
     *     <ul>
     *       <li>DIRECTORY_STRING_SYNTAX</li>
     *       <li>DN_SYNTAX</li>
     *       <li>IA5_STRING_SYNTAX</li>
     *       <li>OBJECT_CLASS_TYPE_SYNTAX</li>
     *       <li>PRINTABLE_STRING_SYNTAX</li>
     *     </ul>
     *   </li>
     * </ul>
     * 
     * @param attributeId The Attribute name or its OID
     * @return <tt>true</tt> if the attribute is binary, <tt>false</tt> otherwise
     */
    public boolean isBinaryAttribute(String attributeId) {
        // Get rid of the attribute's options
        String ldapAttributeName = getLdapAttributeName(attributeId);
        
        // Retrieve the attributeType from the schema
        AttributeType attributeType = schemaManager.getAttributeType(ldapAttributeName);
        
        if (attributeType == null) {
            // Not found. Let's try with the set of hard-coded attributeType
            if (STRING_ATTRIBUTE_NAMES.contains(attributeId.toLowerCase())) {
                return false;
            }
            
            LOG.warn("Uknown attribute {0}, cannot determine if it is binary", ldapAttributeName);
            
            return false;
        }
        
        // Ok, we have the AttributeType, let's get its Syntax
        LdapSyntax syntax = getSyntax(attributeType);
        
        // Should *never* happen, as the getSyntax() method always 
        // return a syntax....
        if (syntax == null) {
            // OpenLDAP does not define some syntaxes that it uses
            return false;
        }
        
        String syntaxOid = syntax.getOid();
        
        // First check in the pre-defined list, just in case
        if (isBinarySyntax(syntaxOid)) {
            return true;
        }
        
        if (isStringSyntax(syntaxOid)) {
            return false;
        }
        
        // Ok, if the syntax is not one of the pre-defined we know of, 
        // try to ask the syntax about its status.
        return !syntax.isHumanReadable();
    }
	
	
    /**
     * Retrieve the Syntax associated with an AttributeType. In theory, every AttributeType
     * must have a syntax, but some rogue and not compliant LDAP Servers don't do that.
     * Typically, if an AttributeType does not have a Syntax, then it should inherit from
     * its parent's Syntax.  
     * 
     * @param attributeType The AttributeType for which we want the Syntax
     * @return The LdapSyntax instance for this AttributeType
     */
    LdapSyntax getSyntax(AttributeType attributeType) {
        LdapSyntax syntax = attributeType.getSyntax();
        
        if (syntax == null && attributeType.getSyntaxOid() != null) {
            // HACK to support ugly servers (such as AD) that do not declare 
            // ldapSyntaxes in the schema
            // We will first check if we can't find the syntax from the
            // SchemaManager, and if not, we will create it
            try
            {
                syntax = schemaManager.lookupLdapSyntaxRegistry( attributeType.getSyntaxOid() );
            }
            catch ( LdapException e )
            {
                // Fallback...
                syntax = new LdapSyntax(attributeType.getSyntaxOid());
            }
        }
        
        return syntax;
    }

	/**
	 * Used to format __UID__ and __NAME__.
	 */
	public String toIcfIdentifierValue(Value<?> ldapValue, String ldapAttributeName, AttributeType ldapAttributeType) {
		if (ldapValue == null) {
			return null;
		}
		if (ldapAttributeType == null) {
			// E.g. ancient OpenLDAP does not have entryUUID in schema
			if (!configuration.isAllowUnknownAttributes()) {
				throw new InvalidAttributeValueException("Unknown LDAP attribute "+ldapAttributeName + " (not present in LDAP schema)");
			}
		}
		
		if ((ldapAttributeType != null) && isBinaryAttribute( ldapAttributeName )) {
			LOG.ok("Converting identifier to ICF: {0} (syntax {1}, value {2}): explicit binary", 
			    ldapAttributeName, getSyntax(ldapAttributeType).getOid(), ldapValue.getClass());
			
			byte[] bytes;
			
			if (ldapValue instanceof BinaryValue) {
				bytes = ldapValue.getBytes();
			} else if (ldapValue instanceof StringValue) {
                // Binary value incorrectly detected as string value. Conversion to Java string has broken the data.
                // We need to do some magic to fix it.
			    bytes = ldapValue.getBytes();
			} else {
				throw new IllegalStateException("Unexpected value type "+ldapValue.getClass());
			}
			
			// Assume that identifiers are short. It is more readable to use hex representation than base64.
			return LdapUtil.binaryToHex(bytes);
		} else {
			LOG.ok("Converting identifier to ICF: {0} (syntax {1}, value {2}): implicit string", ldapAttributeName, 
				ldapAttributeType==null?null:getSyntax(ldapAttributeType).getOid(),
			    ldapValue.getClass());
			
			return ldapValue.getString();
		}
	}
	
	public ObjectClassInfo findObjectClassInfo(ObjectClass icfObjectClass) {
		return icfSchema.findObjectClassInfo(icfObjectClass.getObjectClassValue());
	}
	
    /**
     * Tells if a given Entry has an UID attribute
     * 
     * @param entry The Entry to check
     * @return <tt>true</tt> if the entry contains an UID attribute
     */
    public boolean hasUidAttribute(Entry entry) {
        String uidAttributeName = configuration.getUidAttribute();
        
        if (LdapUtil.isDnAttribute(uidAttributeName)) {
            return true;
        } else {
            return entry.get(uidAttributeName) != null;
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
			dn = getDn(entry);
		}
		cob.setName(dn);
		cob.setObjectClass(new ObjectClass(icfStructuralObjectClassInfo.getType()));
		
		List<ObjectClassInfo> icfAuxiliaryObjectClassInfos = new ArrayList<>(ldapObjectClasses.getLdapAuxiliaryObjectClasses().size());
		if (!ldapObjectClasses.getLdapAuxiliaryObjectClasses().isEmpty()) {
			AttributeBuilder auxAttrBuilder = new AttributeBuilder();
			auxAttrBuilder.setName(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME);
			for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapAuxiliaryObjectClass: ldapObjectClasses.getLdapAuxiliaryObjectClasses()) {
				auxAttrBuilder.addValue(ldapAuxiliaryObjectClass.getName());
				ObjectClassInfo objectClassInfo = icfSchema.findObjectClassInfo(ldapAuxiliaryObjectClass.getName());
//				LOG.ok("ConnId object class info for auxiliary object class {0}:\n{1}", ldapAuxiliaryObjectClass.getName(), objectClassInfo);
				icfAuxiliaryObjectClassInfos.add(objectClassInfo);
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
			uid = toIcfIdentifierValue(uidAttribute.get(), uidAttribute.getId(), attributeType);
		}
		cob.setUid(uid);
		
		Iterator<org.apache.directory.api.ldap.model.entry.Attribute> iterator = entry.iterator();
		while (iterator.hasNext()) {
			org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute = iterator.next();
			String ldapAttrName = getLdapAttributeName(ldapAttribute);
//			LOG.ok("Processing attribute {0}", ldapAttrName);
			if (!shouldTranslateAttribute(ldapAttrName)) {
//				LOG.ok("Should not translate attribute {0}, skipping", ldapAttrName);
				continue;
			}
			AttributeType attributeType = schemaManager.getAttributeType(ldapAttrName);
//			LOG.ok("Type for attribute {0}: {1}", ldapAttrName, attributeType);
			String ldapAttributeNameFromSchema = ldapAttrName;
			if (attributeType == null) {
				if (!configuration.isAllowUnknownAttributes()) {
					throw new InvalidAttributeValueException("Unknown LDAP attribute " + ldapAttrName + " (not present in LDAP schema)");
				}
			} else {
				ldapAttributeNameFromSchema = attributeType.getName();
			}
			if (uidAttributeName.equals(ldapAttributeNameFromSchema)) {
				continue;
			}
			Attribute icfAttribute = toIcfAttribute(connection, entry, ldapAttribute, attributeHandler);
//			LOG.ok("ConnId attribute for {0}: {1}", ldapAttrName, icfAttribute);
			if (icfAttribute == null) {
				continue;
			}
			AttributeInfo attributeInfo = SchemaUtil.findAttributeInfo(icfStructuralObjectClassInfo, icfAttribute);
			if (attributeInfo == null) {
				for (ObjectClassInfo icfAuxiliaryObjectClassInfo: icfAuxiliaryObjectClassInfos) {
					attributeInfo = SchemaUtil.findAttributeInfo(icfAuxiliaryObjectClassInfo, icfAttribute);
//					LOG.ok("Looking for ConnId attribute {0} info in auxiliary class {1}: {2}", icfAttribute, icfAuxiliaryObjectClassInfo==null?null:icfAuxiliaryObjectClassInfo.getType(), attributeInfo);
					if (attributeInfo != null) {
						break;
					}
//					LOG.ok("Failed to find attribute in: {0}", icfAuxiliaryObjectClassInfo);
				}
			}
//			LOG.ok("ConnId attribute info for {0} ({1}): {2}", icfAttribute.getName(), ldapAttrName, attributeInfo);
			if (attributeInfo != null) {
				// Avoid sending unknown attributes (such as createtimestamp)
				cob.addAttribute(icfAttribute);
			} else {
				LOG.ok("ConnId attribute {0} is not part of ConnId schema, skipping", icfAttribute.getName());
			}
			
		}
		
		extendConnectorObject(cob, entry, icfStructuralObjectClassInfo.getType());
		
		return cob.build();
	}
	
	public String getDn(Entry entry) {
		return entry.getDn().getName();
	}
	
	public String getLdapAttributeName(org.apache.directory.api.ldap.model.entry.Attribute ldapAttribute) {
		return getLdapAttributeName(ldapAttribute.getId());
	}
	
	/**
	 * Get back the attribute name, without the options. Typically, RFC 4512 
	 * defines an Attribute description as :
	 * <pre>
	 * attributedescription = attributetype options
     * attributetype = oid
     * options = *( SEMI option )
     * option = 1*keychar
	 * </pre>
	 * 
	 * where <em>oid</em> can be a String or an OID. An example is :
	 * <pre>
	 * cn;lang-de;lang-en
	 * </pre>
	 * where the attribute name is <em>cn</em>.
	 * <p>
	 * @param attributeId The attribute descriptio to parse
	 * @return The attribute name, without the options
	 */
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
		org.apache.directory.api.ldap.model.entry.Attribute objectClassAttribute = entry.get(SchemaConstants.OBJECT_CLASS_AT);
		if (objectClassAttribute == null) {
			throw new InvalidAttributeValueException("No object class attribute in entry "+entry.getDn());
		}
		// Neither structural nor auxiliary. Should not happen. But it does.
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> outstandingObjectClasses = new ArrayList<>();
		for (Value<?> objectClassVal: objectClassAttribute) {
			String objectClassString = objectClassVal.getString();
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
			try {
				ldapObjectClass = schemaManager.lookupObjectClassRegistry(objectClassString);
			} catch (LdapException e) {
				throw new InvalidAttributeValueException(e.getMessage(), e);
			}
			if (ldapObjectClass.isStructural()) {
//				LOG.ok("Objectclass {0}: structural)", ldapObjectClass.getName());
				ocs.getLdapStructuralObjectClasses().add(ldapObjectClass);
			} else if (ldapObjectClass.isAuxiliary()) {
//				LOG.ok("Objectclass {0}: auxiliary)", ldapObjectClass.getName());
				ocs.getLdapAuxiliaryObjectClasses().add(ldapObjectClass);
			} else if (ldapObjectClass.isAbstract()) {
//				LOG.ok("Objectclass {0}: abstract)", ldapObjectClass.getName());
				// We are ignoring this. This is 'top' and things like that.
				// These are not directly useful, not even in the alternative mechanism.
			} else {
//				LOG.ok("Objectclass {0}: outstanding)", ldapObjectClass.getName());
				outstandingObjectClasses.add(ldapObjectClass);
			}
		}
		if (ocs.getLdapStructuralObjectClasses().isEmpty()) {
			throw new InvalidAttributeValueException("Entry "+entry.getDn()+" has no structural object classes");
		}
		if (ocs.getLdapStructuralObjectClasses().size() == 1) {
			ocs.setLdapLowestStructuralObjectClass(ocs.getLdapStructuralObjectClasses().get(0));
		} else {
			for (org.apache.directory.api.ldap.model.schema.ObjectClass structObjectClass: ocs.getLdapStructuralObjectClasses()) {
				if (!hasSubclass(structObjectClass, ocs.getLdapStructuralObjectClasses())) {
					ocs.setLdapLowestStructuralObjectClass(structObjectClass);
					break;
				}
			}
			if (ocs.getLdapLowestStructuralObjectClass() == null) {
				throw new InvalidAttributeValueException("Cannot determine lowest structural object class for set of object classes: "+objectClassAttribute);
			}
		}
		if (getConfiguration().isAlternativeObjectClassDetection()) {
			for (org.apache.directory.api.ldap.model.schema.ObjectClass objectClass: outstandingObjectClasses) {
				// Extra filter to filter out classes such as 'top' if they are not
				// properly marked as abstract
				if (hasSubclass(objectClass, outstandingObjectClasses)) {
					continue;
				}
				if (hasSubclass(objectClass, ocs.getLdapStructuralObjectClasses())) {
					continue;
				}
				if (hasSubclass(objectClass, ocs.getLdapAuxiliaryObjectClasses())) {
					continue;
				}
				LOG.ok("Detected auxliary objectclasse (alternative method): {0})", ocs);
				ocs.getLdapAuxiliaryObjectClasses().addAll(outstandingObjectClasses);
			}
		}
//		LOG.ok("Detected objectclasses: {0})", ocs);
		return ocs;
	}
	
	private boolean hasSubclass(org.apache.directory.api.ldap.model.schema.ObjectClass objectClass, 
			List<org.apache.directory.api.ldap.model.schema.ObjectClass> otherObjectClasses) {
//		LOG.ok("Trying {0} ({1})", structObjectClass.getName(), structObjectClass.getOid());
		for (org.apache.directory.api.ldap.model.schema.ObjectClass otherObjectClass: otherObjectClasses) {
			if (objectClass.getOid().equals(otherObjectClass.getOid())) {
				continue;
			}
//			LOG.ok("  with {0} ({1})", otherObjectClass.getName(), structObjectClass.getOid());
//			LOG.ok("    superiorOids: {0}", otherObjectClass.getSuperiorOids());
			if (otherObjectClass.getSuperiorOids().contains(objectClass.getOid()) 
					|| otherObjectClass.getSuperiorOids().contains(objectClass.getName())) {
//				LOG.ok("    hasSubclass");
				return true;
			}
		}
		return false;
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
		String ldapAttributeNameFromSchema;
		if (ldapAttributeType == null) {
			if (configuration.isAllowUnknownAttributes()) {
				ldapAttributeNameFromSchema = ldapAttributeName;
			} else {
				throw new InvalidAttributeValueException("Unknown LDAP attribute " + ldapAttributeName + " (not present in LDAP schema)");
			}
		} else {
			ldapAttributeNameFromSchema = ldapAttributeType.getName();
		}
		String icfAttributeName = toIcfAttributeName(ldapAttributeNameFromSchema);
		ab.setName(icfAttributeName);
		if (attributeHandler != null) {
			attributeHandler.handle(connection, entry, ldapAttribute, ab);
		}
		boolean incompleteRead = false;
		if (OperationalAttributeInfos.PASSWORD.is(icfAttributeName)) {
			switch (configuration.getPasswordReadStrategy()) {
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_READABLE:
					// Nothing to do. Proceed with ordinary read.
					break;
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_INCOMPLETE_READ:
					incompleteRead = true;
					break;
				case AbstractLdapConfiguration.PASSWORD_READ_STRATEGY_UNREADABLE:
					return null;
				default:
					throw new ConfigurationException("Unknown passoword read strategy "+configuration.getPasswordReadStrategy());
			}
		}
		Iterator<Value<?>> iterator = ldapAttribute.iterator();
		boolean hasValidValue = false;
		while (iterator.hasNext()) {
			Value<?> ldapValue = iterator.next();
			Object icfValue = toIcfValue(icfAttributeName, ldapValue, ldapAttributeNameFromSchema, ldapAttributeType);
			if (icfValue != null) {
				if (!incompleteRead) {
					ab.addValue(icfValue);
				}
				hasValidValue = true;
			}
		}
		if (!hasValidValue) {
			// Do not even try to build. The build will fail.
			return null;
		}
		if (incompleteRead) {
			ab.setAttributeValueCompleteness(AttributeValueCompleteness.INCOMPLETE);
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
			return new Dn(stringDn);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Invalid DN '"+stringDn+"': "+e.getMessage(), e);
		}
	}
	
	public Dn toSchemaAwareDn(Attribute attribute) {
		if (attribute == null) {
			return null;
		}
		return toSchemaAwareDn(SchemaUtil.getSingleStringNonBlankValue(attribute));
	}
	
	public Dn toSchemaAwareDn(Uid icfUid) {
		if (icfUid == null) {
			return null;
		}
		return toSchemaAwareDn(icfUid.getUidValue());
	}

	public Dn toSchemaAwareDn(String stringDn) {
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
	public Dn toSchemaAwareDn(Dn dn) {
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
		for(org.apache.directory.api.ldap.model.schema.ObjectClass superClass: ldapObjectClass.getSuperiors()) {
			String selectedAttribute = selectAttribute(superClass, candidates);
			if (selectedAttribute != null) {
				return selectedAttribute;
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
			if (superior.getName().equalsIgnoreCase(SchemaConstants.TOP_OC)) {
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
	
	public String[] getOperationalAttributes() {
		return configuration.getOperationalAttributes();
	}
	
	public String getUidAttribute() {
		return configuration.getUidAttribute();
	}

	private static class TypeSubType {
		Class<?> type;
		String subtype;
		
		public TypeSubType(Class<?> type, String subtype) {
			super();
			this.type = type;
			this.subtype = subtype;
		}
	}

	private static void addToSyntaxMap(String syntaxOid, Class<?> type) {
		SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, null));
	}

	private static void addToSyntaxMap(String syntaxOid, Class<?> type, String subtype) {
		SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, subtype));
	}

	private static void addToSyntaxMap(String syntaxOid, Class<?> type, AttributeInfo.Subtypes subtype) {
		SYNTAX_MAP.put(syntaxOid, new TypeSubType(type, subtype.toString()));
	}
	
	static {
		addToSyntaxMap(SchemaConstants.NAME_OR_NUMERIC_ID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OBJECT_CLASS_TYPE_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
		addToSyntaxMap(SchemaConstants.NUMERIC_OID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ATTRIBUTE_TYPE_USAGE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.NUMBER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OID_LEN_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OBJECT_NAME_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ACI_ITEM_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ACCESS_POINT_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ATTRIBUTE_TYPE_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.AUDIO_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.BINARY_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.BIT_STRING_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.BOOLEAN_SYNTAX, Boolean.class);
		addToSyntaxMap(SchemaConstants.CERTIFICATE_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.CERTIFICATE_LIST_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.CERTIFICATE_PAIR_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.COUNTRY_STRING_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DN_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_LDAP_DN);
		addToSyntaxMap(SchemaConstants.DATA_QUALITY_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DELIVERY_METHOD_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DIRECTORY_STRING_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DIT_CONTENT_RULE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DIT_STRUCTURE_RULE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DL_SUBMIT_PERMISSION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DSA_QUALITY_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DSE_TYPE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ENHANCED_GUIDE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.FACSIMILE_TELEPHONE_NUMBER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.FAX_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.GENERALIZED_TIME_SYNTAX, Date.class); // Date.class is a placeholder. It will be replaced by real value in the main code
		addToSyntaxMap(SchemaConstants.GUIDE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.IA5_STRING_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.INTEGER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.JPEG_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.MASTER_AND_SHADOW_ACCESS_POINTS_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.MATCHING_RULE_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.MATCHING_RULE_USE_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.MAIL_PREFERENCE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.MHS_OR_ADDRESS_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.NAME_AND_OPTIONAL_UID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.NAME_FORM_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.NUMERIC_STRING_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OBJECT_CLASS_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OTHER_MAILBOX_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.OCTET_STRING_SYNTAX, byte[].class);
		addToSyntaxMap(SchemaConstants.POSTAL_ADDRESS_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.PROTOCOL_INFORMATION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.PRESENTATION_ADDRESS_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.PRINTABLE_STRING_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUBTREE_SPECIFICATION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUPPLIER_INFORMATION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUPPLIER_OR_CONSUMER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUPPLIER_AND_CONSUMER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUPPORTED_ALGORITHM_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.TELEPHONE_NUMBER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.TELETEX_TERMINAL_IDENTIFIER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.TELEX_NUMBER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.UTC_TIME_SYNTAX, long.class);
		addToSyntaxMap(SchemaConstants.LDAP_SYNTAX_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.MODIFY_RIGHTS_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.LDAP_SCHEMA_DEFINITION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.LDAP_SCHEMA_DESCRIPTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SUBSTRING_ASSERTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.ATTRIBUTE_CERTIFICATE_ASSERTION_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.UUID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.CSN_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.CSN_SID_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.JAVA_BYTE_SYNTAX, byte.class);
		addToSyntaxMap(SchemaConstants.JAVA_CHAR_SYNTAX, char.class);
		addToSyntaxMap(SchemaConstants.JAVA_SHORT_SYNTAX, short.class);
		addToSyntaxMap(SchemaConstants.JAVA_LONG_SYNTAX, long.class);
		addToSyntaxMap(SchemaConstants.JAVA_INT_SYNTAX, int.class);
		addToSyntaxMap(SchemaConstants.COMPARATOR_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.NORMALIZER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SYNTAX_CHECKER_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.SEARCH_SCOPE_SYNTAX, String.class);
		addToSyntaxMap(SchemaConstants.DEREF_ALIAS_SYNTAX, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_AUTH_PASSWORD, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_COLLECTIVE_CONFLICT_BEHAVIOR, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_SUN_DEFINED_ACCESS_CONTROL_INFORMATION, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_NIS_NETGROUP_TRIPLE_SYNTAX, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_NIS_BOOT_PARAMETER_SYNTAX, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_CASE_IGNORE_STRING_TELETEX_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_CASE_IGNORE_STRING_SYNTAX, String.class, AttributeInfo.Subtypes.STRING_CASE_IGNORE);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_DN_WITH_STRING_SYNTAX, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_DN_WITH_BINARY_SYNTAX, String.class);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_INTEGER8_SYNTAX, long.class);
		addToSyntaxMap(LdapConstants.SYNTAX_AD_SECURITY_DESCRIPTOR_SYNTAX, byte[].class);
		
		// AD strangeness
		addToSyntaxMap("OctetString", byte[].class);
		
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
		STRING_ATTRIBUTE_NAMES.add(LdapConstants.ATTRIBUTE_389DS_FIRSTCHANGENUMBER.toLowerCase());
		STRING_ATTRIBUTE_NAMES.add(LdapConstants.ATTRIBUTE_389DS_LASTCHANGENUMBER.toLowerCase());
		
	}

}
