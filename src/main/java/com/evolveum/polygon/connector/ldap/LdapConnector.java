/*
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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
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
import org.apache.directory.api.ldap.model.exception.LdapServiceUnavailableException;
import org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.DefaultSchemaLoader;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SimplePagedResultsSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.VlvSearchStrategy;
import com.evolveum.polygon.connector.ldap.sync.SunChangelogSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.SyncStrategy;

@ConnectorClass(displayNameKey = "ldap.connector.display", configurationClass = LdapConfiguration.class)
public class LdapConnector implements PoolableConnector, TestOp, SchemaOp, SearchOp<Filter>, CreateOp, DeleteOp, 
		UpdateAttributeValuesOp, SyncOp{

    private static final Log LOG = Log.getLog(LdapConnector.class);
    
    private LdapConfiguration configuration;
    private LdapNetworkConnection connection;
    private SchemaManager schemaManager = null;
    private SchemaTranslator schemaTranslator = null;

    @Override
    public Configuration getConfiguration() {
        return configuration;
    }

    @Override
    public void init(Configuration configuration) {
        this.configuration = (LdapConfiguration)configuration;
        LOG.info("Connector init");
        connect();
    }
    
    @Override
	public void test() {
    	checkAlive();
    	try {
			connection.unBind();
			bind();
			Entry rootDse = getRootDse();
			LOG.ok("Root DSE: {0}", rootDse);
		} catch (LdapException e) {
			throw processLdapException(null, e);
		}
		// TODO: better error handling
	}
    
    private SchemaManager getSchemaManager() {
    	if (schemaManager == null) {
    		try {
    			boolean schemaQuirksMode = configuration.isSchemaQuirksMode();
    			LOG.info("Loading schema (quirksMode={0})", schemaQuirksMode);
    			DefaultSchemaLoader schemaLoader = new DefaultSchemaLoader(connection, schemaQuirksMode);
    			connection.loadSchema(schemaLoader);
    		} catch (LdapException e) {
    			throw new ConnectorIOException(e.getMessage(), e);
    		}
    		schemaManager = connection.getSchemaManager();
    		try {
				LOG.ok("Schema loaded, {0} schemas, {1} object classes, loader {2}",
						schemaManager.getLoader().getAllSchemas(),
						schemaManager.getObjectClassRegistry().size(),
						schemaManager.getLoader());
			} catch (Exception e) {
				throw new RuntimeException(e.getMessage(),e);
			}
    	}
    	return schemaManager;
    }
    
    private SchemaTranslator getSchemaTranslator() {
    	if (schemaTranslator == null) {
    		schemaTranslator = new SchemaTranslator(getSchemaManager(), configuration);
    	}
    	return schemaTranslator;
    }
    
    @Override
	public Schema schema() {
    	// always fetch fresh schema when this method is called
    	return getSchemaTranslator().translateSchema();
	}

	@Override
	public FilterTranslator<Filter> createFilterTranslator(ObjectClass objectClass, OperationOptions options) {
		// Just return dummy filter translator that does not translate anything. We need better control over the
		// filter translation than what the framework can provide.
		return new FilterTranslator<Filter>() {
			@Override
			public List<Filter> translate(Filter filter) {
				List<Filter> list = new ArrayList<Filter>(1);
				list.add(filter);
				return list;
			}
		};
	}

	@Override
	public void executeQuery(ObjectClass objectClass, Filter icfFilter, ResultsHandler handler, OperationOptions options) {
		SchemaTranslator shcemaTranslator = getSchemaTranslator();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = schemaTranslator.toLdapObjectClass(objectClass);
		
		if (icfFilter != null && (icfFilter instanceof EqualsFilter) && Name.NAME.equals(((EqualsFilter)icfFilter).getName())) {
			// Search by __NAME__, which means DN. This translated to a base search.
			String dn = SchemaUtil.getSingleStringNonBlankValue(((EqualsFilter)icfFilter).getAttribute());
			// We know that this can return at most one object. Therefore always use simple search.
			SearchStrategy searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			try {
				searchStrategy.search(dn, null, SearchScope.OBJECT, attributesToGet);
			} catch (LdapException e) {
				throw processLdapException("Error searching for "+dn, e);
			}
			
		} else {

			String baseDn = getBaseDn(options);
			LdapFilterTranslator filterTranslator = new LdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
			ScopedFilter scopedFilter = filterTranslator.translate(icfFilter, ldapObjectClass);
			ExprNode filterNode = scopedFilter.getFilter();
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			
			if (scopedFilter.getBaseDn() != null) {

				// The filter was limited by a ICF filter clause for __NAME__
				// so we look at exactly one object here
				SearchStrategy searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
				try {
					searchStrategy.search(scopedFilter.getBaseDn(), filterNode, SearchScope.OBJECT, attributesToGet);
				} catch (LdapException e) {
					throw processLdapException("Error searching for "+scopedFilter.getBaseDn(), e);
				}
			
			} else {

				// This is the real (usual) search
				SearchStrategy searchStrategy = chooseSearchStrategy(objectClass, ldapObjectClass, handler, options);
				SearchScope scope = getScope(options);
				try {
					searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
				} catch (LdapException e) {
					throw processLdapException("Error searching in "+baseDn, e);
				}
				
			}
		}
	}

	private String getBaseDn(OperationOptions options) {
		if (options != null && options.getContainer() != null) {
			QualifiedUid containerQUid = options.getContainer();
			// HACK WARNING: this is a hack to overcome bad framework design.
			// Even though this has to be Uid, we interpret it as a DN.
			// The framework uses UID to identify everything. This is naive.
			// Strictly following the framework contract would mean to always
			// do two LDAP searches instead of one in this case.
			// So we deviate from the contract here. It is naughty, but it
			// is efficient.
			return containerQUid.getUid().getUidValue();
		} else {
			return configuration.getBaseContext();
		}
	}

	private SearchScope getScope(OperationOptions options) {
		if (options == null || options.getScope() == null) {
			return SearchScope.SUBTREE;
		}
		String optScope = options.getScope();
		if (LdapConfiguration.SCOPE_SUB.equals(optScope)) {
			return SearchScope.SUBTREE;
		} else if (LdapConfiguration.SCOPE_ONE.equals(optScope)) {
			return SearchScope.ONELEVEL;
		} else if (LdapConfiguration.SCOPE_BASE.equals(optScope)) {
			return SearchScope.OBJECT;
		} else {
			throw new IllegalArgumentException("Unknown scope "+optScope);
		}
	}

	private String[] getAttributesToGet(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, OperationOptions options) {
		if (options == null || options.getAttributesToGet() == null) {
			String[] ldapAttrs = new String[2];
			ldapAttrs[0] = "*";
			ldapAttrs[1] = configuration.getUidAttribute();
			return ldapAttrs;
		}
		String[] icfAttrs = options.getAttributesToGet();
		String[] ldapAttrs = new String[icfAttrs.length + 1];
		int i = 0;
		for (String icfAttr: icfAttrs) {
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr);
			ldapAttrs[i] = ldapAttributeType.getName();
			i++;
		}
		ldapAttrs[i] = configuration.getUidAttribute();
		return ldapAttrs;
	}
	
	private SearchStrategy chooseSearchStrategy(ObjectClass objectClass, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			ResultsHandler handler, OperationOptions options) {
		String pagingStrategy = configuration.getPagingStrategy();
		if (pagingStrategy == null) {
			pagingStrategy = LdapConfiguration.PAGING_STRATEGY_AUTO;
		}
		
		if (options != null && options.getAllowPartialResults() != null && options.getAllowPartialResults() && 
        		options.getPagedResultsOffset() == null && options.getPagedResultsCookie() == null &&
        		options.getPageSize() == null) {
    		// Search that allow partial results, no need for paging. Regardless of the configured strategy.
        	return getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
    	}
		
		if (LdapConfiguration.PAGING_STRATEGY_NONE.equals(pagingStrategy)) {
        	// This may fail on a sizeLimit. But this is what has been configured so we are going to do it anyway.
        	LOG.ok("Selecting default search strategy because strategy setting is set to {0}", pagingStrategy);
        	return getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
        	
        } else if (LdapConfiguration.PAGING_STRATEGY_SPR.equals(pagingStrategy)) {
    		if (supportsControl(PagedResults.OID)) {
    			LOG.ok("Selecting SimplePaged search strategy because strategy setting is set to {0}", pagingStrategy);
    			return new SimplePagedResultsSearchStrategy(connection, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
    		} else {
    			throw new ConfigurationException("Configured paging strategy "+pagingStrategy+", but the server does not support PagedResultsControl.");
    		}
    		
        } else if (LdapConfiguration.PAGING_STRATEGY_VLV.equals(pagingStrategy)) {
    		if (supportsControl(VirtualListViewRequest.OID)) {
    			LOG.ok("Selecting VLV search strategy because strategy setting is set to {0}", pagingStrategy);
    			return new VlvSearchStrategy(connection, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
    		} else {
    			throw new ConfigurationException("Configured paging strategy "+pagingStrategy+", but the server does not support VLV.");
    		}
    		
        } else if (LdapConfiguration.PAGING_STRATEGY_AUTO.equals(pagingStrategy)) {
        	if (options.getPagedResultsOffset() != null && options.getPagedResultsOffset() > 1) {
        		// VLV is the only practical option here
        		if (supportsControl(VirtualListViewRequest.OID)) {
        			LOG.ok("Selecting VLV search strategy because strategy setting is set to {0} and the request specifies an offset", pagingStrategy);
        			return new VlvSearchStrategy(connection, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
        		} else {
        			throw new UnsupportedOperationException("Requested search from offset ("+options.getPagedResultsOffset()+"), but the server does not support VLV. Unable to execute the search.");
        		}
        	} else {
        		if (supportsControl(PagedResults.OID)) {
        			// SPR is usually a better choice if no offset is specified. Less overhead on the server.
        			LOG.ok("Selecting SimplePaged search strategy because strategy setting is set to {0} and the request does not specify an offset", pagingStrategy);
        			return new SimplePagedResultsSearchStrategy(connection, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
        		} else if (supportsControl(VirtualListViewRequest.OID)) {
        			return new VlvSearchStrategy(connection, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
        		} else {
        			throw new UnsupportedOperationException("Requested paged search, but the server does not support VLV or PagedResultsControl. Unable to execute the search.");
        		}
        	}
        }
        
		return getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
	}
	
	private boolean supportsControl(String oid) {
		try {
			return connection.getSupportedControls().contains(oid);
		} catch (LdapException e) {
			throw new ConnectorIOException("Cannot fetch list of supported controls: "+e.getMessage(), e);
		}
	}

	private SearchStrategy getDefaultSearchStrategy(ObjectClass objectClass, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		return new DefaultSearchStrategy(connection, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
	}

	@Override
	public Uid create(ObjectClass icfObjectClass, Set<Attribute> createAttributes, OperationOptions options) {
		
		String dn = null;
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(Name.NAME)) {
				dn = SchemaUtil.getSingleStringNonBlankValue(icfAttr);
			}
		}
		if (dn == null) {
			throw new InvalidAttributeValueException("Missing NAME attribute");
		}
		
		SchemaTranslator shcemaTranslator = getSchemaTranslator();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = shcemaTranslator.toLdapObjectClass(icfObjectClass);
		Entry entry;
		try {
			entry = new DefaultEntry(getSchemaManager(), dn);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Wrong DN '"+dn+"': "+e.getMessage(), e);
		}
		entry.put("objectClass", ldapObjectClass.getName());
		
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(Name.NAME)) {
				continue;
			}
			AttributeType ldapAttrType = shcemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr.getName());
			List<Value<Object>> ldapValues = shcemaTranslator.toLdapValues(ldapAttrType, icfAttr.getValue());
			try {
				entry.put(ldapAttrType, ldapValues.toArray(new Value[ldapValues.size()]));
			} catch (LdapException e) {
				throw new InvalidAttributeValueException("Wrong value for LDAP attribute "+ldapAttrType.getName()+": "+e.getMessage(), e);
			}
		}
		
		try {
			connection.add(entry);
		} catch (LdapException e) {
			throw processLdapException("Error adding LDAP entry "+dn, e);
		}
		
		Uid uid = null;
		String uidAttributeName = configuration.getUidAttribute();
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(uidAttributeName)) {
				uid = new Uid(SchemaUtil.getSingleStringNonBlankValue(icfAttr));
			}
		}
		if (uid != null) {
			return uid;
		}
		
		// read the entry back and return UID
		try {
			EntryCursor cursor = connection.search(dn, LdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT, uidAttributeName);
			if (cursor.next()) {
				Entry entryRead = cursor.get();
				org.apache.directory.api.ldap.model.entry.Attribute uidLdapAttribute = entryRead.get(uidAttributeName);
				if (uidLdapAttribute == null) {
					throw new InvalidAttributeValueException("No value for UID attribute "+uidAttributeName+" in object "+dn);
				}
				if (uidLdapAttribute.size() == 0) {
					throw new InvalidAttributeValueException("No value for UID attribute "+uidAttributeName+" in object "+dn);
				} else if (uidLdapAttribute.size() > 1) {
					throw new InvalidAttributeValueException("More than one value ("+uidLdapAttribute.size()+") for UID attribute "+uidAttributeName+" in object "+dn);
				}
				Value<?> uidLdapAttributeValue = uidLdapAttribute.get();
				uid = new Uid(uidLdapAttributeValue.getString());
			} else {
				// Something wrong happened, the entry was not created.
				throw new UnknownUidException("Entry with dn "+dn+" was not found (right after it was created)");
			}
		} catch (LdapException e) {
			throw processLdapException("Error reading LDAP entry "+dn, e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error reading LDAP entry "+dn+": "+e.getMessage(), e);
		}
		
		return uid;
	}

	@Override
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes,
			OperationOptions options) {
    	
		for (Attribute icfAttr: replaceAttributes) {
			if (icfAttr.is(Name.NAME)) {
				// This is rename. Which means change of DN. This is a special operation
				String oldDn = resolveDn(objectClass, uid, options);
				String newDn = SchemaUtil.getSingleStringNonBlankValue(icfAttr);
				if (oldDn.equals(newDn)) {
					// nothing to rename, just ignore
				} else {
					try {
						LOG.ok("MoveAndRename REQ {0} -> {1}", oldDn, newDn);
						connection.moveAndRename(oldDn, newDn);
						LOG.ok("MoveAndRename RES OK {0} -> {1}", oldDn, newDn);
					} catch (LdapException e) {
						LOG.error("MoveAndRename ERROR {0} -> {1}: {2}", oldDn, newDn, e.getMessage(), e);
						throw processLdapException("Rename/move of LDAP entry from "+oldDn+" to "+newDn+" failed", e);
					}
				}
			}
		}
    	
    	ldapUpdate(objectClass, uid, replaceAttributes, options, ModificationOperation.REPLACE_ATTRIBUTE);
    	
    	return uid;
	}
    
    @Override
	public Uid addAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> valuesToAdd,
			OperationOptions options) {
		
		for (Attribute icfAttr: valuesToAdd) {
			if (icfAttr.is(Name.NAME)) {
				throw new InvalidAttributeValueException("Cannot add value of attribute "+Name.NAME);
			}
		}
		
		ldapUpdate(objectClass, uid, valuesToAdd, options, ModificationOperation.ADD_ATTRIBUTE);
		
		return uid;
	}

	@Override
	public Uid removeAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> valuesToRemove,
			OperationOptions options) {
		
		for (Attribute icfAttr: valuesToRemove) {
			if (icfAttr.is(Name.NAME)) {
				throw new InvalidAttributeValueException("Cannot remove value of attribute "+Name.NAME);
			}
		}

    	ldapUpdate(objectClass, uid, valuesToRemove, options, ModificationOperation.REMOVE_ATTRIBUTE);
    	
    	return uid;
	}
	
	private Uid ldapUpdate(ObjectClass objectClass, Uid uid, Set<Attribute> values,
			OperationOptions options, ModificationOperation modOp) {
		
		String dn = resolveDn(objectClass, uid, options);
		
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = schemaTranslator.toLdapObjectClass(objectClass);
		
		List<Modification> modifications = new ArrayList<Modification>(values.size());
		for (Attribute icfAttr: values) {
			if (icfAttr.is(Name.NAME)) {
				continue;
			}
			AttributeType attributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr.getName());
			if (attributeType == null && !ArrayUtils.contains(configuration.getOperationalAttributes(), icfAttr.getName())) {
				throw new InvalidAttributeValueException("Unknown attribute "+icfAttr.getName()+" in object class "+objectClass);
			}
			List<Value<Object>> ldapValues = schemaTranslator.toLdapValues(attributeType, icfAttr.getValue());
			try {
				modifications.add(new DefaultModification(modOp, attributeType, ldapValues.toArray(new Value[ldapValues.size()])));
			} catch (LdapInvalidAttributeValueException e) {
				throw new InvalidAttributeValueException("Invalid modification value for LDAP attribute "+attributeType.getName()+": "+e.getMessage(), e);
			}
		}
		
		if (modifications.isEmpty()) {
			LOG.ok("Skipping modify({0}) operation as there are no modifications to execute", modOp);
			return uid;
		}
		
		try {
			if (LOG.isOk()) {
				LOG.ok("Modify REQ {0}: {1}", dn, dumpModifications(modifications));
			}
			connection.modify(dn, modifications.toArray(new Modification[modifications.size()]));
			if (LOG.isOk()) {
				LOG.ok("Modify RES {0}: {1}", dn, dumpModifications(modifications));
			}
		} catch (LdapException e) {
			LOG.error("Modify ERROR {0}: {1}: {2}", dn, dumpModifications(modifications), e.getMessage(), e);
			throw processLdapException("Error modifying entry "+dn, e);
		}
		
		return uid;
	}

	private String dumpModifications(List<Modification> modifications) {
		if (modifications == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder("[");
		for (Modification mod: modifications) {
			sb.append(mod);
			sb.append(",");
		}
		sb.append("]");
		return sb.toString();
	}

	@Override
	public void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler,
			OperationOptions options) {
		SyncStrategy strategy = chooseSyncStrategy(objectClass);
		strategy.sync(objectClass, token, handler, options);
	}
	
	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		SyncStrategy strategy = chooseSyncStrategy(objectClass);
		return strategy.getLatestSyncToken(objectClass);
	}
	
	private SyncStrategy chooseSyncStrategy(ObjectClass objectClass) {
		// TODO 
		return new SunChangelogSyncStrategy(configuration, connection);
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		
		String dn = resolveDn(objectClass, uid, options);
		
		try {
			connection.delete(dn);
		} catch (LdapException e) {
			throw processLdapException("Failed to delete entry with DN "+dn+" (UID="+uid+")", e);
		}
	}
	
	private String resolveDn(ObjectClass objectClass, Uid uid, OperationOptions options) {
		String dn;
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME.equals(uidAttributeName)) {
			dn = uid.getUidValue();
		} else {
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = schemaTranslator.toLdapObjectClass(objectClass);
			String baseDn = getBaseDn(options);
			SearchScope scope = getScope(options);
			AttributeType ldapAttributeType;
			try {
				String attributeOid = schemaManager.getAttributeTypeRegistry().getOidByName(uidAttributeName);
				ldapAttributeType = schemaManager.getAttributeTypeRegistry().lookup(attributeOid);
			} catch (LdapException e1) {
				throw new InvalidAttributeValueException("Cannot find schema for UID attribute "+uidAttributeName);
			}
			Value<Object> ldapValue = schemaTranslator.toLdapValue(ldapAttributeType, uid.getUidValue());
			ExprNode filterNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
			try {
				EntryCursor cursor = connection.search(baseDn, filterNode.toString(), scope, uidAttributeName);
				if (cursor.next()) {
					Entry entry = cursor.get();
					dn = entry.getDn().toString();
				} else {
					// Something wrong happened, the entry was not created.
					throw new UnknownUidException("Entry for UID "+uid+" was not found (therefore it cannot be deleted)");
				}
			} catch (LdapException e) {
				throw processLdapException("Error reading LDAP entry for UID "+uid, e);
			} catch (CursorException e) {
				throw new ConnectorIOException("Error reading LDAP entry for UID "+uid+": "+e.getMessage(), e);
			}
		}
		
		return dn;
	}
 
	@Override
	public void checkAlive() {
		if (!connection.isConnected()) {
			throw new ConnectorException("Connection check failed");
		}
	}

	@Override
    public void dispose() {
        configuration = null;
        if (connection != null) {
        	try {
				connection.close();
			} catch (IOException e) {
				throw new ConnectorIOException(e.getMessage(), e);
			}
            connection = null;
        }
    }

	private void connect() {
    	final LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
    	connectionConfig.setLdapHost(configuration.getHost());
    	connectionConfig.setLdapPort(configuration.getPort());
    	
    	LOG.ok("Creating connection object");
		connection = new LdapNetworkConnection(connectionConfig);
		try {
			LOG.info("Connecting to {0}:{1} as {2}", configuration.getHost(), configuration.getPort(), configuration.getBindDn());
			boolean connected = connection.connect();
			LOG.ok("Connected ({0})", connected);
			if (!connected) {
				throw new ConnectorIOException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			throw processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
		}

		bind();
    }
	
	private void bind() {
		final BindRequest bindRequest = new BindRequestImpl();
		String bindDn = configuration.getBindDn();
		try {
			bindRequest.setDn(new Dn(bindDn));
		} catch (LdapInvalidDnException e) {
			throw new ConfigurationException("bindDn is not in DN format: "+e.getMessage(), e);
		}
		
		GuardedString bindPassword = configuration.getBindPassword();
    	if (bindPassword != null) {
    		// I hate this GuardedString!
    		bindPassword.access(new GuardedStringAccessor() {
				@Override
				public void access(char[] chars) {
					bindRequest.setCredentials(new String(chars));
				}
			});
    	}
		
    	BindResponse bindResponse;
		try {
			bindResponse = connection.bind(bindRequest);
		} catch (LdapException e) {
			throw processLdapException("Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn, e);
		}
		LOG.info("Bound to {0}", bindDn);
	}
    
	private Entry getRootDse() throws LdapException {
		LOG.ok("Fetching root DSE");
		return connection.getRootDse();
	}
	
    private RuntimeException processLdapException(String message, LdapException ldapException) {
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

}
