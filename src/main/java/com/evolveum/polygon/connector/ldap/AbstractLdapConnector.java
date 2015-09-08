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
import java.util.Collection;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.codec.api.BinaryAttributeDetector;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
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
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.ldap.client.api.DefaultSchemaLoader;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.PredefinedAttributes;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.ContainsAllValuesFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.common.objects.filter.OrFilter;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.schema.GuardedStringValue;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.ScopedFilter;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SimplePagedResultsSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.VlvSearchStrategy;
import com.evolveum.polygon.connector.ldap.sync.ModifyTimestampSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.SunChangelogSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.SyncStrategy;

public abstract class AbstractLdapConnector<C extends AbstractLdapConfiguration> implements PoolableConnector, TestOp, SchemaOp, SearchOp<Filter>, CreateOp, DeleteOp, 
		UpdateAttributeValuesOp, SyncOp {

    private static final Log LOG = Log.getLog(AbstractLdapConnector.class);
    
    private C configuration;
    private LdapNetworkConnection connection;
    private SchemaManager schemaManager = null;
    private SchemaTranslator<C> schemaTranslator = null;
    private ConnectorBinaryAttributeDetector<C> binaryAttributeDetector = new ConnectorBinaryAttributeDetector<C>();
    private SyncStrategy syncStrategy = null;

    @Override
    public C getConfiguration() {
        return configuration;
    }

    protected LdapNetworkConnection getConnection() {
		return connection;
	}

	@Override
    public void init(Configuration configuration) {
        this.configuration = (C)configuration;
        LOG.info("Connector init");
        this.configuration.recompute();
        connect();
    }
    
    @Override
	public void test() {
    	if (connection != null && connection.isConnected()) {
        	try {
        		LOG.ok("Closing connection ... to reopen it again");
				connection.close();
			} catch (IOException e) {
				throw new ConnectorIOException(e.getMessage(), e);
			}
            connection = null;
            schemaManager = null;
            schemaTranslator = null;
        }
    	connect();
    	checkAlive();
    	try {
			bind();
			Entry rootDse = getRootDse();
			LOG.ok("Root DSE: {0}", rootDse);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException(null, e);
		}
	}
    
    protected SchemaManager getSchemaManager() {
    	if (schemaManager == null) {
    		try {
    			boolean schemaQuirksMode = configuration.isSchemaQuirksMode();
    			LOG.ok("Loading schema (quirksMode={0})", schemaQuirksMode);
    			DefaultSchemaLoader schemaLoader = new DefaultSchemaLoader(connection, schemaQuirksMode);
    			DefaultSchemaManager defSchemaManager = new DefaultSchemaManager(schemaLoader);
    			try {
    				if (schemaQuirksMode) {
        				defSchemaManager.setRelaxed();
        				defSchemaManager.loadAllEnabledRelaxed();
    				} else {
    					defSchemaManager.loadAllEnabled();
    				}
				} catch (Exception e) {
					throw new ConnectorIOException(e.getMessage(), e);
				}
    			if ( !defSchemaManager.getErrors().isEmpty() ) {
    				if (schemaQuirksMode) {
    					LOG.ok("There are {0} schema errors, but we are in quirks mode so we are ignoring them", defSchemaManager.getErrors().size());
    					for (Throwable error: defSchemaManager.getErrors()) {
    						LOG.ok("Schema error (ignored): {0}: {1}", error.getClass().getName(), error.getMessage());
    					}
    				} else {
    					throw new ConnectorIOException("Errors loading schema "+defSchemaManager.getErrors());
    				}
    			}
    			schemaManager = defSchemaManager;
//    			connection.setSchemaManager(defSchemaManager);
//    			connection.loadSchema(defSchemaManager);
    		} catch (LdapException e) {
    			throw new ConnectorIOException(e.getMessage(), e);
    		}
    		
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
    
    protected SchemaTranslator<C> getSchemaTranslator() {
    	if (schemaTranslator == null) {
    		schemaTranslator = createSchemaTranslator();
    		binaryAttributeDetector.setSchemaTranslator(schemaTranslator);
    	}
    	return schemaTranslator;
    }
    
    protected SchemaTranslator<C> createSchemaTranslator() {
    	return new SchemaTranslator<>(getSchemaManager(), configuration);
    }
    
    @Override
	public Schema schema() {
    	if (!connection.isConnected()) {
    		return null;
    	}
    	// always fetch fresh schema when this method is called
    	schemaManager = null;
    	schemaTranslator = null;
    	try {
    		return getSchemaTranslator().translateSchema(connection);
    	} catch (InvalidConnectionException e) {
    		// The connection might have been disconnected. Try to reconnect.
			connect();
			try {
				return getSchemaTranslator().translateSchema(connection);
			} catch (InvalidConnectionException e1) {
				throw new ConnectorException("Reconnect error: "+e.getMessage(), e);
			}
    	}
	}
    
    private void prepareIcfSchema() {
    	try {
    		getSchemaTranslator().prepareIcfSchema(connection);
    	} catch (InvalidConnectionException e) {
    		// The connection might have been disconnected. Try to reconnect.
			connect();
			try {
				getSchemaTranslator().prepareIcfSchema(connection);
			} catch (InvalidConnectionException e1) {
				throw new ConnectorException("Reconnect error: "+e.getMessage(), e);
			}
    	}
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
		prepareIcfSchema();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = getSchemaTranslator().toLdapObjectClass(objectClass);
		
		SearchStrategy searchStrategy;
		if (isEqualsFilter(icfFilter, Name.NAME)) {
			// Search by __NAME__, which means DN. This translated to a base search.
			searchStrategy = searchByDn(SchemaUtil.getSingleStringNonBlankValue(((EqualsFilter)icfFilter).getAttribute()),
					objectClass, ldapObjectClass, handler, options);
			
		} else if (isEqualsFilter(icfFilter, Uid.NAME)) {
			// Search by __UID__. Special case for performance.
			searchStrategy = searchByUid(SchemaUtil.getSingleStringNonBlankValue(((EqualsFilter)icfFilter).getAttribute()),
					objectClass, ldapObjectClass, handler, options);
				
		} else if (isSecondaryIdentifierOrFilter(icfFilter)) {
			// Very special case. Search by DN or other secondary identifier value. It is used by IDMs to get object by 
			// This is not supported by LDAP. But it can be quite common. Therefore we want to support it as a special
			// case by executing two searches.
			
			searchStrategy = searchBySecondaryIdenfiers(icfFilter, objectClass, ldapObjectClass, handler, options);
			
		} else {

			searchStrategy = searchUsual(icfFilter, objectClass, ldapObjectClass, handler, options);
			
		}
		
		if (handler instanceof SearchResultsHandler) {
			String cookie = searchStrategy.getPagedResultsCookie();
			int remainingResults = searchStrategy.getRemainingPagedResults();
			boolean completeResultSet = searchStrategy.isCompleteResultSet();
			SearchResult searchResult = new SearchResult(cookie, remainingResults, completeResultSet);
			((SearchResultsHandler)handler).handleResult(searchResult);
		} else {
			LOG.warn("Result handler is NOT SearchResultsHandler, it is {0}", handler.getClass());
		}
		
	}

	private boolean isEqualsFilter(Filter icfFilter, String icfAttrname) {
		return icfFilter != null && (icfFilter instanceof EqualsFilter) && icfAttrname.equals(((EqualsFilter)icfFilter).getName());
	}

	private boolean isSecondaryIdentifierOrFilter(Filter icfFilter) {
		if (icfFilter == null) {
			return false;
		}
		if (!(icfFilter instanceof OrFilter)) {
			return false;
		}
		Filter leftSubfilter = ((OrFilter)icfFilter).getLeft();
		Filter rightSubfilter = ((OrFilter)icfFilter).getRight();
		if (isEqualsFilter(leftSubfilter,  Name.NAME) && ((rightSubfilter instanceof EqualsFilter) || (rightSubfilter instanceof ContainsAllValuesFilter))) {
			return true;
		}
		if (isEqualsFilter(rightSubfilter,  Name.NAME) && ((leftSubfilter instanceof EqualsFilter) || (leftSubfilter instanceof ContainsAllValuesFilter))) {
			return true;
		}
		return false;
	}

	private SearchStrategy searchByDn(String dn, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		// This translated to a base search.
		// We know that this can return at most one object. Therefore always use simple search.
		SearchStrategy searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		try {
			searchStrategy.search(dn, null, SearchScope.OBJECT, attributesToGet);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error searching for DN '"+dn+"'", e);
		}
		return searchStrategy;
	}
	
	private SearchStrategy searchByUid(String uidValue, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		// We know that this can return at most one object. Therefore always use simple search.
		SearchStrategy searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		SearchScope scope = getScope(options);
		AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, Uid.NAME);
		Value<Object> ldapValue = schemaTranslator.toLdapIdentifierValue(ldapAttributeType, uidValue);
		LOG.ok("UID '{0}' -> {1} ({2})", uidValue, LdapUtil.binaryToHex(ldapValue.getBytes()), Base64.encode(ldapValue.getBytes()));
		ExprNode filterNode = new EqualityNode<>(ldapAttributeType, ldapValue);
		String baseDn = getBaseDn(options);
		try {
			searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error searching for "+ldapAttributeType.getName()+" '"+uidValue+"'", e);
		}
		
		return searchStrategy;
	}
	
	private SearchStrategy searchBySecondaryIdenfiers(Filter icfFilter, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			final ResultsHandler handler, OperationOptions options) {
		// This translated to a base search.
		// We know that this can return at most one object. Therefore always use simple search.
		
		Filter leftSubfilter = ((OrFilter)icfFilter).getLeft();
		Filter rightSubfilter = ((OrFilter)icfFilter).getRight();
		EqualsFilter dnSubfilter;
		Filter otherSubfilter;
		if ((leftSubfilter instanceof EqualsFilter) && Uid.NAME.equals(((EqualsFilter)leftSubfilter).getName())) {
			dnSubfilter = (EqualsFilter) leftSubfilter;
			otherSubfilter = rightSubfilter;
		} else {
			dnSubfilter = (EqualsFilter) rightSubfilter;
			otherSubfilter = leftSubfilter;
		}
		
		final String[] mutableFirstUid = new String[1];
		ResultsHandler innerHandler = new ResultsHandler() {
			@Override
			public boolean handle(ConnectorObject connectorObject) {
				if (mutableFirstUid[0] == null) {
					mutableFirstUid[0] = connectorObject.getUid().getUidValue();
				} else {
					if (connectorObject.getUid().getUidValue().equals(mutableFirstUid[0])) {
						// We have already returned this object, skip it.
						return true;
					}
				}
				return handler.handle(connectorObject);
			}
		};
		
		// Search by DN first. This is supposed to be more efficient.

		String dn = SchemaUtil.getSingleStringNonBlankValue(dnSubfilter.getAttribute());
		try {
			searchByDn(dn, objectClass, ldapObjectClass, innerHandler, options);
		} catch (UnknownUidException e) {
			// No problem. The Dn is not here. Just no on.
			LOG.ok("The DN \"{0}\" not found: {1} (this is OK)", dn, e.getMessage());
		}
		
		// Search by the other attribute now
		
		// We know that this can return at most one object. Therefore always use simple search.
		SearchStrategy searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, innerHandler, options);
		LdapFilterTranslator filterTranslator = new LdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
		ScopedFilter scopedFilter = filterTranslator.translate(otherSubfilter, ldapObjectClass);
		ExprNode filterNode = scopedFilter.getFilter();
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		SearchScope scope = getScope(options);
		String baseDn = getBaseDn(options);
		try {
			searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error searching in "+baseDn, e);
		}
		
		return searchStrategy;
				
	}
	
	private SearchStrategy searchUsual(Filter icfFilter, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		String baseDn = getBaseDn(options);
		LdapFilterTranslator filterTranslator = createLdapFilterTranslator(ldapObjectClass);
		ScopedFilter scopedFilter = filterTranslator.translate(icfFilter, ldapObjectClass);
		ExprNode filterNode = scopedFilter.getFilter();
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		
		SearchStrategy searchStrategy;
		if (scopedFilter.getBaseDn() != null) {

			// The filter was limited by a ICF filter clause for __NAME__
			// so we look at exactly one object here
			searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
			try {
				searchStrategy.search(scopedFilter.getBaseDn(), filterNode, SearchScope.OBJECT, attributesToGet);
			} catch (LdapException e) {
				throw LdapUtil.processLdapException("Error searching for "+scopedFilter.getBaseDn(), e);
			}
		
		} else {

			// This is the real (usual) search
			searchStrategy = chooseSearchStrategy(objectClass, ldapObjectClass, handler, options);
			SearchScope scope = getScope(options);
			try {
				searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
			} catch (LdapException e) {
				throw LdapUtil.processLdapException("Error searching in "+baseDn, e);
			}
			
		}
		
		return searchStrategy;
	}
	
	protected LdapFilterTranslator createLdapFilterTranslator(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		return new LdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
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
		return LdapUtil.getAttributesToGet(ldapObjectClass, options, configuration, getSchemaTranslator());
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
		
		SchemaTranslator<C> shcemaTranslator = getSchemaTranslator();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass = shcemaTranslator.toLdapObjectClass(icfObjectClass);
		
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> ldapAuxiliaryObjectClasses = new ArrayList<>();
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME)) {
				for (Object val: icfAttr.getValue()) {
					ldapAuxiliaryObjectClasses.add(schemaTranslator.toLdapObjectClass(new ObjectClass((String)val)));
				}
			}
		}
		
		String[] ldapObjectClassNames = new String[ldapAuxiliaryObjectClasses.size() + 1];
		ldapObjectClassNames[0] = ldapStructuralObjectClass.getName();
		for (int i = 0; i < ldapAuxiliaryObjectClasses.size(); i++) {
			ldapObjectClassNames[i+1] = ldapAuxiliaryObjectClasses.get(i).getName();
		}
		Entry entry;
		try {
			entry = new DefaultEntry(dn);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Wrong DN '"+dn+"': "+e.getMessage(), e);
		}
		entry.put("objectClass", ldapObjectClassNames);
		
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(Name.NAME)) {
				continue;
			}
			if (icfAttr.is(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME)) {
				continue;
			}
			AttributeType ldapAttrType = shcemaTranslator.toLdapAttribute(ldapStructuralObjectClass, icfAttr.getName());
			List<Value<Object>> ldapValues = shcemaTranslator.toLdapValues(ldapAttrType, icfAttr.getValue());
			// Do NOT set attributeType here. The attributeType may not match the type of the value.
			entry.put(ldapAttrType.getName(), ldapValues.toArray(new Value[ldapValues.size()]));
			// no simple way how to check if he attribute was added. It may end up with ERR_04451. So let's just
			// hope that it worked well. It should - unless there is a connector bug.
		}
		
		if (LOG.isOk()) {
			LOG.ok("Adding entry: {0}", entry);
		}
		
		processEntryBeforeCreate(entry);
		
		AddRequest addRequest = new AddRequestImpl();
		addRequest.setEntry(entry);
		
		AddResponse addResponse;
		try {
			addResponse = connection.add(addRequest);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error adding LDAP entry "+dn, e);
		}
		if (addResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS) {
			throw LdapUtil.processLdapResult("Error adding LDAP entry "+dn, addResponse.getLdapResult());
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
				AttributeType uidLdapAttributeType = getSchemaManager().getAttributeType(uidAttributeName);
				uid = new Uid(getSchemaTranslator().toIcfIdentifierValue(uidLdapAttributeValue, uidLdapAttributeType));
			} else {
				// Something wrong happened, the entry was not created.
				throw new UnknownUidException("Entry with dn "+dn+" was not found (right after it was created)");
			}
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Error reading LDAP entry "+dn, e);
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
						throw LdapUtil.processLdapException("Rename/move of LDAP entry from "+oldDn+" to "+newDn+" failed", e);
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
	
	private Uid ldapUpdate(ObjectClass icfObjectClass, Uid uid, Set<Attribute> values,
			OperationOptions options, ModificationOperation modOp) {
		
		String dn = resolveDn(icfObjectClass, uid, options);
		
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass = schemaTranslator.toLdapObjectClass(icfObjectClass);
		
		List<Modification> modifications = new ArrayList<Modification>(values.size());
		for (Attribute icfAttr: values) {
			if (icfAttr.is(Name.NAME)) {
				continue;
			}
			if (icfAttr.is(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME)) {
				if (modOp == ModificationOperation.REPLACE_ATTRIBUTE) {
					// We need to keep structural object class
					String[] stringValues = new String[icfAttr.getValue().size() + 1];
					stringValues[0] = ldapStructuralObjectClass.getName();
					int i = 1;
					for(Object val: icfAttr.getValue()) {
						stringValues[i] = (String)val;
						i++;
					}
					modifications.add(new DefaultModification(modOp, LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME, stringValues));
				} else {
					String[] stringValues = new String[icfAttr.getValue().size()];
					int i = 0;
					for(Object val: icfAttr.getValue()) {
						stringValues[i] = (String)val;
						i++;
					}
					modifications.add(new DefaultModification(modOp, LdapConfiguration.ATTRIBUTE_OBJECTCLASS_NAME, stringValues));
				}
			} else {
				addAttributeModification(modifications, ldapStructuralObjectClass, icfObjectClass, icfAttr, modOp);
			}
		}
		
		if (modifications.isEmpty()) {
			LOG.ok("Skipping modify({0}) operation as there are no modifications to execute", modOp);
			return uid;
		}
		
		modify(dn, modifications);
		
		postUpdate(icfObjectClass, uid, values, options, modOp, dn, ldapStructuralObjectClass, modifications);
		
		return uid;
	}
	
	protected void modify(String dn, List<Modification> modifications) {
		try {
			if (LOG.isOk()) {
				LOG.ok("Modify REQ {0}: {1}", dn, dumpModifications(modifications));
			}
			// processModificationsBeforeUpdate must happen after logging. Otherwise passwords might be logged.
			connection.modify(dn, processModificationsBeforeUpdate(modifications));
			if (LOG.isOk()) {
				LOG.ok("Modify RES {0}: {1}", dn, dumpModifications(modifications));
			}
		} catch (LdapException e) {
			LOG.error("Modify ERROR {0}: {1}: {2}", dn, dumpModifications(modifications), e.getMessage(), e);
			throw LdapUtil.processLdapException("Error modifying entry "+dn, e);
		}
	}

	protected void addAttributeModification(List<Modification> modifications,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			ObjectClass icfObjectClass, Attribute icfAttr, ModificationOperation modOp) {
		AttributeType attributeType = schemaTranslator.toLdapAttribute(ldapStructuralObjectClass, icfAttr.getName());
		if (attributeType == null && !ArrayUtils.contains(configuration.getOperationalAttributes(), icfAttr.getName())) {
			throw new InvalidAttributeValueException("Unknown attribute "+icfAttr.getName()+" in object class "+icfObjectClass);
		}
		List<Value<Object>> ldapValues = schemaTranslator.toLdapValues(attributeType, icfAttr.getValue());
		if (ldapValues == null || ldapValues.isEmpty()) {
			// Do NOT set AttributeType here
			modifications.add(new DefaultModification(modOp, attributeType.getName()));					
		} else {
			// Do NOT set AttributeType here
			modifications.add(new DefaultModification(modOp, attributeType.getName(), ldapValues.toArray(new Value[ldapValues.size()])));
		}
	}
	
	protected void postUpdate(ObjectClass icfObjectClass, Uid uid, Set<Attribute> values,
			OperationOptions options, ModificationOperation modOp, 
			String dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, List<Modification> modifications) {
		// Nothing to do here. Just for override in subclasses.
	}

	// We want to decrypt GuardedString at the very last moment
	private Modification[] processModificationsBeforeUpdate(List<Modification> modifications) {
		Modification[] out = new Modification[modifications.size()];
		int i = 0;
		for (final Modification modification: modifications) {
			if (modification.getAttribute() != null && modification.getAttribute().get() != null) {
				Value<?> val = modification.getAttribute().get();
				if (val instanceof GuardedStringValue) {
					((GuardedStringValue)val).getGuardedStringValue().access(new GuardedString.Accessor() {
						@Override
						public void access(char[] clearChars) {
							DefaultAttribute attr = new DefaultAttribute( modification.getAttribute().getId(), new String(clearChars));
							modification.setAttribute(attr);
						}
					});
				}
			}
			out[i] = modification;
			i++;
		}
		return out;
	}
	
	// We want to decrypt GuardedString at the very last moment
	private void processEntryBeforeCreate(Entry entry) {
		for(final org.apache.directory.api.ldap.model.entry.Attribute attribute: entry.getAttributes()) {
			Value<?> val = attribute.get();
			if (val instanceof GuardedStringValue) {
				attribute.remove(val);
				((GuardedStringValue)val).getGuardedStringValue().access(new GuardedString.Accessor() {
					@Override
					public void access(char[] clearChars) {
						try {
							attribute.add(new String(clearChars));
						} catch (LdapInvalidAttributeValueException e) {
							throw new InvalidAttributeValueException(e.getMessage(), e);
						}
					}
				});
			}
		}
		
	}

	private String dumpModifications(List<Modification> modifications) {
		if (modifications == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder("[");
		for (Modification mod: modifications) {
			sb.append(mod.getOperation()).append(":").append(mod.getAttribute());
			sb.append(",");
		}
		sb.append("]");
		return sb.toString();
	}

	@Override
	public void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler,
			OperationOptions options) {
		prepareIcfSchema();
		SyncStrategy strategy = chooseSyncStrategy(objectClass);
		strategy.sync(objectClass, token, handler, options);
	}
	
	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		SyncStrategy strategy = chooseSyncStrategy(objectClass);
		return strategy.getLatestSyncToken(objectClass);
	}
	
	private SyncStrategy chooseSyncStrategy(ObjectClass objectClass) {
		if (syncStrategy == null) {
			switch (configuration.getSynchronizationStrategy()) {
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_NONE:
					throw new UnsupportedOperationException("Synchronization disabled (synchronizationStrategy=none)");
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG:
					syncStrategy = new SunChangelogSyncStrategy(configuration, connection, getSchemaManager(), getSchemaTranslator());
					break;
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP:
					syncStrategy = new ModifyTimestampSyncStrategy(configuration, connection, getSchemaManager(), getSchemaTranslator());
					break;
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_AUTO:
					syncStrategy = chooseSyncStrategyAuto(objectClass);
					break;
				default:
					throw new IllegalArgumentException("Unknown synchronization strategy '"+configuration.getSynchronizationStrategy()+"'");
			}
		}
		return syncStrategy;
	}

	private SyncStrategy chooseSyncStrategyAuto(ObjectClass objectClass) {
		Entry rootDse = LdapUtil.getRootDse(connection, SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
		org.apache.directory.api.ldap.model.entry.Attribute changelogAttribute = rootDse.get(SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
		if (changelogAttribute != null) {
			LOG.ok("Choosing Sun ChangeLog sync stategy (found {0} attribute in root DSE)", SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
			return new SunChangelogSyncStrategy(configuration, connection, getSchemaManager(), getSchemaTranslator());
		}
		LOG.ok("Choosing modifyTimestamp sync stategy (fallback)");
		return new ModifyTimestampSyncStrategy(configuration, connection, getSchemaManager(), getSchemaTranslator());
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		
		String dn = resolveDn(objectClass, uid, options);
		
		try {
			LOG.ok("Delete REQ {0}", dn);
			
			connection.delete(dn);
			
			LOG.ok("Delete RES {0}", dn);
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Failed to delete entry with DN "+dn+" (UID="+uid+")", e);
		}
	}
	
	private String resolveDn(ObjectClass objectClass, Uid uid, OperationOptions options) {
		String dn;
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
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
			Value<Object> ldapValue = schemaTranslator.toLdapIdentifierValue(ldapAttributeType, uid.getUidValue());
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
				throw LdapUtil.processLdapException("Error reading LDAP entry for UID "+uid, e);
			} catch (CursorException e) {
				throw new ConnectorIOException("Error reading LDAP entry for UID "+uid+": "+e.getMessage(), e);
			}
		}
		
		return dn;
	}
 
	@Override
	public void checkAlive() {
		if (!connection.isConnected()) {
			LOG.ok("check alive: FAILED");
			throw new ConnectorException("Connection check failed");
		}
		LOG.ok("check alive: OK");
	}

	@Override
    public void dispose() {
        configuration = null;
        if (connection != null) {
        	try {
        		LOG.ok("Closing connection");
				connection.close();
			} catch (IOException e) {
				throw new ConnectorIOException(e.getMessage(), e);
			}
            connection = null;
            schemaManager = null;
            schemaTranslator = null;
        }
    }

	private void connect() {
    	final LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
    	connectionConfig.setLdapHost(configuration.getHost());
    	connectionConfig.setLdapPort(configuration.getPort());
    	connectionConfig.setTimeout(configuration.getConnectTimeout());
    	
    	String connectionSecurity = configuration.getConnectionSecurity();
    	if (LdapConfiguration.CONNECTION_SECURITY_SSL.equals(connectionSecurity)) {
    		connectionConfig.setUseSsl(true);
    	} else if (LdapConfiguration.CONNECTION_SECURITY_STARTTLS.equals(connectionSecurity)) {
    		connectionConfig.setUseTls(true);
    	} else if (connectionSecurity != null) {
    		throw new ConfigurationException("Unknown value for connectionSecurity: "+connectionSecurity);
    	}
    	
		connectionConfig.setBinaryAttributeDetector(binaryAttributeDetector);
    	
    	LOG.ok("Creating connection object");
		connection = new LdapNetworkConnection(connectionConfig);
		try {
			LOG.info("Connecting to {0}:{1} as {2}", configuration.getHost(), configuration.getPort(), configuration.getBindDn());
			boolean connected = connection.connect();
			LOG.ok("Connected ({0})", connected);
			if (!connected) {
				throw new ConnectionFailedException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			throw LdapUtil.processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
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
			throw LdapUtil.processLdapException("Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn, e);
		}
		LdapResult ldapResult = bindResponse.getLdapResult();
		if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
			String msg = "Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn
					+": "+ldapResult.getResultCode().getMessage()+": "+ldapResult.getDiagnosticMessage()+" ("
					+ldapResult.getResultCode().getResultCode()+")";
			throw new ConfigurationException(msg);
		}
		LOG.info("Bound to {0}: {1} ({2})", bindDn, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode());
	}
    
	private Entry getRootDse() throws LdapException {
		LOG.ok("Fetching root DSE");
		return connection.getRootDse();
	}
	
    

}
