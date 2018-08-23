/*
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

package com.evolveum.polygon.connector.ldap;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModify;
import org.apache.directory.api.ldap.extras.controls.permissiveModify.PermissiveModifyImpl;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.CursorLdapReferralException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AddRequest;
import org.apache.directory.api.ldap.model.message.AddRequestImpl;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ModifyRequest;
import org.apache.directory.api.ldap.model.message.ModifyRequestImpl;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.SchemaErrorHandler;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.url.LdapUrl;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.ldap.client.api.DefaultSchemaLoader;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
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
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateAttributeValuesOp;
import org.identityconnectors.framework.spi.operations.UpdateDeltaOp;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.schema.GuardedStringValue;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.ScopedFilter;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SimplePagedResultsSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.VlvSearchStrategy;
import com.evolveum.polygon.connector.ldap.sync.AdDirSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.ModifyTimestampSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.SunChangelogSyncStrategy;
import com.evolveum.polygon.connector.ldap.sync.SyncStrategy;

public abstract class AbstractLdapConnector<C extends AbstractLdapConfiguration> implements PoolableConnector, TestOp, SchemaOp, SearchOp<Filter>, CreateOp, DeleteOp, 
		UpdateDeltaOp, SyncOp {

    private static final Log LOG = Log.getLog(AbstractLdapConnector.class);
    
    private C configuration;
    private ConnectionManager<C> connectionManager;
    private SchemaManager schemaManager = null;
    private AbstractSchemaTranslator<C> schemaTranslator = null;
    private SyncStrategy<C> syncStrategy = null;
    private Boolean usePermissiveModify = null;

    public AbstractLdapConnector() {
		super();
		LOG.info("Creating {0} connector instance {1}", this.getClass().getSimpleName(), this);
	}

	@Override
    public C getConfiguration() {
        return configuration;
    }

    protected ConnectionManager<C> getConnectionManager() {
		return connectionManager;
	}

	@Override
    public void init(Configuration configuration) {
		LOG.info("Initializing {0} connector instance {1}", this.getClass().getSimpleName(), this);
        this.configuration = (C)configuration;
        this.configuration.recompute();
        connectionManager = new ConnectionManager<>(this.configuration);
        connectionManager.connect();
        if (LOG.isOk()) {
        	LOG.ok("Servers:\n{0}", connectionManager.dumpServers());
        }
    }
    
    @Override
	public void test() {
    	LOG.info("Test {0} connector instance {1}", this.getClass().getSimpleName(), this);
    	cleanupBeforeTest();
        connectionManager.connect();
        if (configuration.isEnableExtraTests()) {
        	extraTests();
        }
        reconnectAfterTest();
        checkAlive();
        additionalConnectionTests();
    	try {
    		LOG.ok("Fetching root DSE");
			Entry rootDse = connectionManager.getDefaultConnection().getRootDse();
			LOG.ok("Root DSE: {0}", rootDse);
		} catch (LdapException e) {
			throw processLdapException(null, e);
		}
	}
    
	protected void cleanupBeforeTest() {
    	try {
    		LOG.ok("Closing connections ... to reopen them again");
			connectionManager.close();
		} catch (IOException e) {
			throw new ConnectorIOException(e.getMessage(), e);
		}
        schemaManager = null;
        schemaTranslator = null;
	}
    
    protected void reconnectAfterTest() {
    	
    }
    
    protected void additionalConnectionTests() {
		
	}


	protected void extraTests() {
    	
    	analyzeAttrDef("dc");
    	
    	analyzeDn("CN=foo bar,OU=people,DC=EXamPLE,dc=CoM");
    	analyzeDn(configuration.getBaseContext());
    	analyzeDn(configuration.getBindDn());
    	
    	testAncestor("dc=example,dc=com", "uid=foo,ou=people,dc=example,dc=com", true);
    	testAncestor("uid=foo,ou=people,dc=example,dc=com", "dc=example,dc=com", false);
    	testAncestor("dc=example,dc=com", "dc=example,dc=com", true);
    	testAncestor("dc=example,dc=com", "CN=foo bar,OU=people,DC=example,DC=com", true);
    	// TODO: This fails for LDAP servers (MID-3477)
    	testAncestor("dc=example,dc=com", "CN=foo bar,OU=people,DC=EXamPLE,DC=COM", true);
    	testAncestor("DC=example,DC=com", "cn=foo bar,ou=people,dc=example,dc=com", true);
    	testAncestor("DC=exAMple,DC=com", "CN=foo bar,OU=people,DC=EXamPLE,dc=COM", true);
	    testAncestor("DC=badEXAMPLE,DC=com", "CN=foo bar,OU=people,DC=EXamPLE,dc=COM", false);
	    testAncestor("DC=badexample,DC=com", "CN=foo bar,OU=people,DC=example,dc=com", false);
	    testAncestor("dc=badexample,dc=com", "cn=foo bar,ou=people,dc=example,dc=com", false);
    }
    
	private void analyzeAttrDef(String attrName) {
		AttributeType attributeType = getSchemaManager().getAttributeType(attrName);
		LOG.ok("Definition of LDAP attribute {0}: {1}", attrName, attributeType);
		if (attributeType != null) {
			MatchingRule equality = attributeType.getEquality();
			LOG.ok("Equality matching rule {0}", equality);
			if (equality != null) {
				Normalizer normalizer = equality.getNormalizer();
				LOG.ok("Equality normalizer ({0}): {1}", normalizer==null?null:normalizer.getClass(), normalizer);
				if (normalizer != null) {
					String in = " tHiS is REALLY stRAngE  ";
					try {
						LOG.ok("Normalized ''{0}'' -> ''{1}''", in, normalizer.normalize(in));
					} catch (LdapException e) {
						LOG.error("Normalized error (input: '"+in+"': "+e.getMessage(), e);
					}
				}
			}
			
			LdapSyntax syntax = attributeType.getSyntax();
			LOG.ok("Syntax {0}", syntax);
			if (syntax != null) {
				LOG.ok("Syntax checker {0}", syntax.getSyntaxChecker());
			}
		}
	}

	private void analyzeDn(String stringDn) {
		if (stringDn == null) {
			return;
		}
    	Dn dn = asDn(getSchemaManager(), stringDn);
    	LOG.ok("Parsed DN {0}: {1}", stringDn, dn);
    	List<Rdn> rdns = dn.getRdns();
    	LOG.ok("Parsed RDNs: {0}", rdns);
    	Rdn lastRdn = rdns.get(rdns.size()-1);
    	LOG.ok("Last RDN: {0}", lastRdn);
    	LOG.ok("Last RDN AVA: {0}", lastRdn.getAva());
    	LOG.ok("Last RDN AVA name: {0}", lastRdn.getAva().getName());
    	LOG.ok("Last RDN AVA type: {0}", lastRdn.getAva().getType());
    	LOG.ok("Last RDN AVA attributeType: {0}", lastRdn.getAva().getAttributeType());
	}

	protected void testAncestor(String upper, String lower, boolean expectedMatch) {
    	Dn upperDn = asDn(upper);
    	Dn lowerDn = asDn(lower);
    	boolean ancestorOf = LdapUtil.isAncestorOf(upperDn, lowerDn, getSchemaTranslator());
    	if (ancestorOf && !expectedMatch) {
    		String msg = "Dn '"+upper+"' is wrongly evaluated as ancestor of '"+
    				lower+"' (it should NOT be).";
    		LOG.error("Extra test: {0}", msg);
    		throw new ConnectorException(msg);
    	}
    	if (!ancestorOf && expectedMatch) {
    		String msg = "Dn '"+upper+"' is NOT evaluated as ancestor of '"+
    				lower+"' (but it should be).";
    		LOG.error("Extra test: {0}", msg);
    		throw new ConnectorException(msg);
    	}
    	if (LOG.isOk()) {
    		String msg;
	    	if (ancestorOf) {
	    		msg = "Dn '"+upper+"' is correctly evaluated as ancestor of '"+
	    				lower+"'";
	    	} else {
	    		msg = "Dn '"+upper+"' is correctly evaluated NOT yo be ancestor of '"+
	    				lower+"'";
	    	}
	    	LOG.ok("Extra test: {0}", msg);
    	}
	}
		
	private Dn asDn(String stringDn) {
		try {
			return new Dn(stringDn);
		} catch (LdapInvalidDnException e) {
			throw new ConnectorException("Cannot parse '"+stringDn+" as DN: "+e.getMessage(), e);
		}
	}
	
	private Dn asDn(SchemaManager schemaManager, String stringDn) {
		try {
			return new Dn(schemaManager, stringDn);
		} catch (LdapInvalidDnException e) {
			throw new ConnectorException("Cannot parse '"+stringDn+" as DN: "+e.getMessage(), e);
		}
	}

	protected SchemaManager getSchemaManager() {
    	if (schemaManager == null) {
    		try {
    			boolean schemaQuirksMode = configuration.isSchemaQuirksMode();
    			LOG.ok("Loading schema (quirksMode={0})", schemaQuirksMode);
    			DefaultSchemaLoader schemaLoader = new DefaultSchemaLoader(connectionManager.getDefaultConnection(), schemaQuirksMode);
    			DefaultSchemaManager defSchemaManager = new DefaultSchemaManager(schemaLoader);
    			SchemaErrorHandler schemaErrorHandler = createSchemaErrorHandler();
    			if (schemaErrorHandler != null) {
    				defSchemaManager.setErrorHandler(schemaErrorHandler);
    			}
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
    					if (isLogSchemaErrors()) {
	    					for (Throwable error: defSchemaManager.getErrors()) {
	    						LOG.ok("Schema error (ignored): {0}: {1}", error.getClass().getName(), error.getMessage());
	    					}
    					}
    				} else {
    					throw new ConnectorIOException("Errors loading schema "+defSchemaManager.getErrors());
    				}
    			}
    			schemaManager = defSchemaManager;
//    			connection.setSchemaManager(defSchemaManager);
//    			connection.loadSchema(defSchemaManager);
    		} catch (LdapException e) {
    			Throwable cause = e.getCause();
    			if (cause instanceof ParseException) {
    				// Schema parsing error
    				// We are throwing InvalidAttributeValueException here, even though we should not.
    				// But we take InvalidAttributeValueException to means general schema-related error.
    				throw new InvalidAttributeValueException("Error parsing resource schema: "+cause.getMessage(), e);
    			}
    			throw new ConnectorIOException(e.getMessage(), e);
    		} catch (Exception e) {
    			// Brutal. We cannot really do anything smarter here.
				throw new ConnectorException(e.getMessage(), e);
			}
    		
    		try {
				LOG.info("Schema loaded, {0} schemas, {1} object classes, {2} errors",
						schemaManager.getAllSchemas().size(),
						schemaManager.getObjectClassRegistry().size(),
						schemaManager.getErrors().size());
			} catch (Exception e) {
				throw new RuntimeException(e.getMessage(),e);
			}
    		patchSchemaManager(schemaManager);
    	}
    	return schemaManager;
    }
    
	protected void patchSchemaManager(SchemaManager schemaManager) {
		// Nothing to do here. But useful in subclasses.
	}

    protected SchemaErrorHandler createSchemaErrorHandler() {
		// null by default. This means that a default logging error handler from directory API
    	// will be used. May be overridden by subsclasses.
		return null;
	}
	
	protected boolean isLogSchemaErrors() {
		return true;
	}

	protected AbstractSchemaTranslator<C> getSchemaTranslator() {
    	if (schemaTranslator == null) {
    		schemaTranslator = createSchemaTranslator();
    		connectionManager.setSchemaTranslator(schemaTranslator);
    	}
    	return schemaTranslator;
    }
    
    protected abstract AbstractSchemaTranslator<C> createSchemaTranslator();
    
    @Override
	public Schema schema() {
    	if (!connectionManager.isConnected()) {
    		return null;
    	}
    	// always fetch fresh schema when this method is called
    	schemaManager = null;
    	schemaTranslator = null;
    	try {
    		return getSchemaTranslator().translateSchema(connectionManager);
    	} catch (InvalidConnectionException e) {
    		// The connection might have been disconnected. Try to reconnect.
    		connectionManager.connect();
			try {
				return getSchemaTranslator().translateSchema(connectionManager);
			} catch (InvalidConnectionException e1) {
				throw new ConnectorException("Reconnect error: "+e.getMessage(), e);
			}
    	}
	}
    
    private void prepareIcfSchema() {
    	try {
    		getSchemaTranslator().prepareIcfSchema(connectionManager);
    	} catch (InvalidConnectionException e) {
    		// The connection might have been disconnected. Try to reconnect.
    		connectionManager.connect();
			try {
				getSchemaTranslator().prepareIcfSchema(connectionManager);
			} catch (InvalidConnectionException e1) {
				throw new ConnectorException("Reconnect error: "+e.getMessage(), e);
			}
    	}
    }
    
    protected boolean isUsePermissiveModify() throws LdapException {
    	if (usePermissiveModify == null) {
    		switch (configuration.getUsePermissiveModify()) {
    			case AbstractLdapConfiguration.USE_PERMISSIVE_MODIFY_ALWAYS:
    				usePermissiveModify = true;
    				break;
    			case AbstractLdapConfiguration.USE_PERMISSIVE_MODIFY_NEVER:
    				usePermissiveModify = false;
    				break;
    			case AbstractLdapConfiguration.USE_PERMISSIVE_MODIFY_AUTO:
    				usePermissiveModify = connectionManager.getDefaultConnection().isControlSupported(PermissiveModify.OID);
    				break;
    			default:
    				throw new ConfigurationException("Unknown usePermissiveModify value "+configuration.getUsePermissiveModify());
    		}
    	}
    	return usePermissiveModify;
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
		
		SearchStrategy<C> searchStrategy;
		if (isEqualsFilter(icfFilter, Name.NAME)) {
			// Search by __NAME__, which means DN. This translated to a base search.
			searchStrategy = searchByDn(schemaTranslator.toDn(((EqualsFilter)icfFilter).getAttribute()),
					objectClass, ldapObjectClass, handler, options);
			
		} else if (isEqualsFilter(icfFilter, Uid.NAME)) {
			// Search by __UID__. Special case for performance.
			searchStrategy = searchByUid((Uid)((EqualsFilter)icfFilter).getAttribute(),
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
			if (searchStrategy == null) {
				// We have found nothing
				SearchResult searchResult = new SearchResult(null, 0, true);
				((SearchResultsHandler)handler).handleResult(searchResult);
			} else {
				String cookie = searchStrategy.getPagedResultsCookie();
				int remainingResults = searchStrategy.getRemainingPagedResults();
				boolean completeResultSet = searchStrategy.isCompleteResultSet();
				SearchResult searchResult = new SearchResult(cookie, remainingResults, completeResultSet);
				((SearchResultsHandler)handler).handleResult(searchResult);
			}
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

	protected SearchStrategy<C> searchByDn(Dn dn, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		// This translated to a base search.
		// We know that this can return at most one object. Therefore always use simple search.
		SearchStrategy<C> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		try {
			
			searchStrategy.search(dn, null, SearchScope.OBJECT, attributesToGet);
			
		} catch (UnknownUidException e) {
			// This is not really an error. This means that the object does not exist. But in this
			// case we are supposed to return nothing. We are NOT supposed to throw an error.
			// So our job id done. We already returned nothing. And we will just ignore the
			// exception.
			return searchStrategy;
			
		} catch (LdapException e) {
			throw processLdapException("Error searching for DN '"+dn+"'", e);
			
		}
		return searchStrategy;
	}
	
	/**
	 * Returns a complete object based on ICF UID.
	 * 
	 * This is different from resolveDn() method in that it returns a complete object.
	 * The resolveDn() method is supposed to be optimized to only return DN.
	 */
	protected SearchStrategy<C> searchByUid(Uid uid, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		String uidValue = SchemaUtil.getSingleStringNonBlankValue(uid);
		if (LdapUtil.isDnAttribute(configuration.getUidAttribute())) {
			return searchByDn(schemaTranslator.toDn(uidValue), objectClass, ldapObjectClass, handler, options);
		} else {
			// We know that this can return at most one object. Therefore always use simple search.
			SearchStrategy<C> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			SearchScope scope = getScope(options);			
			ExprNode filterNode = LdapUtil.createUidSearchFilter(uidValue, ldapObjectClass, getSchemaTranslator());
			Dn baseDn = getBaseDn(options);
			checkBaseDnPresent(baseDn);
			try {
				searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
			} catch (LdapException e) {
				throw processLdapException("Error searching for UID '"+uidValue+"'", e);
			}
			
			return searchStrategy;
		}
	}
	
	private SearchStrategy<C> searchBySecondaryIdenfiers(Filter icfFilter, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			final ResultsHandler handler, OperationOptions options) {
		// This translated to a base search.
		// We know that this can return at most one object. Therefore always use simple search.
		
		Filter leftSubfilter = ((OrFilter)icfFilter).getLeft();
		Filter rightSubfilter = ((OrFilter)icfFilter).getRight();
		EqualsFilter dnSubfilter;
		Filter otherSubfilter;
		if ((leftSubfilter instanceof EqualsFilter) && Name.NAME.equals(((EqualsFilter)leftSubfilter).getName())) {
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

		Dn dn = schemaTranslator.toDn(dnSubfilter.getAttribute());
		try {
			searchByDn(dn, objectClass, ldapObjectClass, innerHandler, options);
		} catch (UnknownUidException e) {
			// No problem. The Dn is not here. Just no on.
			LOG.ok("The DN \"{0}\" not found: {1} (this is OK)", dn, e.getMessage());
		}
		
		// Search by the other attribute now
		
		// We know that this can return at most one object. Therefore always use simple search.
		SearchStrategy<C> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, innerHandler, options);
		LdapFilterTranslator filterTranslator = new LdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
		ScopedFilter scopedFilter = filterTranslator.translate(otherSubfilter, ldapObjectClass);
		ExprNode filterNode = scopedFilter.getFilter();
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		SearchScope scope = getScope(options);
		Dn baseDn = getBaseDn(options);
		checkBaseDnPresent(baseDn);
		try {
			searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
		} catch (LdapException e) {
			throw processLdapException("Error searching in "+baseDn, e);
		}
		
		return searchStrategy;
				
	}

	private void checkBaseDnPresent(Dn baseDn) {
		if (baseDn == null) {
			throw new ConfigurationException("No base DN present. Are you sure you have set up the base context in connector configuration?");
		}
	}

	private SearchStrategy<C> searchUsual(Filter icfFilter, ObjectClass objectClass, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		Dn baseDn = getBaseDn(options);
		LdapFilterTranslator filterTranslator = createLdapFilterTranslator(ldapObjectClass);
		ScopedFilter scopedFilter = filterTranslator.translate(icfFilter, ldapObjectClass);
		ExprNode filterNode = scopedFilter.getFilter();
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
		
		SearchStrategy<C> searchStrategy;
		if (scopedFilter.getBaseDn() != null) {

			// The filter was limited by a ICF filter clause for __NAME__
			// so we look at exactly one object here
			searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
			try {
				searchStrategy.search(scopedFilter.getBaseDn(), filterNode, SearchScope.OBJECT, attributesToGet);
			} catch (LdapException e) {
				throw processLdapException("Error searching for "+scopedFilter.getBaseDn(), e);
			}
		
		} else {

			// This is the real (usual) search
			searchStrategy = chooseSearchStrategy(objectClass, ldapObjectClass, handler, options);
			SearchScope scope = getScope(options);
			checkBaseDnPresent(baseDn);
			try {
				searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
			} catch (LdapException e) {
				throw processLdapException("Error searching in "+baseDn, e);
			}
			
		}
		
		return searchStrategy;
	}
	
	protected LdapFilterTranslator createLdapFilterTranslator(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		return new LdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
	}
	
	private Dn getBaseDn(OperationOptions options) {
		if (options != null && options.getContainer() != null) {
			QualifiedUid containerQUid = options.getContainer();
			// HACK WARNING: this is a hack to overcome bad framework design.
			// Even though this has to be Uid, we interpret it as a DN.
			// The framework uses UID to identify everything. This is naive.
			// Strictly following the framework contract would mean to always
			// do two LDAP searches instead of one in this case.
			// So we deviate from the contract here. It is naughty, but it
			// is efficient.
			return getSchemaTranslator().toDn(containerQUid.getUid());
		} else {
			return getSchemaTranslator().toDn(configuration.getBaseContext());
		}
	}

	private SearchScope getScope(OperationOptions options) {
		if (options == null || options.getScope() == null) {
			return SearchScope.SUBTREE;
		}
		return SearchScope.getSearchScope( SearchScope.getSearchScope( options.getScope() ) );
	}

	protected String[] getAttributesToGet(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, OperationOptions options) {
		return LdapUtil.getAttributesToGet(ldapObjectClass, options, getSchemaTranslator());
	}
	
	protected SearchStrategy<C> chooseSearchStrategy(ObjectClass objectClass, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			ResultsHandler handler, OperationOptions options) {
		AbstractSchemaTranslator<C> schemaTranslator = getSchemaTranslator();
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
    			return new SimplePagedResultsSearchStrategy<>(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
    		} else {
    			throw new ConfigurationException("Configured paging strategy "+pagingStrategy+", but the server does not support PagedResultsControl.");
    		}
    		
        } else if (LdapConfiguration.PAGING_STRATEGY_VLV.equals(pagingStrategy)) {
    		if (supportsControl(VirtualListViewRequest.OID)) {
    			LOG.ok("Selecting VLV search strategy because strategy setting is set to {0}", pagingStrategy);
    			return new VlvSearchStrategy<>(connectionManager, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
    		} else {
    			throw new ConfigurationException("Configured paging strategy "+pagingStrategy+", but the server does not support VLV.");
    		}
    		
        } else if (LdapConfiguration.PAGING_STRATEGY_AUTO.equals(pagingStrategy)) {
        	if (options.getPagedResultsOffset() != null) {
        		// Always prefer VLV even if the offset is 1. We expect that the client will use paging and subsequent
        		// queries will come with offset other than 1. The server may use a slightly different sorting for VLV and other
        		// paging mechanisms. Bu we want consisten results. Therefore in this case prefer VLV even if it might be less efficient.
        		if (supportsControl(VirtualListViewRequest.OID)) {
        			LOG.ok("Selecting VLV search strategy because strategy setting is set to {0} and the request specifies an offset", pagingStrategy);
        			return new VlvSearchStrategy<>(connectionManager, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
        		} else {
        			throw new UnsupportedOperationException("Requested search from offset ("+options.getPagedResultsOffset()+"), but the server does not support VLV. Unable to execute the search.");
        		}
        	} else {
        		if (supportsControl(PagedResults.OID)) {
        			// SPR is usually a better choice if no offset is specified. Less overhead on the server.
        			LOG.ok("Selecting SimplePaged search strategy because strategy setting is set to {0} and the request does not specify an offset", pagingStrategy);
        			return new SimplePagedResultsSearchStrategy<>(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
        		} else if (supportsControl(VirtualListViewRequest.OID)) {
        			return new VlvSearchStrategy<>(connectionManager, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
        		} else {
        			throw new UnsupportedOperationException("Requested paged search, but the server does not support VLV or PagedResultsControl. Unable to execute the search.");
        		}
        	}
        }
        
		return getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
	}
	
	private boolean supportsControl(String oid) {
		try {
			return connectionManager.getDefaultConnection().getSupportedControls().contains(oid);
		} catch (LdapException e) {
			throw new ConnectorIOException("Cannot fetch list of supported controls: "+e.getMessage(), e);
		}
	}

	protected SearchStrategy<C> getDefaultSearchStrategy(ObjectClass objectClass, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		return new DefaultSearchStrategy<>(connectionManager, configuration, getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
	}

	@Override
	public Uid create(ObjectClass icfObjectClass, Set<Attribute> createAttributes, OperationOptions options) {
		
		String dnStringFromName = null;
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(Name.NAME)) {
				dnStringFromName = SchemaUtil.getSingleStringNonBlankValue(icfAttr);
			}
		}
		if (dnStringFromName == null) {
			throw new InvalidAttributeValueException("Missing NAME attribute");
		}
		
		AbstractSchemaTranslator<C> shcemaTranslator = getSchemaTranslator();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass = shcemaTranslator.toLdapObjectClass(icfObjectClass);
		
		List<org.apache.directory.api.ldap.model.schema.ObjectClass> ldapAuxiliaryObjectClasses = new ArrayList<>();
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME)) {
				for (Object val: icfAttr.getValue()) {
					ldapAuxiliaryObjectClasses.add(getSchemaTranslator().toLdapObjectClass(new ObjectClass((String)val)));
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
			entry = new DefaultEntry(dnStringFromName);
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Wrong DN '"+dnStringFromName+"': "+e.getMessage(), e);
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
			List<Value> ldapValues = shcemaTranslator.toLdapValues(ldapAttrType, icfAttr.getValue());
			// Do NOT set attributeType here. The attributeType may not match the type of the value.
			entry.put(ldapAttrType.getName(), ldapValues.toArray(new Value[ldapValues.size()]));
			// no simple way how to check if he attribute was added. It may end up with ERR_04451. So let's just
			// hope that it worked well. It should - unless there is a connector bug.
		}
		
		preCreate(ldapStructuralObjectClass, entry);
		
		if (LOG.isOk()) {
			LOG.ok("Adding entry: {0}", entry);
		}
		
		processEntryBeforeCreate(entry);
		
		AddRequest addRequest = new AddRequestImpl();
		addRequest.setEntry(entry);
		
		Dn entryDn = addRequest.getEntryDn();
		LdapNetworkConnection connection = connectionManager.getConnection(entryDn);
		
		OperationLog.logOperationReq(connection, "Add REQ Entry:\n{0}" , entry);
		
		AddResponse addResponse;
		try {
			
			addResponse = connection.add(addRequest);
			
		} catch (LdapException e) {
			OperationLog.logOperationErr(connection, "Add ERROR {0}: {1}", dnStringFromName, e.getMessage(), e);
			throw processLdapException("Error adding LDAP entry "+dnStringFromName, e);
		}
		
		OperationLog.logOperationRes(connection, "Add RES {0}: {1}", dnStringFromName, addResponse.getLdapResult());
		
		if (addResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS) {
			throw processCreateResult(dnStringFromName, addResponse);
		}

		String uidAttributeName = configuration.getUidAttribute();
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
			return new Uid(dnStringFromName);
		}
		
		Uid uid = null;
		for (Attribute icfAttr: createAttributes) {
			if (icfAttr.is(uidAttributeName)) {
				uid = new Uid(SchemaUtil.getSingleStringNonBlankValue(icfAttr));
			}
		}
		if (uid != null) {
			return uid;
		}
		
		// read the entry back and return UID
		
		Entry entryRead = searchSingleEntry(connectionManager, entry.getDn(), LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
				new String[]{ uidAttributeName }, "re-reading entry to get UID");
		org.apache.directory.api.ldap.model.entry.Attribute uidLdapAttribute = entryRead.get(uidAttributeName);
		if (uidLdapAttribute == null) {
			throw new InvalidAttributeValueException("No value for UID attribute "+uidAttributeName+" in object "+dnStringFromName);
		}
		if (uidLdapAttribute.size() == 0) {
			throw new InvalidAttributeValueException("No value for UID attribute "+uidAttributeName+" in object "+dnStringFromName);
		} else if (uidLdapAttribute.size() > 1) {
			throw new InvalidAttributeValueException("More than one value ("+uidLdapAttribute.size()+") for UID attribute "+uidAttributeName+" in object "+dnStringFromName);
		}
		Value uidLdapAttributeValue = uidLdapAttribute.get();
		AttributeType uidLdapAttributeType = getSchemaManager().getAttributeType(uidAttributeName);
		uid = new Uid(getSchemaTranslator().toIcfIdentifierValue(uidLdapAttributeValue, uidAttributeName, uidLdapAttributeType));
		
		return uid;
	}
	
	protected RuntimeException processCreateResult(String dn, AddResponse addResponse) {
		 return processLdapResult("Error adding LDAP entry " + dn, addResponse.getLdapResult());
	}

	protected void preCreate(org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, Entry entry) {
		// Nothing to do here. Hooks for subclasses.
	}

	
	
	@Override
	public Set<AttributeDelta> updateDelta(ObjectClass connIdObjectClass, Uid uid, Set<AttributeDelta> deltas,
			OperationOptions options) {
    	
		Dn dn = null;
		for (AttributeDelta delta: deltas) {
			if (delta.is(Name.NAME)) {
				// This is rename. Which means change of DN. This is a special operation
				dn = getSchemaTranslator().toDn(delta);
				ldapRename(connIdObjectClass, uid, dn, options);
				
				// Do NOT return here. There may still be other (non-name) attributes to update
			}
		}
    	
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass = getSchemaTranslator().toLdapObjectClass(connIdObjectClass);
		
		if (dn == null) {
			
			if (getConfiguration().isUseUnsafeNameHint() && uid.getNameHint() != null) {
				String dnHintString = uid.getNameHintValue();
				dn = getSchemaTranslator().toDn(dnHintString);
				LOG.ok("Using (unsafe) DN from the name hint: {0} for update", dn);
				try {
					
					return ldapUpdateAttempt(connIdObjectClass, uid, dn, deltas, options, ldapStructuralObjectClass);
				
				} catch (Throwable e) {
					LOG.warn("Attempt to delete object with DN failed (DN taked from the name hint). The operation will continue with next attempt. Error: {0}",
							e.getMessage(), e);
				}
			}
			
			dn = resolveDn(connIdObjectClass, uid, options);
			LOG.ok("Resolved DN: {0}", dn);
		}
			
		return ldapUpdateAttempt(connIdObjectClass, uid, dn, deltas, options, ldapStructuralObjectClass);
	}
	
	

	private void ldapRename(ObjectClass objectClass, Uid uid, Dn newDn, OperationOptions options) {
		Dn oldDn;
		
		if (getConfiguration().isUseUnsafeNameHint() && uid.getNameHint() != null) {
			String dnHintString = uid.getNameHintValue();
			oldDn = getSchemaTranslator().toDn(dnHintString);
			LOG.ok("Using (unsafe) DN from the name hint: {0} for rename", oldDn);
			try {
				
				ldapRenameAttempt(oldDn, newDn);
				return;
			
			} catch (Throwable e) {
				LOG.warn("Attempt to delete object with DN failed (DN taked from the name hint). The operation will continue with next attempt. Error: {0}",
						e.getMessage(), e);
			}
		}
		
		oldDn = resolveDn(objectClass, uid, options);
		LOG.ok("Resolved DN: {0}", oldDn);
		
		ldapRenameAttempt(oldDn, newDn);
	}
	
	private void ldapRenameAttempt(Dn oldDn, Dn newDn) {
		if (oldDn.equals(newDn)) {
			// nothing to rename, just ignore
		} else {
			LdapNetworkConnection connection = connectionManager.getConnection(oldDn);
			try {
				OperationLog.logOperationReq(connection, "MoveAndRename REQ {0} -> {1}", oldDn, newDn);
				// Make sure that DNs are passed in as (user-provided) strings. Otherwise the Directory API
				// will convert it do OID=value notation. And some LDAP servers (such as OpenDJ) does not handle
				// that well.
				connection.moveAndRename(oldDn.getName(), newDn.getName());
				OperationLog.logOperationRes(connection, "MoveAndRename RES OK {0} -> {1}", oldDn, newDn);
			} catch (LdapException e) {
				OperationLog.logOperationErr(connection, "MoveAndRename ERROR {0} -> {1}: {2}", oldDn, newDn, e.getMessage(), e);
				throw processLdapException("Rename/move of LDAP entry from "+oldDn+" to "+newDn+" failed", e);
			}
		}
	}
		
	private Set<AttributeDelta> ldapUpdateAttempt(ObjectClass connIdObjectClass, Uid uid, Dn dn, Set<AttributeDelta> deltas,
			OperationOptions options, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass) {
		
		List<Modification> ldapModifications = new ArrayList<Modification>();
		for (AttributeDelta delta: deltas) {
			if (delta.is(Name.NAME)) {
				// Already processed
				continue;
			}
			if (delta.is(PredefinedAttributes.AUXILIARY_OBJECT_CLASS_NAME)) {
				List<Object> valuesToReplace = delta.getValuesToReplace();
				if (valuesToReplace != null) {
					// We need to keep structural object class
					String[] stringValues = new String[valuesToReplace.size() + 1];
					stringValues[0] = ldapStructuralObjectClass.getName();
					int i = 1;
					for(Object val: valuesToReplace) {
						stringValues[i] = (String)val;
						i++;
					}
					ldapModifications.add(new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, SchemaConstants.OBJECT_CLASS_AT, stringValues));
				} else {
					addLdapModificationString(ldapModifications, ModificationOperation.ADD_ATTRIBUTE, SchemaConstants.OBJECT_CLASS_AT, delta.getValuesToAdd());
					addLdapModificationString(ldapModifications, ModificationOperation.REMOVE_ATTRIBUTE, SchemaConstants.OBJECT_CLASS_AT, delta.getValuesToRemove());
				}
			} else {
				addAttributeModification(dn, ldapModifications, ldapStructuralObjectClass, connIdObjectClass, delta);
			}
		}
		
		if (ldapModifications.isEmpty()) {
			LOG.ok("Skipping modify operation as there are no modifications to execute");
		} else {
		
			modify(dn, ldapModifications);
			
			postUpdate(connIdObjectClass, uid, deltas, options, dn, ldapStructuralObjectClass, ldapModifications);
			
		}
		
		Set<AttributeDelta> sideEffects = null;
		
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
			sideEffects = new HashSet<>();
			sideEffects.add(createUidDelta(dn.toString()));
			return sideEffects;
		}
		
		for (AttributeDelta delta: deltas) {
			if (delta.is(uidAttributeName)) {
				sideEffects = new HashSet<>();
				sideEffects.add(createUidDelta(SchemaUtil.getSingleStringNonBlankReplaceValue(delta)));
			}
		}
		
		return sideEffects;
	}
	
	private AttributeDelta createUidDelta(String string) {
		return AttributeDeltaBuilder.build(Uid.NAME, string);
	}

	private void addLdapModificationString(List<Modification> ldapModifications,
			ModificationOperation modOp, String ldapAttributeName, List<Object> values) {
		if (values == null) {
			return;
		}
		String[] stringValues = new String[values.size()];
		int i = 0;
		for(Object val: values) {
			stringValues[i] = (String)val;
			i++;
		}
		ldapModifications.add(new DefaultModification(modOp, ldapAttributeName, stringValues));

	}
	
	private void addLdapModification(List<Modification> ldapModifications,
			ModificationOperation modOp, AttributeType ldapAttributeType, List<Object> values) {
		if (values == null) {
			return;
		}
		List<Value> ldapValues = schemaTranslator.toLdapValues(ldapAttributeType, values);
		if (ldapValues == null || ldapValues.isEmpty()) {
			// Do NOT set AttributeType here
			// The attributeType might not match the Value class
			// e.g. human-readable jpegPhoto attribute will expect StringValue
			ldapModifications.add(new DefaultModification(modOp, ldapAttributeType.getName()));					
		} else {
			// Do NOT set AttributeType here
			// The attributeType might not match the Value class
			// e.g. human-readable jpegPhoto attribute will expect StringValue
			DefaultAttribute ldapAttribute = new DefaultAttribute(ldapAttributeType.getName(),  ldapValues.toArray(new Value[ldapValues.size()]));
			ldapModifications.add(new DefaultModification(modOp, ldapAttribute));
		}
	}

	protected void modify(Dn dn, List<Modification> modifications) {
		LdapNetworkConnection connection = connectionManager.getConnection(dn);
		try {
			PermissiveModify permissiveModifyControl = null;
			if (isUsePermissiveModify()) {
				permissiveModifyControl = new PermissiveModifyImpl();
			}
			if (LOG.isOk()) {
				OperationLog.logOperationReq(connection, "Modify REQ {0}: {1}, control={2}", dn, dumpModifications(modifications), 
						LdapUtil.toShortString(permissiveModifyControl));
			}
			ModifyRequest modRequest = new ModifyRequestImpl();
			modRequest.setName(dn);
			if (permissiveModifyControl != null) {
				modRequest.addControl(permissiveModifyControl);
			}
			// processModificationsBeforeUpdate must happen after logging. Otherwise passwords might be logged.
			for (Modification mod: processModificationsBeforeUpdate(modifications)) {
				modRequest.addModification(mod);
			}
			ModifyResponse modifyResponse = connection.modify(modRequest);
			
			if (LOG.isOk()) {
				OperationLog.logOperationRes(connection, "Modify RES {0}: {1}", dn, modifyResponse.getLdapResult());
			}
			
			if (modifyResponse.getLdapResult().getResultCode() != ResultCodeEnum.SUCCESS) {
				throw processModifyResult(dn, modifications, modifyResponse);
			}
		} catch (LdapException e) {
			OperationLog.logOperationErr(connection, "Modify ERROR {0}: {1}: {2}", dn, dumpModifications(modifications), e.getMessage(), e);
			throw processModifyResult(dn.toString(), modifications, e);
		}
	}

	protected RuntimeException processModifyResult(Dn dn, List<Modification> modifications, ModifyResponse modifyResponse) {
		return processLdapResult("Error modifying LDAP entry "+dn+": "+dumpModifications(modifications), modifyResponse.getLdapResult());
	}

	protected RuntimeException processModifyResult(String dn, List<Modification> modifications, LdapException e) {
		return processLdapException("Error modifying LDAP entry "+dn, e);
	}
		
	protected void addAttributeModification(Dn dn, List<Modification> modifications,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			ObjectClass connIdObjectClass, AttributeDelta delta) {
		AbstractSchemaTranslator<C> schemaTranslator = getSchemaTranslator();
		AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapStructuralObjectClass, delta.getName());
		if (ldapAttributeType == null && !configuration.isAllowUnknownAttributes() 
				&& !ArrayUtils.contains(configuration.getOperationalAttributes(), delta.getName())) {
			throw new InvalidAttributeValueException("Unknown attribute "+delta.getName()+" in object class "+connIdObjectClass);
		}
		addLdapModification(modifications, ModificationOperation.REPLACE_ATTRIBUTE, ldapAttributeType, delta.getValuesToReplace());
		addLdapModification(modifications, ModificationOperation.ADD_ATTRIBUTE, ldapAttributeType, delta.getValuesToAdd());
		addLdapModification(modifications, ModificationOperation.REMOVE_ATTRIBUTE, ldapAttributeType, delta.getValuesToRemove());
	}
	
	protected void postUpdate(ObjectClass connIdObjectClass, Uid uid, Set<AttributeDelta> deltas,
			OperationOptions options, 
			Dn dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, List<Modification> ldapModifications) {
		// Nothing to do here. Just for override in subclasses.
	}

	// We want to decrypt GuardedString at the very last moment
	private Modification[] processModificationsBeforeUpdate(List<Modification> modifications) {
		Modification[] out = new Modification[modifications.size()];
		int i = 0;
		for (final Modification modification: modifications) {
			if (modification.getAttribute() != null && modification.getAttribute().get() != null) {
				Value val = modification.getAttribute().get();
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
			Value val = attribute.get();
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

	protected String dumpModifications(List<Modification> modifications) {
		if (modifications == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder("[");
		for (Modification mod: modifications) {
			sb.append(mod.getOperation()).append(":");
			org.apache.directory.api.ldap.model.entry.Attribute attribute = mod.getAttribute();
			sb.append(attribute.getUpId()).append("=");
			if (isSensitiveAttribute(attribute)) {
				sb.append("..hidden.value..");
			} else {
				Value value = attribute.get();
				if (value == null) {
					sb.append("null");
				} else {
					if (value.isHumanReadable()) {
						sb.append(value.getValue());
					} else {
						byte[] bytes = value.getBytes();
						if (bytes == null) {
							sb.append("null");
						} else {
							sb.append("binary value ").append(bytes.length).append(" bytes");
						}
					}
				}
			}
			sb.append(",");
		}
		sb.append("]");
		return sb.toString();
	}

	private boolean isSensitiveAttribute(org.apache.directory.api.ldap.model.entry.Attribute attribute) {
		return attribute.getId().equalsIgnoreCase(getConfiguration().getPasswordAttribute());
	}

	@Override
	public void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler,
			OperationOptions options) {
		prepareIcfSchema();
		SyncStrategy<C> strategy = chooseSyncStrategy();
		strategy.sync(objectClass, token, handler, options);
	}
	
	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		SyncStrategy<C> strategy = chooseSyncStrategy();
		return strategy.getLatestSyncToken(objectClass);
	}
	
	private SyncStrategy<C> chooseSyncStrategy() {
		if (syncStrategy == null) {
			switch (configuration.getSynchronizationStrategy()) {
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_NONE:
					throw new UnsupportedOperationException("Synchronization disabled (synchronizationStrategy=none)");
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG:
					syncStrategy = new SunChangelogSyncStrategy<>(configuration, connectionManager, getSchemaManager(), getSchemaTranslator());
					break;
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP:
					syncStrategy = new ModifyTimestampSyncStrategy<>(configuration, connectionManager, getSchemaManager(), getSchemaTranslator());
					break;
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_AD_DIR_SYNC:
					syncStrategy = new AdDirSyncStrategy<>(configuration, connectionManager, getSchemaManager(), getSchemaTranslator());
					break;
				case LdapConfiguration.SYNCHRONIZATION_STRATEGY_AUTO:
					syncStrategy = chooseSyncStrategyAuto();
					break;
				default:
					throw new IllegalArgumentException("Unknown synchronization strategy '"+configuration.getSynchronizationStrategy()+"'");
			}
		}
		return syncStrategy;
	}

	private SyncStrategy<C> chooseSyncStrategyAuto() {
		Entry rootDse = LdapUtil.getRootDse(connectionManager, SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
		org.apache.directory.api.ldap.model.entry.Attribute changelogAttribute = rootDse.get(SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
		if (changelogAttribute != null) {
			LOG.ok("Choosing Sun ChangeLog sync stategy (found {0} attribute in root DSE)", SunChangelogSyncStrategy.ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
			return new SunChangelogSyncStrategy<>(configuration, connectionManager, getSchemaManager(), getSchemaTranslator());
		}
		LOG.ok("Choosing modifyTimestamp sync stategy (fallback)");
		return new ModifyTimestampSyncStrategy<>(configuration, connectionManager, getSchemaManager(), getSchemaTranslator());
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		
		Dn dn;
		if (getConfiguration().isUseUnsafeNameHint() && uid.getNameHint() != null) {
			String dnHintString = uid.getNameHintValue();
			dn = getSchemaTranslator().toDn(dnHintString);
			LOG.ok("Using (unsafe) DN from the name hint: {0}", dn);
			try {
				
				deleteAttempt(dn, uid);
				
				return;
				
			} catch (Throwable e) {
				LOG.warn("Attempt to delete object with DN failed (DN taked from the name hint). The operation will continue with next attempt. Error: {0}",
						e.getMessage(), e);
			}
		}
		
		dn = resolveDn(objectClass, uid, options);
		LOG.ok("Resolved DN: {0}", dn);
		
		deleteAttempt(dn, uid);
	}
		
	private void deleteAttempt(Dn dn, Uid uid) {
		LdapNetworkConnection connection = connectionManager.getConnection(dn);
		
		try {
			OperationLog.logOperationReq(connection, "Delete REQ {0}", dn);
			
			connection.delete(dn);
			
			OperationLog.logOperationRes(connection, "Delete RES {0}", dn);
		} catch (LdapException e) {
			OperationLog.logOperationErr(connection, "Delete ERROR {0}: {1}", dn, e.getMessage(), e);
			throw processLdapException("Failed to delete entry with DN "+dn+" (UID="+uid+")", e);
		}
	}
	
	/**
	 * Very efficient method that translates ICF UID to Dn. In case that the ICF UID is
	 * entryUUID we need to make LDAP search to translate it do DN. DN is needed for operations
	 * such as modify or delete.
	 * 
	 * This is different from searchByUid() method in that it returns only the dn. Therefore
	 * the search may be optimized. The searchByUid() method has to retrieve a complete object.
	 */
	protected Dn resolveDn(ObjectClass objectClass, Uid uid, OperationOptions options) {
		Dn dn;
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapUtil.isDnAttribute(uidAttributeName)) {
			dn = getSchemaTranslator().toDn(uid);
		} else {
			Dn baseDn = getBaseDn(options);
			checkBaseDnPresent(baseDn);
			SearchScope scope = getScope(options);
			AttributeType ldapAttributeType = null;
			SchemaManager schemaManager = getSchemaManager();
			try {
				ldapAttributeType = schemaManager.lookupAttributeTypeRegistry(uidAttributeName);
			} catch (LdapException e) {
				// E.g. ancient OpenLDAP does not have entryUUID in schema
				if (!configuration.isAllowUnknownAttributes()) {
					throw new InvalidAttributeValueException("Cannot find schema for UID attribute "+uidAttributeName, e);
				} 
				ldapAttributeType = schemaTranslator.createFauxAttributeType(uidAttributeName);
			}
			Value ldapValue = getSchemaTranslator().toLdapIdentifierValue(ldapAttributeType, uid.getUidValue());
			ExprNode filterNode = new EqualityNode<Object>(ldapAttributeType, ldapValue);
			LOG.ok("Resolving DN for UID {0}", uid);
			Entry entry = searchSingleEntry(getConnectionManager(), baseDn, filterNode, scope,
					new String[]{uidAttributeName}, "LDAP entry for UID "+uid);
			dn = entry.getDn();
		}
		
		return dn;
	}
	
	/**
	 * The most efficient simple search for a single entry. Follows referrals based on the configured strategy.
	 */
	protected Entry searchSingleEntry(ConnectionManager<C> connectionManager, Dn baseDn, ExprNode filterNode, 
			SearchScope scope, String[] attributesToGet, String descMessage) {
		return searchSingleEntry(connectionManager, baseDn, filterNode, 
				scope, attributesToGet, descMessage, baseDn);
	}
	
	/**
	 * The most efficient simple search for a single entry. Follows referrals based on the configured strategy.
	 * Additional parameter dnHint is used to select the server. But baseDn is still used as a base for search.
	 * This is needed in case where the nameHing in the __NAME__ may be out of date and we need to search by
	 * primary identifier. But we still want to use the nameHint to select the server. Chances are it is still
	 * good for that. 
	 */
	protected Entry searchSingleEntry(ConnectionManager<C> connectionManager, Dn baseDn, ExprNode filterNode, 
			SearchScope scope, String[] attributesToGet, String descMessage, Dn dnHint) {
		
		LdapNetworkConnection connection = connectionManager.getConnection(dnHint);
		String filterString = filterNode.toString();
		
		Entry entry = null;
		int referralAttempts = 0;
		while (referralAttempts < configuration.getMaximumNumberOfAttempts()) {
			referralAttempts++;
			if (OperationLog.isLogOperations()) {
				OperationLog.logOperationReq(connection, "Search REQ base={0}, filter={1}, scope={2}, attributes={3}, controls=null, dnHint={4}",
					baseDn, filterString, scope, Arrays.toString(attributesToGet), dnHint);
			}
			
			SearchRequest searchReq = new SearchRequestImpl();
			searchReq.setBase(baseDn);
			searchReq.setFilter(filterNode);
			searchReq.setScope(scope);
			searchReq.addAttributes(attributesToGet);
			searchReq.setDerefAliases(AliasDerefMode.NEVER_DEREF_ALIASES);
			
			SearchCursor cursor = null;
			try {
				cursor = connection.search(searchReq);
				if (cursor.next()) {
					Response response = cursor.get();
					if (response instanceof SearchResultEntry) {
						entry = ((SearchResultEntry)response).getEntry();
						if (OperationLog.isLogOperations()) {
							OperationLog.logOperationRes(connection, "Search RES {0}", entry);
						}
						break;
					}
				} else {
					// Something wrong happened, the entry was not created.
					throw new UnknownUidException(descMessage + " was not found");
				}
			} catch (CursorLdapReferralException e) {
				LOG.ok("Got cursor referral exception while resolving {0}: {1}", descMessage, e.getReferralInfo());
				if (configuration.isReferralStrategyFollow()) {
					LdapUrl referralUrl;
					try {
						referralUrl = new LdapUrl(e.getReferralInfo());
					} catch (LdapURLEncodingException ee) {
						throw new InvalidAttributeValueException("Invalid URL in referral '"+e.getReferralInfo()+": "+ee.getMessage(), ee);
					}
					connection = connectionManager.getConnection(baseDn, referralUrl);
					if (referralUrl.getDn() != null) {
						baseDn = referralUrl.getDn();
					}
					if (LOG.isOk()) {
						LOG.ok("Following referral to {0} / {1}", LdapUtil.formatConnectionInfo(connection), baseDn);
					}
				} else if (configuration.isReferralStrategyIgnore()) {
					// We cannot really "ignore" this referral otherwise we cannot resolve DN
					throw new ConfigurationException("Got referral to "+e.getReferralInfo()+" while resolving DN. "
							+ "The referral strategy is set to ignore therefore we cannot follow the referral and complete"
							+ " DN resolving.");
				} else {
					throw new ConnectorIOException("Error reading "+descMessage+": "+e.getMessage(), e);
				}
			} catch (LdapException e) {
				throw processLdapException("Error reading "+descMessage, e);
			} catch (CursorException e) {
				throw new ConnectorIOException("Error reading "+descMessage+": "+e.getMessage(), e);
			} finally {
				if (cursor != null) {
					LdapUtil.closeCursor(cursor);
				}
			}
		}
		return entry;

	}
 
	@Override
	public void checkAlive() {
		if (!connectionManager.isAlive()) {
			LOG.ok("check alive: FAILED");
			throw new ConnectorException("Connection check failed");
		}
		LOG.ok("check alive: OK");
	}

	@Override
    public void dispose() {
		LOG.info("Disposing {0} connector instance {1}", this.getClass().getSimpleName(), this);
        configuration = null;
        if (connectionManager != null) {
        	try {
				connectionManager.close();
			} catch (IOException e) {
				throw new ConnectorIOException(e.getMessage(), e);
			}
            connectionManager = null;
            schemaManager = null;
            schemaTranslator = null;
        } else {
        	LOG.ok("Not closing connection because connection manager is already null");
        }
    }

	protected RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
		return LdapUtil.processLdapException(connectorMessage, ldapException);
	}
	
	protected RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
		return LdapUtil.processLdapResult(connectorMessage, ldapResult);
	}

}
