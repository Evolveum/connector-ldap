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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.BindResponse;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.DefaultSchemaLoader;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.future.SearchFuture;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
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
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SimpleSearchStrategy;

@ConnectorClass(displayNameKey = "ldap.connector.display", configurationClass = LdapConfiguration.class)
public class LdapConnector implements PoolableConnector, TestOp, SchemaOp, SearchOp<Filter>, CreateOp, DeleteOp, 
		UpdateAttributeValuesOp, SyncOp{

    private static final Log LOG = Log.getLog(LdapConnector.class);


	private static final String SEARCH_FILTER_ALL = "(objectclass=*)";
    

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
		// TODO
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
    
    private SchemaTranslator getShcemaTranslator() {
    	if (schemaTranslator == null) {
    		schemaTranslator = new SchemaTranslator(getSchemaManager(), configuration);
    	}
    	return schemaTranslator;
    }

    @Override
	public Schema schema() {
		return getShcemaTranslator().translateSchema();
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
		SchemaTranslator shcemaTranslator = getShcemaTranslator();
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = schemaTranslator.toLdapObjectClass(objectClass);
		
		if (icfFilter != null && (icfFilter instanceof EqualsFilter) && Name.NAME.equals(((EqualsFilter)icfFilter).getName())) {
			// Search by __NAME__, which means DN. This translated to a base search.
			String dn = SchemaUtil.getSingleStringNonBlankValue(((EqualsFilter)icfFilter).getAttribute());
			// We know that this can return at most one object. Therefore always use simple search.
			SearchStrategy searchStrategy = getSimpleSearchStrategy(handler);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			try {
				searchStrategy.search(dn, null, SearchScope.OBJECT, attributesToGet);
			} catch (LdapException e) {
				handleLdapException(e);
			}
			return;
			
		} else {
			String baseDn = getBaseDn(options);
			ExprNode filterNode = null;
			if (icfFilter != null) {
				LdapFilterTranslator filterTranslator = new LdapFilterTranslator(getShcemaTranslator(), ldapObjectClass);
				filterNode = filterTranslator.translate(icfFilter);
			}
			SearchStrategy searchStrategy = chooseSearchStrategy(handler, options);
			SearchScope scope = getScope(options);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			try {
				searchStrategy.search(baseDn, filterNode, scope, attributesToGet);
			} catch (LdapException e) {
				handleLdapException(e);
			}
			return;
		}
	}

	private void handleLdapException(LdapException e) {
		// TODO better error handling
		throw new ConnectorIOException(e.getMessage(), e);
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
			return null;
		}
		String[] icfAttrs = options.getAttributesToGet();
		String[] ldapAttrs = new String[icfAttrs.length];
		int i = 0;
		for (String icfAttr: icfAttrs) {
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr);
			ldapAttrs[i] = ldapAttributeType.getName();
			i++;
		}
		return ldapAttrs;
	}
	
	private SearchStrategy chooseSearchStrategy(ResultsHandler handler, OperationOptions options) {
		// TODO
		return getSimpleSearchStrategy(handler);
	}
	
	private SearchStrategy getSimpleSearchStrategy(ResultsHandler handler) {
		return new SimpleSearchStrategy(connection, configuration, getShcemaTranslator(), handler);
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
		
		SchemaTranslator shcemaTranslator = getShcemaTranslator();
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
			throw new ConnectorIOException("Error adding LDAP entry "+dn+": "+e.getMessage(), e);
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
			EntryCursor cursor = connection.search(dn, SEARCH_FILTER_ALL, SearchScope.OBJECT, uidAttributeName);
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
			throw new ConnectorIOException("Error reading LDAP entry "+dn+": "+e.getMessage(), e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error reading LDAP entry "+dn+": "+e.getMessage(), e);
		}
		
		return uid;
	}

	
    @Override
	public Uid update(ObjectClass objectClass, Uid uid, Set<Attribute> replaceAttributes,
			OperationOptions options) {
    	
    	ldapUpdate(objectClass, uid, replaceAttributes, options, ModificationOperation.REPLACE_ATTRIBUTE);
    	
    	return uid;
	}

	@Override
	public void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler,
			OperationOptions options) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		// TODO Auto-generated method stub
		throw new UnsupportedOperationException("TODO");
	}

	@Override
	public Uid addAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> valuesToAdd,
			OperationOptions options) {
		
		ldapUpdate(objectClass, uid, valuesToAdd, options, ModificationOperation.ADD_ATTRIBUTE);
		
		return uid;
	}
	
	private Uid ldapUpdate(ObjectClass objectClass, Uid uid, Set<Attribute> values,
			OperationOptions options, ModificationOperation modOp) {
		
		String dn = resolveDn(objectClass, uid, options);
		
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = schemaTranslator.toLdapObjectClass(objectClass);
		Modification[] modifications = new Modification[values.size()];
		int i = 0;
		for (Attribute icfAttr: values) {
			AttributeType attributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr.getName());
			List<Value<Object>> ldapValues = schemaTranslator.toLdapValues(attributeType, icfAttr.getValue());
			try {
				modifications[i] = new DefaultModification(modOp, attributeType, ldapValues.toArray(new Value[ldapValues.size()]));
			} catch (LdapInvalidAttributeValueException e) {
				throw new InvalidAttributeValueException("Invalid modification value for LDAP attribute "+attributeType.getName()+": "+e.getMessage(), e);
			}
		}
		
		try {
			connection.modify(dn, modifications);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error modifying entry "+dn+": "+e.getMessage(), e);
		}
		
		return uid;
	}

	@Override
	public Uid removeAttributeValues(ObjectClass objectClass, Uid uid, Set<Attribute> valuesToRemove,
			OperationOptions options) {

    	ldapUpdate(objectClass, uid, valuesToRemove, options, ModificationOperation.REMOVE_ATTRIBUTE);
    	
    	return uid;
	}

	@Override
	public void delete(ObjectClass objectClass, Uid uid, OperationOptions options) {
		
		String dn = resolveDn(objectClass, uid, options);
		
		try {
			connection.delete(dn);
		} catch (LdapException e) {
			throw new ConnectorIOException("Failed to delete entry with DN "+dn+" (UID="+uid+"): "+e.getMessage(), e);
		}
	}
	
	private String resolveDn(ObjectClass objectClass, Uid uid, OperationOptions options) {
		String dn;
		String uidAttributeName = configuration.getUidAttribute();
		if (LdapConfiguration.ATTRIBUTE_NAME_DN.equals(uidAttributeName)) {
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
				throw new ConnectorIOException("Error reading LDAP entry for UID "+uid+": "+e.getMessage(), e);
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
			throw new ConnectorIOException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+": "+e.getMessage(), e);
		}
		
//		LOG.ok("Fetching root DSE");
//		connection.getRootDse();

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
			throw new ConnectorIOException("Unable to bind to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" as "+bindDn+": "+e.getMessage(), e);
		}
		LOG.info("Bound to {0}", bindDn);
    }
    	
}
