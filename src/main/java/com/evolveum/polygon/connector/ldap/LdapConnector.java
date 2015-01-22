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

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.TestOp;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SimpleSearchStrategy;

@ConnectorClass(displayNameKey = "ldap.connector.display", configurationClass = LdapConfiguration.class)
public class LdapConnector implements PoolableConnector, TestOp, SchemaOp, SearchOp<Filter> {

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
    			connection.loadSchema();
    		} catch (LdapException e) {
    			throw new ConnectorIOException(e.getMessage(), e);
    		}
    		schemaManager = connection.getSchemaManager();
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
	
	// TODO: methods
    
    
    


	private void connect() {
    	final LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
    	connectionConfig.setLdapHost(configuration.getHost());
    	connectionConfig.setLdapPort(configuration.getPort());
    	connectionConfig.setName(configuration.getBindDn());
    	
    	GuardedString bindPassword = configuration.getBindPassword();
    	if (bindPassword != null) {
    		// I hate this GuardedString!
    		bindPassword.access(new GuardedString.Accessor() {
				@Override
				public void access(char[] chars) {
					connectionConfig.setCredentials(new String(chars));
				}
			});
    	}
    	
		connection = new LdapNetworkConnection(connectionConfig);
		try {
			boolean connected = connection.connect();
			if (!connected) {
				throw new ConnectorIOException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
			}
		} catch (LdapException e) {
			throw new ConnectorIOException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+": "+e.getMessage(), e);
		}
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
	
	
}
