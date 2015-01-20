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

package com.evolveum.polygon;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.model.exception.LdapException;
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
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.TestOp;

@ConnectorClass(displayNameKey = "ldap.connector.display", configurationClass = LdapConfiguration.class)
public class LdapConnector implements PoolableConnector, TestOp, SchemaOp {

    private static final Log LOG = Log.getLog(LdapConnector.class);
    private static final Map<String, Class<?>> SYNTAX_MAP = new HashMap<String,Class<?>>(); 

    private LdapConfiguration configuration;
    private LdapNetworkConnection connection;

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

    @Override
	public Schema schema() {
		try {
			connection.loadSchema();
		} catch (LdapException e) {
			throw new ConnectorIOException(e.getMessage(), e);
		}
		SchemaManager schemaManager = connection.getSchemaManager();
		SchemaBuilder schemaBuilder = new SchemaBuilder(LdapConnector.class);
		for (org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass: schemaManager.getObjectClassRegistry()) {
			ObjectClassInfoBuilder ocib = new ObjectClassInfoBuilder();
			ocib.setType(ldapObjectClass.getName());
			addAttributeTypes(ocib, ldapObjectClass.getMustAttributeTypes(), true);
			addAttributeTypes(ocib, ldapObjectClass.getMayAttributeTypes(), false);
			schemaBuilder.defineObjectClass(ocib.build());
		}
		return schemaBuilder.build();
	}
    
    
    private Class<?> toIcfType(LdapSyntax syntax) {
    	Class<?> type = SYNTAX_MAP.get(syntax.getName());
    	if (type == null) {
    		LOG.warn("No type mapping for syntax {0}, using string", syntax.getName());
    		return String.class;
    	} else {
    		return type;
    	}
	}

	private void addAttributeTypes(ObjectClassInfoBuilder ocib, List<AttributeType> attributeTypes, boolean isRequired) {
		for (AttributeType ldapAttribute: attributeTypes) {
			AttributeInfoBuilder aib = new AttributeInfoBuilder(ldapAttribute.getName());
			aib.setRequired(isRequired);
			aib.setType(toIcfType(ldapAttribute.getSyntax()));
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
			ocib.addAttributeInfo(aib.build());
		}
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
	
	static {
		SYNTAX_MAP.put("TODO",String.class);
	}

}
