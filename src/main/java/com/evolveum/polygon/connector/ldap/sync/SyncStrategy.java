/*
 * Copyright (c) 2015-2020 Evolveum
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
package com.evolveum.polygon.connector.ldap.sync;

import com.evolveum.polygon.connector.ldap.ErrorHandler;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public abstract class SyncStrategy<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(SyncStrategy.class);

    private final AbstractLdapConfiguration configuration;
    private final ConnectionManager<C> connectionManager;
    private final SchemaManager schemaManager;
    private final AbstractSchemaTranslator<C> schemaTranslator;
    private final ErrorHandler errorHandler;

    public SyncStrategy(AbstractLdapConfiguration configuration, ConnectionManager<C> connectionManager,
            SchemaManager schemaManager, AbstractSchemaTranslator<C> schemaTranslator, ErrorHandler errorHandler) {
        super();
        this.configuration = configuration;
        this.connectionManager = connectionManager;
        this.schemaManager = schemaManager;
        this.schemaTranslator = schemaTranslator;
        this.errorHandler = errorHandler;
    }

    public AbstractLdapConfiguration getConfiguration() {
        return configuration;
    }

    public ConnectionManager<C> getConnectionManager() {
        return connectionManager;
    }

    public SchemaManager getSchemaManager() {
        return schemaManager;
    }

    public AbstractSchemaTranslator getSchemaTranslator() {
        return schemaTranslator;
    }

    public abstract void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler, OperationOptions options);

    public abstract SyncToken getLatestSyncToken(ObjectClass objectClass);

    public ErrorHandler getErrorHandler() {
        return errorHandler;
    }

    protected boolean isAcceptableForSynchronization(Entry entry,
                                                     org.apache.directory.api.ldap.model.schema.ObjectClass requiredldapObjectClass,
                                                     String[] modifiersNamesToFilterOut) {
        if (requiredldapObjectClass != null) {
            if (!LdapUtil.isObjectClass(entry, requiredldapObjectClass)) {
                LOG.ok("Skipping synchronization of entry {0} because object class does not match", entry.getDn());
                return false;
            }
        }
        if (modifiersNamesToFilterOut != null && modifiersNamesToFilterOut.length > 0) {
            if (LdapUtil.hasModifierName(entry, modifiersNamesToFilterOut)) {
                LOG.ok("Skipping synchronization of entry {0} because modifiers name is filtered out", entry.getDn());
                return false;
            }
        }
        return true;
    }

    protected void returnConnection(LdapNetworkConnection connection) {
        connectionManager.returnConnection(connection);
    }

    protected String determineSyncBaseContext() {
        if (getConfiguration().getBaseContextToSynchronize() != null ) {
            return getConfiguration().getBaseContextToSynchronize();
        } else {
            return getConfiguration().getBaseContext();
        }
    }

}
