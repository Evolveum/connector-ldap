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

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ErrorHandler;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.schema.ReferenceAttributeTranslator;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;



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
    protected ReferenceAttributeTranslator referenceAttributeHandler = null;

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

    protected Entry fetchEntry(LdapNetworkConnection connection, String dn,
                                   org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                   OperationOptions options) {
        String[] attributesToGet = schemaTranslator.determineAttributesToGet(ldapObjectClass, options);
        Entry entry = null;
        LOG.ok("Search REQ base={0}, filter={1}, scope={2}, attributes={3}",
                dn, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT, attributesToGet);

        try {
            entry = connection.lookup( dn, attributesToGet );
        } catch (LdapException e) {
            LOG.error("Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
            throw errorHandler.processLdapException("Search for "+dn+" failed", e);
        }

        LOG.ok("Search RES {0}", entry);

        return entry;
    }

    public Entry fetchEntryByUid(LdapNetworkConnection connection, String uid,
                                        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                        OperationOptions options) {
        String[] attributesToGet = getSchemaTranslator().determineAttributesToGet(ldapObjectClass, options);
        ExprNode filter = getSchemaTranslator().createUidSearchFilter(uid, ldapObjectClass);
        return searchSingleEntry(connection, configuration.getBaseContext(), SearchScope.SUBTREE, filter, attributesToGet);
    }

    public Entry searchSingleEntry(LdapNetworkConnection connection, String baseDn, SearchScope scope,
                                          ExprNode filter, String[] attributesToGet) {
        SearchRequest req = new SearchRequestImpl();
        try {
            req.setBase(new Dn(baseDn));
        } catch (LdapInvalidDnException e) {
            throw new IllegalArgumentException(e.getMessage(), e);
        }
        req.setScope(scope);
        req.setFilter(filter);
        if (attributesToGet != null) {
            req.addAttributes(attributesToGet);
        }
        Entry entry = null;
        try {
            SearchCursor searchCursor = connection.search(req);
            while (searchCursor.next()) {
                Response response = searchCursor.get();
                if (response instanceof SearchResultEntry) {
                    if (entry != null) {
                        LOG.error("Search for {0} in {1} (scope {2}) returned more than one entry:\n{1}",
                                filter, baseDn, scope, searchCursor.get());
                        throw new IllegalStateException("Search for "+filter+" in "+baseDn+" returned unexpected entries");
                    }
                    entry = ((SearchResultEntry)response).getEntry();
                }
            }
            LdapUtil.closeDoneCursor(searchCursor);
        } catch (LdapException e) {
            throw errorHandler.processLdapException("Search for "+filter+" in "+baseDn+" failed", e);
        } catch (CursorException e) {
            throw new ConnectorIOException("Search for "+filter+" in "+baseDn+" failed: "+e.getMessage(), e);
        }
        if (entry == null) {
            // This is a suspicious situation. The caller usually assumes that an entry will be found.
            // If nothing is found, it may be a permission problem, or something similar, which is usually hard to diagnose.
            // Let's help the poor engineer by logging the details of the search.
            LOG.ok("Search for single entry baseDn={0}, scope={1}, filter={2} returned no result", baseDn, scope, filter);
        }
        return entry;
    }
}
