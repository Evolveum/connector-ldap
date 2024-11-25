/*
 * Copyright (c) 2015-2021 Evolveum
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
package com.exclamationlabs.polygon.connector.ldap.search;

import com.exclamationlabs.polygon.connector.ldap.*;
import com.exclamationlabs.polygon.connector.ldap.connection.ConnectionManager;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortRequestImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SortKey;

import com.exclamationlabs.polygon.connector.ldap.schema.AttributeHandler;
import com.exclamationlabs.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author Radovan Semancik
 *
 */
public abstract class SearchStrategy<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(SearchStrategy.class);

    private final ConnectionManager<C> connectionManager;
    private final AbstractLdapConfiguration configuration;
    private final AbstractSchemaTranslator<C> schemaTranslator;
    private final ObjectClass objectClass;
    private final org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
    private final ResultsHandler handler;
    private final ErrorHandler errorHandler;
    private final OperationOptions options;
    private boolean isCompleteResultSet = true;
    private AttributeHandler attributeHandler;
    private LdapNetworkConnection explicitConnection = null;
    private int numberOfEntriesFound = 0;
    private int retryAttempts = 0;
    protected LdapNetworkConnection connection;
    private final ConnectionLog connectionLog;

    protected SearchStrategy(ConnectionManager<C> connectionManager, AbstractLdapConfiguration configuration,
            AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
            ResultsHandler handler, ErrorHandler errorHandler, ConnectionLog connectionLog, OperationOptions options) {
        super();
        this.connectionManager = connectionManager;
        this.configuration = configuration;
        this.schemaTranslator = schemaTranslator;
        this.objectClass = objectClass;
        this.ldapObjectClass = ldapObjectClass;
        this.handler = handler;
        this.errorHandler = errorHandler;
        this.connectionLog = connectionLog;
        this.options = options;
    }

    public ConnectionManager<C> getConnectionManager() {
        return connectionManager;
    }

    public AbstractLdapConfiguration getConfiguration() {
        return configuration;
    }

    public OperationOptions getOptions() {
        return options;
    }

    public AbstractSchemaTranslator getSchemaTranslator() {
        return schemaTranslator;
    }

    public ObjectClass getObjectClass() {
        return objectClass;
    }

    public org.apache.directory.api.ldap.model.schema.ObjectClass getLdapObjectClass() {
        return ldapObjectClass;
    }

    public abstract void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException;

    public int getRemainingPagedResults() {
        return -1;
    }

    public String getPagedResultsCookie() {
        return null;
    }

    public boolean isCompleteResultSet() {
        return isCompleteResultSet;
    }

    public void setCompleteResultSet(boolean isCompleteResultSet) {
        this.isCompleteResultSet = isCompleteResultSet;
    }

    public AttributeHandler getAttributeHandler() {
        return attributeHandler;
    }

    public void setAttributeHandler(AttributeHandler attributeHandler) {
        this.attributeHandler = attributeHandler;
    }

    protected abstract String getStrategyTag();

    public boolean allowPartialResults() {
        if (options == null) {
            return false;
        }
        return options.getAllowPartialResults() == Boolean.TRUE;
    }

    public boolean allowPartialAttributeValues() {
        if (options == null) {
            return false;
        }
        return options.getAllowPartialAttributeValues() == Boolean.TRUE;
    }

    protected int getDefaultPageSize() {
        return configuration.getPagingBlockSize();
    }

    public LdapNetworkConnection getExplicitConnection() {
        return explicitConnection;
    }

    public void setExplicitConnection(LdapNetworkConnection explicitConnection) {
        this.explicitConnection = explicitConnection;
    }

    public int getNumberOfEntriesFound() {
        return numberOfEntriesFound;
    }

    protected void applyCommonConfiguration(SearchRequest req) {
        req.ignoreReferrals();
        req.setDerefAliases(AliasDerefMode.NEVER_DEREF_ALIASES);
    }

    protected SearchCursor executeSearch(SearchRequest req) throws LdapException {
        if (req.getFilter() == null) {
            req.setFilter(LdapConfiguration.SEARCH_FILTER_ALL);
        }
        logSearchRequest(req);
        SearchCursor searchCursor;
        try {
            searchCursor = connection.search(req);
        } catch (LdapReferralException e) {
            logSearchError(req, 0, e);
            returnConnection();
            LOG.ok("Ignoring referral {0}", e.getReferralInfo());
            return null;
        } catch (LdapException e) {
            logSearchError(req, 0, e);
            returnConnection();
            throw e;
        }
        return searchCursor;
    }

    protected void logSearchRequest(SearchRequest req) {
        if (LOG.isOk()) {
            OperationLog.logOperationReq(connection, "Search REQ base={0}, filter={1}, scope={2}, attributes={3}, controls={4}",
                    req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), LdapUtil.toShortString(req.getControls()));
        }
    }

    protected void logSearchResult(Entry entry) {
        if (LOG.isOk()) {
            OperationLog.logOperationRes(connection, "Search RES {0}", entry);
        }
    }

    protected void logSearchOperationDone(SearchRequest req, Integer numEntries, SearchResultDone searchResultDone) {
        if (searchResultDone == null) {
            connectionLog.searchWarning(connection, req, numEntries, getStrategyTag(), "Search ended without DONE message");
        } else {
            connectionLog.searchSuccess(connection, req, numEntries, getStrategyTag());
            // TODO: referral?
        }
    }

    protected void logSearchResult(String type, LdapResult ldapResult, String extra) {
        if (LOG.isOk()) {
            OperationLog.logOperationRes(connection, "Search RES {0}: {1}\n{2}", type, extra, ldapResult);
        }
    }

    protected void logSearchError(SearchRequest req, Integer numEntries, LdapException e) {
        OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
        connectionLog.searchError(connection, e, req, numEntries, getStrategyTag());
    }

    protected boolean handleResult(Entry entry) {
        numberOfEntriesFound++;
        return handler.handle(schemaTranslator.toConnIdObject(connection, objectClass, entry, attributeHandler, options));
    }

    protected void logSearchResult(String type, LdapResult ldapResult) {
        if (LOG.isOk()) {
            OperationLog.logOperationRes(connection, "Search RES {0}:\n{1}", type, ldapResult);
        }
    }

    protected boolean hasSortOption() {
        return getOptions() != null && getOptions().getSortKeys() != null && getOptions().getSortKeys().length > 0;
    }

    protected SortRequest createSortControl(String defaultSortLdapAttribute, String defaultSortOrderingRule) {
        SortRequest sortReqControl = null;
        if (hasSortOption()) {
            sortReqControl = new SortRequestImpl();
            sortReqControl.setCritical(true);
            for (SortKey icfSortKey: getOptions().getSortKeys()) {
                AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), icfSortKey.getField());
                String attributeTypeDesc = attributeType.getName();
                String matchingRuleId = attributeType.getOrderingOid();
                if (matchingRuleId == null) {
                    matchingRuleId = defaultSortOrderingRule;
                }
                boolean reverseOrder = !icfSortKey.isAscendingOrder();
                org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey =
                        new org.apache.directory.api.ldap.model.message.controls.SortKey(attributeTypeDesc, matchingRuleId, reverseOrder);
                sortReqControl.addSortKey(ldapSortKey);
            }
        } else if (defaultSortLdapAttribute != null) {
            sortReqControl = new SortRequestImpl();
            AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), defaultSortLdapAttribute);
            String matchingRuleId = attributeType.getOrderingOid();
            if (matchingRuleId == null) {
                matchingRuleId = defaultSortOrderingRule;
            }
            org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey =
                    new org.apache.directory.api.ldap.model.message.controls.SortKey(defaultSortLdapAttribute, matchingRuleId, false);
            sortReqControl.addSortKey(ldapSortKey);
        }
        return sortReqControl;
    }

    protected void connect(Dn base) {
        if (explicitConnection == null) {
            connection = connectionManager.getConnection(getEffectiveBase(base), options);
        } else {
            connection = explicitConnection;
        }
    }

    protected void connectionReconnect(Dn base, Exception reconnectReason) {
        if (explicitConnection != null) {
            return;
        }
        connectionManager.returnConnection(connection);
        connection = connectionManager.getConnectionReconnect(connection, getEffectiveBase(base), options, reconnectReason);
    }

    /**
     * Forces reconnect of current connection, reusing the same connection parameters (server, DN, etc.)
     * This method is used if there is a problem with the connection and the operation has to be re-tried on the same server.
     */
    protected void reconnectSameServer(Exception reason) {
        connection = connectionManager.reconnect(connection, reason);
    }

    private Dn getEffectiveBase(Dn origBase) {
        if (origBase.isSchemaAware()) {
            return origBase;
        } else {
            // Insanity such as <GUID=....>. No good using that to select
            // the connection. Try to use the container from options instead.
            if (options != null && options.getContainer() != null) {
                QualifiedUid containerQUid = options.getContainer();
                // HACK WARNING: this is a hack to overcome bad framework design.
                // Even though this has to be Uid, we interpret it as a DN.
                // The framework uses UID to identify everything. This is naive.
                // Strictly following the framework contract would mean to always
                // do two LDAP searches instead of one in this case.
                // So we deviate from the contract here. It is naughty, but it
                // is efficient.
                return schemaTranslator.toDn(containerQUid.getUid());
            } else {
                return origBase;
            }
        }
    }

    protected void returnConnection() {
        connectionManager.returnConnection(connection);
    }

    protected ExprNode preProcessSearchFilter(ExprNode filterNode) {
        return filterNode;
    }

    public ErrorHandler getErrorHandler() {
        return errorHandler;
    }

    public ConnectionLog getConnectionLog() { return connectionLog; }

    protected RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
        return getErrorHandler().processLdapException(connectorMessage, ldapException);
    }

    protected RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
        return getErrorHandler().processLdapResult(connectorMessage, ldapResult);
    }

    protected void incrementRetryAttempts() {
        retryAttempts++;
        if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
            returnConnection();
            // TODO: better exception. Maybe re-throw exception from the last error?
            throw new ConnectorIOException("Maximum number of attempts exceeded");
        }
    }
}
