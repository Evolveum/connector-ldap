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

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.exclamationlabs.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * Very simple search without any controls (paging). The most efficient thing to do.
 *
 * @author Radovan Semancik
 */
public class DefaultSearchStrategy<C extends AbstractLdapConfiguration> extends SearchStrategy<C> {

    private static final Log LOG = Log.getLog(DefaultSearchStrategy.class);

    public DefaultSearchStrategy(ConnectionManager<C> connectionManager, AbstractLdapConfiguration configuration,
                                 AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
                                 org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                 ResultsHandler handler, ErrorHandler errorHandler, ConnectionLog connectionLog,
                                 OperationOptions options) {
        super(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, errorHandler, connectionLog, options);
    }

    /* (non-Javadoc)
     * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.identityconnectors.framework.common.objects.ResultsHandler)
     */
    @Override
    public void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException {
        SearchRequest req = new SearchRequestImpl();
        req.setBase(baseDn);
        req.setFilter(preProcessSearchFilter(filterNode));
        req.setScope(scope);
        applyCommonConfiguration(req);
        if (attributes != null) {
            req.addAttributes(attributes);
        }

        connect(baseDn);
        Referral referral = null; // remember this in case we need a reconnect

        OUTER: while (true) {
            incrementRetryAttempts();

            int responseResultCount = 0;
            SearchCursor searchCursor = executeSearch(req);
            try {
                while (true) {
                    try {
                        if (!searchCursor.next()) {
                            break;
                        }
                    } catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
                        logSearchError(req, responseResultCount, e);
                        // Server disconnected. And by some miracle this was not caught by
                        // checkAlive or connection manager.
                        LOG.ok("Connection error ({0}), reconnecting", e.getMessage(), e);
                        // No need to close the cursor here. It is already closed as part of error handling in next() method.
                        connectionReconnect(baseDn, e);
                        continue OUTER;
                    }
                    Response response = searchCursor.get();
                    if (response instanceof SearchResultEntry) {
                        responseResultCount++;
                        Entry entry = ((SearchResultEntry)response).getEntry();
                        logSearchResult(entry);
                        boolean handlerProceed = handleResult(entry);
                        if (!handlerProceed) {
                            LOG.ok("Ending search because handler returned false");
                            // Try to get next entry before going for abandon.
                            // Chances are that the search will end in a natural way anyway.
                            // In fact, this happens quite a lot for searches that expect just a single entry as result.
                            // E.g. search using primary identifier (entryUUID).
                            // The handler returns false, as it is satisfied with a single result.
                            // The LDAP server is done with the search as well, with "done" message waiting in the queue (cursor).
                            // We want to give the Directory API a change to read and process the "done" message.
                            // In that case the cursor will be closed quietly, and we do not have to do explicit abandon.
                            searchCursor.next();
                            // We do not really care what entry the cursor points at this point.
                            // If it is "done" entry, the cursor is closed already and the next command will NOT issue an abandon.
                            // It it is a regular entry, then the abandon is in order and the following attempt to close the cursor will do it.
                            LdapUtil.closeAbandonCursor(searchCursor);
                            break;
                        }

                    } else {
                        LOG.warn("Got unexpected response: {0}", response);
                    }
                }

                SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
                // We really want to call searchCursor.next() here, even though we do not care about the result.
                // The implementation of cursor.next() sets the "done" status of the cursor.
                // If we do not do that, the subsequent close() operation on the cursor will send an
                // ABANDON command, even though the operation is already finished. (MID-7091)
                searchCursor.next();
                // We want to do close with ABANDON here, in case that the operation is not finished.
                // However, make sure we call searchCursor.next() before closing, we do not want to send abandons when not needed.
                LdapUtil.closeAbandonCursor(searchCursor);

                logSearchOperationDone(req, responseResultCount, searchResultDone);
                if (searchResultDone == null) {
                    break;
                } else {
                    LdapResult ldapResult = searchResultDone.getLdapResult();
                    logSearchResult("Done", searchResultDone.getLdapResult());

                    if (ldapResult.getResultCode() == ResultCodeEnum.REFERRAL) {
                        referral = ldapResult.getReferral();
                        LOG.ok("Ignoring referral {0}", referral);

                    } else if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
                        break;

                    } else {
                        String msg = "LDAP error during search: "+LdapUtil.formatLdapMessage(ldapResult);
                        if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
                            LOG.ok("{0} (allowed error)", msg);
                            setCompleteResultSet(false);
                            break;
                        } else {
                            RuntimeException connidException = processLdapResult("LDAP error during search in " + baseDn, ldapResult);
                            if (connidException instanceof ReconnectException) {
                                reconnectSameServer(connidException);
                                // Next iteration of the loop will re-try the operation with the same parameter, but different connection
                                continue OUTER;
                            } else {
                                LOG.error("{0}", msg);
                                returnConnection();
                                throw connidException;
                            }
                        }
                    }

                }

            } catch (CursorException e) {
                returnConnection();
                // TODO: better error handling ?
                throw new ConnectorIOException(e.getMessage(), e);
            }
        }

        returnConnection();
    }

    @Override
    protected String getStrategyTag() {
        // null means default, absolutely normal LDAP search
        return null;
    }

}
