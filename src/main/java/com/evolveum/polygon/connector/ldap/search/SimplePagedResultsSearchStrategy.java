/*
 * Copyright (c) 2014-2021 Evolveum
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
package com.evolveum.polygon.connector.ldap.search;

import java.util.Base64;

import com.evolveum.polygon.connector.ldap.*;
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
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.PagedResultsImpl;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class SimplePagedResultsSearchStrategy<C extends AbstractLdapConfiguration> extends SearchStrategy<C> {

    private static final Log LOG = Log.getLog(SimplePagedResultsSearchStrategy.class);

    private int lastListSize = -1;
    private byte[] cookie = null;
    private LdapNetworkConnection connection;

    public SimplePagedResultsSearchStrategy(ConnectionManager<C> connectionManager,
                                            AbstractLdapConfiguration configuration, AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
                                            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
                                            ResultsHandler handler, ErrorHandler errorHandler, OperationOptions options) {
        super(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, errorHandler, options);
        if (options != null && options.getPagedResultsCookie() != null) {
            cookie = Base64.getDecoder().decode(options.getPagedResultsCookie());
        }
    }

    /* (non-Javadoc)
     * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
     */
    @Override
    public void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes)
            throws LdapException {

        SortRequest sortReqControl = createSortControl(null, null);

        int pageSize = getDefaultPageSize();
        int offset = 0;
        if (getOptions() != null && getOptions().getPagedResultsOffset() != null) {
            offset = getOptions().getPagedResultsOffset() - 1;
            if (offset != 0) {
                LOG.info("Inefficient search using SimplePaged control and offset {0}",offset);
            }
        }


        boolean proceed = true;
        int numberOfResutlsHandled = 0;
        int numberOfResultsSkipped = 0;

        connect(baseDn);
        Referral referral = null; // remember this in case we need a reconnect

        OUTER: do {
            if (getOptions() != null && getOptions().getPageSize() != null &&
                    ((numberOfResutlsHandled + numberOfResultsSkipped + pageSize) > offset + getOptions().getPageSize())) {
                pageSize = offset + getOptions().getPageSize() - (numberOfResutlsHandled + numberOfResultsSkipped);
            }

            SearchRequest req = prepareSearchRequest(baseDn, filterNode, scope, attributes, "LDAP search request", sortReqControl, pageSize);

            int responseResultCount = 0;
            SearchCursor searchCursor = executeSearch(req);
            try {
                while (proceed) {
                    try {
                        if (!searchCursor.next()) {
                            break;
                        }
                    } catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
                        logSearchError(e);
                        // Server disconnected. And by some miracle this was not caught by
                        // checkAlive or connection manager.
                        LOG.ok("Connection error ({0}), reconnecting", e.getMessage(), e);
                        LdapUtil.closeDoneCursor(searchCursor);
                        connectionReconnect(baseDn, referral);
                        incrementRetryAttempts();
                        continue OUTER;
                    }
                    Response response = searchCursor.get();
                    if (response instanceof SearchResultEntry) {
                        responseResultCount++;
                        if (offset > numberOfResultsSkipped) {
                            numberOfResultsSkipped++;
                            // skip processing
                        } else {
                            numberOfResutlsHandled++;
                            Entry entry = ((SearchResultEntry)response).getEntry();
                            logSearchResult(entry);
                            proceed = handleResult(entry);
                            if (!proceed) {
                                LOG.ok("Ending search because handler returned false");
                                // We really want to abandon the operation here.
                                LdapUtil.closeAbandonCursor(searchCursor);
                                break;
                            }
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

                if (searchResultDone != null) {
                    LdapResult ldapResult = searchResultDone.getLdapResult();
                    PagedResults pagedResultsResponseControl = (PagedResults)searchResultDone.getControl(PagedResults.OID);
                    if (pagedResultsResponseControl != null) {
                        cookie = pagedResultsResponseControl.getCookie();
                        if (cookie.length == 0) {
                            cookie = null;
                        }
                        lastListSize = pagedResultsResponseControl.getSize();
                        if (lastListSize == 0) {
                            // RFC2696 specifies zero as "I do not know". We use -1 for that.
                            lastListSize = -1;
                        }
                    } else {
                        LOG.ok("no paged result control in the response");
                        cookie = null;
                        lastListSize = -1;
                    }
                    logSearchResult("Done", ldapResult, compileExtraMessage(pagedResultsResponseControl));

                    if (ldapResult.getResultCode() == ResultCodeEnum.REFERRAL && !getConfiguration().isReferralStrategyThrow()) {
                        referral = ldapResult.getReferral();
                        if (getConfiguration().isReferralStrategyIgnore()) {
                            LOG.ok("Ignoring referral {0}", referral);
                        } else {
                            LOG.ok("Following referral {0}", referral);
                            incrementRetryAttempts();
                            connect(baseDn, referral);
                            if (connection == null) {
                                throw new ConnectorIOException("Cannot get connection based on referral "+referral);
                            }
                            lastListSize = -1;
                            cookie = null;
                            continue;
                        }

                    } else if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
                        // continue the loop

                    } else {
                        String msg = "LDAP error during search: "+LdapUtil.formatLdapMessage(ldapResult);
                        if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
                            LOG.ok("{0} (allowed error)", msg);
                            setCompleteResultSet(false);
                        } else {
                            RuntimeException connidException = processLdapResult("LDAP error during search in " + baseDn, ldapResult);
                            if (connidException instanceof ReconnectException) {
                                reconnectSameServer(connidException.getMessage());
                                incrementRetryAttempts();
                                // Next iteration of the loop will re-try the operation with the same parameter, but different connection
                                // TODO: Handling of cookie and lastListSize is questionable here.
                                // Will the cookie be useful in a new connection? We have to experiment with this to see.
                                // However, these errors are rare, and almost impossible to reproduce in controlled environment.
                                continue;
                            } else {
                                LOG.error("{0}", msg);
                                returnConnection();
                                throw connidException;
                            }
                        }
                        break;
                    }
                }

            } catch (CursorException e) {
                returnConnection();
                // TODO: better error handling
                LOG.error("Error:", e);
                throw new ConnectorIOException(e.getMessage(), e);
            }

            if (responseResultCount == 0) {
                // Zero results returned. This is either a hidden error or end of search.
                LOG.warn("Zero results returned from paged search");
                break;
            }
            if (!proceed) {
                break;
            }
            if (getOptions() != null && getOptions().getPageSize() != null &&
                    ((numberOfResutlsHandled + numberOfResultsSkipped) >= offset + getOptions().getPageSize())) {
                break;
            }
        } while (cookie != null);

        finishSearch(baseDn, filterNode, scope, attributes, sortReqControl);

        returnConnection();
    }

    private String compileExtraMessage(PagedResults pagedResultsResponseControl) {
        if (pagedResultsResponseControl == null) {
            return "no paged response control";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("paged control size=");
        sb.append(pagedResultsResponseControl.getSize());
        if (pagedResultsResponseControl.getCookie() != null) {
            sb.append(" cookie=");
            byte[] cookie = pagedResultsResponseControl.getCookie();
            if (cookie == null) {
                sb.append("null");
            } else {
                sb.append(Base64.getEncoder().encodeToString(cookie));
            }
        }
        return sb.toString();
    }

    private SearchRequest prepareSearchRequest(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes, String messagePrefix, SortRequest sortReqControl, int pageSize) {
        SearchRequest req = new SearchRequestImpl();
        req.setBase(baseDn);
        req.setFilter(preProcessSearchFilter(filterNode));
        req.setScope(scope);
        applyCommonConfiguration(req);
        if (attributes != null) {
            req.addAttributes(attributes);
        }

        if (sortReqControl != null) {
            req.addControl(sortReqControl);
        }

        // Simple Paged Results control

        PagedResults pagedResultsControl = new PagedResultsImpl();
        pagedResultsControl.setCookie(cookie);
        pagedResultsControl.setCritical(true);
        pagedResultsControl.setSize(pageSize);
        if (LOG.isOk()) {
            LOG.ok("{0}: PagedResults( pageSize = {1}, cookie = {2} )", messagePrefix,
                    pageSize, cookie==null?null:Base64.getEncoder().encodeToString(cookie));
        }
        req.addControl(pagedResultsControl);

        return req;
    }

    /**
     * Properly finish the paged search by sending request with size=0 and cookie=lastCookie.
     * Most of the errors in this method are ignored.
     * Error in ending the search is not critical, search was already done.
     * However, we still want to see warnings about the problems.
     */
    private void finishSearch(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes, SortRequest sortReqControl) {
        // Setting pageSize explicitly to zero "abandons" the search request.
        SearchRequest req = prepareSearchRequest(baseDn, filterNode, scope, attributes, "Finish SPR request", sortReqControl, 0);
        SearchCursor searchCursor = null;
        try {
            searchCursor = executeSearch(req);
        } catch (LdapException e) {
            LOG.warn("Error sending request to finish SPR search (ignoring): {0}", e.getMessage(), e);
            return;
        }
        try {
            while (searchCursor.next()) {
                Response response = searchCursor.get();
                LOG.warn("Unexpected finish SPR response (ignoring):\n{0}", response);
            }
            SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
            LdapResult ldapResult = searchResultDone.getLdapResult();
            PagedResults pagedResultsResponseControl = (PagedResults)searchResultDone.getControl(PagedResults.OID);
            logSearchResult("Finish SPR search done", ldapResult, compileExtraMessage(pagedResultsResponseControl));
            LOG.ok("Finish SPR search response done:\n{0}", searchResultDone);
            if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
                LOG.warn("LDAP error during finishing SPR search (ignoring): {0}", LdapUtil.formatLdapMessage(ldapResult));
                return;
            }
        } catch (CursorException e) {
            LOG.warn("Error finishing SPR search", e);
        } catch (LdapException e) {
            logSearchError(e);
        } finally {
            LdapUtil.closeDoneCursor(searchCursor);
        }
    }

    @Override
    public int getRemainingPagedResults() {
        if (lastListSize < 0) {
            return lastListSize;
        } else {
            return lastListSize - getNumberOfEntriesFound();
        }
    }

    @Override
    public String getPagedResultsCookie() {
        if (cookie == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(cookie);
    }



}
