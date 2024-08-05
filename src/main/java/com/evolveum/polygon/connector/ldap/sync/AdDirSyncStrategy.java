/*
 * Copyright (c) 2015-2022 Evolveum
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

import java.util.Arrays;
import java.util.Base64;

import com.evolveum.polygon.connector.ldap.*;
import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncRequestImpl;
import org.apache.directory.api.ldap.extras.controls.ad.AdDirSyncResponse;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeleted;
import org.apache.directory.api.ldap.extras.controls.ad.AdShowDeletedImpl;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;

import com.evolveum.polygon.connector.ldap.ad.AdConstants;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * Active Directory synchronization using the DirSync control.
 *
 * @author semancik
 *
 */
public class AdDirSyncStrategy<C extends AbstractLdapConfiguration> extends SyncStrategy<C> {

    private static final Log LOG = Log.getLog(AdDirSyncStrategy.class);

    public AdDirSyncStrategy(AbstractLdapConfiguration configuration, ConnectionManager<C> connectionManager,
                             SchemaManager schemaManager, AbstractSchemaTranslator<C> schemaTranslator,
                             ErrorHandler errorHandler) {
        super(configuration, connectionManager, schemaManager, schemaTranslator, errorHandler);
    }

    @Override
    public void sync(ObjectClass icfObjectClass, SyncToken fromToken, SyncResultsHandler handler,
            OperationOptions options) {

        ObjectClassInfo icfObjectClassInfo = null;
        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = null;
        //noinspection StatementWithEmptyBody
        if (icfObjectClass.is(ObjectClass.ALL_NAME)) {
            // It is OK to leave the icfObjectClassInfo and ldapObjectClass as null. These need to be determined
            // for every changelog entry anyway
        } else {
            icfObjectClassInfo = getSchemaTranslator().findObjectClassInfo(icfObjectClass);
            if (icfObjectClassInfo == null) {
                throw new InvalidAttributeValueException("No definition for object class "+icfObjectClass);
            }
            ldapObjectClass = getSchemaTranslator().toLdapObjectClass(icfObjectClass);
        }

        String filter = LdapConfiguration.SEARCH_FILTER_ALL;

        if (getConfiguration().getAdditionalSearchFilter() != null) {
            filter = getConfiguration().getAdditionalSearchFilter();
        }

        SearchRequest req = createSearchRequest(filter, fromToken);
        AdShowDeleted showDeletedReqControl = new AdShowDeletedImpl();
        req.addControl(showDeletedReqControl);

        int numFoundEntries = 0;
        int numProcessedEntries = 0;
        byte[] lastEntryCookie = null;

        LdapNetworkConnection connection = getConnectionManager().getConnection(req.getBase(), options);
        if (LOG.isOk()) {
            OperationLog.logOperationReq(connection, "Search(DirSync) REQ base={0}, filter={1}, scope={2}, attributes={3}, controls={4}",
                    req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), LdapUtil.toShortString(req.getControls()));
        }

        try {
            SearchCursor searchCursor = connection.search(req);
            while (searchCursor.next()) {
                Response response = searchCursor.get();
                if (response instanceof SearchResultEntry) {
                    Entry dirSyncEntry = ((SearchResultEntry)response).getEntry();
                    if (LOG.isOk()) {
                        OperationLog.logOperationRes(connection, "Search(DirSync) RES {0}", dirSyncEntry);
                    }
                    numFoundEntries++;

                    byte[] entryCookie = null;
                    AdDirSyncResponse dirSyncRespControl = (AdDirSyncResponse) response.getControl(AdDirSyncResponse.OID);
                    if (dirSyncRespControl != null) {
                        entryCookie = dirSyncRespControl.getCookie();
                        if (entryCookie != null) {
                            lastEntryCookie = entryCookie;
                        }
                    }

                    // Explicitly fetch each object. AD will return only changed attributes.
                    // Not even objectClass is returned on modifications.
                    // Luckily, it looks like we always have objectGUID

                    String targetUid = LdapUtil.getUidValue(dirSyncEntry, ldapObjectClass, getConfiguration(), getSchemaTranslator());

                    SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();

                    SyncToken entryToken = new SyncToken(entryCookie==null?"":Base64.getEncoder().encodeToString(entryCookie));
                    deltaBuilder.setToken(entryToken);

                    boolean isDelted = LdapUtil.getBooleanAttribute(dirSyncEntry, AdConstants.ATTRIBUTE_IS_DELETED, Boolean.FALSE);
                    if (isDelted) {
                        deltaBuilder.setDeltaType(SyncDeltaType.DELETE);
                        deltaBuilder.setUid(new Uid(targetUid));

                    } else {
                        deltaBuilder.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
                        Entry targetEntry = fetchEntryByUid(connection, targetUid, ldapObjectClass, options);
                        LOG.ok("Got target entry based on dirSync, targetUid={0}:\n{1}", targetUid, targetEntry);
                        if (targetEntry == null) {
                            // The entry may not exist any more. Maybe it was already deleted.
                            // Then it may be OK to just ignore this event. The related DELETE event
                            // should be detected separately.
                            continue;
                        }

                        if (!isAcceptableForSynchronization(targetEntry, ldapObjectClass,
                                getConfiguration().getModifiersNamesToFilterOut())) {
                            continue;
                        }

                        ConnectorObject targetObject = getSchemaTranslator().toConnIdObject(connection,
                                icfObjectClassInfo, targetEntry, referenceAttributeHandler);
                        deltaBuilder.setObject(targetObject);
                    }

                    handler.handle(deltaBuilder.build());
                    numProcessedEntries++;
                } else {
                    LOG.ok("Non-entry response: {0}", response);
                }
            }

            SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
            if (searchResultDone != null) {
                if (LOG.isOk()) {
                    OperationLog.logOperationRes(connection, "Search(DirSync) RES Done:\n{0}", searchResultDone);
                }
                LdapResult ldapResult = searchResultDone.getLdapResult();
                if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
                    AdDirSyncResponse dirSyncRespControl = (AdDirSyncResponse) searchResultDone.getControl(AdDirSyncResponse.OID);
                    if (dirSyncRespControl == null) {
                        LOG.warn("No DirSync response control in search done response (sync)");
                    } else {
                        lastEntryCookie = dirSyncRespControl.getCookie();
                        if (lastEntryCookie == null) {
                            LOG.warn("No entry cookie in DirSync response in search done response");
                        }
                    }
                } else {
                    LOG.error("LDAP error during DirSync search: {0}", LdapUtil.formatLdapMessage(ldapResult));
                    returnConnection(connection);
                    throw getErrorHandler().processLdapResult("LDAP error during DirSync search", ldapResult);
                }
            }

            LdapUtil.closeDoneCursor(searchCursor);
            LOG.ok("Search(DirSync) DN {0} with {1}: {2} entries, {3} processed", req.getBase(), req.getFilter(), numFoundEntries, numProcessedEntries);
        } catch (LdapException | CursorException e) {
            OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
            returnConnection(connection);
            throw new ConnectorIOException("Error searching for changes ("+req.getFilter()+"): "+e.getMessage(), e);
        }

        // Send a final token with the time that the scan started. This will stop repeating the
        // last change over and over again.
        // NOTE: this assumes that the clock of client and server are synchronized
        if (handler instanceof SyncTokenResultsHandler && lastEntryCookie != null) {
            SyncToken finalToken = new SyncToken(Base64.getEncoder().encodeToString(lastEntryCookie));
            ((SyncTokenResultsHandler)handler).handleResult(finalToken);
        }

        returnConnection(connection);
    }

    @Override
    public SyncToken getLatestSyncToken(ObjectClass objectClass) {
        byte[] cookie = null;
        SearchRequest req = createSearchRequest("(cn=__entry_like_this_is_unlikely_to_exist__)", null);
        LdapNetworkConnection connection = getConnectionManager().getConnection(req.getBase(), null);
        if (LOG.isOk()) {
            OperationLog.logOperationReq(connection, "Search(DirSync) REQ base={0}, filter={1}, scope={2}, attributes={3}, controls={4}",
                    req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), LdapUtil.toShortString(req.getControls()));
        }
        try {
            SearchCursor searchCursor = connection.search(req);
            while (searchCursor.next()) {
                Response response = searchCursor.get();
                if (response instanceof SearchResultEntry) {
                    Entry entry = ((SearchResultEntry)response).getEntry();
                    if (LOG.isOk()) {
                        OperationLog.logOperationRes(connection, "Search(DirSync) RES {0}", entry);
                    }
                }
            }

            SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
            if (LOG.isOk()) {
                OperationLog.logOperationRes(connection, "Search(DirSync) RES Done:\n{0}", searchResultDone);
            }
            if (searchResultDone != null) {
                LdapResult ldapResult = searchResultDone.getLdapResult();
                if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
                    AdDirSyncResponse dirSyncRespControl = (AdDirSyncResponse) searchResultDone.getControl(AdDirSyncResponse.OID);
                    if (dirSyncRespControl == null) {
                        LOG.warn("No DirSync response control in search done response (getLatestSyncToken)");
                    } else {
                        cookie = dirSyncRespControl.getCookie();
                        if (cookie == null) {
                            LOG.warn("No entry cookie in DirSync response in search done response");
                        }
                    }
                } else {
                    LOG.error("LDAP error during DirSync search: {0}", LdapUtil.formatLdapMessage(ldapResult));
                    returnConnection(connection);
                    throw getErrorHandler().processLdapResult("LDAP error during DirSync search", ldapResult);
                }
            }
            LdapUtil.closeDoneCursor(searchCursor);
        } catch (LdapException | CursorException e) {
            returnConnection(connection);
            throw new ConnectorIOException("Error searching for changes ("+req.getFilter()+"): "+e.getMessage(), e);
        }

        if (cookie == null) {
            return null;
        }
        SyncToken token = new SyncToken(Base64.getEncoder().encodeToString(cookie));
        LOG.ok("Found latest sync token: {0}", token);

        returnConnection(connection);

        return token;
    }

    private SearchRequest createSearchRequest(String searchFilter, SyncToken fromToken) {

        AdDirSyncRequestImpl dirSyncReqControl = new AdDirSyncRequestImpl();
        dirSyncReqControl.setCritical(true);
        byte[] cookie = null;
        if (fromToken != null) {
            Object tokenValue = fromToken.getValue();
            if (tokenValue instanceof String) {
                if (StringUtils.isNotBlank((String) tokenValue)) {
                    cookie = Base64.getDecoder().decode((String) tokenValue);
                }
            } else if (tokenValue instanceof byte[]) {
                cookie = (byte[]) tokenValue;
            } else {
                throw new IllegalArgumentException("Unexpected type of sync token: "+tokenValue.getClass());
            }
            dirSyncReqControl.setCookie(cookie);
        }

        String baseContext = determineSyncBaseContext();

        // Always leave attribute list to default.
        // AD does not seem to understand expression such as "* objectGUID" in DirSync
        String[] attributesToGet = new String[0];

        if (LOG.isOk()) {
            LOG.ok("Searching DN {0} with {1}, attrs: {2}, cookie: {3}",
                    baseContext, searchFilter, Arrays.toString(attributesToGet),
                    cookie==null?null:Base64.getEncoder().encodeToString(cookie));
        }

        SearchRequest req = new SearchRequestImpl();
        try {
            req.setBase(new Dn(baseContext));
            req.setFilter(searchFilter);
            req.setScope(SearchScope.SUBTREE);
            req.addAttributes(attributesToGet);
            req.addControl(dirSyncReqControl);
        } catch (LdapException e) {
            throw new IllegalStateException("Error constructing search request: "+e.getMessage(), e);
        }

        return req;
    }
}
