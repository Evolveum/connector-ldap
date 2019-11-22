/**
 * Copyright (c) 2015-2019 DAASI International and Evolveum
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
import java.util.Iterator;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author gietz
 *
 */
public class OpenLdapAccessLogSyncStrategy<C extends AbstractLdapConfiguration> extends ModifyTimestampSyncStrategy<C> {

    private static final Log LOG = Log.getLog(OpenLdapAccessLogSyncStrategy.class);

    private final static String ACCESS_LOG_DELETE_OBJECT_CLASS = "auditDelete";
    private final static String ACCESS_LOG_OLD_ATTRIBUTE_NAME = "reqOld";
    private final static String ACCESS_LOG_REQ_START_ATTRIBUTE_NAME = "reqStart";
    private final static String ACCESS_LOG_TARGET_DN_ATTRIBUTE_NAME = "reqDN";
    private final static String ACCESS_LOG_ENTRY_UUID_ATTRIBUTE_NAME = "reqEntryUUID";
    private final static String ACCESS_LOG_REQ_RESULT_ATTRIBUTE_NAME = "reqResult";

    public OpenLdapAccessLogSyncStrategy(AbstractLdapConfiguration configuration,
            ConnectionManager<C> connectionManager, SchemaManager schemaManager,
            AbstractSchemaTranslator<C> schemaTranslator) {
        super(configuration, connectionManager, schemaManager, schemaTranslator);
    }

    @Override
    public void sync(ObjectClass icfObjectClass, SyncToken fromToken, SyncResultsHandler handler,
            OperationOptions options) {
        LOG.ok("Starting OpenLDAP access log synchronisation...");
        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = getLdapObjectClass(icfObjectClass);

        //create search filter
        String searchFilter;
        if (fromToken == null) {
            fromToken = getLatestSyncToken(icfObjectClass);
        }
        Object fromTokenValue = fromToken.getValue();
        if (fromTokenValue instanceof String) {
            searchFilter = createAccessLogFilter((String) fromTokenValue, ldapObjectClass);
        } else {
            throw new IllegalArgumentException("Synchronization token is not string, it is " + fromToken.getClass());
        }
        // perform deletes
        performDeletes(icfObjectClass, handler, options, searchFilter);
        // perform add & modifies
        super.sync(icfObjectClass, fromToken, handler, options);
    }

    /**
     * builds the deleteDeltas for all found entries with the incoming
     * LDAPsearchfilter and sends them to the incoming handler. Depending on the
     * configured uid attribute, this method must find the attribute in the reqOld
     * attributes. If the uid attribute is not dn or entryUuid an reqOld attribute
     * with the value <uidAttr>:... is searched.
     *
     * @param icfObjectClass
     * @param handler        SyncResultHandler that performs the deletes (and other
     *                       sync operations) in midpoint
     * @param options
     * @param searchFilter   The LDAP-searchfilter that finds all entries that were
     *                       successfully deleted since the last sync
     */
    private void performDeletes(ObjectClass icfObjectClass, SyncResultsHandler handler, OperationOptions options,
            String searchFilter) {
        String[] attributesToGet = new String[] { ACCESS_LOG_DELETE_OBJECT_CLASS, ACCESS_LOG_REQ_START_ATTRIBUTE_NAME,
                ACCESS_LOG_OLD_ATTRIBUTE_NAME, ACCESS_LOG_TARGET_DN_ATTRIBUTE_NAME,
                ACCESS_LOG_ENTRY_UUID_ATTRIBUTE_NAME };
        AbstractLdapConfiguration config = getConfiguration();
        if(!(config instanceof LdapConfiguration)) {
            throw new ConfigurationException("The used configuration class is not of type LdapConfiguration");
        }

        String baseContext = ((LdapConfiguration)getConfiguration()).getOpenLdapAccessLogDn();

        if (LOG.isOk()) {
            LOG.ok("Searching DN {0} with {1}, attrs: {2}", baseContext, searchFilter,
                    Arrays.toString(attributesToGet));
        }

        // Remember final token before we start searching. This will avoid missing
        // the changes that come when the search is already running and do not make
        // it into the search.
        SyncToken finalToken = getLatestSyncToken(icfObjectClass);

        int numProcessedEntries = 0;
        int numAccessLogEntries = 0;

        LdapNetworkConnection connection = getConnectionManager().getConnection(getSchemaTranslator().toDn(baseContext),
                options);
        try {
            EntryCursor searchCursor = connection.search(baseContext, searchFilter, SearchScope.SUBTREE,
                    attributesToGet);
            while (searchCursor.next()) {
                Entry entry = searchCursor.get();
                LOG.ok("Got changelog entry: {0}", entry);
                numAccessLogEntries++;

                SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
                deltaBuilder.setToken(finalToken);
                SyncDeltaType deltaType = SyncDeltaType.DELETE;

                String targetDn = LdapUtil.getStringAttribute(entry, ACCESS_LOG_TARGET_DN_ATTRIBUTE_NAME);
                String targetEntryUuid = LdapUtil.getStringAttribute(entry, ACCESS_LOG_ENTRY_UUID_ATTRIBUTE_NAME);

                String oldUid = null;
                String uidAttributeName = this.getConfiguration().getUidAttribute();
                if (LdapUtil.isDnAttribute(uidAttributeName)) {
                    oldUid = targetDn;
                } else if (LdapUtil.isEntryUuidAttribute(uidAttributeName)) {
                    oldUid = targetEntryUuid;
                } else {
                    boolean foundUidAttr = false;
                    LOG.ok("Starting to find uidAttribute {0} in reqOld attributes of accesslog", uidAttributeName);
                    org.apache.directory.api.ldap.model.entry.Attribute uidAttribute = entry
                            .get(ACCESS_LOG_OLD_ATTRIBUTE_NAME);
                    Iterator<Value> atrValIterator = uidAttribute.iterator();
                    while (atrValIterator.hasNext()) {
                        Value next = atrValIterator.next();
                        if (next.getString().contains(uidAttributeName + ":")) {
                            LOG.ok("Found uid attribute");
                            foundUidAttr = true;
                            // spliting at first ':'. Everything after that is the uid attribute
                            // this is pretty safe because it's not possible to but ':' in an attribute
                            // deffinition
                            try {
                                String[] splitArr = next.getString().split(":");
                                oldUid = String.join("", Arrays.copyOfRange(splitArr, 1, splitArr.length)).trim();
                            } catch (Exception e) {
                                LOG.info(
                                        "There was a problem while generating uid Attribute value from reqOld attribute",
                                        e);
                            }
                            break;
                        }
                    }
                    if (!foundUidAttr) {
                        LOG.info("There was no {0} in reqOld Attributes of entry {1}", uidAttribute, targetDn);
                    }
                }
                if (oldUid == null) {
                    LOG.info("Ignoring DELETE delta because we are not able to determine UID");
                    continue;
                }
                LOG.ok("Setting oldUid of entry {0} to {1}", targetDn, oldUid);
                numProcessedEntries++;
                deltaBuilder.setDeltaType(deltaType);
                deltaBuilder.setUid(new Uid(oldUid));
                handler.handle(deltaBuilder.build());
            }
            LdapUtil.closeCursor(searchCursor);
            LOG.ok("Search accesslog {0} with {1}: {2} entries, {3} processed", baseContext, searchFilter,
                    numAccessLogEntries, numProcessedEntries);

        } catch (LdapException | CursorException e) {
            returnConnection(connection);
            throw new ConnectorIOException("Error searching for deletes (" + searchFilter + "): " + e.getMessage(), e);
        }
    }

    private org.apache.directory.api.ldap.model.schema.ObjectClass getLdapObjectClass(ObjectClass icfObjectClass) {
        if (StringUtils.isBlank(((LdapConfiguration)getConfiguration()).getOpenLdapAccessLogDn())) {
            throw new InvalidAttributeValueException("The accesslog DN must not be empty!");
        }

        // copied from super class
        ObjectClassInfo icfObjectClassInfo = null;
        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = null;
        if (icfObjectClass.is(ObjectClass.ALL_NAME)) {
            // It is OK to leave the icfObjectClassInfo and ldapObjectClass as null. These
            // need to be determined
            // for every changelog entry anyway
        } else {
            icfObjectClassInfo = getSchemaTranslator().findObjectClassInfo(icfObjectClass);
            if (icfObjectClassInfo == null) {
                throw new InvalidAttributeValueException("No definition for object class " + icfObjectClass);
            }
            ldapObjectClass = getSchemaTranslator().toLdapObjectClass(icfObjectClass);
        }
        return ldapObjectClass;
    }

    /**
     * creates the filter for the OpenLDAP access log search. Default filter:
     * (&(objectClass=auditDelete)(reqResult=0)(reqStart>=<timestamp>))
     *
     * If there is an additional OpenLDAP access log filter configured it is
     * appended to the default filter
     *
     * @param fromTokenValue
     * @param ldapObjectClass
     * @return
     */
    private String createAccessLogFilter(String fromTokenValue,
            org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
        ExprNode filterNode;
        try {
            filterNode = new GreaterEqNode<>(ACCESS_LOG_REQ_START_ATTRIBUTE_NAME, fromTokenValue);
        } catch (LdapSchemaException e) {
            throw new IllegalArgumentException("Invalid token value " + fromTokenValue, e);
        }
        filterNode = new AndNode(
                new EqualityNode<String>(SchemaConstants.OBJECT_CLASS_AT, ACCESS_LOG_DELETE_OBJECT_CLASS),
                new EqualityNode<String>(ACCESS_LOG_REQ_RESULT_ATTRIBUTE_NAME, "0"), filterNode);
        String additionalFilter = ((LdapConfiguration)getConfiguration()).getOpenLdapAccessLogAdditionalFilter();
        if (additionalFilter != null) {
            filterNode = LdapUtil.filterAnd(filterNode, LdapUtil.parseSearchFilter(additionalFilter));
        }

        LOG.ok("Created filter: {0}", filterNode.toString());
        return filterNode.toString();
    }
}
