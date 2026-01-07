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

import java.io.IOException;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.evolveum.polygon.connector.ldap.*;
import com.evolveum.polygon.connector.ldap.connection.ConnectionManager;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.ldif.LdifAttributesReader;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
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

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class GenericChangeLogSyncStrategy<C extends AbstractLdapConfiguration> extends SyncStrategy<C> {


    protected static final Log LOG = Log.getLog(GenericChangeLogSyncStrategy.class);
    private static final String CHANGELOG_ATTRIBUTE_CHANGE_TIME = "changeTime";
    private static final String CHANGELOG_ATTRIBUTE_CHANGE_TYPE = "changeType";
    private static final String CHANGELOG_ATTRIBUTE_CHANGES = "changes";
    private static final String CHANGELOG_ATTRIBUTE_REPLICATION_CSN = "replicationCSN";
    private static final String CHANGELOG_ATTRIBUTE_REPLICA_IDENTIFIER = "replicaIdenifier";
    private static final String CHANGELOG_ATTRIBUTE_CHANGELOG_COOKIE = "changeLogCookie";
    private static final String CHANGELOG_ATTRIBUTE_CHANGELOG_INITIATORS_NAME = "changeInitiatorsName";
    private static final String CHANGELOG_ATTRIBUTE_NEW_RDN_NAME = "newRdn";
    private static final String CHANGELOG_ATTRIBUTE_NEW_SUPERIOR_NAME = "newSuperior";
    private static final String CHANGELOG_ATTRIBUTE_DELETE_OLD_RDN_NAME = "deleteOldRdn";

    private static final Object CHANGE_TYPE_MODIFY = "modify";
    private static final Object CHANGE_TYPE_ADD = "add";
    private static final Object CHANGE_TYPE_DELETE = "delete";
    private static final Object CHANGE_TYPE_MODRDN = "modrdn";


    public GenericChangeLogSyncStrategy(AbstractLdapConfiguration configuration, ConnectionManager<C> connection,
                                    SchemaManager schemaManager, AbstractSchemaTranslator<C> schemaTranslator,
                                    ErrorHandler errorHandler) {
        super(configuration, connection, schemaManager, schemaTranslator, errorHandler);
    }

    protected String getChangeLogDN() {
    	Entry rootDse = getConnectionManager().getRootDse();
    	String changeLogAttributeName = getConfiguration().getChangeLogRootDSEAttribute();
    	Attribute changelogAttribute = rootDse.get(changeLogAttributeName);
    	if (changelogAttribute == null) {
            LOG.warn("Unable to locate changelog from the root DSE attribute "+changeLogAttributeName+".");
            
            String configuredChangeLogDN = getConfiguration().getChangeLogDN();
            if (configuredChangeLogDN == AbstractLdapConfiguration.CHANGELOG_DEFAULT_CHANGE_LOG_DN) {
            	LOG.warn("Falling back to default changelog DN: "+AbstractLdapConfiguration.CHANGELOG_DEFAULT_CHANGE_LOG_DN);
            }
            else {
            	LOG.warn("Falling back to user configured changelog DN: "+configuredChangeLogDN);
            }
            
            return configuredChangeLogDN;
        }
    	
        try {
            return changelogAttribute.getString();
        } catch (LdapInvalidAttributeValueException e) {
            throw new InvalidAttributeValueException("Invalid type of root DSE attribute "+changeLogAttributeName+": "+e.getMessage(), e);
        }
	}

    /**
     * Filter attributes from an LDIF block.
     * Utilised for directories such as Isode M-Vault that contains 'dn' and 'changeType' 
     * attributes in the changes LDIF on an 'add' operation. The first of the two of these
     * attributes causes issues with the apache directory ldap API LdifAttributesReader
     * 
     * @param changeLogEntry The DN of the changelog entry containing the LDIF being filtered
     * @param ldif The LDIF to filter attributes from
     * @return The filtered LDIF
     */
    private String filterLdifChanges(String changeLogEntry, String ldif, String[] changeLogFilteredAttributes) {
        return Stream.of(ldif.split("\n"))
                     .filter(line -> {
                        for (String filteredAttribute : changeLogFilteredAttributes) {
                            if (line.startsWith(filteredAttribute)) {
                                LOG.ok("Changelog entry {0} contains filtered attribute {1}, removing.", changeLogEntry, filteredAttribute);
                                return false;
                            }
                        }

                        return true;
                     })
                     .collect(Collectors.joining("\n"));
    }
    
    @Override
    public void sync(ObjectClass icfObjectClass, SyncToken fromToken, SyncResultsHandler handler,
            OperationOptions options) {
        ObjectClassInfo icfObjectClassInfo = null;
        org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = null;
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

        
        String changelogDn = getChangeLogDN();

        String changeNumberAttributeName = getConfiguration().getChangeNumberAttribute();
        String targetUniqueIdAttributeName = getConfiguration().getChangeLogTargetUniqueIdAttribute();
        String targetEntryUUIDAttributeName = getConfiguration().getChangeLogTargetEntryUUIDAttribute();
        String targetEntryDNAttributeName = getConfiguration().getChangeLogTargetDNAttribute();
        String uidAttributeName = getConfiguration().getUidAttribute();

        Dn syncBaseContext;

        try {
            syncBaseContext = new Dn(determineSyncBaseContext());
        } catch (LdapInvalidDnException e) {
            LOG.error(e, "Invalid base context to use for syncing: {0}", e.getMessage());
            throw new IllegalArgumentException("Invalid base context to use for syncing.", e);
        }

        String changelogSearchFilter = LdapConfiguration.SEARCH_FILTER_ALL;
        if (fromToken != null) {
            Object fromTokenValue = fromToken.getValue();
            if (fromTokenValue instanceof Integer) {
                changelogSearchFilter = createSeachFilter((Integer)fromTokenValue);
            } else {
                LOG.warn("Synchronization token is not integer, ignoring");
            }
        }
        SyncToken finalToken = fromToken;
        LOG.ok("Searching changelog {0} with {1}", changelogDn, changelogSearchFilter);
        int numChangelogEntries = 0;
        int numProcessedEntries = 0;
        // Do not ask connection for changelogDn here. Connection manager is NOT configured to recognize this DN.
        // Ask the default connection (dn=null), connection to top-level base context servers
        LdapNetworkConnection connection = getConnectionManager().getConnection(null, options);
        try {
            EntryCursor searchCursor = connection.search(changelogDn, changelogSearchFilter, SearchScope.ONELEVEL,
                    changeNumberAttributeName,
                    targetUniqueIdAttributeName,
                    targetEntryDNAttributeName,
                    CHANGELOG_ATTRIBUTE_CHANGE_TIME,
                    CHANGELOG_ATTRIBUTE_CHANGE_TYPE,
                    CHANGELOG_ATTRIBUTE_CHANGES,
                    CHANGELOG_ATTRIBUTE_NEW_RDN_NAME,
                    CHANGELOG_ATTRIBUTE_NEW_SUPERIOR_NAME,
                    CHANGELOG_ATTRIBUTE_DELETE_OLD_RDN_NAME);
            while (searchCursor.next()) {
                Entry entry = searchCursor.get();
                LOG.ok("Got changelog entry: {0}", entry);
                numChangelogEntries++;

                SyncToken deltaToken = null;
                Attribute changeNumberAttribute = entry.get(changeNumberAttributeName);
                if (changeNumberAttribute != null) {
                    int changeNumber = Integer.parseInt(changeNumberAttribute.getString());
                    deltaToken = new SyncToken(changeNumber);
                    finalToken = deltaToken;
                }

                // TODO: filter out by modifiersName

                SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
                deltaBuilder.setToken(deltaToken);

                String targetDn = LdapUtil.getStringAttribute(entry, targetEntryDNAttributeName);
                if (!syncBaseContext.isAncestorOf(targetDn)) {
                    LOG.ok("Changelog entry {0} refers to an entry {1} outside of the base synchronisation context {2}, ignoring", entry.getDn(), targetDn, determineSyncBaseContext());
                    continue;
                }

                String targetEntryUuid = LdapUtil.getStringAttribute(entry, targetEntryUUIDAttributeName);
                String targetUniqueId = LdapUtil.getStringAttribute(entry, targetUniqueIdAttributeName);
                String oldUid = null;
                if (LdapUtil.isDnAttribute(uidAttributeName)) {
                    oldUid = targetDn;
                } else if (LdapUtil.isEntryUuidAttribute(uidAttributeName)) {
                    // Prefer targetEntryUUID. targetUniqueID has wrong format in OpenDJ 2.4.x
                    if (targetEntryUuid != null) {
                        oldUid = targetEntryUuid;
                    } else if (targetUniqueId != null) {
                        oldUid = targetUniqueId;
                    }
                }

                String[] changeLogFilteredAttributes = getConfiguration().getChangeLogFilteredAttributes();

                SyncDeltaType deltaType;
                String changeType = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGE_TYPE);
                if (changeType != null) {

                    if (CHANGE_TYPE_MODIFY.equals(changeType)) {
                        deltaType = SyncDeltaType.UPDATE;
                        //                        String changesString = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGES);
//                        LdifEntry ldifEntry = new LdifEntry(targetDn, changesString);
//                        List<Modification> modifications = ldifEntry.getModifications();
                        Entry targetEntry = fetchEntry(connection, targetDn, ldapObjectClass, options);
                        if (targetEntry == null) {
                            LOG.warn("Changelog entry {0} refers to an entry {1} that no longer exists, ignoring", entry.getDn(), targetDn);
                            continue;
                        }
                        if (!LdapUtil.isObjectClass(targetEntry, ldapObjectClass)) {
                            LOG.ok("Changelog entry {0} does not match object class, skipping", targetEntry.getDn());
                            continue;
                        }
                        // Best effort reference handling in case of subject side of association
                        ConnectorObject targetObject = getSchemaTranslator().toConnIdObject(connection,
                                icfObjectClassInfo, targetEntry, options);

                        deltaBuilder.setObject(targetObject);

                    } else if (CHANGE_TYPE_ADD.equals(changeType)) {
                        deltaType = SyncDeltaType.CREATE;
                        String changesString = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGES);


                        if (changeLogFilteredAttributes.length > 0) {
                            changesString = filterLdifChanges(entry.getDn().getName(), changesString, changeLogFilteredAttributes);
                        }

                        LdifAttributesReader reader = new LdifAttributesReader();
                        Entry targetEntry = reader.parseEntry( getSchemaManager(), changesString);
                        try {
                            reader.close();
                        } catch (IOException e) {
                            throw new ConnectorIOException(e);
                        }
                        if (!LdapUtil.isObjectClass(targetEntry, ldapObjectClass)) {
                            LOG.ok("Changelog entry {0} does not match object class, skipping", targetEntry.getDn());
                            continue;
                        }
                        if (!getSchemaTranslator().hasUidAttribute(targetEntry)) {
                            // No UID attribute in the changelog entry. We need to re-read it explicitly.
                            targetEntry = fetchEntry(connection, targetDn, ldapObjectClass, options);
                            if (targetEntry == null) {
                                LOG.warn("Changelog entry {0} refers to an entry {1} that no longer exists, ignoring", entry.getDn(), targetDn);
                                continue;
                            }
                        }
                        // Best effort reference handling in case of subject side of association
                        ConnectorObject targetObject = getSchemaTranslator().toConnIdObject(connection,
                                icfObjectClassInfo, targetEntry, targetDn, options);
                        deltaBuilder.setObject(targetObject);

                    } else if (CHANGE_TYPE_DELETE.equals(changeType)) {
                        if (oldUid == null) {
                            LOG.info("Ignoring DELETE delta because we are not able to determine UID");
                            continue;
                        }
                        deltaType = SyncDeltaType.DELETE;
                        deltaBuilder.setUid(new Uid(oldUid));
                        // Cannot filter out by object class here because we simply do not know it.
                        // Therefore just use all deltas.

                    } else if (CHANGE_TYPE_MODRDN.equals(changeType)) {
                        deltaType = SyncDeltaType.UPDATE;
                        Dn oldDn = new Dn(targetDn);
                        Rdn[] newRdns = new Rdn[oldDn.size()];
                        String newRdn = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_NEW_RDN_NAME);
                        for(int i=1; i < oldDn.size(); i++) {
                            newRdns[i] = oldDn.getRdn(i);
                        }
                        newRdns[0] = new Rdn(newRdn);
                        Dn newDn = new Dn(newRdns);
                        LOG.ok("ModRdn (RDN: {0}) -> {1}", newRdn, newDn.toString());
                        Entry targetEntry = fetchEntry(connection, newDn.toString(), ldapObjectClass, options);
                        if (targetEntry == null) {
                            LOG.warn("Changelog entry {0} refers to an entry {1} that no longer exists, ignoring", entry.getDn(), newDn);
                            continue;
                        }
                        if (!LdapUtil.isObjectClass(targetEntry, ldapObjectClass)) {
                            LOG.ok("Changelog entry {0} does not match object class, skipping", targetEntry.getDn());
                            continue;
                        }
                        if (LdapUtil.isDnAttribute(getConfiguration().getUidAttribute())) {
                            // We cannot pass enough information about the rename in this case.
                            // The best thing that we can do is simulate a delete delta for the
                            // old entry
                            SyncDeltaBuilder deleteDeltaBuilder = new SyncDeltaBuilder();
                            deleteDeltaBuilder.setDeltaType(SyncDeltaType.DELETE);
                            deleteDeltaBuilder.setUid(new Uid(oldDn.getName()));
                            deleteDeltaBuilder.setToken(deltaToken);
                            LOG.ok("Sending simulated delete delta for {0}", oldDn.getName());
                            handler.handle(deleteDeltaBuilder.build());
                        }
                        ConnectorObject targetObject = getSchemaTranslator().toConnIdObject(connection,
                                icfObjectClassInfo, targetEntry, options);

                        deltaBuilder.setObject(targetObject);
                        LOG.ok("ModRdn Obj UID: {0},  changelog UID: {1}", targetObject.getUid(), oldUid);

                    } else {
                        throw new InvalidAttributeValueException("Unknown value '"+changeType+"' of changeType attribute in changelog entry "+entry.getDn());
                    }
                } else {
                    throw new InvalidAttributeValueException("No value of changeType attribute in changelog entry "+entry.getDn());
                }
                deltaBuilder.setDeltaType(deltaType);

                handler.handle(deltaBuilder.build());
                numProcessedEntries++;
            }
            searchCursor.close();
            LOG.ok("Search changelog {0} with {1}: {2} entries, {3} processed", changelogDn, changelogSearchFilter, numChangelogEntries, numProcessedEntries);
        } catch (LdapException | CursorException | IOException e) {
            returnConnection(connection);
            throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
        }

        if (handler instanceof SyncTokenResultsHandler && finalToken != null) {
            ((SyncTokenResultsHandler)handler).handleResult(finalToken);
        }

        returnConnection(connection);
    }

    private String createSeachFilter(Integer fromTokenValue) {
        String changeNumberAttributeName = getConfiguration().getChangeNumberAttribute();
        GreaterEqNode<String> filterNode;
        String tokenValue = Integer.toString(fromTokenValue + 1);
        try {
            filterNode = new GreaterEqNode<String>(changeNumberAttributeName, tokenValue);
        } catch (LdapSchemaException e) {
            throw new IllegalArgumentException("Invalid token value "+tokenValue, e);
        }
        return filterNode.toString();
    }

    @Override
    public SyncToken getLatestSyncToken(ObjectClass objectClass) {
        Boolean getChangeNumbersFromRootDSE = getConfiguration().getChangeLogChangeNumberAttributesOnRootDSE();
        String lastChangeNumberAttributeName = getConfiguration().getChangeLogLastChangeNumberAttribute();

        Entry entryToReadFrom = null;
        String readContextString = null;

        if (getChangeNumbersFromRootDSE) {
            // We want to get a very fresh root DSE.
            // Root DSE might be cached with outdated lastChangeNumber value.
            // We have to make sure we have the most recent value
            entryToReadFrom = getConnectionManager().getRootDseFresh();
            readContextString = "root DSE";
        }
        else {
            String configuredChangeLogDN = getConfiguration().getChangeLogDN();
            LdapNetworkConnection connection = getConnectionManager().getConnection(null, null);            

            try {
                entryToReadFrom = connection.lookup(configuredChangeLogDN, lastChangeNumberAttributeName);
            }
            catch (LdapException ex) {
                LOG.error(ex, "Failed to read configured changelog DN '{0}': {1}", configuredChangeLogDN, ex.getMessage());
                return null;
            }
            finally {
                returnConnection(connection);
            }

            readContextString = configuredChangeLogDN;
        }

        Attribute lastChangeNumberAttribute = entryToReadFrom.get(lastChangeNumberAttributeName);
        if (lastChangeNumberAttribute == null) {
            LOG.warn("Failed to retrieve the latest sync token from {0}.", readContextString);
            return null;
        }

        try {
            String stringValue = lastChangeNumberAttribute.getString();
            if (StringUtils.isEmpty(stringValue)) {
                LOG.warn("Empty sync token retrieved from {0}.", readContextString);
                return null;
            }

            LOG.ok("Fetched sync token from {0}: {1}", readContextString, stringValue);
            
            return new SyncToken(Integer.parseInt(stringValue));
        } catch (LdapInvalidAttributeValueException ex) {
            throw new InvalidAttributeValueException("Invalid type of attribute " + lastChangeNumberAttributeName + " on " + readContextString + ": " + ex.getMessage(), ex);
        }
    }

}
