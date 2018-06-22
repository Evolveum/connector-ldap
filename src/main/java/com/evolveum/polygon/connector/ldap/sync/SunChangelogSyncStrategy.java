/**
 * Copyright (c) 2015-2018 Evolveum
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

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
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

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class SunChangelogSyncStrategy<C extends AbstractLdapConfiguration> extends SyncStrategy<C> {
	
	public static final String ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME = "changelog";
	private static final String ROOT_DSE_ATTRIBUTE_FIRST_CHANGE_NUMBER_NAME = "firstChangeNumber";
	private static final String ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME = "lastChangeNumber";
	
	private static final Log LOG = Log.getLog(SunChangelogSyncStrategy.class);
	private static final String CHANGELOG_ATTRIBUTE_TARGET_UNIQUE_ID = "targetUniqueID";
	private static final String CHANGELOG_ATTRIBUTE_TARGET_ENTRY_UUID = "targetEntryUUID";
	private static final String CHANGELOG_ATTRIBUTE_TARGET_DN = "targetDN";
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
	

	public SunChangelogSyncStrategy(AbstractLdapConfiguration configuration, ConnectionManager<C> connection, 
			SchemaManager schemaManager, AbstractSchemaTranslator<C> schemaTranslator) {
		super(configuration, connection, schemaManager, schemaTranslator);
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
		
		Entry rootDse = LdapUtil.getRootDse(getConnectionManager(), ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME, ROOT_DSE_ATTRIBUTE_FIRST_CHANGE_NUMBER_NAME, ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME);
		Attribute changelogAttribute = rootDse.get(ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME);
		if (changelogAttribute == null) {
			throw new ConnectorException("Cannot locate changelog, the root DSE attribute "+ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME+" is not present");
		}
		String changelogDn;
		try {
			changelogDn = changelogAttribute.getString();
		} catch (LdapInvalidAttributeValueException e) {
			throw new InvalidAttributeValueException("Invalid type of  root DSE attribute "+ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME+": "+e.getMessage(), e);
		}
		
		String changeNumberAttributeName = getConfiguration().getChangeNumberAttribute();
		String uidAttributeName = getConfiguration().getUidAttribute();
		
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
		LdapNetworkConnection connection = getConnectionManager().getConnection(getSchemaTranslator().toDn(changelogDn));
		try {
			EntryCursor searchCursor = connection.search(changelogDn, changelogSearchFilter, SearchScope.ONELEVEL, 
					changeNumberAttributeName,
					CHANGELOG_ATTRIBUTE_TARGET_UNIQUE_ID,
					CHANGELOG_ATTRIBUTE_TARGET_DN,
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
				
				String targetDn = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_DN);
				String targetEntryUuid = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_ENTRY_UUID);
				String targetUniqueId = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_UNIQUE_ID);
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
				
				SyncDeltaType deltaType;
				String changeType = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGE_TYPE);
				if (changeType != null) {
					
					if (CHANGE_TYPE_MODIFY.equals(changeType)) {
						deltaType = SyncDeltaType.UPDATE;
						//						String changesString = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGES);
//						LdifEntry ldifEntry = new LdifEntry(targetDn, changesString);
//						List<Modification> modifications = ldifEntry.getModifications();
						Entry targetEntry = LdapUtil.fetchEntry(connection, targetDn, ldapObjectClass, options, getSchemaTranslator());
						if (targetEntry == null) {
							LOG.warn("Changelog entry {0} refers to an entry {1} that no longer exists, ignoring", entry.getDn(), targetDn);
							continue;
						}
						if (!LdapUtil.isObjectClass(targetEntry, ldapObjectClass)) {
							LOG.ok("Changelog entry {0} does not match object class, skipping", targetEntry.getDn());
							continue;
						}
						ConnectorObject targetObject = getSchemaTranslator().toIcfObject(connection, icfObjectClassInfo, targetEntry);
						deltaBuilder.setObject(targetObject);
						
					} else if (CHANGE_TYPE_ADD.equals(changeType)) {
						deltaType = SyncDeltaType.CREATE;
						String changesString = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_CHANGES);
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
							targetEntry = LdapUtil.fetchEntry(connection, targetDn, ldapObjectClass, options, getSchemaTranslator());
							if (targetEntry == null) {
								LOG.warn("Changelog entry {0} refers to an entry {1} that no longer exists, ignoring", entry.getDn(), targetDn);
								continue;
							}
						}
						ConnectorObject targetObject = getSchemaTranslator().toIcfObject(connection, icfObjectClassInfo, targetEntry, targetDn);
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
						Entry targetEntry = LdapUtil.fetchEntry(connection, newDn.toString(), ldapObjectClass, options, getSchemaTranslator());
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
						ConnectorObject targetObject = getSchemaTranslator().toIcfObject(connection, icfObjectClassInfo, targetEntry);
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
		} catch (LdapException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		} catch (IOException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		}
		
		if (handler instanceof SyncTokenResultsHandler && finalToken != null) {
			((SyncTokenResultsHandler)handler).handleResult(finalToken);
		}
				
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
		Entry rootDse;
		try {
			rootDse = getConnectionManager().getDefaultConnection().getRootDse(ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error getting latest sync token from root DSE: "+e.getMessage(), e);
		}
		Attribute lastChangeNumberAttribute = rootDse.get(ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME);
		if (lastChangeNumberAttribute == null) {
			return null;
		}
		try {
			String stringValue = lastChangeNumberAttribute.getString();
			LOG.ok("Fetched {0} from root DSE: {1}", ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME, stringValue);
			if (StringUtils.isEmpty(stringValue)) {
				return null;
			}
			return new SyncToken(Integer.parseInt(lastChangeNumberAttribute.getString()));
		} catch (LdapInvalidAttributeValueException e) {
			throw new InvalidAttributeValueException("Invalid type of  root DSE attribute "+ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME+": "+e.getMessage(), e);
		}
	}

}
