/**
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
package com.evolveum.polygon.connector.ldap.sync;

import java.io.IOException;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.StringValue;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.ldif.LdifAttributesReader;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.SchemaTranslator;

/**
 * @author semancik
 *
 */
public class SunChangelogSyncStrategy extends SyncStrategy {
	
	private static String ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME = "changelog";
	private static String ROOT_DSE_ATTRIBUTE_FIRST_CHANGE_NUMBER_NAME = "firstChangeNumber";
	private static String ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME = "lastChangeNumber";
	
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
	

	public SunChangelogSyncStrategy(LdapConfiguration configuration, LdapNetworkConnection connection, 
			SchemaManager schemaManager, SchemaTranslator schemaTranslator) {
		super(configuration, connection, schemaManager, schemaTranslator);
	}

	@Override
	public void sync(ObjectClass icfObjectClass, SyncToken fromToken, SyncResultsHandler handler,
			OperationOptions options) {
		// TODO: "ALL" object class
		ObjectClassInfo icfObjectClassInfo = getSchemaTranslator().findObjectClassInfo(icfObjectClass);
		if (icfObjectClassInfo == null) {
			throw new InvalidAttributeValueException("No definition for object class "+icfObjectClass);
		}
		org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass = getSchemaTranslator().toLdapObjectClass(icfObjectClass);
		
		Entry rootDse;
		try {
			rootDse = getConnection().getRootDse(ROOT_DSE_ATTRIBUTE_CHANGELOG_NAME, ROOT_DSE_ATTRIBUTE_FIRST_CHANGE_NUMBER_NAME, ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error getting changelog data from root DSE: "+e.getMessage(), e);
		}
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
		LOG.ok("Searching changelog '"+changelogDn+"' with "+changelogSearchFilter);
		try {
			EntryCursor searchCursor = getConnection().search(changelogDn, changelogSearchFilter, SearchScope.ONELEVEL, 
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
				
				// TODO: filter out by modifiersName
				
				// TODO: filter out by object class
				
				SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
				
				SyncToken deltaToken = null;
				Attribute changeNumberAttribute = entry.get(changeNumberAttributeName);
				if (changeNumberAttribute != null) {
					int changeNumber = Integer.parseInt(changeNumberAttribute.getString());
					deltaToken = new SyncToken(changeNumber);
				}
				deltaBuilder.setToken(deltaToken);
				
				String targetDn = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_DN);
				String targetEntryUuid = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_ENTRY_UUID);
				String targetUniqueId = LdapUtil.getStringAttribute(entry, CHANGELOG_ATTRIBUTE_TARGET_UNIQUE_ID);
				String oldUid = null;
				if (LdapUtil.isDnAttribute(uidAttributeName)) {
					oldUid = targetDn;
				} else if (LdapUtil.isEntryUuidAttribute(uidAttributeName)) {
					if (targetUniqueId != null) {
						oldUid = targetUniqueId;
					} else if (targetEntryUuid != null) {
						oldUid = targetEntryUuid;
					} else {
						// TODO
						throw new UnsupportedOperationException("TODO");
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
						Entry targetEntry = LdapUtil.fetchEntry(getConnection(), targetDn, ldapObjectClass, options, getConfiguration(), getSchemaTranslator());
						ConnectorObject targetObject = getSchemaTranslator().toIcfObject(icfObjectClassInfo, targetEntry);
						deltaBuilder.setObject(targetObject);
						deltaBuilder.setUid(new Uid(oldUid));
						
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
						ConnectorObject targetObject = getSchemaTranslator().toIcfObject(icfObjectClassInfo, targetEntry);
						deltaBuilder.setObject(targetObject);
						
					} else if (CHANGE_TYPE_DELETE.equals(changeType)) {
						deltaType = SyncDeltaType.DELETE;
						deltaBuilder.setUid(new Uid(oldUid));
						
					} else {
						throw new InvalidAttributeValueException("Unknown value '"+changeType+"' of changeType attribute in changelog entry "+entry.getDn());
					}
				} else {
					throw new InvalidAttributeValueException("No value of changeType attribute in changelog entry "+entry.getDn());
				}
				deltaBuilder.setDeltaType(deltaType);
				
				handler.handle(deltaBuilder.build());
			}
			searchCursor.close();
		} catch (LdapException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		}
				
	}

	private String createSeachFilter(Integer fromTokenValue) {
		String changeNumberAttributeName = getConfiguration().getChangeNumberAttribute();
		Value<String> ldapValue = new StringValue(Integer.toString(fromTokenValue + 1));
		GreaterEqNode<String> filterNode = new GreaterEqNode<String>(changeNumberAttributeName, ldapValue);
		return filterNode.toString();
	}

	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		Entry rootDse;
		try {
			rootDse = getConnection().getRootDse(ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME);
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
