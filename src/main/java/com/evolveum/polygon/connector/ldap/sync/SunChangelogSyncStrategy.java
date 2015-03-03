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

import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;

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
	

	public SunChangelogSyncStrategy(LdapConfiguration configuration, LdapNetworkConnection connection) {
		super(configuration, connection);
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.sync.SyncStrategy#sync(org.identityconnectors.framework.common.objects.ObjectClass, org.identityconnectors.framework.common.objects.SyncToken, org.identityconnectors.framework.common.objects.SyncResultsHandler, org.identityconnectors.framework.common.objects.OperationOptions)
	 */
	@Override
	public void sync(ObjectClass objectClass, SyncToken token, SyncResultsHandler handler,
			OperationOptions options) {
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
		
		String changelogSearchFilter = LdapConfiguration.SEARCH_FILTER_ALL;
		try {
			EntryCursor searchCursor = getConnection().search(changelogDn, changelogSearchFilter, SearchScope.ONELEVEL, 
					getConfiguration().getChangeNumberAttribute(),
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
			}
			searchCursor.close();
		} catch (LdapException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error searching changelog ("+changelogDn+"): "+e.getMessage(), e);
		}
				
				
				
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.sync.SyncStrategy#getLatestSyncToken(org.identityconnectors.framework.common.objects.ObjectClass)
	 */
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
			return new SyncToken(lastChangeNumberAttribute.getString());
		} catch (LdapInvalidAttributeValueException e) {
			throw new InvalidAttributeValueException("Invalid type of  root DSE attribute "+ROOT_DSE_ATTRIBUTE_LAST_CHANGE_NUMBER_NAME+": "+e.getMessage(), e);
		}
	}

}
