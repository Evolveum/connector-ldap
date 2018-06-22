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

import java.util.Arrays;
import java.util.Calendar;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.GeneralizedTime;
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
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class ModifyTimestampSyncStrategy<C extends AbstractLdapConfiguration> extends SyncStrategy<C> {
	
	private static final Log LOG = Log.getLog(ModifyTimestampSyncStrategy.class);


	public ModifyTimestampSyncStrategy(AbstractLdapConfiguration configuration, ConnectionManager<C> connectionManager, 
			SchemaManager schemaManager, AbstractSchemaTranslator<C> schemaTranslator) {
		super(configuration, connectionManager, schemaManager, schemaTranslator);
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
		
		String searchFilter;
		if (fromToken == null) {
			fromToken = getLatestSyncToken(icfObjectClass);
		}
		Object fromTokenValue = fromToken.getValue();
		if (fromTokenValue instanceof String) {
			searchFilter = createSeachFilter((String)fromTokenValue, ldapObjectClass);
		} else {
			throw new IllegalArgumentException("Synchronization token is not string, it is "+fromToken.getClass());
		}
		
		String[] attributesToGet = LdapUtil.getAttributesToGet(ldapObjectClass, options, 
				getSchemaTranslator(), SchemaConstants.MODIFY_TIMESTAMP_AT, 
				SchemaConstants.CREATE_TIMESTAMP_AT, SchemaConstants.MODIFIERS_NAME_AT, 
				SchemaConstants.CREATORS_NAME_AT);
		
		String baseContext = getConfiguration().getBaseContext();
		if (LOG.isOk()) {
			LOG.ok("Searching DN {0} with {1}, attrs: {2}", baseContext, searchFilter, Arrays.toString(attributesToGet));
		}
		
		// Remember final token before we start searching. This will avoid missing
		// the changes that come when the search is already running and do not make
		// it into the search.
		SyncToken finalToken = getLatestSyncToken(icfObjectClass);
		
		int numFoundEntries = 0;
		int numProcessedEntries = 0;
		
		LdapNetworkConnection connection = getConnectionManager().getConnection(getSchemaTranslator().toDn(baseContext));
		try {
			EntryCursor searchCursor = connection.search(baseContext, searchFilter, SearchScope.SUBTREE, attributesToGet);
			while (searchCursor.next()) {
				Entry entry = searchCursor.get();
				LOG.ok("Found entry: {0}", entry);
				numFoundEntries++;
				
				if (!isAcceptableForSynchronization(entry, ldapObjectClass, 
						getConfiguration().getModifiersNamesToFilterOut())) {
					continue;
				}
								
				SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
				SyncDeltaType deltaType = SyncDeltaType.CREATE_OR_UPDATE;
				
				// Send "final" token for all entries (which means do NOT sent
				// modify/create timestamp of an entry). This is a lazy method
				// so we do not need to sort the changes.
				deltaBuilder.setToken(finalToken);
				
				deltaBuilder.setDeltaType(deltaType);
				ConnectorObject targetObject = getSchemaTranslator().toIcfObject(connection, icfObjectClassInfo, entry);
				deltaBuilder.setObject(targetObject);
				
				handler.handle(deltaBuilder.build());
				numProcessedEntries++;
			}
			LdapUtil.closeCursor(searchCursor);
			LOG.ok("Search DN {0} with {1}: {2} entries, {3} processed", baseContext, searchFilter, numFoundEntries, numProcessedEntries);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error searching for changes ("+searchFilter+"): "+e.getMessage(), e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Error searching for changes ("+searchFilter+"): "+e.getMessage(), e);
		}
		
		// Send a final token with the time that the scan started. This will stop repeating the
		// last change over and over again.
		// NOTE: this assumes that the clock of client and server are synchronized
		if (handler instanceof SyncTokenResultsHandler) {
			((SyncTokenResultsHandler)handler).handleResult(finalToken);
		}
	}

	private String createSeachFilter(String fromTokenValue, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		ExprNode filterNode;
		try {
			filterNode = new OrNode(
					new GreaterEqNode<String>(SchemaConstants.MODIFY_TIMESTAMP_AT, fromTokenValue),
					new GreaterEqNode<String>(SchemaConstants.CREATE_TIMESTAMP_AT, fromTokenValue)
			);
		} catch (LdapSchemaException e) {
			throw new IllegalArgumentException("Invalid token value "+fromTokenValue, e);
		}
		if (ldapObjectClass != null) {
			filterNode = new AndNode(new EqualityNode<String>(SchemaConstants.OBJECT_CLASS_AT, 
					ldapObjectClass.getName()), filterNode);
		}
		return filterNode.toString();
	}

	@Override
	public SyncToken getLatestSyncToken(ObjectClass objectClass) {
		Calendar calNow = Calendar.getInstance();
		calNow.setTimeInMillis(System.currentTimeMillis());
		GeneralizedTime gtNow = new GeneralizedTime(calNow);
		return new SyncToken(gtNow.toGeneralizedTimeWithoutFraction());
	}

}
