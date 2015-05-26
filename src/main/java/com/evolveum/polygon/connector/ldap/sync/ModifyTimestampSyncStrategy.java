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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
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
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.GreaterEqNode;
import org.apache.directory.api.ldap.model.filter.OrNode;
import org.apache.directory.api.ldap.model.ldif.LdifAttributesReader;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.util.GeneralizedTime;
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
import org.identityconnectors.framework.spi.SyncTokenResultsHandler;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.SchemaTranslator;

/**
 * @author semancik
 *
 */
public class ModifyTimestampSyncStrategy extends SyncStrategy {
	
	private static final String MODIFYTIMESTAMP_ATTRIBUTE = "modifyTimestamp";
	private static final String MODIFIERSNAME_ATTRIBUTE = "modifiersName";
	private static final String CREATETIMESTAMP_ATTRIBUTE = "createTimestamp";
	private static final String CREATORSNAME_ATTRIBUTE = "creatorsName";
	
	private static final Log LOG = Log.getLog(ModifyTimestampSyncStrategy.class);


	public ModifyTimestampSyncStrategy(LdapConfiguration configuration, LdapNetworkConnection connection, 
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
		
		String searchFilter = LdapConfiguration.SEARCH_FILTER_ALL;
		if (fromToken == null) {
			fromToken = getLatestSyncToken(icfObjectClass);
		}
		Object fromTokenValue = fromToken.getValue();
		if (fromTokenValue instanceof String) {
			searchFilter = createSeachFilter((String)fromTokenValue);
		} else {
			throw new IllegalArgumentException("Synchronization token is not string, it is "+fromToken.getClass());
		}
		
		String[] attributesToGet = LdapUtil.getAttributesToGet(ldapObjectClass, options, getConfiguration(), 
				getSchemaTranslator(), MODIFYTIMESTAMP_ATTRIBUTE, CREATETIMESTAMP_ATTRIBUTE, MODIFIERSNAME_ATTRIBUTE, CREATORSNAME_ATTRIBUTE);
		
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
		
		try {
			EntryCursor searchCursor = getConnection().search(baseContext, searchFilter, SearchScope.SUBTREE, attributesToGet);
			while (searchCursor.next()) {
				Entry entry = searchCursor.get();
				LOG.ok("Found entry: {0}", entry);
				numFoundEntries++;
				
				// TODO: filter out by modifiersName
				
				// TODO: filter out by object class
				
				SyncDeltaBuilder deltaBuilder = new SyncDeltaBuilder();
				SyncDeltaType deltaType = SyncDeltaType.CREATE_OR_UPDATE;
				
				SyncToken deltaToken = null;
				Attribute modifyTimestampAttribute = entry.get(MODIFYTIMESTAMP_ATTRIBUTE);
				if (modifyTimestampAttribute != null) {
					deltaToken = new SyncToken(modifyTimestampAttribute.getString());
				} else {
					Attribute createTimestampAttribute = entry.get(CREATETIMESTAMP_ATTRIBUTE);
					deltaToken = new SyncToken(createTimestampAttribute.getString());
					deltaType = SyncDeltaType.CREATE;
				}
				deltaBuilder.setToken(deltaToken);
				
				deltaBuilder.setDeltaType(deltaType);
				ConnectorObject targetObject = getSchemaTranslator().toIcfObject(icfObjectClassInfo, entry);
				deltaBuilder.setObject(targetObject);
				
				handler.handle(deltaBuilder.build());
				numProcessedEntries++;
			}
			searchCursor.close();
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

	private String createSeachFilter(String fromTokenValue) {
		Value<String> ldapValue = new StringValue(fromTokenValue);
		ExprNode filterNode =
				new OrNode(
						new GreaterEqNode<String>(MODIFYTIMESTAMP_ATTRIBUTE, ldapValue),
						new GreaterEqNode<String>(CREATETIMESTAMP_ATTRIBUTE, ldapValue)
				);
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
