/**
 * Copyright (c) 2015-2016 Evolveum
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
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * Very simple search without any controls (paging). The most efficient thing to do.
 * 
 * @author Radovan Semancik
 */
public class DefaultSearchStrategy<C extends AbstractLdapConfiguration> extends SearchStrategy<C> {
	
	private static final Log LOG = Log.getLog(DefaultSearchStrategy.class);

	public DefaultSearchStrategy(ConnectionManager<C> connectionManager, AbstractLdapConfiguration configuration,
			AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, ResultsHandler handler,
			OperationOptions options) {
		super(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.identityconnectors.framework.common.objects.ResultsHandler)
	 */
	@Override
	public void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException {
		SearchRequest req = new SearchRequestImpl();
		req.setBase(baseDn);
		req.setFilter(filterNode);
		req.setScope(scope);
		applyCommonConfiguration(req);
		if (attributes != null) {
			req.addAttributes(attributes);
		}
		
		LdapNetworkConnection connection = getConnection(baseDn);
		Referral referral = null; // remember this in case we need a reconnect
		
		int numAttempts = 0;
		OUTER: while (true) {
			numAttempts++;
			if (numAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
				// TODO: better exception. Maybe re-throw exception from the last error?
				throw new ConnectorIOException("Maximum number of attemps exceeded");
			}
		
			SearchCursor searchCursor = executeSearch(connection, req);
			boolean proceed = true;
			try {
				while (proceed) {
					try {
						boolean hasNext = searchCursor.next();
						if (!hasNext) {
							break;
						}
					} catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
						logSearchError(connection, e);
						// Server disconnected. And by some miracle this was not caught by
						// checkAlive or connection manager.
						LOG.ok("Connection error ({0}), reconnecting", e.getMessage(), e);
						LdapUtil.closeCursor(searchCursor);
						connection = getConnectionReconnect(baseDn, referral);
						continue OUTER;
					}
					Response response = searchCursor.get();
					if (response instanceof SearchResultEntry) {
				        Entry entry = ((SearchResultEntry)response).getEntry();
				        logSearchResult(connection, entry);
				        proceed = handleResult(connection, entry);
				        
					} else {
				    	LOG.warn("Got unexpected response: {0}", response);
				    }
				}
				
				SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
				LdapUtil.closeCursor(searchCursor);
				
				if (searchResultDone == null) {
					break;
				} else {
					LdapResult ldapResult = searchResultDone.getLdapResult();
			    	logSearchResult(connection, "Done", ldapResult);
			    	
			    	if (ldapResult.getResultCode() == ResultCodeEnum.REFERRAL && !getConfiguration().isReferralStrategyThrow()) {
			    		referral = ldapResult.getReferral();
			    		if (getConfiguration().isReferralStrategyIgnore()) {
			    			LOG.ok("Ignoring referral {0}", referral);
			    		} else {
			    			LOG.ok("Following referral {0}", referral);
			    			connection = getConnection(baseDn, referral);
			    			if (connection == null) {
			    				throw new ConnectorIOException("Cannot get connection based on referral "+referral);
			    			}
			    		}
			    		
			    	} else if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
			    		break;
			    		
			    	} else {
						String msg = "LDAP error during search: "+LdapUtil.formatLdapMessage(ldapResult);
						if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
							LOG.ok("{0} (allowed error)", msg);
							setCompleteResultSet(false);
							break;
						} else {
							LOG.error("{0}", msg);
							throw LdapUtil.processLdapResult("LDAP error during search in "+baseDn, ldapResult);
						}
					}
			    	
				}
				
			} catch (CursorException e) {
				// TODO: better error handling
				throw new ConnectorIOException(e.getMessage(), e);
			}
		}
	}

}
