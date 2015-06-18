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
package com.evolveum.polygon.connector.ldap.search;

import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SearchResult;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

/**
 * Very simple search without any controls (paging). The most efficient thing to do.
 * 
 * @author Radovan Semancik
 */
public class DefaultSearchStrategy extends SearchStrategy {
	
	private static final Log LOG = Log.getLog(DefaultSearchStrategy.class);

	public DefaultSearchStrategy(LdapNetworkConnection connection, LdapConfiguration configuration,
			SchemaTranslator schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, ResultsHandler handler,
			OperationOptions options) {
		super(connection, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.identityconnectors.framework.common.objects.ResultsHandler)
	 */
	@Override
	public void search(String baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException {
		SearchRequest req = new SearchRequestImpl();
		req.setBase(new Dn(baseDn));
		req.setFilter(filterNode);
		req.setScope(scope);
		applyCommonConfiguration(req);
		if (attributes != null) {
			req.addAttributes(attributes);
		};
		
		SearchCursor searchCursor = executeSearch(req);
		boolean proceed = true;
		try {
			while (proceed && searchCursor.next()) {
				Response response = searchCursor.get();
				if (response instanceof SearchResultEntry) {
			        Entry entry = ((SearchResultEntry)response).getEntry();
			        logSearchResult(entry);
			        proceed = handleResult(entry);
			        
				} else {
			    	LOG.warn("Got unexpected response: {0}", response);
			    }
			}
			
			SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
			if (searchResultDone != null) {
				LdapResult ldapResult = searchResultDone.getLdapResult();
		    	logSearchResult("Done", ldapResult);    				
		    	if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
					String msg = "LDAP error during search: "+LdapUtil.formatLdapMessage(ldapResult);
					if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
						LOG.ok("{0} (allowed error)", msg);
						setCompleteResultSet(false);
					} else {
						LOG.error("{0}", msg);
						throw LdapUtil.processLdapResult("LDAP error during search", ldapResult);
					}
				}
			}
			
			searchCursor.close();
		} catch (CursorException e) {
			// TODO: better error handling
			throw new ConnectorIOException(e.getMessage(), e);
		}
	}

}
